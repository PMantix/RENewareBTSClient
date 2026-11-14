"""Channel control commands for BTS83 (devType 25): pause, resume, jump, clear flag.

All four were verified live on 62-1-1 (docs/findings.md F-CS-12, F-CS-13). Guards, in
order, before anything is sent:
  1. the channel must be in config/test_channels.json (allowlist);
  2. the live feed must show a fresh reading in an allowed state for the action;
  3. (MCP) a prepare/execute token pair, so a human-visible summary precedes sending.
Each command uses its own short session (login, command, graceful close) so the
long-running live feed stays read-only. Everything is logged to logs/control_*.log.

Start is in btsmon/start.py (multi-packet transaction; built from code, not yet verified live).
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import protocol as P

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWLIST_PATH = os.environ.get("BTSMON_ALLOWLIST", os.path.join(REPO, "config", "test_channels.json"))
TOKEN_TTL_S = 60

CMD_STOP, CMD_CONTINUE, CMD_CLEAR, CMD_JUMP83 = 0x000A, 0x000D, 0x0097, 0x00EC


@dataclass(frozen=True)
class Action:
    name: str
    cmd_ex: int
    allowed_from: tuple[str, ...]
    expect: str
    description: str


ACTIONS = {
    "pause": Action("pause", CMD_STOP, ("running",), "stopped",
                    "Pause the running test (BTS 'stop'; resumable with resume)."),
    "resume": Action("resume", CMD_CONTINUE, ("stopped",), "running",
                     "Resume a paused/stopped test from where it stopped."),
    "jump": Action("jump", CMD_JUMP83, ("running",), "running",
                   "Jump the running test to schedule step <step> (GUI step number)."),
    "clear": Action("clear", CMD_CLEAR, ("stopped", "protect", "pause"), "idle",
                    "Clear the channel flag; ends the stopped/protected test, channel becomes idle."),
}


class ControlRefused(Exception):
    pass


# ---- packets ---------------------------------------------------------------------------
def pkt_chl_cmd(cmd_ex: int, dev_type: int, dev_id: int, unit: int, chl: int) -> bytes:
    """Legacy BTSCS channel command: devType u8 + channel mask u64 (stop/continue/clear)."""
    if cmd_ex not in (CMD_STOP, CMD_CONTINUE, CMD_CLEAR):
        raise ValueError("only stop/continue/clear-flag use this layout")
    if not 1 <= chl <= 64:
        raise ValueError("bad channel")
    body = bytes([0xFE]) + struct.pack("<H", cmd_ex) + bytes([dev_type]) + struct.pack("<Q", 1 << (chl - 1))
    return P.frame(body, dev_id, unit)


def _pb(fieldno: int, value: int) -> bytes:
    return P._varint(fieldno << 3) + P._varint(value & 0xFFFFFFFFFFFFFFFF)


def pkt_jump83(dev_type: int, dev_id: int, unit: int, chl: int, step_id: int) -> bytes:
    """PacketProto 0x00EC ProtocJump83{DevType, DevID, UnitID, Channel mask, StepID}."""
    if not 1 <= chl <= 64 or not 1 <= step_id <= 65535:
        raise ValueError("bad channel or step")
    proto = _pb(1, dev_type) + _pb(2, dev_id) + _pb(3, unit) + _pb(4, 1 << (chl - 1)) + _pb(5, step_id)
    return P.frame(bytes([0xFE]) + struct.pack("<HI", CMD_JUMP83, len(proto)) + proto, dev_id, unit)


def _file_hash(path: str) -> str:
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---- allowlist -------------------------------------------------------------------------
def load_allowlist(path: str = ALLOWLIST_PATH) -> dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("channels", {})
    except (OSError, ValueError):
        return {}


def build_packet(action: str, ch: dict, step: int | None) -> bytes:
    a = ACTIONS[action]
    if action == "jump":
        if step is None:
            raise ControlRefused("jump needs a step number")
        return pkt_jump83(ch["dev_type"], ch["dev_id"], ch["unit"], ch["chl"], step)
    return pkt_chl_cmd(a.cmd_ex, ch["dev_type"], ch["dev_id"], ch["unit"], ch["chl"])


# ---- execution -------------------------------------------------------------------------
@dataclass
class Result:
    ok: bool
    action: str
    channel: str
    sent_hex: str
    response: dict | None
    before: dict | None
    after: dict | None
    log: list[str] = field(default_factory=list)


_KEYS = ("work_state", "work_type", "step_no", "step_time_s", "voltage_v", "current_ma", "age_s")


@dataclass(frozen=True)
class Expect:
    """What the caller (agent) believes the channel looks like, from the user's description
    or the plan, NOT copied from a fresh reading. Checked against the live feed at prepare
    and again right before sending; any mismatch refuses the command (the check a person
    makes at the GUI before touching a channel)."""
    state: str                      # idle | running | stopped | protect | ...
    voltage_min_v: float
    voltage_max_v: float
    test_id: int | None = None      # the test expected on the channel (not for start)

    def as_dict(self) -> dict:
        return {"state": self.state, "voltage_v": [self.voltage_min_v, self.voltage_max_v],
                "test_id": self.test_id}


def check_expect(channel: str, live: dict, exp: Expect | None) -> None:
    if exp is None:
        return
    if not exp.voltage_min_v < exp.voltage_max_v:
        raise ControlRefused("expected voltage window must have min < max")
    seen_v = live.get("voltage_v")
    bad = []
    if live.get("work_state") != exp.state:
        bad.append(f"state is {live.get('work_state')!r}, expected {exp.state!r}")
    if seen_v is None or not exp.voltage_min_v <= seen_v <= exp.voltage_max_v:
        bad.append(f"voltage is {seen_v} V, expected {exp.voltage_min_v}..{exp.voltage_max_v} V")
    if exp.test_id is not None and live.get("test_id") != exp.test_id:
        bad.append(f"test id is {live.get('test_id')}, expected {exp.test_id}")
    if bad:
        raise ControlRefused(f"{channel} does not match what was expected: " + "; ".join(bad)
                             + ". Nothing sent. Tell the user what was found; do not adjust the "
                             "expectation to the reading without their OK.")


class Controller:
    """Runs control commands with guards. `feed` is a started btsmon.live.LiveFeed."""

    def __init__(self, feed, host: str = "127.0.0.1", port: int = 8001, log_dir: str | None = None):
        self.feed, self.host, self.port = feed, host, port
        self.log_dir = log_dir or os.path.join(REPO, "logs")
        self._tokens: dict[str, dict] = {}
        self._lock = threading.Lock()   # one control command at a time

    # -- checks
    def check(self, action: str, channel: str, step: int | None = None,
              expect: Expect | None = None) -> tuple[dict, dict, bytes]:
        if action not in ACTIONS:
            raise ControlRefused(f"unknown action {action!r}; one of {sorted(ACTIONS)}")
        allow = load_allowlist()
        ch = allow.get(channel)
        if ch is None:
            raise ControlRefused(f"{channel} is not in the control allowlist ({sorted(allow)}). "
                                 "Only the user can add channels to config/test_channels.json.")
        live = self.feed.channel(channel) if self.feed else None
        if not live or not live.get("live"):
            raise ControlRefused(f"no fresh live reading for {channel}; live feed must be connected")
        a = ACTIONS[action]
        if live["work_state"] not in a.allowed_from:
            raise ControlRefused(f"{action} needs {channel} to be {' or '.join(a.allowed_from)}, "
                                 f"it is {live['work_state']}")
        check_expect(channel, live, expect)
        pkt = build_packet(action, ch, step)
        return ch, live, pkt

    # -- two-step (MCP)
    def prepare(self, action: str, channel: str, step: int | None = None,
                expect: Expect | None = None) -> dict:
        ch, live, pkt = self.check(action, channel, step, expect)
        token = secrets.token_hex(4)
        with self._lock:
            now = time.time()
            self._tokens = {k: v for k, v in self._tokens.items() if v["expires"] > now}
            self._tokens[token] = {"action": action, "channel": channel, "step": step,
                                   "expect": expect, "expires": now + TOKEN_TTL_S}
        return {"token": token, "expires_in_s": TOKEN_TTL_S, "action": action, "channel": channel,
                "step": step, "what_it_does": ACTIONS[action].description,
                "expected": expect and expect.as_dict(),
                "channel_now": {k: live.get(k) for k in _KEYS},
                "expected_after": ACTIONS[action].expect, "load_on_channel": ch.get("load"),
                "bytes": pkt.hex(" ")}

    # -- start (btsmon.start; first live start OK 2026-11-14, test 142)
    def _start_plan(self, channel: str, step_file: str, expect: Expect | None = None):
        from . import gui_defaults, start
        ch = start.check_start(channel, self.feed)
        if expect is not None and expect.state != "idle":
            raise ControlRefused("a start expects the channel to be idle (no test running)")
        check_expect(channel, self.feed.channel(channel), expect)
        dev = (self.feed.snapshot().get("devices", {}) if self.feed else {}).get(ch["dev_id"])
        if not dev or not dev.get("zwj_func"):
            raise ControlRefused(f"no device info for device {ch['dev_id']} yet; live feed still connecting")
        try:
            plan = start.build_plan(step_file, ch, dev, gui_defaults.load_sysset(), start.load_sysglobal())
        except (ValueError, OSError) as e:
            raise ControlRefused(f"cannot start {step_file}: {e}")
        return ch, plan

    def prepare_start(self, channel: str, step_file: str, expect: Expect | None = None) -> dict:
        from . import start
        step_file = os.path.abspath(step_file)
        ch, plan = self._start_plan(channel, step_file, expect)
        live = self.feed.channel(channel)
        token = secrets.token_hex(4)
        with self._lock:
            now = time.time()
            self._tokens = {k: v for k, v in self._tokens.items() if v["expires"] > now}
            self._tokens[token] = {"action": "start", "channel": channel, "step": None,
                                   "step_file": step_file, "sha256": _file_hash(step_file),
                                   "expect": expect, "expires": now + TOKEN_TTL_S}
        return {"token": token, "expires_in_s": TOKEN_TTL_S, "action": "start", "channel": channel,
                "step_file": step_file, "steps": start.describe(plan.records),
                "expected": expect and expect.as_dict(),
                "what_it_does": "Start this schedule on the channel from step 1 (a new test).",
                "channel_now": {k: live.get(k) for k in _KEYS}, "expected_after": "running",
                "load_on_channel": ch.get("load"), "packets": [s.name for s in plan.stages] + ["confirm"]}

    def execute_start(self, channel: str, step_file: str, sha256: str | None = None,
                      expect: Expect | None = None) -> Result:
        with self._lock:
            return self._execute_start(channel, step_file, sha256, expect)

    def _execute_start(self, channel: str, step_file: str, sha256: str | None,
                       expect: Expect | None = None) -> Result:
        from . import start
        os.makedirs(self.log_dir, exist_ok=True)
        logf = open(os.path.join(self.log_dir, f"control_{datetime.now():%Y%m%d_%H%M%S}_start_{channel}.log"),
                    "w", encoding="utf-8")
        lines: list[str] = []

        def out(s: str) -> None:
            lines.append(s)
            logf.write(s + "\n")
            logf.flush()

        try:
            if sha256 is not None and _file_hash(step_file) != sha256:
                raise ControlRefused("the step file changed since prepare; prepare again")
            ch, plan = self._start_plan(channel, step_file, expect)   # re-check right before sending
            before = self.feed.channel(channel)
            out(f"start {step_file} on {channel}, guid {plan.guid_hex}")
            out(f"before: {{{', '.join(f'{k}: {before.get(k)}' for k in _KEYS)}}}")
            r = start.run_plan(plan, self.host, self.port, out=out)
            after = None
            test_id = r.tests[0][2] if r.ok and r.tests else None
            if test_id is not None:
                t_end = time.time() + 15
                while time.time() < t_end:
                    time.sleep(1)
                    after = self.feed.channel(channel)
                    if after and after.get("age_s", 99) < 3 and after.get("work_state") == "running" \
                            and after.get("test_id") == test_id:
                        break
            ok = bool(test_id is not None and after and after.get("work_state") == "running"
                      and after.get("test_id") == test_id)
            keys = _KEYS + ("test_id",)
            out(f"after: {after and {k: after.get(k) for k in keys}}")
            out("RESULT: " + ("OK" if ok else "NOT CONFIRMED - check the GUI"))
            resp = {"tests": r.tests, "failed_stage": r.failed_stage, "start_sent": r.start_sent,
                    "safety_pause_sent": r.stop_sent, "guid": plan.guid_hex}
            return Result(ok, "start", channel, "", resp, {k: before.get(k) for k in _KEYS},
                          after and {k: after.get(k) for k in keys}, lines)
        except ControlRefused as e:
            out(f"REFUSED: {e}. Nothing sent.")
            raise
        finally:
            logf.close()

    def execute_token(self, token: str) -> Result:
        with self._lock:
            t = self._tokens.get(token)
            if t is not None and t["action"] == "start":
                self._tokens.pop(token, None)
        if t is not None and t["action"] == "start":
            if t["expires"] < time.time():
                raise ControlRefused("unknown or expired token; call prepare again")
            return self.execute_start(t["channel"], t["step_file"], t["sha256"], t.get("expect"))
        with self._lock:
            t = self._tokens.pop(token, None)
        if t is None or t["expires"] < time.time():
            raise ControlRefused("unknown or expired token; call prepare again")
        return self.execute(t["action"], t["channel"], t["step"], t.get("expect"))

    # -- send
    def execute(self, action: str, channel: str, step: int | None = None,
                expect: Expect | None = None) -> Result:
        with self._lock:
            return self._execute(action, channel, step, expect)

    def _execute(self, action: str, channel: str, step: int | None, expect: Expect | None = None) -> Result:
        os.makedirs(self.log_dir, exist_ok=True)
        logf = open(os.path.join(self.log_dir, f"control_{datetime.now():%Y%m%d_%H%M%S}_{action}_{channel}.log"),
                    "w", encoding="utf-8")
        lines: list[str] = []

        def out(s: str) -> None:
            line = f"{datetime.now():%H:%M:%S.%f} {s}"
            lines.append(line)
            logf.write(line + "\n")
            logf.flush()

        try:
            ch, before, pkt = self.check(action, channel, step, expect)   # re-check right before sending
            a = ACTIONS[action]
            out(f"before: {{{', '.join(f'{k}: {before.get(k)}' for k in _KEYS)}}}")
            response = self._send(pkt, a.cmd_ex, out, action, channel)
            after = self._wait_after(channel, a, before, step)
            out(f"after: {after and {k: after.get(k) for k in _KEYS}}")
            ok = bool(response and response.get("result") == 0 and after and self._reached(a, before, after, step))
            out("RESULT: " + ("OK" if ok else "NOT CONFIRMED - check the GUI"))
            return Result(ok, action, channel, pkt.hex(" "), response,
                          {k: before.get(k) for k in _KEYS}, after and {k: after.get(k) for k in _KEYS}, lines)
        except ControlRefused as e:
            out(f"REFUSED: {e}. Nothing sent.")
            raise
        finally:
            logf.close()

    def _send(self, pkt: bytes, cmd_ex: int, out, action: str, channel: str) -> dict | None:
        s = socket.create_connection((self.host, self.port), timeout=5)
        s.settimeout(0.5)
        buf = bytearray()
        try:
            s.sendall(P.pkt_login())
            out("TX login")
            if not self._wait_login(s, buf, out):
                raise ControlRefused("login to BtsServer failed")
            out(f"TX {action} 0x{cmd_ex:04X} {channel}: {pkt.hex(' ')}")
            s.sendall(pkt)
            t0 = time.time()
            while time.time() - t0 < 5:
                try:
                    buf += s.recv(65536)
                except socket.timeout:
                    continue
                for raw in P.split_frames(buf):
                    f = P.parse_frame(raw)
                    if f.cmd_ex != (cmd_ex | 0x8000):
                        continue
                    if cmd_ex == CMD_JUMP83:
                        n = struct.unpack_from("<I", raw, 16)[0]
                        pf = {k: v for k, _, v in P.pb_fields(raw[20:20 + n])}
                        resp = {"cmd_ex": hex(f.cmd_ex), "result": pf.get(4, f.result), "channel_mask": pf.get(5)}
                    else:
                        resp = {"cmd_ex": hex(f.cmd_ex), "result": f.result,
                                "channel_mask": struct.unpack_from("<Q", raw, 17)[0]}
                    out(f"RX {resp}: {raw.hex(' ')}")
                    return resp
            out("no response within 5 s")
            return None
        finally:
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            s.close()

    @staticmethod
    def _wait_login(s, buf, out) -> bool:
        t0 = time.time()
        while time.time() - t0 < 5:
            try:
                buf += s.recv(65536)
            except socket.timeout:
                continue
            for raw in P.split_frames(buf):
                if raw[12] == 0x80:
                    out(f"RX login result={raw[13]}")
                    return raw[13] == 0
        return False

    @staticmethod
    def _reached(a: Action, before: dict, after: dict, step: int | None) -> bool:
        if after.get("work_state") != a.expect:
            return False
        if a.name == "jump":
            return after.get("step_no") == step and after.get("step_time_s", 1e9) < before.get("step_time_s", 0)
        return True

    def _wait_after(self, channel: str, a: Action, before: dict, step: int | None) -> dict | None:
        t_end = time.time() + 15
        after = None
        while time.time() < t_end:
            time.sleep(1)
            after = self.feed.channel(channel)
            if after and after.get("age_s", 99) < 3 and self._reached(a, before, after, step):
                break
        return after
