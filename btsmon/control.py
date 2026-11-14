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


class Controller:
    """Runs control commands with guards. `feed` is a started btsmon.live.LiveFeed."""

    def __init__(self, feed, host: str = "127.0.0.1", port: int = 8001, log_dir: str | None = None):
        self.feed, self.host, self.port = feed, host, port
        self.log_dir = log_dir or os.path.join(REPO, "logs")
        self._tokens: dict[str, dict] = {}
        self._lock = threading.Lock()   # one control command at a time

    # -- checks
    def check(self, action: str, channel: str, step: int | None = None) -> tuple[dict, dict, bytes]:
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
        pkt = build_packet(action, ch, step)
        return ch, live, pkt

    # -- two-step (MCP)
    def prepare(self, action: str, channel: str, step: int | None = None) -> dict:
        ch, live, pkt = self.check(action, channel, step)
        token = secrets.token_hex(4)
        with self._lock:
            now = time.time()
            self._tokens = {k: v for k, v in self._tokens.items() if v["expires"] > now}
            self._tokens[token] = {"action": action, "channel": channel, "step": step,
                                   "expires": now + TOKEN_TTL_S}
        return {"token": token, "expires_in_s": TOKEN_TTL_S, "action": action, "channel": channel,
                "step": step, "what_it_does": ACTIONS[action].description,
                "channel_now": {k: live.get(k) for k in _KEYS},
                "expected_after": ACTIONS[action].expect, "load_on_channel": ch.get("load"),
                "bytes": pkt.hex(" ")}

    def execute_token(self, token: str) -> Result:
        with self._lock:
            t = self._tokens.pop(token, None)
        if t is None or t["expires"] < time.time():
            raise ControlRefused("unknown or expired token; call prepare again")
        return self.execute(t["action"], t["channel"], t["step"])

    # -- send
    def execute(self, action: str, channel: str, step: int | None = None) -> Result:
        with self._lock:
            return self._execute(action, channel, step)

    def _execute(self, action: str, channel: str, step: int | None) -> Result:
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
            ch, before, pkt = self.check(action, channel, step)   # re-check right before sending
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
