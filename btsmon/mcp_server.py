"""MCP server exposing the Neware BTS monitor (and guarded controls) to AI agents.

Monitoring tools are read-only: they read BtsServer's live .ndc files with full file
sharing (btsmon.safe_read) and the live feed. Results are cached for MIN_POLL_S so agents
cannot poll the files faster than that. Control tools (pause/resume/jump/clear/start) work
only on allowlisted channels and need a prepare call, the user's OK and an execute call.

Run (stdio):  .venv\\Scripts\\python -m btsmon.mcp_server
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import asdict

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import logcodes
from .live import LiveFeed
from .control import ACTIONS, ControlRefused, Controller, Expect, load_allowlist
from .ndc import STEP_TYPES
from .monitor import DEFAULT_ROOT, MIN_POLL_S, ChannelState, TestFiles, discover, read_state
from .ndc import parse_data, parse_log, parse_runinfo, parse_steps
from .safe_read import read_shared

ROOT = os.environ.get("BTSMON_NDC_ROOT", DEFAULT_ROOT)
DAYS = int(os.environ.get("BTSMON_DAYS", "60"))
LIVE_ENABLED = os.environ.get("BTSMON_LIVE", "1") != "0"
_live: LiveFeed | None = None
RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
CTRL = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
_ctl: Controller | None = None

server = MCPServer(
    name="neware-bts-monitor",
    instructions=(
        "Read-only monitor of Neware BTS battery cyclers on this PC. Channels are named "
        "'<devID>-<unit>-<channel>' (e.g. '35-4-1'). State is running / finished / stopped / "
        "protect / unknown. When the live feed is connected (get_system_status), V/I/step/"
        "capacity come from the server's realtime stream (~2 s old, source='live'); otherwise "
        "from the server's data files (up to a few minutes old, source='files'). Device clocks run ~1 h ahead of the PC; 'device_time' fields use the "
        "device clock. Current is in mA (negative = discharge), capacity in mAh. "
        "CONTROL: pause/resume/jump/clear exist ONLY for channels in the user's allowlist "
        "(list_control_channels) and need two calls: prepare_channel_command (checks, returns a "
        "summary + token) then execute_channel_command(token). Every prepare call states what you "
        "expect on the channel (state, voltage window, test id; for a start: idle and the cell's "
        "voltage window). Take these from the user or the plan, never from a reading you just "
        "made; a mismatch means the channel is not what everyone thinks it is: stop and tell the user. Show the summary to the user and "
        "get their explicit OK before executing. Never try to control a channel that is not "
        "allowlisted, and never retry a refused command in a different way. "
        "START: prepare_start_test(channel, step_file) checks an idle allowlisted channel and a "
        "BTS .xml step file (plain CC/CV/CCCV/rest/cycle/end schedules; others are refused) and "
        "returns the steps in readable units + a token; show them to the user, get an explicit "
        "OK, then execute_channel_command(token). A started test is stopped with pause + clear."),
)

_lock = threading.Lock()
_cache: dict[str, tuple[float, object]] = {}


def _cached(key: str, fn):
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < MIN_POLL_S:
            return hit[1]
    val = fn()
    with _lock:
        _cache[key] = (time.monotonic(), val)
    return val


def _tests() -> dict[str, TestFiles]:
    return _cached("discover", lambda: {tf.channel: tf for tf in discover(ROOT, DAYS).values()})


def _state(channel: str) -> ChannelState:
    tf = _tests().get(channel)
    if tf is None:
        raise ValueError(f"unknown channel {channel!r}; call list_channels for valid names")
    return _cached(f"state:{channel}", lambda: read_state(tf))


def _overlay_live(d: dict) -> dict:
    """Replace file-based values with the realtime feed when it is fresh."""
    lv = _live.channel(d["channel"]) if _live else None
    if not lv or not lv["live"]:
        d["source"] = "files"
        return d
    d.update({
        "source": "live", "data_age_min": round(lv["age_s"] / 60, 2),
        "voltage_v": round(lv["voltage_v"], 5), "current_ma": round(lv["current_ma"] or 0.0, 5),
        "step_no": lv["step_no"],
        "step_type": STEP_TYPES.get(lv["step_type_code"], d.get("step_type")),
        "step_time_h": round(lv["step_time_s"] / 3600, 3),
        "charge_mah": round(lv["charge_mah"], 4), "discharge_mah": round(lv["discharge_mah"], 4),
        "work_state": lv["work_state"], "protect_code": lv["protect_code"],
    })
    if lv["work_state"] == "running":
        d["state"], d["reason"] = "running", None
    elif lv["work_state"] == "stopped" and d["state"] == "running":
        d["state"] = "stopped"
    if lv["protect_code"]:
        d["protect_text"] = logcodes.describe(lv["protect_code"])
    return d


def _summary(s: ChannelState) -> dict:
    return _overlay_live(_summary_files(s))


def _summary_files(s: ChannelState) -> dict:
    n = s.snapshot or {}
    return {
        "channel": s.channel, "state": s.state, "reason": s.reason, "test_id": s.test_id,
        "started": s.started, "data_age_min": round(s.file_age_s / 60, 1),
        "voltage_v": n.get("voltage_v"), "current_ma": n.get("current_ma"),
        "cycle": n.get("cycle"), "step_no": n.get("step_no"), "step_type": n.get("step_type"),
        "step_time_h": None if n.get("step_time_s") is None else round(n["step_time_s"] / 3600, 3),
        "test_time_h": None if n.get("elapsed_s") is None else round(n["elapsed_s"] / 3600, 3),
        "charge_mah": n.get("charge_mah"), "discharge_mah": n.get("discharge_mah"),
        "error": s.error,
    }


@server.tool(annotations=RO)
def list_channels(only_running: bool = False) -> list[dict]:
    """List every channel with its latest test: state, V, mA, step, capacity, data age.

    only_running: return only channels whose test is currently running.
    """
    out = [_summary(_state(ch)) for ch in sorted(_tests())]
    return [s for s in out if s["state"] == "running"] if only_running else out


@server.tool(annotations=RO)
def get_system_status() -> dict:
    """Health of the monitor: realtime feed connection, BTS server version, devices
    (IP, channel count, current/voltage ranges = hardware limits), data sources."""
    snap = _live.snapshot() if _live else None
    return {
        "live_feed": "disabled" if snap is None else ("connected" if snap["connected"] else "disconnected"),
        "live_last_error": snap and snap["last_error"],
        "live_channels_fresh": snap and sum(1 for c in snap["channels"].values() if c["live"]),
        "server": snap and snap["server"],
        "devices": snap and snap["devices"],
        "files_root": ROOT,
    }


@server.tool(annotations=RO)
def get_channel(channel: str, events: int = 10) -> dict:
    """Full status of one channel ('devID-unit-chl', e.g. '62-3-1'): latest values, the
    executed step sequence, and the last `events` log events (step changes, finish, stop,
    protection codes with text)."""
    s = _state(channel)
    tf = _tests()[channel]

    def load():
        steps = parse_steps(read_shared(tf.path("_step"))) if os.path.exists(tf.path("_step")) else []
        evs = parse_log(read_shared(tf.path("_log"))) if os.path.exists(tf.path("_log")) else []
        return steps, evs
    steps, evs = _cached(f"detail:{channel}", load)
    d = _summary(s)
    d["files"] = tf.stem
    d["device_clock_offset_s"] = s.device_clock_offset_s
    d["steps_executed"] = [asdict(x) for x in steps]
    d["events"] = [{"seq": e.seq, "device_time": e.device_time.isoformat(sep=" ") if e.device_time else None,
                    "step_no": e.step_no, "step_type": e.step_type, "voltage_v": round(e.voltage_v, 4),
                    "current_ma": round(e.current_ma, 4), "step_time_s": e.step_time_s,
                    "event": logcodes.describe(e.code)} for e in evs[-max(1, min(events, 500)):]]
    return d


@server.tool(annotations=RO)
def get_channel_data(channel: str, last_hours: float = 2.0, max_points: int = 500) -> dict:
    """Recent voltage/current points for one channel, downsampled to at most
    `max_points`. Times are seconds since test start (device clock), filled between the
    sparse runInfo records using the recording interval."""
    tf = _tests().get(channel)
    if tf is None:
        raise ValueError(f"unknown channel {channel!r}")

    def load():
        pts = parse_data(read_shared(tf.path()))
        ri = parse_runinfo(read_shared(tf.path("_runInfo"))) if os.path.exists(tf.path("_runInfo")) else []
        return pts, ri
    pts, ri = _cached(f"data:{channel}", load)
    if not pts:
        return {"channel": channel, "points": []}
    # test time per point: anchor on runInfo records, step forward with their dt
    t0 = ri[0].timestamp.timestamp() if ri else None
    anchors = {r.index: (r.timestamp.timestamp() - t0 if t0 else None, r.dt_s) for r in ri}
    times, cur_t, cur_dt = [], None, 0.0
    for p in pts:
        if p.index in anchors:
            cur_t, cur_dt = anchors[p.index]
        elif cur_t is not None:
            cur_t += cur_dt
        times.append(cur_t)
    end = times[-1]
    sel = [(t, p) for t, p in zip(times, pts) if t is None or end is None or t >= end - last_hours * 3600]
    max_points = max(1, max_points)
    step = -(-len(sel) // max_points)  # ceil
    sel = sel[::-1][::step][::-1]       # keep the newest point
    return {"channel": channel, "test": tf.stem, "units": {"t": "s since start", "v": "V", "i": "mA"},
            "points": [{"t": None if t is None else round(t, 1), "v": round(p.voltage_v, 5),
                        "i": round(p.current_ma, 5), "index": p.index} for t, p in sel]}


@server.tool(annotations=RO)
def explain_log_code(code: str) -> dict:
    """Look up a Neware log/protection code (hex like '0x186' or decimal) in LogCode.csv."""
    c = int(code, 16) if code.lower().startswith("0x") else int(code)
    lc = logcodes.load().get(c)
    return {"code": hex(c), "name": lc.name if lc else None, "text": lc.text if lc else None,
            "severity_lamp": lc.lamp if lc else None}


@server.tool(annotations=RO)
def list_control_channels() -> dict:
    """Channels the user has released for control commands (config/test_channels.json),
    with their live state, and the available actions."""
    allow = load_allowlist()
    out = {}
    for name, ch in allow.items():
        lv = _live.channel(name) if _live else None
        out[name] = {"load": ch.get("load"), "approved": ch.get("approved"),
                     "work_state": lv and lv["work_state"], "step_no": lv and lv["step_no"],
                     "live": bool(lv and lv["live"])}
    return {"channels": out,
            "actions": dict({k: {"allowed_from": a.allowed_from, "result": a.expect, "what": a.description}
                             for k, a in ACTIONS.items()},
                            start={"allowed_from": ("idle",), "result": "running",
                                   "what": "Start a step file from step 1 (use prepare_start_test)."})}


@server.tool(annotations=RO)
def prepare_channel_command(channel: str, action: str, expected_state: str,
                            expected_voltage_min_v: float, expected_voltage_max_v: float,
                            expected_test_id: int, step: int | None = None) -> dict:
    """Step 1 of 2 for a control command. Checks the allowlist, then that the channel looks
    the way you expect it to, then returns a summary and a one-time token (valid 60 s).
    Sends nothing.

    action: pause | resume | jump | clear.  step: target step number (jump only).
    expected_*: what you believe is on the channel, from the user or your plan (which test,
    its state, the cell voltage range), NOT copied from a reading you just took. Any mismatch
    refuses the command; report it to the user instead of changing the expectation.
    Show the returned summary to the user and get an explicit OK before step 2.
    """
    if _ctl is None:
        return {"refused": "controls unavailable: live feed disabled"}
    try:
        exp = Expect(expected_state, expected_voltage_min_v, expected_voltage_max_v, expected_test_id)
        return _ctl.prepare(action, channel, step, exp)
    except (ControlRefused, ValueError) as e:
        return {"refused": str(e)}


@server.tool(annotations=RO)
def prepare_start_test(channel: str, step_file: str, expected_voltage_min_v: float,
                       expected_voltage_max_v: float) -> dict:
    """Step 1 of 2 for starting a test. Checks that the channel is allowlisted, idle (no test
    running) and shows a voltage inside the expected window (e.g. a cell just loaded for
    formation: its open-circuit voltage range, from the user / cell spec, not copied from a
    reading you just took; a channel with no cell floats near 0.4-0.5 V). Then loads
    the BTS .xml step file (refusing anything not supported, or currents/voltages beyond the
    channel's range), applies the GUI's start defaults, and returns the steps in readable
    units plus a one-time token (valid 60 s). Sends nothing.

    step_file: absolute path of a BTS Client step file (.xml).
    Show the steps to the user and get an explicit OK, then execute_channel_command(token).
    """
    if _ctl is None:
        return {"refused": "controls unavailable: live feed disabled"}
    try:
        return _ctl.prepare_start(channel, step_file,
                                  Expect("idle", expected_voltage_min_v, expected_voltage_max_v))
    except (ControlRefused, ValueError, OSError) as e:
        return {"refused": str(e)}


@server.tool(annotations=CTRL)
def execute_channel_command(token: str) -> dict:
    """Step 2 of 2: send the command prepared with prepare_channel_command or
    prepare_start_test, after the user explicitly approved it. Re-checks allowlist and state, sends, then verifies the result on
    the live feed. Returns ok, the server response and the before/after channel state."""
    if _ctl is None:
        return {"refused": "controls unavailable: live feed disabled"}
    try:
        r = _ctl.execute_token(token)
    except (ControlRefused, ValueError, OSError) as e:
        return {"refused": str(e), "sent": False}
    if r.action == "start":
        return {"ok": r.ok, "action": "start", "channel": r.channel, "result": r.response,
                "before": r.before, "after": r.after, "log": r.log[-12:],
                "note": None if r.ok else ("Not confirmed. If start_sent is true a safety pause was "
                                           "attempted; ask the user to check the GUI.")}
    return {"ok": r.ok, "action": r.action, "channel": r.channel, "response": r.response,
            "before": r.before, "after": r.after, "sent_bytes": r.sent_hex,
            "note": None if r.ok else "Not confirmed on the live feed: ask the user to check the GUI."}


def main() -> None:
    global _live, _ctl
    if LIVE_ENABLED:
        _live = LiveFeed(log_dir=os.environ.get("BTSMON_LOG_DIR", os.path.join(os.getcwd(), "logs"))).start()
        _ctl = Controller(_live)
    try:
        server.run("stdio")
    finally:
        if _live:
            _live.stop()


if __name__ == "__main__":
    main()
