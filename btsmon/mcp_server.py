"""MCP server exposing the read-only Neware BTS monitor to AI agents.

All tools are read-only: they read BtsServer's live .ndc files with full file sharing
(btsmon.safe_read) and send nothing to BtsServer, the cyclers or MySQL. Results are
cached for MIN_POLL_S so agents cannot poll the files faster than that.

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
from .ndc import STEP_TYPES
from .monitor import DEFAULT_ROOT, MIN_POLL_S, ChannelState, TestFiles, discover, read_state
from .ndc import parse_data, parse_log, parse_runinfo, parse_steps
from .safe_read import read_shared

ROOT = os.environ.get("BTSMON_NDC_ROOT", DEFAULT_ROOT)
DAYS = int(os.environ.get("BTSMON_DAYS", "60"))
LIVE_ENABLED = os.environ.get("BTSMON_LIVE", "1") != "0"
_live: LiveFeed | None = None
RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

server = MCPServer(
    name="neware-bts-monitor",
    instructions=(
        "Read-only monitor of Neware BTS battery cyclers on this PC. Channels are named "
        "'<devID>-<unit>-<channel>' (e.g. '35-4-1'). State is running / finished / stopped / "
        "protect / unknown. When the live feed is connected (get_system_status), V/I/step/"
        "capacity come from the server's realtime stream (~2 s old, source='live'); otherwise "
        "from the server's data files (up to a few minutes old, source='files'). Device clocks run ~1 h ahead of the PC; 'device_time' fields use the "
        "device clock. Current is in mA (negative = discharge), capacity in mAh. "
        "This server cannot start, stop or change anything."),
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


def main() -> None:
    global _live
    if LIVE_ENABLED:
        _live = LiveFeed(log_dir=os.environ.get("BTSMON_LOG_DIR", os.path.join(os.getcwd(), "logs"))).start()
    try:
        server.run("stdio")
    finally:
        if _live:
            _live.stop()


if __name__ == "__main__":
    main()
