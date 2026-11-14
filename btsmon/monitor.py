"""Passive, read-only monitor of Neware BTS channels from the server's live .ndc files.

Sends nothing to BtsServer, the cyclers or MySQL. Files are read with full sharing
(btsmon.safe_read) and handles are held for milliseconds. Keep polling >= 30 s.

    python -m btsmon.monitor                 # table of the latest test per channel
    python -m btsmon.monitor --json
    python -m btsmon.monitor --watch 60      # refresh every 60 s
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone

from . import logcodes
from .ndc import NdcFormatError, Snapshot, parse_log, snapshot
from .safe_read import read_shared

DEFAULT_ROOT = r"C:\Program Files (x86)\NEWARE\BTSServer80\NdcFile"
MIN_POLL_S = 30

STEM_RE = re.compile(r"^(?P<date>\d{8})_(?P<time>\d{6})_(?P<devuid>\d+)_(?P<unit>\d+)_(?P<chl>\d+)_(?P<test>\d+)$")


@dataclass
class TestFiles:
    stem: str
    folder: str
    dev_type: int
    dev_id: int
    unit: int
    chl: int
    test_id: int
    started: datetime        # from file name, PC local time
    mtime: float             # newest mtime of the data file (PC clock)

    @property
    def channel(self) -> str:
        return f"{self.dev_id}-{self.unit}-{self.chl}"

    def path(self, suffix: str = "") -> str:
        return os.path.join(self.folder, f"{self.stem}{suffix}.ndc")


def discover(root: str = DEFAULT_ROOT, days: int = 60) -> dict[tuple[int, int, int, int], TestFiles]:
    """Latest test per channel (devType, devID, unit, chl). Directory listing only."""
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")
    latest: dict[tuple[int, int, int, int], TestFiles] = {}
    with os.scandir(root) as it:
        dirs = [e for e in it if e.is_dir() and e.name[:8].isdigit() and e.name[:8] >= cutoff
                and not e.name.endswith("NoTestInfoData")]
    for d in dirs:
        with os.scandir(d.path) as it:
            for e in it:
                if not e.name.endswith(".ndc"):
                    continue
                m = STEM_RE.match(e.name[:-4])
                if not m:
                    continue  # suffixed file (_runInfo, _step, ...)
                devuid = int(m["devuid"])
                key = (devuid // 10000, devuid % 10000, int(m["unit"]), int(m["chl"]))
                tf = TestFiles(e.name[:-4], d.path, key[0], key[1], key[2], key[3],
                               int(m["test"]),
                               datetime.strptime(m["date"] + m["time"], "%Y%m%d%H%M%S"),
                               e.stat().st_mtime)
                cur = latest.get(key)
                if cur is None or (tf.started, tf.test_id) > (cur.started, cur.test_id):
                    latest[key] = tf
    return latest


@dataclass
class ChannelState:
    channel: str
    dev_type: int
    test_id: int
    stem: str
    started: str
    file_age_s: float
    live: bool               # data file written recently
    snapshot: dict | None
    device_clock_offset_s: float | None
    state: str = "unknown"   # running / finished / stopped / protect / unknown
    reason: str | None = None
    last_events: list | None = None
    error: str | None = None


def read_state(tf: TestFiles, live_window_s: float = 900) -> ChannelState:
    age = time.time() - tf.mtime
    err = None
    snap: Snapshot | None = None
    events = []
    try:
        data = read_shared(tf.path())
        ri = read_shared(tf.path("_runInfo")) if os.path.exists(tf.path("_runInfo")) else None
        st = read_shared(tf.path("_step")) if os.path.exists(tf.path("_step")) else None
        snap = snapshot(data, ri, st)
        if os.path.exists(tf.path("_log")):
            events = parse_log(read_shared(tf.path("_log")))
    except (OSError, NdcFormatError, ValueError) as e:
        err = f"{type(e).__name__}: {e}"
    live = age < live_window_s
    state, reason = logcodes.end_state(events)
    if state not in ("finished", "stopped", "protect", "cleared"):
        state, reason = ("running", None) if live else ("unknown", reason)
    elif live and snap and events and max(e.index for e in events) < snap.index:
        # a terminal event older than the newest data point belongs to an earlier
        # stop/resume; the channel is running again
        state, reason = "running", None
    last_events = [{"seq": e.seq, "time": e.device_time.isoformat(sep=" ") if e.device_time else None,
                    "step_no": e.step_no, "step_type": e.step_type, "code": e.code,
                    "event": logcodes.describe(e.code)} for e in events[-5:]]
    offset = None
    if snap and snap.device_time and not snap.extrapolated:
        offset = snap.device_time.timestamp() - tf.mtime
    elif snap and snap.device_time:
        offset = snap.device_time.timestamp() - tf.mtime  # rough when extrapolated
    return ChannelState(tf.channel, tf.dev_type, tf.test_id, tf.stem,
                        tf.started.isoformat(sep=" "), round(age, 1), live,
                        snap.as_dict() if snap else None,
                        round(offset, 0) if offset is not None else None,
                        state, reason, last_events, err)


def scan(root: str = DEFAULT_ROOT, days: int = 60, only_live: bool = False) -> list[ChannelState]:
    states = [read_state(tf) for _, tf in sorted(discover(root, days).items())]
    return [s for s in states if s.live] if only_live else states


def _fmt(v, f):
    return "-" if v is None else format(v, f)


def print_table(states: list[ChannelState]) -> None:
    print(f"{'channel':<10} {'test':>5} {'state':<9} {'age':>6} {'V':>8} {'mA':>10} "
          f"{'cyc':>4} {'step':>4} {'type':<10} {'step(h)':>7} {'test(h)':>7} {'Qc mAh':>9} {'Qd mAh':>9}")
    for s in states:
        n = s.snapshot or {}
        print(f"{s.channel:<10} {s.test_id:>5} {s.state:<9} "
              f"{_fmt(s.file_age_s / 60, '5.0f')}m "
              f"{_fmt(n.get('voltage_v'), '8.4f')} {_fmt(n.get('current_ma'), '10.4f')} "
              f"{_fmt(n.get('cycle'), '4d')} {_fmt(n.get('step_no'), '4d')} "
              f"{(n.get('step_type') or '-'):<10} "
              f"{_fmt(None if n.get('step_time_s') is None else n['step_time_s'] / 3600, '7.2f')} "
              f"{_fmt(None if n.get('elapsed_s') is None else n['elapsed_s'] / 3600, '7.2f')} "
              f"{_fmt(n.get('charge_mah'), '9.3f')} {_fmt(n.get('discharge_mah'), '9.3f')}"
              + (f"  {s.reason}" if s.reason and s.state in ("protect", "cleared") else "")
              + (f"  ERROR {s.error}" if s.error else ""))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--days", type=int, default=60, help="only look at test folders this recent")
    ap.add_argument("--live", action="store_true", help="only channels written in the last 15 min")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--watch", type=float, default=0, help=f"refresh period in s (min {MIN_POLL_S})")
    a = ap.parse_args(argv)
    while True:
        states = scan(a.root, a.days, a.live)
        if a.json:
            print(json.dumps([asdict(s) for s in states], indent=1))
        else:
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            print_table(states)
        if not a.watch:
            return 0
        time.sleep(max(a.watch, MIN_POLL_S))


if __name__ == "__main__":
    sys.exit(main())
