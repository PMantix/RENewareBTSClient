"""Parse Neware .ndc files written live by BtsServer 8.0 (NDC version 11).

Pure Python, no pandas/numpy. Layouts follow the open-source NewareNDA package
(BSD-3-Clause, `_read_ndc_11_filetype_*`) and were checked against this PC's files
(docs/findings.md F-DATA-4).

A test is a set of files sharing one stem, e.g. ``20261111_154358_250062_4_1_141``:
  <stem>.ndc          filetype 1:  per-point voltage/current
  <stem>_runInfo.ndc  filetype 18: sparse time/capacity/energy/timestamp records
  <stem>_step.ndc     filetype 7:  one record per executed step (cycle, step no, type)
All files: 4096-byte header page, then 4096-byte pages with a 132-byte page header.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

PAGE = 4096
PAGE_HDR = 132

STEP_TYPES = {
    1: "CC_Chg", 2: "CC_DChg", 3: "CV_Chg", 4: "Rest", 5: "Cycle", 6: "End",
    7: "CCCV_Chg", 8: "CP_DChg", 9: "CP_Chg", 10: "CR_DChg", 13: "Pause",
    16: "Pulse", 17: "SIM", 19: "CV_DChg", 20: "CCCV_DChg", 21: "Control",
    22: "OCV", 26: "CPCV_DChg", 27: "CPCV_Chg",
}


class NdcFormatError(ValueError):
    pass


def header(buf: bytes) -> tuple[int, int]:
    """Return (filetype, version) from the first page."""
    if len(buf) < 4:
        raise NdcFormatError("file too short")
    return buf[0], buf[2]


def _pages(buf: bytes):
    # Ignore a trailing partial page (file being extended while we read).
    for off in range(PAGE, len(buf) - PAGE + 1, PAGE):
        yield buf[off:off + PAGE]


def _check(buf: bytes, filetype: int) -> None:
    ft, ver = header(buf)
    if ver != 11:
        raise NdcFormatError(f"unsupported NDC version {ver} (only 11)")
    if ft != filetype:
        raise NdcFormatError(f"expected filetype {filetype}, got {ft}")


@dataclass
class Point:
    index: int          # 1-based record index, shared with runInfo
    voltage_v: float
    current_ma: float


def parse_data(buf: bytes) -> list[Point]:
    _check(buf, 1)
    out: list[Point] = []
    idx = 0
    for page in _pages(buf):
        for v, c in struct.iter_unpack("<ff", page[PAGE_HDR:-4]):
            idx += 1
            if v != 0:
                out.append(Point(idx, v * 1e-4, c))
    return out


@dataclass
class RunInfo:
    index: int
    step_time_s: float    # time within the current step
    dt_s: float
    charge_mah: float
    discharge_mah: float
    charge_mwh: float
    discharge_mwh: float
    timestamp: datetime   # device clock, UTC-aware; may be offset from PC clock
    step_seq: int         # ordinal of the executed step (1 = first step run)


_RI = struct.Struct("<ixffff8xiiiih")


def parse_runinfo(buf: bytes) -> list[RunInfo]:
    _check(buf, 18)
    out: list[RunInfo] = []
    seen: set[int] = set()
    last_raw = None
    seq = 0
    for page in _pages(buf):
        for t, qc, qd, ec, ed, dt, ts, step, index, ms in _RI.iter_unpack(page[PAGE_HDR:-16]):
            if index == 0 or index in seen:
                continue
            seen.add(index)
            if step != last_raw:      # NewareNDA _count_changes
                seq += 1
                last_raw = step
            out.append(RunInfo(index, t / 1000, dt / 1000, qc / 3600, qd / 3600,
                               ec / 3600, ed / 3600,
                               datetime.fromtimestamp(ts + ms / 1000, timezone.utc), seq))
    return out


@dataclass
class StepRec:
    seq: int            # 1-based ordinal, matches RunInfo.step_seq
    cycle: int
    step_no: int        # step number in the schedule
    step_type: str


def parse_steps(buf: bytes) -> list[StepRec]:
    _check(buf, 7)
    out: list[StepRec] = []
    for page in _pages(buf):
        for cycle, step_no, _, status, _ in struct.iter_unpack("<ii16sb12s", page[PAGE_HDR:-5]):
            if step_no != 0:
                out.append(StepRec(len(out) + 1, cycle + 1, step_no,
                                   STEP_TYPES.get(status, f"type{status}")))
    return out


@dataclass
class Snapshot:
    """Latest known state of one test, built from its three files."""
    points: int
    index: int
    voltage_v: float
    current_ma: float
    cycle: int | None
    step_no: int | None
    step_type: str | None
    step_seq: int | None
    step_time_s: float | None
    elapsed_s: float | None   # since first record (device clock)
    charge_mah: float | None
    discharge_mah: float | None
    device_time: datetime | None
    extrapolated: bool   # time/capacity extrapolated from last runInfo record

    def as_dict(self) -> dict:
        d = asdict(self)
        if self.device_time is not None:
            d["device_time"] = self.device_time.isoformat()
        return d


def snapshot(data: bytes, runinfo: bytes | None, steps: bytes | None) -> Snapshot | None:
    pts = parse_data(data)
    if not pts:
        return None
    last = pts[-1]
    ri = parse_runinfo(runinfo) if runinfo else []
    st = parse_steps(steps) if steps else []
    r = ri[-1] if ri else None
    step = None
    if r is not None and st:
        step = next((s for s in st if s.seq == r.step_seq), None)
    if step is None and st:
        step = st[-1]

    t = qc = qd = None
    when = None
    extrap = False
    if r is not None:
        t, qc, qd, when = r.step_time_s, r.charge_mah, r.discharge_mah, r.timestamp
        n = last.index - r.index
        if n > 0 and r.dt_s > 0:
            # Same approach as NewareNDA _data_interpolation, for the trailing points.
            extrap = True
            for p in pts:
                if p.index > r.index:
                    dq = r.dt_s * p.current_ma / 3600
                    if dq >= 0:
                        qc += dq
                    else:
                        qd -= dq
            t += n * r.dt_s
            when = datetime.fromtimestamp(when.timestamp() + n * r.dt_s, timezone.utc)
    elapsed = (when - ri[0].timestamp).total_seconds() if (when and ri) else None
    return Snapshot(len(pts), last.index, last.voltage_v, last.current_ma,
                    step.cycle if step else None, step.step_no if step else None,
                    step.step_type if step else None, step.seq if step else None,
                    t, elapsed, qc, qd, when, extrap)
