"""Tests for btsmon.ndc / btsmon.monitor using synthetic NDC v11 files (no hardware)."""
import os
import struct
import time
from datetime import datetime, timezone

import pytest

from btsmon import ndc
from btsmon.monitor import discover, read_state

PAGE, HDR = 4096, 132


def _file(filetype: int, records: list[bytes], rec_size: int, tail: int) -> bytes:
    head = bytearray(PAGE)
    head[0], head[2] = filetype, 11
    per_page = (PAGE - HDR - tail) // rec_size
    out = bytes(head)
    for i in range(0, max(len(records), 1), per_page):
        chunk = b"".join(records[i:i + per_page])
        body = chunk + bytes(PAGE - HDR - tail - len(chunk))
        out += bytes(HDR) + body + bytes(tail)
    return out


def make_data(points):  # [(V, mA)]
    return _file(1, [struct.pack("<ff", v / 1e-4, c) for v, c in points], 8, 4)


RI = struct.Struct("<ixffff8xiiiih")
T0 = 1_800_000_000


def make_runinfo(recs):  # [(index, step_raw, step_time_ms, qc_mAs, dt_ms, ts)]
    return _file(18, [RI.pack(t, qc, 0, 0, 0, dt, ts, step, idx, 0)
                      for idx, step, t, qc, dt, ts in recs], RI.size, 16)


def make_steps(steps):  # [(cycle0, step_no, type)]
    return _file(7, [struct.pack("<ii16sb12s", c, n, b"", t, b"") for c, n, t in steps], 37, 5)


def test_header_and_version_check():
    buf = make_data([(3.5, 1.0)])
    assert ndc.header(buf) == (1, 11)
    bad = bytearray(buf)
    bad[2] = 14
    with pytest.raises(ndc.NdcFormatError):
        ndc.parse_data(bytes(bad))
    with pytest.raises(ndc.NdcFormatError):
        ndc.parse_runinfo(buf)  # wrong filetype


def test_parse_data_skips_zero_and_keeps_index():
    pts = ndc.parse_data(make_data([(3.0, 0.0), (0.0, 0.0), (3.2, -5.0)]))
    assert [p.index for p in pts] == [1, 3]
    assert pts[1].voltage_v == pytest.approx(3.2, abs=1e-6)
    assert pts[1].current_ma == pytest.approx(-5.0)


def test_parse_data_spans_pages_and_ignores_partial_page():
    n = 1200  # > 2 pages of 495 records
    buf = make_data([(3.0 + i * 1e-4, 1.0) for i in range(n)])
    assert len(ndc.parse_data(buf)) == n
    assert len(ndc.parse_data(buf + b"\x01" * 100)) == n  # being extended


def test_runinfo_step_seq_counts_changes_and_dedups():
    buf = make_runinfo([(1, 5, 0, 0, 100, T0), (1, 5, 0, 0, 100, T0),
                        (2, 5, 100, 0, 100, T0), (3, 9, 0, 0, 100, T0 + 1)])
    ri = ndc.parse_runinfo(buf)
    assert [r.index for r in ri] == [1, 2, 3]
    assert [r.step_seq for r in ri] == [1, 1, 2]
    assert ri[2].timestamp == datetime.fromtimestamp(T0 + 1, timezone.utc)


def test_snapshot_extrapolates_trailing_points():
    data = make_data([(3.6, 10.0)] * 5)
    ri = make_runinfo([(1, 1, 0, 0, 10_000, T0), (3, 2, 20_000, 3600 * 2, 10_000, T0 + 20)])
    st = make_steps([(0, 1, 4), (0, 2, 7)])
    s = ndc.snapshot(data, ri, st)
    assert s.index == 5 and s.extrapolated
    assert (s.step_no, s.step_type, s.cycle) == (2, "CCCV_Chg", 1)
    assert s.step_time_s == pytest.approx(40.0)               # 20 s + 2 points * 10 s
    assert s.charge_mah == pytest.approx(2 + 2 * 10 * 10 / 3600)
    assert s.elapsed_s == pytest.approx(40.0)


def test_discover_and_read_state(tmp_path):
    day = tmp_path / datetime.now().strftime("%Y%m%d")
    day.mkdir()
    old = "20000101_000000_250035_4_1_10"
    new = datetime.now().strftime("%Y%m%d_%H%M%S") + "_250035_4_1_11"
    for stem in (old, new):
        (day / f"{stem}.ndc").write_bytes(make_data([(3.7, 1.0)]))
        (day / f"{stem}_runInfo.ndc").write_bytes(make_runinfo([(1, 1, 0, 0, 1000, T0)]))
        (day / f"{stem}_step.ndc").write_bytes(make_steps([(0, 1, 7)]))
    found = discover(str(tmp_path), days=5)
    tf = found[(25, 35, 4, 1)]
    assert tf.test_id == 11 and tf.channel == "35-4-1"
    st = read_state(tf)
    assert st.error is None and st.live
    assert st.snapshot["voltage_v"] == pytest.approx(3.7, abs=1e-6)


# ---- _log.ndc ----------------------------------------------------------------------
from btsmon import logcodes  # noqa: E402


def make_log_rec(seq, step_no, step_type, code, v=3.5, ma=0.0, step_ms=0, index=1,
                 when=(2026, 11, 11, 10, 0, 0)):
    r = bytearray(88)
    r[0] = 0xAA
    struct.pack_into("<I", r, 1, seq)
    r[9], r[11] = step_no, step_type
    struct.pack_into("<I", r, 17, step_ms)
    struct.pack_into("<ff", r, 25, v / 1e-4, ma)
    struct.pack_into("<H", r, 33, code)
    struct.pack_into("<HBBBBB", r, 69, *when)
    struct.pack_into("<I", r, 80, index)
    return bytes(r)


def make_log(recs):
    return _file(9, recs, 88, 4096 - 132 - 3960)


CODES = {
    0x1: logcodes.LogCode(0x1, "LOG_FINISH", "Finish", 0),
    0x2: logcodes.LogCode(0x2, "LOG_STOP", "Stop", 0),
    0x186: logcodes.LogCode(0x186, "LOG_CCC_VOL_UP", "CC, exceeding voltage limit.", 2),
    0x1B2: logcodes.LogCode(0x1B2, "LOG_TIME_LIMIT_CONDITION_JUMP", "Time limit jump", -1),
    0x285: logcodes.LogCode(0x285, "LOG_CHL_STATUS_CHANGED", "Channel status changed", 0),
    0xE4: logcodes.LogCode(0xE4, "LOG_USER_CLEAR_CHANNEL", "User clear channel", 0),
}


def test_parse_log_fields():
    ev = ndc.parse_log(make_log([make_log_rec(7, 38, 1, 0x186, v=4.3603, ma=23.94,
                                              step_ms=200, index=24219)]))
    e = ev[0]
    assert (e.seq, e.step_no, e.step_type, e.code, e.index) == (7, 38, "CC_Chg", 0x186, 24219)
    assert e.voltage_v == pytest.approx(4.3603, abs=1e-6)
    assert e.step_time_s == pytest.approx(0.2)
    assert e.device_time == datetime(2026, 11, 11, 10, 0, 0)


def test_parse_log_spans_pages():
    ev = ndc.parse_log(make_log([make_log_rec(i, 1, 4, 0x1B2) for i in range(1, 100)]))
    assert [e.seq for e in ev] == list(range(1, 100))


@pytest.mark.parametrize("codes,expected", [
    ([0x1B2, 0x1, 0x285], ("finished", None)),
    ([0x1B2, 0x2, 0x285], ("stopped", None)),
    ([0x1B2, 0x186, 0x285, 0xE4, 0x285], ("protect", "0x186 CC, exceeding voltage limit.")),
    ([0x1B2], ("unknown", "0x1B2 Time limit jump")),
    ([], ("unknown", None)),
])
def test_end_state(codes, expected):
    events = ndc.parse_log(make_log([make_log_rec(i + 1, 1, 4, c) for i, c in enumerate(codes)])) if codes else []
    assert logcodes.end_state(events, CODES) == expected
