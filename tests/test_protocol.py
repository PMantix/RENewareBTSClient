"""Offline tests for btsmon.protocol, replaying frames captured on 2026-11-13."""
import os
import struct

import pytest

from btsmon import protocol as P

CAP = os.path.join(os.path.dirname(__file__), "..", "captures", "2026-11-13", "probe_devices.log")


def _captured(marker: str) -> list[bytes]:
    if not os.path.exists(CAP):
        pytest.skip("capture not present")
    lines = open(CAP, encoding="utf-8").read().splitlines()
    return [bytes.fromhex(lines[i + 1].strip()) for i, l in enumerate(lines)
            if marker in l and i + 1 < len(lines) and lines[i + 1].startswith("        ff")]


def test_packets_match_observed_bytes():
    assert P.pkt_login().hex(" ") == "ff ff ff ff ff ff ff ff 00 00 12 00 00 03 01 02 18 5a"
    assert P.pkt_heartbeat(0).hex(" ") == "ff ff ff ff ff ff ff ff 00 00 17 00 fe 11 02 00 02 00 00 08 00 32 5a"
    assert P.pkt_get_device_info(35).hex(" ") == "ff ff ff ff ff ff ff ff 23 00 15 00 fe 01 02 19 02 00 00 54 5a"
    assert P.pkt_select_dev(35).hex(" ") == "ff ff ff ff ff ff ff ff 23 00 15 00 fe 1f 02 19 02 00 00 72 5a"


def test_unsafe_commands_refused():
    for code in (0x0208, 0x0209, 0x020A, 0x0203, 0x000A):   # stop/continue/jump/start/legacy stop
        with pytest.raises(ValueError):
            P.pkt_plus(code)


def test_split_frames_resync_and_checksum():
    a, b = P.pkt_login(), P.pkt_heartbeat(3)
    bad = bytearray(P.pkt_heartbeat(4))
    bad[-2] ^= 0xFF
    buf = bytearray(b"\x01\x02garbage" + a + bytes(bad) + b + b[:5])
    assert P.split_frames(buf) == [a, b]
    assert bytes(buf) == b[:5]


def test_rt_frame_from_capture():
    frames = _captured(" RT dev=35 unit=4")
    assert frames
    f = P.parse_frame(frames[0])
    assert f.cmd_ex == P.RT_DATA_83
    msg = P.decode(f.payload, P.RTDATA82_RESP)
    assert (msg["DevType"], msg["DevID"], msg["UnitID"]) == (25, 35, 4)
    rts = msg["RTData83"]
    assert [r["ChlID"] for r in rts] == list(range(1, 9))
    ch = P.rt_to_channel(rts[0])
    assert ch["work_state"] == "running"
    assert 3.0 < ch["voltage_v"] < 4.5 and 13 < ch["current_ma"] < 14


def test_device_info_from_capture():
    lines = open(CAP, encoding="utf-8").read().splitlines() if os.path.exists(CAP) else []
    raws = [bytes.fromhex(lines[i + 1].strip()) for i, l in enumerate(lines) if "PLUS 0x8201" in l]
    if not raws:
        pytest.skip("capture not present")
    infos = {}
    for r in raws:
        f = P.parse_frame(r)
        infos[f.dev_id] = P.decode(f.payload, P.RESP_GET_DEVICE_INFO)
    assert infos[35]["IP"] == "192.168.1.35" and infos[62]["IP"] == "192.168.0.2"
    assert len(infos[35]["DeviceInfo83"]["ChlMap"]) == 40
    assert infos[62]["DeviceInfo83"]["XwjInfo"][0]["CurrRange"] == [1.0, 25.0, 50.0]


def test_redact_svr_version():
    raw = bytearray(P.frame(bytes([0xFE, 0xFF]) + struct.pack("<H", 0x81) + bytes(640)))
    raw[60] = 0x41
    assert not any(P.redact_svr_version(bytes(raw))[48:168])


def test_livefeed_handles_captured_frames(tmp_path):
    from btsmon.live import LiveFeed
    frames = _captured(" RT dev=35 unit=4")
    feed = LiveFeed(log_dir=str(tmp_path))
    feed._handle(P.parse_frame(P.frame(bytes([0x80, 0x00]))), [], {})   # login ok
    assert feed.connected
    feed._handle(P.parse_frame(frames[0]), [], {})
    c = feed.channel("35-4-1")
    assert c and c["live"] and c["work_state"] == "running" and 3.0 < c["voltage_v"] < 4.5
    assert feed.channel("35-4-9") is None and feed.channel("bad") is None


def test_livefeed_schedules_info_and_select_from_device_list(tmp_path):
    from btsmon.live import LiveFeed
    devs = bytes.fromhex("0a0908191023180120 9b02 0a090819103e180120 9b02".replace(" ", ""))
    body = bytes([0xFF, 0x00]) + struct.pack("<H", 0x821B) + bytes(4) + bytes([0, 2]) + struct.pack("<H", 0) + devs
    f = P.parse_frame(P.frame(body))
    pending = []
    LiveFeed(log_dir=str(tmp_path))._handle(f, pending, {})
    sent = [p[1] for p in pending]
    assert sent == [P.pkt_get_device_info(35), P.pkt_select_dev(35), P.pkt_get_device_info(62), P.pkt_select_dev(62)] \
        or sorted(sent) == sorted([P.pkt_get_device_info(35), P.pkt_select_dev(35), P.pkt_get_device_info(62), P.pkt_select_dev(62)])
