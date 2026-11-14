"""Offline tests for btsmon.start: packet layouts (from the decompiled CmdStart76..83), the
step-global record vs the server's StartInfo log, and the full transaction against a fake
BtsServer on localhost (never the real one)."""
import os
import socket
import struct
import threading
import zlib
from datetime import datetime

import pytest

from btsmon import protocol as P
from btsmon import start as T
from btsmon import steps as S

DATA = os.path.join(os.path.dirname(__file__), "data")
CH = {"dev_type": 25, "dev_id": 62, "unit": 1, "chl": 1}
DEV62 = {"zwj_func": [255, 255, 127],                       # observed device info, 2026-11-14
         "chl_ranges": {"1-1": {"chg_range_ma": 50.0, "ranges_ma": [1.0, 25.0, 50.0], "parallel": False}},
         "chl_map": {"1-1": {"real_chl": None, "aux_id": None}}}
SYSSET = {"StartModee": "0", "PrtWhenSingleStartt": "0", "IsSplitCCCV": "False", "IsCCCVRange": "True",
          "CurrAbsDefault": "100", "IsCVContinueCutoffDelay": "True", "CVContinueCutoffDelay": "100",
          "IsCCCVCurr0NotProtect": "False", "CapRetentionRateCycle": "5"}
SYSGLOBAL = {"ZeroRecord": "0", "PrtWhenPanErr": "0", "IsRevDataAddTime": "False", "IsCCDelaySampling": "False"}
GUID = bytes.fromhex("A6C4A6E710416B40B17F82478518DE26")
NOW = datetime(2026, 11, 13, 21, 30, 45)


def plan():
    return T.build_plan(os.path.join(DATA, "test_rest.xml"), CH, DEV62, SYSSET, SYSGLOBAL, NOW, GUID)


def _proto(pkt: bytes) -> dict:
    n = struct.unpack_from("<I", pkt, 15)[0]
    out: dict = {}
    for k, _, v in P.pb_fields(pkt[19:19 + n]):
        out.setdefault(k, []).append(v)
    return out


def test_stage_order_matches_gui_log():
    assert [s.name for s in plan().stages] == ["map", "barcode", "remark", "step", "step_global",
                                               "global_prt", "start"]


def test_map_packet():
    body = bytes([0xFE, 0x76, 0x00, 25]) + GUID + bytes([1, 0, 1, 1, 0, 0])   # 1 map: 1-1-0-0 (GUI log)
    assert plan().stages[0].packet == P.frame(body, 62, 1)
    assert plan().stages[0].packet[:12].hex(" ") == "ff ff ff ff ff ff ff ff 3e 01 28 00"


def test_barcode_and_start_contents():
    p = plan()
    bc = p.stages[1].packet
    assert bc[9] == 0 and bc[12:15] == bytes([0xFE, 0xD6, 0x00]) and bc[15:17] == bytes([25, 0])
    n = struct.unpack_from("<I", bc, 21)[0]
    f = {k: v for k, _, v in P.pb_fields(bc[25:25 + n])}
    assert f[1] == 25 and f[2] == 62 and f[4] == GUID and f[5] == 0 and 3 not in f
    assert f[6] == b"test_rest.xml" and f[7] == b"2026-11-13 21-30-45" and f[8] == b"" and f[10] == 0
    st = _proto(p.stages[-1].packet)
    assert st[5] == [GUID] and st[6] == [1] and st[8] == [b""] and st[9] == [b"2026-11-13 21-30-45"]
    assert st[11] == [b"2026-11-13 21-30-45"] and struct.unpack("<d", st[7][0])[0] == 0.0


def test_step_packet_carries_the_logged_records():
    p = plan()
    f = _proto(p.stages[3].packet)
    buf = f[9][0]
    assert f[5] == [3] and f[6] == [len(buf)] and f[7] == [1] and f[8] == [2] and f[10] == [GUID]
    pos, recs = 0, []
    while pos < len(buf):
        r, pos = S.decode_record(buf, pos)
        recs.append(r)
    assert [S.logged_form(r) for r in recs] == [S.logged_form(r) for r in p.records]


def test_step_global_matches_logged_254_record():
    buf = T.step_global_buf(100, None)
    body, crc = buf[:-4], struct.unpack("<I", buf[-4:])[0]
    maps = "".join(f"{x:08X}" for x in struct.unpack("<3I", body[:12]))
    assert (maps, body[12:].hex()) == ("800000008000000000000010", "0564000000")   # StartInfo rows
    assert crc == zlib.crc32(body)


def test_global_prt_by_capability():
    b = T.global_prt_buf(SYSGLOBAL, DEV62["zwj_func"])
    assert b[:5] == struct.pack("<IB", 0x400, 0) and struct.unpack("<I", b[5:])[0] == zlib.crc32(b[:5])
    assert T.global_prt_buf(SYSGLOBAL, [])[:4] == b"\0\0\0\0"
    with pytest.raises(ValueError):
        T.global_prt_buf(dict(SYSGLOBAL, FireTempH="60"), DEV62["zwj_func"])


def test_step_chunking():
    recs = [S.encode_record(S.StepRecord(4, {"limit_time": 1000, "remark": "x"}, i, i)) for i in range(1, 80)]
    pk = T.pkts_step(25, 62, 1, GUID, 1, recs)
    fs = [_proto(x) for x in pk]
    assert len(pk) > 1 and all(len(f[9][0]) <= T.STEP_CHUNK for f in fs)
    assert [f[7][0] for f in fs] == list(range(1, len(pk) + 1))
    assert [f[8][0] for f in fs] == [1] * (len(pk) - 1) + [2]
    assert b"".join(f[9][0] for f in fs) == b"".join(recs) and {f[6][0] for f in fs} == {len(b"".join(recs))}


def test_build_plan_refusals():
    with pytest.raises(ValueError, match="Ver16"):
        T.build_plan(os.path.join(DATA, "test_rest.xml"), CH, dict(DEV62, zwj_func=[255]), SYSSET, SYSGLOBAL)
    with pytest.raises(ValueError, match="aux"):
        T.build_plan(os.path.join(DATA, "test_rest.xml"), CH,
                     dict(DEV62, chl_map={"1-1": {"real_chl": 0, "aux_id": 3}}), SYSSET, SYSGLOBAL)


# ---- transaction against a fake server -------------------------------------------------
def _reply(cmd_ex, result=0, tests=()):
    req = cmd_ex & 0x7FFF
    if req == T.CMD_MAP:
        body = bytes([25]) + GUID
    elif req == T.CMD_BARCODE:
        pr = T.pb_int(1, 25) + T.pb_int(2, 62) + T.pb_int(4, result) + T.pb_bytes(5, GUID)
        body = bytes([25, 0]) + struct.pack("<II", 0, len(pr)) + pr
    elif req == 0x000A:
        body = bytes([25]) + struct.pack("<Q", 1)
    else:
        pr = T.pb_int(1, 25) + T.pb_int(2, 62) + T.pb_int(3, 1) + T.pb_int(4, result)
        for u, c, t in tests:
            pr += T.pb_bytes(5, T.pb_int(1, u) + T.pb_int(2, c) + T.pb_int(3, t))
        body = struct.pack("<I", len(pr)) + pr
    return P.frame(bytes([0xFE, result]) + struct.pack("<H", cmd_ex) + body, 62, 1)


def _fake_server(received, start_result=0):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        c, _ = srv.accept()
        c.settimeout(5)
        buf = bytearray()
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
                for f in P.split_frames(buf):
                    received.append(f)
                    if f[12] == 0x00:
                        c.sendall(P.frame(bytes([0x80, 0x00])))
                        continue
                    cmd = struct.unpack_from("<H", f, 13)[0]
                    c.sendall(P.frame(bytes([0xFE, 0x00]) + struct.pack("<H", 0x80E4) + b"\0" * 8, 62, 1))  # a push
                    if cmd == T.CMD_START:
                        c.sendall(_reply(cmd | 0x8000, start_result, [(1, 1, 142)] if start_result == 0 else []))
                    else:
                        c.sendall(_reply(cmd | 0x8000))
        except OSError:
            pass
        finally:
            c.close()
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_full_start_against_fake_server():
    received = []
    p = plan()
    r = T.run_plan(p, port=_fake_server(received), out=lambda s: None)
    assert r.ok and r.tests == [(1, 1, 142)] and not r.stop_sent
    sent = [struct.unpack_from("<H", f, 13)[0] for f in received[1:]]
    assert sent == [0x76, 0xD6, 0xC6, 0xD1, 0xF0, 0xD7, 0xEB, 0xE3]
    conf = _proto(received[-1])
    assert conf[5] == [GUID] and {k: v for k, _, v in P.pb_fields(conf[4][0])} == {1: 1, 2: 1, 3: 142}


def test_failed_start_reply_sends_safety_pause():
    received = []
    r = T.run_plan(plan(), port=_fake_server(received, start_result=3), out=lambda s: None)
    assert not r.ok and r.failed_stage == "start" and r.start_sent and r.stop_sent
    assert received[-1][12:15] == bytes([0xFE, 0x0A, 0x00])
