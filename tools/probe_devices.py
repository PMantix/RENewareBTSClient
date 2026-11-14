"""Second live, read-only probe: device info for both devices + subscribe to ONE device.

Sends ONLY: login, Plus heartbeat (0x0211), get-device-list (0x021B), get-device-info
(0x0201) and select-device (0x021F, the realtime-data subscription). No channel commands.
Logs everything to logs/probe_dev_<time>.log; DB credentials in 0x0081 are redacted.

    python tools/probe_devices.py [--select 35] [--seconds 60]
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from collections import Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe_login import (describe, frame, pb_decode, pkt_getdevlist, pkt_heartbeat,  # noqa: E402
                         pkt_login, split_frames)

DEV_TYPE = 25
ALLOWED_TX = {"login", "heartbeat", "getdevlist", "getdevinfo", "selectdev"}
PLUS_RESP = {0x8201, 0x8211, 0x821B, 0x821F, 0x821D}

RT83 = {1: "DataFlag", 2: "ChlID", 3: "AuxChlID", 4: "Cycle", 5: "StepID", 6: "StepType",
        7: "WorkType", 8: "TestTime", 9: "Volt", 10: "Curr", 11: "IR", 12: "Temp", 13: "CCap",
        14: "DCCap", 15: "CEng", 16: "DCEng", 17: "CurStepRange", 18: "PrtCode", 19: "TotalTime",
        20: "SeqID", 21: "DfSeqIDCurr", 22: "TestID", 23: "ReserveStopStep",
        24: "ReserveStopCycle", 25: "ReserveStopType", 26: "TotalCap", 27: "TotalEng",
        28: "CapRetentionRate"}


def pkt_plus_dev(cmd_ex: int, dev_id: int, proto: bytes = b"") -> bytes:
    body = bytes([0xFE]) + struct.pack("<H", cmd_ex) + bytes([DEV_TYPE, 2]) + struct.pack("<H", 0) + proto
    return frame(body, dev_id & 0xFF, dev_id >> 8)


def pb_raw(b: bytes):
    """Decode protobuf keeping wire types (fixed64 as double, fixed32 as float)."""
    out, i = [], 0
    while i < len(b):
        key, i = _uv(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _uv(b, i)
        elif wt == 1:
            v = struct.unpack_from("<d", b, i)[0]; i += 8
        elif wt == 5:
            v = struct.unpack_from("<f", b, i)[0]; i += 4
        elif wt == 2:
            n, i = _uv(b, i); v = b[i:i + n]; i += n
        else:
            raise ValueError(f"wire type {wt}")
        out.append((f, v))
    return out


def _uv(b, i):
    v = s = 0
    while True:
        c = b[i]; i += 1
        v |= (c & 0x7F) << s; s += 7
        if not c & 0x80:
            return v, i


def decode_rt(proto: bytes):
    top = pb_raw(proto)
    hdr = {k: v for k, v in top if k in (1, 2, 3, 4, 5)}
    rows = []
    for k, v in top:
        if k == 7:
            rows.append({RT83.get(f, f): x for f, x in pb_raw(v)})
    return hdr, rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--select", type=int, default=35, help="DevID to subscribe to")
    ap.add_argument("--info", type=int, nargs="*", default=[35, 62])
    ap.add_argument("--seconds", type=float, default=60)
    a = ap.parse_args(argv)
    os.makedirs("logs", exist_ok=True)
    logpath = os.path.join("logs", f"probe_dev_{datetime.now():%Y%m%d_%H%M%S}.log")
    log = open(logpath, "w", encoding="utf-8")
    t0 = time.monotonic()
    counts = Counter()
    chunks: dict[tuple, bytearray] = {}
    rt_seen: dict[tuple, dict] = {}

    def emit(direction, text, raw=b"", quiet=False):
        line = f"{time.monotonic() - t0:7.3f} {direction} {text}" + (f"\n        {raw.hex(' ')}" if raw else "")
        if not quiet:
            print(line[:700] + (" ..." if len(line) > 700 else ""))
        log.write(line + "\n"); log.flush()

    def send(sock, kind, data):
        if kind not in ALLOWED_TX:
            raise RuntimeError(f"refusing to send {kind!r}: not in allowlist")
        emit("TX", kind, data)
        sock.sendall(data)

    def handle(f: bytes):
        cmd = f[12]
        if cmd in (0xFE, 0xFF) and len(f) >= 18:
            cmd_ex = struct.unpack_from("<H", f, 14)[0]
            counts[hex(cmd_ex)] += 1
            if cmd_ex in PLUS_RESP and cmd_ex != 0x8211 and len(f) >= 26:
                dev = f[8] | (f[9] << 8)
                sub_flag, sub_idx = f[21], struct.unpack_from("<H", f, 22)[0]
                key = (cmd_ex, dev)
                if sub_idx == 0:
                    chunks[key] = bytearray()
                chunks.setdefault(key, bytearray()).extend(f[24:-2])
                emit("RX", f"PLUS 0x{cmd_ex:04X} dev={dev} result={f[13]} chunk {sub_idx} flag {sub_flag} ({len(f)} B)", f, quiet=True)
                if sub_flag == 2:
                    data = bytes(chunks.pop(key))
                    top = pb_raw(data)
                    if cmd_ex == 0x8201:
                        summary = {}
                        for k, v in top:
                            if k == 2:
                                summary["IP"] = v.decode("latin1", "replace") if isinstance(v, bytes) else v
                            elif k == 3:
                                summary["Version"] = v
                            elif k == 4:
                                summary["Remark"] = v.decode("utf-8", "replace")
                            elif k in (1, 5):
                                summary["DevInfo" + ("83" if k == 5 else "")] = f"{len(v)} B"
                            elif k == 6:
                                summary["LockedChl"] = summary.get("LockedChl", 0) + 1
                        emit("RX", f"DEVINFO dev={dev}: {summary}")
                        emit("RX", f"DEVINFO dev={dev} full proto: {pb_decode(data)}", quiet=True)
                    else:
                        emit("RX", f"PLUS 0x{cmd_ex:04X} dev={dev} result={f[13]} proto={pb_decode(data)}")
                return
            if cmd_ex == 0x80D4:  # legacy proto realtime data
                n = struct.unpack_from("<I", f, 16)[0]
                hdr, rows = decode_rt(f[20:20 + n])
                for r in rows:
                    rt_seen[(hdr.get(2), hdr.get(3), r.get("ChlID"))] = r
                emit("RX", f"RT dev={hdr.get(2)} unit={hdr.get(3)} n={len(rows)} first={rows[0] if rows else None}", f,
                     quiet=counts[hex(cmd_ex)] > 3)
                return
        text, safe = describe(f)
        emit("RX", text, safe, quiet=(cmd in (0xFE, 0xFF) and counts[hex(struct.unpack_from('<H', f, 14)[0])] > 3))

    buf = bytearray()
    sock = socket.create_connection((a.host, a.port), timeout=5)
    try:
        sock.settimeout(0.5)
        emit("--", f"connected {a.host}:{a.port} local {sock.getsockname()}")
        send(sock, "login", pkt_login())
        plan = [(1.5, "heartbeat", lambda: pkt_heartbeat(0)),
                (2.0, "getdevlist", pkt_getdevlist)]
        t = 3.0
        for d in a.info:
            plan.append((t, "getdevinfo", lambda d=d: pkt_plus_dev(0x0201, d))); t += 1.5
        plan.append((t + 1.0, "selectdev", lambda: pkt_plus_dev(0x021F, a.select)))
        hb = 1
        for ht in range(12, int(a.seconds), 10):
            plan.append((float(ht), "heartbeat", lambda c=hb: pkt_heartbeat(c))); hb += 1
        plan.sort(key=lambda x: x[0])
        while time.monotonic() - t0 < a.seconds:
            while plan and time.monotonic() - t0 >= plan[0][0]:
                _, kind, mk = plan.pop(0)
                send(sock, kind, mk())
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                emit("--", "server closed the connection")
                break
            buf += chunk
            for f in split_frames(buf):
                handle(f)
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
            end = time.monotonic() + 1.0
            while time.monotonic() < end and sock.recv(65536):
                pass
        except OSError:
            pass
        sock.close()
        emit("--", f"closed. frames by cmdEx: {dict(counts)}")
        emit("--", "latest RT per (dev, unit, chl):")
        for k in sorted(rt_seen, key=lambda x: tuple(v or 0 for v in x)):
            r = rt_seen[k]
            emit("--", f"  {k}: WorkType={r.get('WorkType')} Step={r.get('StepID')}/{r.get('StepType')} "
                       f"Volt={r.get('Volt')} Curr={r.get('Curr')} CCap={r.get('CCap')} "
                       f"TestTime={r.get('TestTime')} PrtCode={r.get('PrtCode')}")
        emit("--", f"log at {logpath}")
        log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
