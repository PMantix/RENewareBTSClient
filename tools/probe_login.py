"""First live, read-only probe of BtsServer (TCP 8001).

Sends ONLY: login (cmd 0x00), Plus heartbeat (0x0211), Plus get-device-list (0x021B).
Never selects a device, never sends a channel command. Every frame in both directions is
logged with timestamps to logs/probe_<time>.log (git-ignored). Database credentials in the
server-version push (0x0081) are redacted from all output and logs.

    python tools/probe_login.py [--host 127.0.0.1] [--port 8001] [--seconds 30]
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from datetime import datetime

START = b"\xff" * 8
END = 0x5A
ALLOWED_TX = {"login", "heartbeat", "getdevlist"}  # hard allowlist


def frame(body_after_len: bytes, dev_lo=0, dev_hi=0) -> bytes:
    n = 8 + 2 + 2 + len(body_after_len) + 2
    head = START + bytes([dev_lo, dev_hi]) + struct.pack("<H", n)
    s = sum(head[8:] + body_after_len) & 0xFF
    return head + body_after_len + bytes([s, END])


def pkt_login() -> bytes:
    return frame(bytes([0x00, 0x03]) + struct.pack("<H", 0x0201))


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def pkt_plus(cmd_ex: int, proto: bytes, dev_type=0) -> bytes:
    return frame(bytes([0xFE]) + struct.pack("<H", cmd_ex) + bytes([dev_type, 2]) + struct.pack("<H", 0) + proto)


def pkt_heartbeat(counter: int) -> bytes:
    return pkt_plus(0x0211, b"\x08" + _varint(counter))


def pkt_getdevlist(client_ver: str = "8.0.1.493") -> bytes:
    s = client_ver.encode()
    return pkt_plus(0x021B, b"\x0a" + _varint(len(s)) + s)


# ---- decoding -----------------------------------------------------------------------
def split_frames(buf: bytearray):
    out = []
    while True:
        i = buf.find(START)
        if i < 0:
            del buf[:max(0, len(buf) - 7)]
            return out
        if i:
            del buf[:i]
        if len(buf) < 15:
            return out
        n = struct.unpack_from("<h", buf, 10)[0]
        if n < 15 or n >= 65536:
            del buf[:1]
            continue
        if len(buf) < n:
            return out
        f = bytes(buf[:n])
        del buf[:n]
        out.append(f)


def pb_decode(b: bytes, depth=0):
    """Generic protobuf decode -> list of (field, value); nested messages guessed."""
    out, i = [], 0
    try:
        while i < len(b):
            key = 0
            shift = 0
            while True:
                c = b[i]; i += 1
                key |= (c & 0x7F) << shift; shift += 7
                if not c & 0x80:
                    break
            f, wt = key >> 3, key & 7
            if wt == 0:
                v = 0; shift = 0
                while True:
                    c = b[i]; i += 1
                    v |= (c & 0x7F) << shift; shift += 7
                    if not c & 0x80:
                        break
                out.append((f, v))
            elif wt == 2:
                ln = 0; shift = 0
                while True:
                    c = b[i]; i += 1
                    ln |= (c & 0x7F) << shift; shift += 7
                    if not c & 0x80:
                        break
                raw = b[i:i + ln]; i += ln
                sub = pb_decode(raw, depth + 1) if depth < 4 else None
                if sub and isinstance(sub, list) and sub and all(isinstance(x, tuple) for x in sub) and raw and not raw.isascii():
                    out.append((f, sub))
                else:
                    try:
                        out.append((f, raw.decode("utf-8") if raw.isascii() else raw.hex()))
                    except UnicodeDecodeError:
                        out.append((f, raw.hex()))
            elif wt == 5:
                out.append((f, struct.unpack_from("<f", b, i)[0])); i += 4
            elif wt == 1:
                out.append((f, struct.unpack_from("<d", b, i)[0])); i += 8
            else:
                return None
        return out
    except (IndexError, struct.error):
        return None


def describe(f: bytes) -> tuple[str, bytes]:
    """Return (text, frame bytes safe to log)."""
    cmd = f[12]
    if cmd == 0x80:
        return f"LOGIN_RESP result={f[13]}", f
    if cmd in (0xFE, 0xFF) and len(f) >= 18:
        res, cmd_ex = f[13], struct.unpack_from("<H", f, 14)[0]
        if cmd_ex == 0x0081:
            ver = struct.unpack_from("<H", f, 16)[0]
            svr = f[18:48].split(b"\0", 1)[0].decode("latin1")
            red = bytearray(f)
            red[48:168] = b"\x00" * min(120, max(0, len(f) - 2 - 48))  # dbUser[20] + dbPwd[100]
            rest = f[168:-2]
            fields = [x.split(b"\0", 1)[0].decode("latin1", "replace") for x in
                      (rest[0:32], rest[32:132], rest[132:232], rest[232:488])]
            return (f"SVR_VERSION result={res} version=0x{ver:04X} svrVer={svr!r} "
                    f"svrGuid={fields[0]!r} sysVer={fields[2]!r} computer={fields[3]!r} "
                    f"(db credentials redacted)"), bytes(red)
        if cmd_ex & 0x0200 and len(f) >= 26:   # Plus response
            res_ex = struct.unpack_from("<I", f, 16)[0]
            dev_type, sub_flag, sub_idx = f[20], f[21], struct.unpack_from("<H", f, 22)[0]
            pb = pb_decode(f[24:-2])
            return (f"PLUS_RESP 0x{cmd_ex:04X} result={res} resultEx={res_ex} devType={dev_type} "
                    f"sub={sub_flag}/{sub_idx} proto={pb}"), f
        return f"EXT_RESP 0x{cmd_ex:04X} result={res} len={len(f)}", f
    if cmd == 0x7F and len(f) >= 19:
        cmd_ex = struct.unpack_from("<H", f, 13)[0]
        return f"SVR_CMD 0x{cmd_ex:04X} devType={f[15]} len={len(f)} proto={pb_decode(f[19:-2])}", f
    return f"OTHER cmd=0x{cmd:02X} len={len(f)}", f


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--seconds", type=float, default=30)
    a = ap.parse_args(argv)
    os.makedirs("logs", exist_ok=True)
    logpath = os.path.join("logs", f"probe_{datetime.now():%Y%m%d_%H%M%S}.log")
    log = open(logpath, "w", encoding="utf-8")
    t0 = time.monotonic()

    def emit(direction, text, raw):
        line = f"{time.monotonic() - t0:7.3f} {direction} {text}\n        {raw.hex(' ')}"
        print(line[:600] + (" ..." if len(line) > 600 else ""))
        log.write(line + "\n"); log.flush()

    def send(sock, kind, data):
        if kind not in ALLOWED_TX:
            raise RuntimeError(f"refusing to send {kind!r}: not in allowlist")
        emit("TX", kind, data)
        sock.sendall(data)

    buf = bytearray()
    sock = socket.create_connection((a.host, a.port), timeout=5)
    try:
        sock.settimeout(0.5)
        emit("--", f"connected {a.host}:{a.port} local {sock.getsockname()}", b"")
        send(sock, "login", pkt_login())
        plan = [(2.0, "heartbeat", lambda: pkt_heartbeat(0)),
                (3.0, "getdevlist", pkt_getdevlist),
                (12.0, "heartbeat", lambda: pkt_heartbeat(1)),
                (22.0, "heartbeat", lambda: pkt_heartbeat(2))]
        while time.monotonic() - t0 < a.seconds:
            while plan and time.monotonic() - t0 >= plan[0][0]:
                _, kind, mk = plan.pop(0)
                send(sock, kind, mk())
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                emit("--", "server closed the connection", b"")
                break
            buf += chunk
            for f in split_frames(buf):
                text, safe = describe(f)
                emit("RX", text, safe)
    finally:
        # Graceful half-close so the server sees an orderly FIN before we drop the socket
        # (an abrupt close made BtsServer log SessionDisconnect error 10038).
        try:
            sock.shutdown(socket.SHUT_WR)
            end = time.monotonic() + 1.0
            while time.monotonic() < end and sock.recv(65536):
                pass
        except OSError:
            pass
        sock.close()
        emit("--", f"closed; log at {logpath}", b"")
        log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
