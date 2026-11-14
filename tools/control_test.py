"""Pause (legacy Stop 0x000A) / resume (Continue 0x000D) ONE allowlisted channel, verified.

Only channels in config/test_channels.json are accepted. Before sending, the live feed
must show the channel in the right state (pause: running; resume: stopped); after
sending, the tool waits for the response frame and for the live state to change.
Every frame is logged to logs/control_<time>.log.

Byte layout (BTSLib decompile, Inferred until this tool runs):
  FFx8 | devID u8 | unitID u8 | len u16 | FE | cmdEx u16 | devType u8 | chlMask u64 | sum | 5A
  mask bit = ChlID-1 (Network/Network/Client.cs:12162-12217, NetworkBase/BTSCS/PacketStop.cs)
  responses 0x800A / 0x800D with the same body.

    python tools/control_test.py pause  62-1-1
    python tools/control_test.py resume 62-1-1
    python tools/control_test.py jump   62-1-1 <step_no>
    python tools/control_test.py clear  62-1-1
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from btsmon import protocol as P  # noqa: E402
from btsmon.live import LiveFeed  # noqa: E402

# action: (cmdEx, required state(s) before, expected state after)
CMDS = {"pause": (0x000A, ("running",), "stopped"),
        "resume": (0x000D, ("stopped",), "running"),
        "jump": (0x00EC, ("running",), "running"),
        "clear": (0x0097, ("stopped", "protect", "pause"), "idle")}


def pkt_chl_cmd(cmd_ex: int, dev_type: int, dev_id: int, unit: int, chl: int) -> bytes:
    """Legacy BTSCS channel command: devType u8 + channel mask u64 (stop/continue/clear)."""
    if cmd_ex not in (0x000A, 0x000D, 0x0097):
        raise ValueError("only stop/continue/clear-flag are implemented")
    if not 1 <= chl <= 64:
        raise ValueError("bad channel")
    body = bytes([0xFE]) + struct.pack("<H", cmd_ex) + bytes([dev_type]) + struct.pack("<Q", 1 << (chl - 1))
    return P.frame(body, dev_id, unit)


def _pb(field: int, value: int) -> bytes:
    return P._varint(field << 3) + P._varint(value & 0xFFFFFFFFFFFFFFFF)


def pkt_jump83(dev_type: int, dev_id: int, unit: int, chl: int, step_id: int) -> bytes:
    """PacketProto 0x00EC ProtocJump83{DevType, DevID, UnitID, Channel mask, StepID}
    (Network/Network/Client.cs SendJump83). All fields written, as the C# proto2 code does."""
    if not 1 <= chl <= 64 or not 1 <= step_id <= 65535:
        raise ValueError("bad channel or step")
    proto = _pb(1, dev_type) + _pb(2, dev_id) + _pb(3, unit) + _pb(4, 1 << (chl - 1)) + _pb(5, step_id)
    body = bytes([0xFE]) + struct.pack("<HI", 0x00EC, len(proto)) + proto
    return P.frame(body, dev_id, unit)


def main(argv) -> int:
    action, name = argv[1], argv[2]
    step = int(argv[3]) if action == "jump" else None
    cmd_ex, need_before, want_after = CMDS[action]
    cfg = json.load(open(os.path.join(os.path.dirname(__file__), "..", "config", "test_channels.json")))
    ch = cfg["channels"].get(name)
    if ch is None:
        print(f"REFUSED: {name} is not in config/test_channels.json")
        return 2
    if action == "jump":
        pkt = pkt_jump83(ch["dev_type"], ch["dev_id"], ch["unit"], ch["chl"], step)
    else:
        pkt = pkt_chl_cmd(cmd_ex, ch["dev_type"], ch["dev_id"], ch["unit"], ch["chl"])
    os.makedirs("logs", exist_ok=True)
    log = open(os.path.join("logs", f"control_{datetime.now():%Y%m%d_%H%M%S}_{action}_{name}.log"), "w", encoding="utf-8")

    def out(s):
        line = f"{datetime.now():%H:%M:%S.%f} {s}"
        print(line); log.write(line + "\n"); log.flush()

    feed = LiveFeed().start()
    try:
        t_end = time.time() + 20
        while time.time() < t_end and not (feed.channel(name) or {}).get("live"):
            time.sleep(0.5)
        before = feed.channel(name)
        keys = ('work_state', 'work_type', 'step_no', 'step_time_s', 'voltage_v', 'current_ma', 'age_s')
        out(f"before: {before and {k: before[k] for k in keys}}")
        if not before or before["work_state"] not in need_before:
            out(f"REFUSED: {name} must be '{need_before}' for {action}, is "
                f"'{before and before['work_state']}'. Nothing sent.")
            return 3
        # separate short session for the command, so the feed's session stays read-only
        s = socket.create_connection(("127.0.0.1", 8001), timeout=5)
        s.settimeout(0.5)
        buf, got = bytearray(), None
        try:
            s.sendall(P.pkt_login()); out("TX login")
            t0 = time.time()
            logged_in = False
            while time.time() - t0 < 5 and not logged_in:
                try:
                    buf += s.recv(65536)
                except socket.timeout:
                    continue
                for raw in P.split_frames(buf):
                    if raw[12] == 0x80:
                        logged_in = raw[13] == 0
                        out(f"RX login result={raw[13]}")
            if not logged_in:
                out("login failed; nothing sent")
                return 4
            out(f"TX {action} 0x{cmd_ex:04X} {name}: {pkt.hex(' ')}")
            s.sendall(pkt)
            t0 = time.time()
            while time.time() - t0 < 5 and got is None:
                try:
                    buf += s.recv(65536)
                except socket.timeout:
                    continue
                for raw in P.split_frames(buf):
                    f = P.parse_frame(raw)
                    if f.cmd_ex == (cmd_ex | 0x8000):
                        got = f.result
                        if cmd_ex == 0x00EC:
                            n = struct.unpack_from("<I", raw, 16)[0]
                            resp = {fn: v for fn, _, v in P.pb_fields(raw[20:20 + n])}
                            got = resp.get(4, f.result)
                            out(f"RX response 0x{f.cmd_ex:04X} result={f.result} proto={resp}: {raw.hex(' ')}")
                        else:
                            dt, mask = raw[16], struct.unpack_from("<Q", raw, 17)[0]
                            out(f"RX response 0x{f.cmd_ex:04X} dev={f.dev_id} unit={f.unit} result={f.result} "
                                f"devType={dt} mask=0x{mask:X}: {raw.hex(' ')}")
                    elif f.cmd_ex is not None and f.cmd_ex not in (P.RT_DATA_83, P.SVR_VERSION, 0x80E4):
                        out(f"RX other 0x{f.cmd_ex:04X} result={f.result}: {raw[:40].hex(' ')}")
            if got is None:
                out("no response within 5 s")
        finally:
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            s.close()
        t_end = time.time() + 15
        after = None
        while time.time() < t_end:
            time.sleep(1)
            after = feed.channel(name)
            if after and after["work_state"] == want_after and after["age_s"] < 3 and (
                    action != "jump" or (after["step_no"] == step and after["step_time_s"] < before["step_time_s"])):
                break
        out(f"after: {after and {k: after[k] for k in keys}}")
        ok = got == 0 and after and after["work_state"] == want_after and (
            action != "jump" or (after["step_no"] == step and after["step_time_s"] < before["step_time_s"]))
        out("RESULT: " + ("OK" if ok else "NOT CONFIRMED - check the GUI"))
        return 0 if ok else 1
    finally:
        feed.stop()
        log.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
