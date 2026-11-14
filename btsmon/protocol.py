"""BtsServer 8.0 client protocol (TCP 8001): framing, the few packets we send, decoders.

Only packets that are Observed safe on the live rig are buildable here (login, Plus
heartbeat, get-device-list, get-device-info, select-device). See docs/findings.md
F-CS-3..9 and docs/protocol-clientserver.md. Nothing in this module controls a channel.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

START = b"\xff" * 8
END = 0x5A
DEV_TYPE_BTS83 = 25
CLIENT_VERSION = 0x0201          # Client801, as BTS.exe 8.0 sends (must have bits in 0xFE00)
CLIENT_VERSION_STR = "8.0.1.493"

# Plus command codes (request; response = | 0x8000)
PLUS_GET_DEVICE_INFO = 0x0201
PLUS_HEARTBEAT = 0x0211
PLUS_GET_DEVICE_LIST = 0x021B
PLUS_SELECT_DEV = 0x021F
PLUS_RESPONSES = {0x8201, 0x8211, 0x821B, 0x821D, 0x821F}
RT_DATA_83 = 0x80D4
SVR_VERSION = 0x0081

SAFE_REQUESTS = {"login", PLUS_HEARTBEAT, PLUS_GET_DEVICE_LIST, PLUS_GET_DEVICE_INFO, PLUS_SELECT_DEV}


# ---- framing ---------------------------------------------------------------------------
def frame(body_after_len: bytes, dev_lo: int = 0, dev_hi: int = 0) -> bytes:
    n = 8 + 2 + 2 + len(body_after_len) + 2
    head = START + bytes([dev_lo & 0xFF, dev_hi & 0xFF]) + struct.pack("<H", n)
    return head + body_after_len + bytes([sum(head[8:] + body_after_len) & 0xFF, END])


def split_frames(buf: bytearray) -> list[bytes]:
    """Remove and return complete frames from *buf* (resyncs on garbage)."""
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
        n = struct.unpack_from("<H", buf, 10)[0]
        if n < 15:
            del buf[:1]
            continue
        if len(buf) < n:
            return out
        f = bytes(buf[:n])
        del buf[:n]
        if f[-1] != END or (sum(f[8:-2]) & 0xFF) != f[-2]:
            continue  # corrupt frame: drop
        out.append(f)


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def pkt_login() -> bytes:
    return frame(bytes([0x00, 0x03]) + struct.pack("<H", CLIENT_VERSION))


def pkt_plus(cmd_ex: int, proto: bytes = b"", dev_type: int = 0, dev_id: int = 0) -> bytes:
    if cmd_ex not in SAFE_REQUESTS:
        raise ValueError(f"0x{cmd_ex:04X} is not an approved read-only request")
    body = bytes([0xFE]) + struct.pack("<H", cmd_ex) + bytes([dev_type, 2]) + struct.pack("<H", 0) + proto
    return frame(body, dev_id & 0xFF, dev_id >> 8)


def pkt_heartbeat(counter: int) -> bytes:
    return pkt_plus(PLUS_HEARTBEAT, b"\x08" + _varint(counter))


def pkt_get_device_list() -> bytes:
    s = CLIENT_VERSION_STR.encode()
    return pkt_plus(PLUS_GET_DEVICE_LIST, b"\x0a" + _varint(len(s)) + s)


def pkt_get_device_info(dev_id: int, dev_type: int = DEV_TYPE_BTS83) -> bytes:
    return pkt_plus(PLUS_GET_DEVICE_INFO, b"", dev_type, dev_id)


def pkt_select_dev(dev_id: int, dev_type: int = DEV_TYPE_BTS83) -> bytes:
    return pkt_plus(PLUS_SELECT_DEV, b"", dev_type, dev_id)


# ---- protobuf --------------------------------------------------------------------------
def _uv(b: bytes, i: int) -> tuple[int, int]:
    v = s = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return v, i


def pb_fields(b: bytes) -> list[tuple[int, int, object]]:
    """[(field, wiretype, value)]; length-delimited values stay bytes."""
    out, i = [], 0
    while i < len(b):
        key, i = _uv(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _uv(b, i)
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        elif wt == 2:
            n, i = _uv(b, i)
            v = b[i:i + n]
            i += n
        else:
            raise ValueError(f"unsupported wire type {wt}")
        out.append((f, wt, v))
    return out


def _signed32(v: int) -> int:
    v &= 0xFFFFFFFFFFFFFFFF
    return v - (1 << 64) if v >= 1 << 63 else v


def _val(wt: int, v, kind: str):
    if kind == "float":
        return struct.unpack("<f", v)[0]
    if kind == "double":
        return struct.unpack("<d", v)[0]
    if kind == "int":
        return _signed32(v)
    if kind == "bytes":
        return v
    if kind == "str":
        return v.split(b"\0", 1)[0].decode("latin1")
    return v  # uint


def decode(b: bytes, schema: dict) -> dict:
    """Decode with schema {field: (name, kind, repeated, subschema|None)}."""
    out: dict = {}
    for f, wt, v in pb_fields(b):
        spec = schema.get(f)
        if spec is None:
            continue
        name, kind, rep, sub = spec
        if sub is not None:
            vals = [decode(v, sub)]
        elif rep and wt == 2 and kind in ("float", "uint", "int"):  # packed
            vals = []
            if kind == "float":
                vals = [x[0] for x in struct.iter_unpack("<f", v)]
            else:
                j = 0
                while j < len(v):
                    x, j = _uv(v, j)
                    vals.append(_signed32(x) if kind == "int" else x)
        else:
            vals = [_val(wt, v, kind)]
        if rep:
            out.setdefault(name, []).extend(vals)
        else:
            out[name] = vals[0]
    return out


def S(name, kind="uint", rep=False, sub=None):
    return (name, kind, rep, sub)


RTDATA83 = {1: S("DataFlag", "int"), 2: S("ChlID", "int"), 3: S("AuxChlID", "int"), 4: S("Cycle"),
            5: S("StepID", "int"), 6: S("StepType", "int"), 7: S("WorkType"), 8: S("TestTime"),
            9: S("Volt", "float"), 10: S("Curr", "float"), 11: S("IR", "int"), 12: S("Temp"),
            13: S("CCap", "double"), 14: S("DCCap", "double"), 15: S("CEng", "double"),
            16: S("DCEng", "double"), 17: S("CurStepRange", "float"), 18: S("PrtCode"),
            19: S("TotalTime"), 20: S("SeqID"), 21: S("DfSeqIDCurr"), 22: S("TestID"),
            23: S("ReserveStopStep", "int"), 24: S("ReserveStopCycle"), 25: S("ReserveStopType", "int"),
            26: S("TotalCap", "double"), 27: S("TotalEng", "double"), 28: S("CapRetentionRate", "float")}
RTDATA82_RESP = {1: S("DevType", "int"), 2: S("DevID", "int"), 3: S("UnitID", "int"), 4: S("Result", "int"),
                 5: S("RTCount", "int"), 7: S("RTData83", rep=True, sub=RTDATA83)}

XWJ83 = {1: S("XwjNo"), 2: S("XwjChannel"), 3: S("ChlType"), 4: S("ChgRange", "float"),
         5: S("DChgRange", "float"), 6: S("CurrRange", "float", True), 7: S("VolRange", "float"),
         8: S("TempRange", "float"), 9: S("InnerResRange", "float"), 10: S("SampleRate"),
         13: S("FactorySN", "str"), 14: S("FactoryTime", "str"), 15: S("SoftVersion", "str"),
         16: S("Function"), 19: S("FirstCaliTime", "str"), 20: S("LatestCaliTime", "str")}
CHLMAP83 = {1: S("UnitID"), 2: S("ChlID"), 3: S("AuxID"), 4: S("RealChlID"), 5: S("ChlType")}
PARAL83 = {1: S("UnitID"), 2: S("ChlID"), 3: S("InsertTime")}
TEMPBOX83 = {1: S("UnitID"), 2: S("ChlID"), 3: S("TempBoxID"), 4: S("FloorID"), 5: S("ThermostatType")}
CHLMODE83 = {1: S("RealChlID"), 2: S("IsMainMode"), 4: S("SoftVersion", "str")}
DEVINFO83 = {2: S("RangeStruct"), 5: S("CreateNo", "str"), 6: S("FactoryTime", "str"),
             9: S("CNPLanguage"), 11: S("SoftVersion", "str"), 12: S("SN", "str"),
             13: S("ZwjFunc", "uint", True), 14: S("XwjInfo", rep=True, sub=XWJ83),
             15: S("ChlMap", rep=True, sub=CHLMAP83), 16: S("ParalInfo", rep=True, sub=PARAL83),
             17: S("TempBox", rep=True, sub=TEMPBOX83), 18: S("ChlMode", rep=True, sub=CHLMODE83)}
RESP_GET_DEVICE_INFO = {2: S("IP", "str"), 3: S("Version", "int"), 4: S("Remark", "str"),
                        5: S("DeviceInfo83", sub=DEVINFO83)}
DEVPARAM = {1: S("DevType"), 2: S("DevID"), 3: S("OnLineStatus"), 4: S("Version")}
RESP_GET_DEVICE_LIST = {1: S("Devs", rep=True, sub=DEVPARAM)}


# ---- received frames -------------------------------------------------------------------
@dataclass
class Frame:
    raw: bytes
    dev_id: int
    unit: int
    cmd: int
    cmd_ex: int | None
    result: int | None
    payload: bytes          # protobuf / body after the type-specific header
    sub_flag: int = 2
    sub_index: int = 0


def parse_frame(f: bytes) -> Frame:
    cmd = f[12]
    if cmd in (0xFE, 0xFF) and len(f) >= 18:
        cmd_ex = struct.unpack_from("<H", f, 14)[0]
        if cmd_ex in PLUS_RESPONSES and len(f) >= 26:
            return Frame(f, f[8] | (f[9] << 8), 0, cmd, cmd_ex, f[13], f[24:-2], f[21],
                         struct.unpack_from("<H", f, 22)[0])
        if cmd_ex == RT_DATA_83 and len(f) >= 22:
            n = struct.unpack_from("<I", f, 16)[0]
            return Frame(f, f[8], f[9], cmd, cmd_ex, f[13], f[20:20 + n])
        return Frame(f, f[8], f[9], cmd, cmd_ex, f[13], f[16:-2])
    if cmd == 0x7F and len(f) >= 19:
        return Frame(f, f[8] | (f[9] << 8), 0, cmd, struct.unpack_from("<H", f, 13)[0], None, f[19:-2])
    return Frame(f, f[8], f[9], cmd, None, f[13] if len(f) > 15 else None, f[14:-2])


def parse_svr_version(f: Frame) -> dict:
    """Server version push (0x0081). DB credentials in the frame are NOT returned."""
    b = f.raw
    return {"version": struct.unpack_from("<H", b, 16)[0],
            "svr_ver": b[18:48].split(b"\0", 1)[0].decode("latin1")}


def redact_svr_version(raw: bytes) -> bytes:
    r = bytearray(raw)
    r[48:min(168, len(r) - 2)] = bytes(max(0, min(168, len(r) - 2) - 48))
    return bytes(r)


# ---- interpretation --------------------------------------------------------------------
# Raw RTData83.WorkType -> state, as Common.WorkType.ToType (Common/common/WorkType.cs:121-157):
# values > 255 use the high byte; otherwise bits 0x30: 0 finish/idle, 16 running, 32 stop,
# anything else protect. Observed: 0, 16, 32 (F-CS-9).
_WT_HIGH = {1: "pause", 2: "finished", 3: "offline_pause", 4: "beep", 5: "sync_ctrl", 7: "light",
            8: "vacuum", 9: "release", 10: "leakage_rate", 11: "jam", 12: "wait_timeout",
            13: "reserve_pause", 14: "wait_start", 15: "finish_protect"}


def work_state(raw: int | None) -> str:
    if raw is None:
        return "unknown"
    if raw > 255:
        hi = raw >> 8
        if hi == 6:
            raw &= 0xFF
        else:
            return _WT_HIGH.get(hi, f"code{raw}")
    return {0: "idle", 16: "running", 32: "stopped"}.get(raw & 0x30, "protect")


def rt_to_channel(rt: dict) -> dict:
    """RTData83 raw -> engineering units (F-CS-9)."""
    return {
        "work_type": rt.get("WorkType"),
        "work_state": work_state(rt.get("WorkType")),
        "cycle": rt.get("Cycle"),
        "step_no": rt.get("StepID"),
        "step_type_code": rt.get("StepType"),
        "step_time_s": (rt.get("TestTime") or 0) / 1000,
        "voltage_v": (rt.get("Volt") or 0.0) * 1e-4,
        "current_ma": rt.get("Curr"),
        "charge_mah": (rt.get("CCap") or 0.0) / 3600,
        "discharge_mah": (rt.get("DCCap") or 0.0) / 3600,
        "charge_mwh": (rt.get("CEng") or 0.0) / 3600,
        "discharge_mwh": (rt.get("DCEng") or 0.0) / 3600,
        "protect_code": rt.get("PrtCode"),
        "test_id": rt.get("TestID"),
    }
