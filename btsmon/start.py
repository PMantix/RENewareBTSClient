"""Start a test on one BTS83 channel: the GUI's CmdStart83 transaction, ported from the
decompiled client (NetworkBase/Network/CmdStart76.cs, CmdStart80.cs, CmdStart82.cs,
CmdStart83.cs; Network/Network/Client.cs SendStart83 / OnRespStart83).

STATUS: Inferred from code. The stage order and the logged contents (step records, the
step-global record, test row) match what the server logged for GUI starts (F-STEP-5,
F-START-*), but these packet bytes have not been seen on the wire yet. Nothing here may
be sent to the real BtsServer until the user approves a first start on a free channel
(CLAUDE.md rules 8/9).

Stages for one channel (each sent after the previous stage's reply, result 0):
  Map 0x0076 -> Barcode 0x00D6 -> Remark 0x00C6 -> Step 0x00D1 (1+ chunks)
  -> StepGlobal 0x00F0 -> GlobalPrt 0x00D7 -> Start 0x00EB -> StartConfirm 0x00E3
(Aux is skipped by CmdStart83; DBC/Smbus/GuidFile/SimFile/Paral/... are empty for the
schedules we support.)
"""
from __future__ import annotations

import os
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime

from . import protocol as P
from . import steps as S

DEV_TYPE_BTS83 = 25

CMD_MAP = 0x0076            # PacketSendChlMap70
CMD_BARCODE = 0x00D6        # PacketSendBarcode760 carrying ProtocBarcode
CMD_REMARK = 0x00C6         # ProtocRemark
CMD_STEP = 0x00D1           # ProtocSetStep82
CMD_STEP_GLOBAL = 0x00F0    # ProtocSetStepGlobal
CMD_GLOBAL_PRT = 0x00D7     # ProtocSetGrobalProtect82
CMD_START = 0x00EB          # ProtocStart83
CMD_CONFIRM = 0x00E3        # ProtocStartConfirm
START_COMMANDS = {CMD_MAP, CMD_BARCODE, CMD_REMARK, CMD_STEP, CMD_STEP_GLOBAL,
                  CMD_GLOBAL_PRT, CMD_START, CMD_CONFIRM}

STEP_CHUNK = 3500           # CmdStart82.SetStep: max StepBuf per packet for devType >= 25
BARCODE_CHUNK = 4000        # CmdStart76.SetBarcodeCmd


# ---- device capabilities (Device.EnableVer: EnumZwjVer.VerN = bit N-1 of ZwjFunc) -----
def has_ver(zwj_func: list[int], n: int) -> bool:
    i = n - 1
    return i // 8 < len(zwj_func) and bool(zwj_func[i // 8] >> (i % 8) & 1)


# ---- protobuf 2 writer (protobuf-csharp-port writes set fields in field-number order) --
def _key(n: int, wt: int) -> bytes:
    return P._varint(n << 3 | wt)


def pb_int(n: int, v: int) -> bytes:
    return _key(n, 0) + P._varint(int(v) & 0xFFFFFFFFFFFFFFFF)   # int32 < 0: 10-byte varint


def pb_bytes(n: int, b: bytes) -> bytes:
    return _key(n, 2) + P._varint(len(b)) + b


def pb_str(n: int, s: str) -> bytes:
    return pb_bytes(n, s.encode("utf-8"))


def pb_double(n: int, v: float) -> bytes:
    return _key(n, 1) + struct.pack("<d", v)


def _chl_info(unit: int, chl: int) -> bytes:
    """StartChlInfo / UnitChlInfo {1 UnitID, 2 ChlID}."""
    return pb_int(1, unit) + pb_int(2, chl)


def _ansi(s: str) -> bytes:
    """C# Encoding.Default = the PC's ANSI code page."""
    return s.encode("mbcs", "replace") if s else b""


def _utf8_limit(s: str, n: int) -> bytes:
    """CmdStart76.ToTuf8Bytes: whole characters while the UTF-8 length stays <= n."""
    out = b""
    for ch in s:
        b = ch.encode("utf-8")
        if len(out) + len(b) > n:
            break
        out += b
    return out


# ---- frames ----------------------------------------------------------------------------
def frame_proto(cmd_ex: int, proto: bytes, dev_id: int, unit: int) -> bytes:
    """PacketProto: FE | u16 cmdEx | u32 proto length | proto. Header bytes 8/9 are the
    proto's DevID/UnitID (PacketProto.Encode). Same layout as the verified jump (F-CS-13)."""
    return P.frame(bytes([0xFE]) + struct.pack("<HI", cmd_ex, len(proto)) + proto, dev_id & 0xFF, unit & 0xFF)


def frame_ex(cmd_ex: int, body: bytes, dev_id: int, unit: int) -> bytes:
    """Legacy PacketSendEx: FE | u16 cmdEx | body (as the verified pause/resume, F-CS-12)."""
    return P.frame(bytes([0xFE]) + struct.pack("<H", cmd_ex) + body, dev_id & 0xFF, unit & 0xFF)


# ---- stage packets ---------------------------------------------------------------------
def pkt_map(dev_type: int, dev_id: int, unit: int, guid: bytes, maps: list[tuple[int, int, int, int]]) -> bytes:
    """PacketSendChlMap70.Encode: devType u8 | guid[16] | u16 n | n x (unit, chl, aux, realChl)."""
    body = bytes([dev_type]) + guid + struct.pack("<H", len(maps))
    for m in maps:
        body += bytes(m)
    return frame_ex(CMD_MAP, body, dev_id, unit)


def proto_barcode(dev_type: int, dev_id: int, guid: bytes, step_name: str, batch_no: str,
                  test_name: str, barcodes: list[dict], is_cycle_start: int = 0) -> bytes:
    """CmdStart76.SetBarcodeCmd -> ProtocBarcode (UnitID and BatteryMass not set)."""
    b = pb_int(1, dev_type) + pb_int(2, dev_id) + pb_bytes(4, guid) + pb_int(5, 0)
    b += pb_str(6, step_name) + pb_str(7, batch_no) + pb_str(8, test_name)
    for bc in barcodes:
        sub = pb_int(1, bc["unit"]) + pb_int(2, bc["chl"]) + pb_str(3, bc.get("barcode", "").strip("\0"))
        sub += pb_bytes(4, _utf8_limit(bc.get("remark", "").strip("\0"), 100))
        sub += pb_str(5, bc.get("creator", "").strip("\0"))
        b += pb_bytes(9, sub)
    return b + pb_int(10, is_cycle_start)


def pkts_barcode(dev_type: int, dev_id: int, proto: bytes) -> list[bytes]:
    """PacketSendBarcode760: devType u8 | flag u8 (1 data, 0 last) | u32 index | u32 n | bytes.
    Header unit byte is 0 (UnitID not set)."""
    out = []
    chunks = [proto[i:i + BARCODE_CHUNK] for i in range(0, len(proto), BARCODE_CHUNK)] or [b""]
    for i, c in enumerate(chunks):
        flag = 0 if i == len(chunks) - 1 else 1
        out.append(frame_ex(CMD_BARCODE, bytes([dev_type, flag]) + struct.pack("<II", i, len(c)) + c, dev_id, 0))
    return out


def pkt_remark(dev_type: int, dev_id: int, unit: int, guid: bytes, mask: int, remark: str,
               chl_remarks: list[tuple[int, int, str]]) -> bytes:
    """CmdStart80.SetRemark -> ProtocRemark (cmdEx 198). chl_remarks: (unit, chl, remark);
    an empty channel remark falls back to the test remark."""
    b = pb_int(1, dev_type) + pb_int(2, dev_id) + pb_int(3, unit) + pb_bytes(4, _chl_info(unit, mask))
    b += pb_bytes(5, _ansi(remark)) + pb_bytes(6, guid)
    for u, c, r in chl_remarks:
        b += pb_bytes(7, pb_bytes(1, _chl_info(u, c)) + pb_bytes(2, _ansi(r.strip() and r or remark)))
    return frame_proto(CMD_REMARK, b, dev_id, unit)


def pkts_step(dev_type: int, dev_id: int, unit: int, guid: bytes, mask: int, records: list[bytes]) -> list[bytes]:
    """CmdStart82.SetStep: records packed into chunks of <= 3500 B, EndFlag 1 / 2 (last),
    PackIndex from 1, StepFileLen = total bytes, StepCount = number of steps."""
    chunks: list[bytes] = []
    cur = b""
    for r in records:
        if cur and len(cur) + len(r) > STEP_CHUNK:
            chunks.append(cur)
            cur = b""
        cur += r
    chunks.append(cur)
    total = sum(len(r) for r in records)
    out = []
    for j, c in enumerate(chunks):
        b = pb_int(1, dev_type) + pb_int(2, dev_id) + pb_int(3, unit) + pb_bytes(4, _chl_info(unit, mask))
        b += pb_int(5, len(records)) + pb_int(6, total) + pb_int(7, j + 1)
        b += pb_int(8, 2 if j == len(chunks) - 1 else 1) + pb_bytes(9, c) + pb_bytes(10, guid)
        out.append(frame_proto(CMD_STEP, b, dev_id, unit))
    return out


def step_global_buf(cv_continue_cutoff_delay: int | None, cap_retention_cycle: int | None,
                    cccv_curr0_not_protect: bool = False) -> bytes:
    """StepGlobalPrt.Encode for the fields this PC uses (Map3 bits 4/5/6):
    u32 maps (trailing zero maps dropped, NEXT_MAP on all but last) | data | u32 CRC-32
    over maps+data. The server logs maps+data as the type-254 / step-65535 record."""
    m3 = 0
    data = b""
    if cv_continue_cutoff_delay:
        m3 |= 1 << 4
        v = struct.pack("<I", cv_continue_cutoff_delay)
        data += bytes([len(v) + 1]) + v
    if cccv_curr0_not_protect:
        m3 |= 1 << 5
        data += bytes([2, 1])
    if cap_retention_cycle:
        m3 |= 1 << 6
        v = struct.pack("<I", cap_retention_cycle)
        data += bytes([len(v) + 1]) + v
    maps = [0, 0, m3]
    while len(maps) > 1 and maps[-1] == 0:
        maps.pop()
    maps = [m | S.NEXT_MAP for m in maps[:-1]] + [maps[-1]]
    body = b"".join(struct.pack("<I", m) for m in maps) + data
    return body + struct.pack("<I", zlib.crc32(body))


def pkt_step_global(dev_type: int, dev_id: int, unit: int, guid: bytes, mask: int, buf: bytes) -> bytes:
    """CmdStart82.SetStepGlobal -> ProtocSetStepGlobal (only if Device.EnableGlobalPrt)."""
    b = pb_int(1, dev_type) + pb_int(2, dev_id) + pb_int(3, unit) + pb_bytes(4, _chl_info(unit, mask))
    b += pb_bytes(5, buf) + pb_bytes(6, guid)
    return frame_proto(CMD_STEP_GLOBAL, b, dev_id, unit)


def global_prt_buf(sysglobal: dict, zwj_func: list[int]) -> bytes:
    """SysGlobalPrt.Encode for the settings ported: u32 map | values | u32 CRC-32.
    Only PrtWhenPanErr (bit 0x400, if the device has Ver8) and ZeroRecord (0x80, Ver2);
    any other non-empty setting raises."""
    unported = [k for k in ("FireTempH", "FireTempL", "FixErrVoltH", "FixErrVoltL", "ReleaseP1",
                            "FixErrAuxVoltH", "FixErrAuxVoltL", "PressCheckCnd")
                if sysglobal.get(k, "").strip()]
    if sysglobal.get("IsRevDataAddTime", "False") == "True" or sysglobal.get("IsCCDelaySampling", "False") == "True":
        unported.append("IsRevDataAddTime/IsCCDelaySampling")
    if unported:
        raise ValueError(f"global protection settings not ported: {unported}")
    m = 0
    vals = b""
    zero = int(sysglobal.get("ZeroRecord", "0") or 0)
    if has_ver(zwj_func, 2) and zero != 0:
        m |= 0x80
        vals += struct.pack("<B", zero)       # ZeroRecord is a byte in SysGlobalPrt
    if has_ver(zwj_func, 8):
        m |= 0x400
        vals += struct.pack("<B", int(sysglobal.get("PrtWhenPanErr", "0") or 0))
    body = struct.pack("<I", m) + vals
    return body + struct.pack("<I", zlib.crc32(body))


def pkt_global_prt(dev_type: int, dev_id: int, buf: bytes) -> bytes:
    """CmdStart82.SendGlobalPrt -> ProtocSetGrobalProtect82 {DevType, DevID, DataBuf}."""
    return frame_proto(CMD_GLOBAL_PRT, pb_int(1, dev_type) + pb_int(2, dev_id) + pb_bytes(4, buf), dev_id, 0)


def pkt_start(dev_type: int, dev_id: int, unit: int, guid: bytes, mask: int, start_step: int,
              creator: str, sn: str, remark: str, test_sn: str, battery_mass: float = 0.0) -> bytes:
    """CmdStart83.SendStart -> ProtocStart83."""
    b = pb_int(1, dev_type) + pb_int(2, dev_id) + pb_int(3, unit) + pb_bytes(4, _chl_info(unit, mask))
    b += pb_bytes(5, guid) + pb_int(6, start_step) + pb_double(7, battery_mass)
    b += pb_str(8, creator) + pb_str(9, sn) + pb_str(10, remark) + pb_str(11, test_sn)
    return frame_proto(CMD_START, b, dev_id, unit)


def pkt_confirm(dev_type: int, dev_id: int, unit: int, guid: bytes, tests: list[tuple[int, int, int]]) -> bytes:
    """CmdStart83.SendStartConfirm -> ProtocStartConfirm, tests = (unit, chl, test_id) from
    the Start reply."""
    b = pb_int(1, dev_type) + pb_int(2, dev_id) + pb_int(3, unit)
    for u, c, t in tests:
        b += pb_bytes(4, pb_int(1, u) + pb_int(2, c) + pb_int(3, t))
    return frame_proto(CMD_CONFIRM, b + pb_bytes(5, guid), dev_id, unit)


# ---- replies ---------------------------------------------------------------------------
def parse_reply(raw: bytes) -> dict:
    """Reply frames: FE | result u8 @13 | cmdEx u16 @14 | body. Proto replies carry
    u32 length @16 + proto (Result = field 4); map/barcode replies are legacy layouts."""
    cmd_ex = struct.unpack_from("<H", raw, 14)[0]
    out = {"cmd_ex": cmd_ex, "result": raw[13]}
    req = cmd_ex & 0x7FFF
    if req == CMD_MAP:
        out["guid"] = raw[17:33].hex().upper()
    elif req == CMD_BARCODE:
        n = struct.unpack_from("<I", raw, 22)[0]
        pf = P.pb_fields(raw[26:26 + n])
        out["index"] = struct.unpack_from("<I", raw, 18)[0]
        out["result"] = max(out["result"], next((v for k, _, v in pf if k == 4), 0))
    elif req in START_COMMANDS:
        n = struct.unpack_from("<I", raw, 16)[0]
        pf = P.pb_fields(raw[20:20 + n])
        out["result"] = max(out["result"], next((v for k, _, v in pf if k == 4), 0))
        if req == CMD_START:
            out["tests"] = []
            for k, _, v in pf:
                if k == 5:
                    sub = {kk: vv for kk, _, vv in P.pb_fields(v)}
                    out["tests"].append((sub.get(1, 0), sub.get(2, 0), sub.get(3, 0)))
    return out


# ---- the plan --------------------------------------------------------------------------
@dataclass
class Stage:
    name: str
    cmd_ex: int
    packet: bytes


@dataclass
class StartPlan:
    channel: str
    dev_type: int
    dev_id: int
    unit: int
    chl: int
    guid: bytes
    stages: list[Stage]
    records: list[S.StepRecord]
    info: dict = field(default_factory=dict)

    @property
    def guid_hex(self) -> str:
        return self.guid.hex().upper()

    def confirm(self, tests: list[tuple[int, int, int]]) -> Stage:
        return Stage("confirm", CMD_CONFIRM, pkt_confirm(self.dev_type, self.dev_id, self.unit, self.guid, tests))


def check_limits(records: list[S.StepRecord], max_curr_ma: float, max_volt_v: float | None) -> None:
    """Refuse a schedule whose currents exceed the channel's range or whose voltages exceed
    the device's voltage range."""
    for r in records:
        for k in ("limit_curr", "cutoff_curr"):
            v = r.fields.get(k)
            if v is not None and abs(float(v)) > max_curr_ma + 1e-9:
                raise ValueError(f"step {r.step_index} {k} {v} mA exceeds the channel range {max_curr_ma} mA")
        if max_volt_v:
            for k in ("limit_volt", "cutoff_volt"):
                v = r.fields.get(k)
                if v is not None and abs(float(v)) / 10000 > max_volt_v + 1e-9:
                    raise ValueError(f"step {r.step_index} {k} {float(v) / 10000} V exceeds the device range {max_volt_v} V")


_DESC = {"limit_curr": ("I", 1, "mA"), "limit_volt": ("V", 1e-4, "V"), "limit_time": ("t", 1e-3, "s"),
         "limit_cap": ("cap", 1 / 3600, "mAh"), "cutoff_curr": ("stop I", 1, "mA"),
         "cutoff_volt": ("stop V", 1e-4, "V"), "limit_rate": ("rate", 1, "C"),
         "cycle_count": ("cycles", 1, ""), "start_step": ("from step", 1, ""),
         "prt_volt_h": ("prot V <", 1e-4, "V"), "prt_volt_l": ("prot V >", 1e-4, "V"),
         "prt_curr_abs": ("prot |dI| <", 1, "mA")}


def describe(records: list[S.StepRecord]) -> list[str]:
    """One human-readable line per step (V, mA, mAh, s)."""
    out = []
    for r in records:
        parts = []
        for k, v in r.fields.items():
            if k in _DESC:
                name, scale, unit = _DESC[k]
                parts.append(f"{name} {float(v) * scale:g}" + (f" {unit}" if unit else ""))
        rem = r.fields.get("remark")
        line = f"{r.step_index}: {r.type_name}" + (": " + ", ".join(parts) if parts else "")
        if isinstance(rem, str) and rem:
            line += f"  ({rem})"
        out.append(line)
    return out


def build_plan(step_file: str, ch: dict, device: dict, sysset: dict, sysglobal: dict,
               now: datetime | None = None, guid: bytes | None = None) -> StartPlan:
    """Everything the GUI would send for a single-channel start of `step_file` on channel
    ch = {"dev_type", "dev_id", "unit", "chl"}, given the device info from the live feed
    (chl_ranges, chl_map, zwj_func) and the GUI settings (SysConfigParam [sysSet],
    SysGlobalPrt [SysConfigParam]). Raises on anything not ported."""
    from . import gui_defaults, stepfile

    dev_type, dev_id, unit, chl = ch["dev_type"], ch["dev_id"], ch["unit"], ch["chl"]
    if dev_type != DEV_TYPE_BTS83:
        raise ValueError(f"devType {dev_type} not supported")
    if not 1 <= chl <= 31:
        raise ValueError("channel id must be 1..31")      # mask must stay a positive int32
    name = f"{unit}-{chl}"
    zwj = device.get("zwj_func") or []
    for n, what in ((1, "capacity enable / step remark"), (16, "global protection"), (18, "C-rate fields")):
        if not has_ver(zwj, n):
            raise ValueError(f"device lacks Ver{n} ({what}); encoding not verified for it")
    if has_ver(zwj, 34):
        raise ValueError("device has Ver34 (capacity retention rate): not ported")
    rng = (device.get("chl_ranges") or {}).get(name)
    cmap = (device.get("chl_map") or {}).get(name)
    if rng is None or cmap is None:
        raise ValueError(f"no device info for channel {name}")
    if cmap.get("aux_id"):
        raise ValueError("channel has an aux mapping: not ported")

    records, info = stepfile.load(step_file)
    gui_defaults.apply(records, sysset, rng["chg_range_ma"], rng["ranges_ma"], rng["parallel"])
    check_limits(records, rng["chg_range_ma"], device.get("voltage_range_v"))
    if info.get("start_step", 1) != 1:
        raise ValueError("Start_Step != 1 not supported")

    now = now or datetime.now()
    guid = guid or uuid.uuid4().bytes_le                 # C# Guid.NewGuid().ToByteArray()
    sn = now.strftime("%Y-%m-%d %H-%M-%S")               # batch no / Sn / TestSn when no SN
    mask = 1 << (chl - 1)                                # Client.GetStartChl
    creator, remark = info.get("creator", ""), info.get("remark", "")
    step_name = os.path.basename(step_file)

    stages = [Stage("map", CMD_MAP, pkt_map(dev_type, dev_id, unit, guid, [(unit, chl, 0, cmap.get("real_chl") or 0)]))]
    bproto = proto_barcode(dev_type, dev_id, guid, step_name, sn, "",
                           [{"unit": unit, "chl": chl, "barcode": "", "remark": "", "creator": ""}])
    stages += [Stage("barcode", CMD_BARCODE, p) for p in pkts_barcode(dev_type, dev_id, bproto)]
    stages.append(Stage("remark", CMD_REMARK, pkt_remark(dev_type, dev_id, unit, guid, mask, remark, [(unit, chl, "")])))
    stages += [Stage("step", CMD_STEP, p)
               for p in pkts_step(dev_type, dev_id, unit, guid, mask, [S.encode_record(r) for r in records])]
    delay = int(sysset.get("CVContinueCutoffDelay", "0") or 0) if sysset.get("IsCVContinueCutoffDelay") == "True" else 0
    curr0 = sysset.get("IsCCCVCurr0NotProtect") == "True"
    cap_ret = int(sysset.get("CapRetentionRateCycle", "0") or 0)   # encoded only with Ver34 (refused above)
    sg = step_global_buf(delay or None, None, curr0)
    if delay or curr0 or cap_ret:                       # Step.MergeSysSetStepGlobalPrt -> Count() > 0
        stages.append(Stage("step_global", CMD_STEP_GLOBAL, pkt_step_global(dev_type, dev_id, unit, guid, mask, sg)))
    stages.append(Stage("global_prt", CMD_GLOBAL_PRT, pkt_global_prt(dev_type, dev_id, global_prt_buf(sysglobal, zwj))))
    stages.append(Stage("start", CMD_START, pkt_start(dev_type, dev_id, unit, guid, mask, 1, creator, sn, remark, sn)))
    return StartPlan(f"{dev_id}-{unit}-{chl}", dev_type, dev_id, unit, chl, guid, stages, records,
                     {"step_file": step_file, "sn": sn, "creator": creator, "remark": remark,
                      "steps": len(records), "step_bytes": sum(len(S.encode_record(r)) for r in records)})


def load_sysglobal(path: str | None = None) -> dict:
    """[SysConfigParam] of SysGlobalPrt.iconf (GlobalPrtApplyToAll=True on this PC)."""
    from .gui_defaults import SYSCONFIG_PATH
    path = path or os.path.join(os.path.dirname(SYSCONFIG_PATH), "SysGlobalPrt.iconf")
    raw = open(path, "rb").read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", "replace")
    out, sec = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            sec = line[1:-1]
        elif sec == "SysConfigParam" and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


# ---- sending ---------------------------------------------------------------------------
REPLY_TIMEOUT_S = 5.0


@dataclass
class StartResult:
    ok: bool
    channel: str
    guid: str
    tests: list = field(default_factory=list)
    failed_stage: str | None = None
    start_sent: bool = False
    stop_sent: bool = False
    log: list = field(default_factory=list)


def run_plan(plan: StartPlan, host: str = "127.0.0.1", port: int = 8001, out=print) -> StartResult:
    """Send the stages one at a time on a fresh session, each after a result-0 reply.
    Stops at the first failure. If the Start packet was sent and the transaction did not
    finish cleanly (bad/missing reply to Start or Confirm), sends a pause (stop 0x000A) to
    the channel so nothing keeps running unconfirmed (CLAUDE.md rule 6)."""
    import socket
    from .control import CMD_STOP, pkt_chl_cmd

    res = StartResult(False, plan.channel, plan.guid_hex)
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(0.5)
    buf = bytearray()

    def log(msg: str) -> None:
        line = f"{datetime.now():%H:%M:%S.%f} {msg}"
        res.log.append(line)
        out(line)

    def wait_reply(cmd_ex: int) -> dict | None:
        import time
        t0 = time.time()
        while time.time() - t0 < REPLY_TIMEOUT_S:
            try:
                d = s.recv(65536)
                if not d:
                    return None
                buf.extend(d)
            except socket.timeout:
                continue
            for raw in P.split_frames(buf):
                if raw[12] == 0x80:                       # login reply
                    log(f"RX login result={raw[13]}")
                    if cmd_ex == -1:
                        return {"result": raw[13]}
                    continue
                if raw[12] != 0xFE or len(raw) < 18:
                    continue
                if struct.unpack_from("<H", raw, 14)[0] != (cmd_ex | 0x8000):
                    continue                              # pushes, other replies
                r = parse_reply(raw)
                log(f"RX 0x{r['cmd_ex']:04X} {r}: {raw.hex(' ')}")
                return r
        return None

    try:
        s.sendall(P.pkt_login())
        log("TX login")
        r = wait_reply(-1)
        if not r or r["result"] != 0:
            res.failed_stage = "login"
            return res
        stages = list(plan.stages)
        i = 0
        while i < len(stages):
            st = stages[i]
            log(f"TX {st.name} 0x{st.cmd_ex:04X}: {st.packet.hex(' ')}")
            s.sendall(st.packet)
            if st.cmd_ex == CMD_START:
                res.start_sent = True
            r = wait_reply(st.cmd_ex)
            if r is None or r["result"] != 0 or (st.cmd_ex == CMD_MAP and r.get("guid") != plan.guid_hex):
                res.failed_stage = st.name
                log(f"FAILED at {st.name}: {r}")
                return res
            if st.cmd_ex == CMD_START:
                res.tests = r.get("tests", [])
                if not res.tests:
                    res.failed_stage = "start (no test ids in reply)"
                    return res
                stages.append(plan.confirm(res.tests))
            i += 1
        res.ok = True
        log(f"START OK guid={plan.guid_hex} tests={res.tests}")
        return res
    finally:
        if res.start_sent and not res.ok:
            try:
                pkt = pkt_chl_cmd(CMD_STOP, plan.dev_type, plan.dev_id, plan.unit, plan.chl)
                log(f"TX safety pause {plan.channel}: {pkt.hex(' ')}")
                s.sendall(pkt)
                res.stop_sent = True
                wait_reply(CMD_STOP)
            except OSError as e:
                log(f"safety pause failed: {e}")
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        s.close()


def check_start(channel: str, feed) -> dict:
    """Guards before a start: allowlisted channel, fresh live reading, channel idle."""
    from .control import ControlRefused, load_allowlist
    allow = load_allowlist()
    ch = allow.get(channel)
    if ch is None:
        raise ControlRefused(f"{channel} is not in the control allowlist ({sorted(allow)}). "
                             "Only the user can add channels to config/test_channels.json.")
    live = feed.channel(channel) if feed else None
    if not live or not live.get("live"):
        raise ControlRefused(f"no fresh live reading for {channel}; live feed must be connected")
    if live.get("work_state") != "idle":
        raise ControlRefused(f"start needs {channel} to be idle, it is {live.get('work_state')}")
    return ch
