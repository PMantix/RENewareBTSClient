"""Step-file codec for BTS83 (devType >= 25): Python port of the subset of
Common.Step.EncodeBts80 / StepItem.EncodeF / DecodeF that real schedules on this PC use.

Wire layout of one step record (Step.EncodeBts80, BTS83 branch):
    u16 record length (whole record) | u16 step index (GUI step number) | i16 step id
    | u8 step type | u32 map[n] | data | u32 1
The maps are bit sets, 12 at most (EncodeMapF1..F10, Map11, Map12). Trailing zero maps
are dropped, keeping at least two; every map but the last has bit 31 (NEXT_MAP) set.
Each set bit adds one field to `data`, in map/bit order, most of them with a leading
compare-operator byte (CompareBase.compareType). Values are little-endian.

Units are BTS base units, as in the GUI's step data: time ms, voltage 0.1 mV,
current mA, capacity mAs (same as the RT feed and NDC files).

The server logs every started step as (bitmap_data, step_data) hex in
BTSServer80/bin/StartInfo/StartInfo<date>.log, with bitmap_data printed as big-endian
u32 hex words. `decode_logged` / `encode` are verified against those rows
(tests/test_steps.py).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

NEXT_MAP = 0x80000000

# StepType.type
STEP_TYPE = {
    "cc_chg": 1, "cc_dchg": 2, "cv_chg": 3, "rest": 4, "cycle": 5, "end": 6, "cccv_chg": 7,
    "cp_dchg": 8, "cp_chg": 9, "cr_dchg": 10, "cr_chg": 11, "ir": 12, "pause": 13,
    "pulse": 16, "sim": 17, "pcccv_chg": 18, "cv_dchg": 19, "cccv_dchg": 20, "ctrl": 21,
    "ocv": 22, "follow": 24, "slope": 25, "cpcv_dchg": 26, "cpcv_chg": 27,
    "crcv_dchg": 28, "crcv_chg": 29, "cv": 30,
}
STEP_NAME = {v: k for k, v in STEP_TYPE.items()}
CHARGE = {1, 3, 7, 9, 11, 18, 27, 29}
DISCHARGE = {2, 8, 10, 19, 20, 26, 28}

# CompareBase.compareType
EQ, NE, GT, GE, LT, LE = 1, 2, 3, 4, 5, 6


def _op_limit_curr(t: int) -> int:
    return LE if (t == 10 or t in CHARGE) else GE


def _op_limit_volt(t: int) -> int:
    return GE if t in CHARGE else LE


def _op_cutoff_curr(t: int) -> int:
    return GE if t == 8 else LE


def _op_cutoff_volt(t: int) -> int:
    return LE if t in DISCHARGE else GE


@dataclass(frozen=True)
class F:
    map: int          # 1-based map number
    bit: int
    name: str
    fmt: str          # struct format of the value, or "cnd" (33-byte condition) / "50s"
    op: object = None  # None (no operator byte), an int, or a function(step_type) -> int


# Fields seen in this PC's schedules (StartInfo logs), with the encoder's operator rules
# (StepItem.EncodeMapF1 etc.). Order within a map = bit order = wire order.
FIELDS: list[F] = [
    F(1, 0, "limit_curr", "f", _op_limit_curr),
    F(1, 1, "limit_volt", "f", _op_limit_volt),
    F(1, 2, "limit_time", "Q", GE),
    F(1, 3, "limit_cap", "f", GE),
    F(1, 4, "limit_temp", "f", GE),
    F(1, 5, "limit_pow", "f", GE),
    F(1, 6, "limit_ir", "f", GE),
    F(1, 7, "cutoff_curr", "f", _op_cutoff_curr),
    F(1, 8, "cutoff_volt", "f", _op_cutoff_volt),
    F(1, 9, "cutoff_dv", "f", GE),
    F(1, 10, "start_step", "i", EQ),
    F(1, 11, "cycle_count", "i", EQ),
    F(1, 12, "jump_step", "i", EQ),
    F(1, 13, "param1", "i"),             # Step._operator (GUI fills it)
    F(1, 14, "param2", "i"),             # Step.RateType
    F(1, 15, "prt_volt_h", "f", GE),
    F(1, 16, "prt_volt_l", "f", LE),
    F(1, 17, "prt_curr_h", "f", GE),
    F(1, 18, "prt_curr_l", "f", LT),
    F(1, 19, "prt_temp_h", "f", GE),
    F(1, 20, "prt_temp_l", "f", LE),
    F(1, 21, "delay_time", "i", GT),
    F(1, 22, "prt_bfgs_time", "i", GE),
    F(1, 23, "prt_bfgs_volt", "f", GE),
    F(1, 24, "record_time", "q", GE),
    F(1, 25, "record_curr", "f", GE),
    F(1, 26, "record_volt", "f", GE),
    F(1, 27, "record_temp", "f", GE),
    F(1, 28, "plat_volt1", "f", GE),
    F(1, 29, "plat_volt2", "f", GE),
    F(1, 30, "plat_volt3", "f", GE),
    F(2, 25, "prt_cap_h", "f", GE),
    F(3, 6, "prt_curr_abs", "f", GE),    # Atl CCChg/CCCVChg/CCDChg.prtCurrAbs
    F(4, 2, "condition1", "cnd"),
    F(4, 3, "condition2", "cnd"),
    F(4, 4, "condition3", "cnd"),
    F(4, 5, "condition4", "cnd"),
    F(4, 6, "condition5", "cnd"),
    F(4, 7, "curr_range", "f"),
    F(7, 4, "nominal_capacity", "f"),
    F(10, 13, "remark", "50s"),          # only when Device.EnableCapEnable
    F(11, 11, "limit_rate", "f"),        # only when Device.EnableCRate
    F(11, 12, "cutoff_rate", "f"),
]
_BY_POS = {(f.map, f.bit): f for f in FIELDS}
_BY_NAME = {f.name: f for f in FIELDS}
COND_LEN = 33


class StepCodecError(ValueError):
    pass


@dataclass
class StepRecord:
    step_type: int
    fields: dict = field(default_factory=dict)
    step_index: int = 0      # GUI step number (num2 in EncodeBts80)
    step_id: int = 0         # sequential record id
    extra_maps: int = 0      # trailing all-zero maps kept beyond the minimum (see encode_maps)

    @property
    def type_name(self) -> str:
        return STEP_NAME.get(self.step_type, f"type{self.step_type}")


# ---- data ------------------------------------------------------------------------------
def _size(fmt: str) -> int:
    return COND_LEN if fmt == "cnd" else struct.calcsize("<" + fmt)


def decode_data(step_type: int, maps: list[int], data: bytes) -> dict:
    """Inverse of StepItem.EncodeF for the fields in FIELDS. Raises on unknown bits or
    if the data is not consumed exactly."""
    out: dict = {}
    pos = 0
    for mi, m in enumerate(maps, start=1):
        for bit in range(31):
            if not m >> bit & 1:
                continue
            f = _BY_POS.get((mi, bit))
            if f is None:
                raise StepCodecError(f"unsupported field map {mi} bit {bit} (step type {step_type})")
            if f.op is not None:
                op = data[pos]
                pos += 1
                want = f.op(step_type) if callable(f.op) else f.op
                if op != want:
                    raise StepCodecError(f"{f.name}: operator {op}, encoder would write {want}")
            n = _size(f.fmt)
            raw = data[pos:pos + n]
            if len(raw) != n:
                raise StepCodecError(f"data too short at {f.name}")
            pos += n
            if f.fmt in ("cnd", "50s"):
                out[f.name] = bytes(raw)
            else:
                out[f.name] = struct.unpack("<" + f.fmt, raw)[0]
    if pos != len(data):
        raise StepCodecError(f"{len(data) - pos} bytes left over")
    return out


def _f32(v) -> bytes:
    return struct.pack("<f", float(v))


def encode_data(step_type: int, fields: dict) -> tuple[list[int], bytes]:
    """StepItem.EncodeF for the fields in FIELDS: returns (maps before trimming, data)."""
    unknown = set(fields) - set(_BY_NAME)
    if unknown:
        raise StepCodecError(f"unknown fields {sorted(unknown)}")
    maps = [0] * 12
    data = bytearray()
    for f in FIELDS:              # FIELDS is in wire order
        if f.name not in fields or fields[f.name] is None:
            continue
        v = fields[f.name]
        maps[f.map - 1] |= 1 << f.bit
        if f.op is not None:
            data.append(f.op(step_type) if callable(f.op) else f.op)
        if f.fmt == "cnd":
            if len(v) != COND_LEN:
                raise StepCodecError(f"{f.name} must be {COND_LEN} bytes")
            data += v
        elif f.fmt == "50s":
            # C#: Encoding.Default = the PC's ANSI code page ("mbcs" in Python on Windows)
            b = v.encode("mbcs", "replace") if isinstance(v, str) else bytes(v)
            data += b[:50].ljust(50, b"\0")
        elif f.fmt == "f":
            data += _f32(v)
        else:
            data += struct.pack("<" + f.fmt, int(v))
    return maps, bytes(data)


def trim_maps(maps: list[int]) -> list[int]:
    """EncodeF tail: drop trailing zero maps (keep >= 2), set NEXT_MAP on all but the last."""
    m = list(maps)
    while len(m) > 2 and m[-1] == 0:
        m.pop()
    return [x | NEXT_MAP for x in m[:-1]] + [m[-1]]


# ---- record ----------------------------------------------------------------------------
def encode_record(rec: StepRecord) -> bytes:
    """One step record exactly as Step.EncodeBts80 appends it (BTS83 branch)."""
    maps, data = encode_data(rec.step_type, rec.fields)
    maps = trim_maps(maps)
    body = b"".join(struct.pack("<I", m) for m in maps) + data
    n = len(body) + 11
    return struct.pack("<HHhB", n, rec.step_index, rec.step_id, rec.step_type) + body + struct.pack("<I", 1)


def decode_record(buf: bytes, pos: int = 0) -> tuple[StepRecord, int]:
    n, idx, sid, typ = struct.unpack_from("<HHhB", buf, pos)
    end = pos + n
    p = pos + 7
    maps = []
    while True:
        m = struct.unpack_from("<I", buf, p)[0]
        p += 4
        maps.append(m & ~NEXT_MAP)
        if not m & NEXT_MAP:
            break
    if struct.unpack_from("<I", buf, end - 4)[0] != 1:
        raise StepCodecError("record trailer is not 1")
    fields = decode_data(typ, maps, buf[p:end - 4])
    return StepRecord(typ, fields, idx, sid), end


def decode_logged(step_type: int, bitmap_hex: str, data_hex: str) -> dict:
    """Decode a (bitmap_data, step_data) pair from the server's StartInfo log."""
    maps = [int(bitmap_hex[i:i + 8], 16) & ~NEXT_MAP for i in range(0, len(bitmap_hex), 8)]
    return decode_data(step_type, maps, bytes.fromhex(data_hex))


def logged_form(rec: StepRecord) -> tuple[str, str]:
    """(bitmap_data, step_data) as the server logs them, for comparison with StartInfo."""
    maps, data = encode_data(rec.step_type, rec.fields)
    maps = trim_maps(maps) + [0] * rec.extra_maps
    if rec.extra_maps:
        maps = [m | NEXT_MAP for m in maps[:-1]] + [maps[-1]]
    return "".join(f"{m:08X}" for m in maps), data.hex().upper()
