"""Reader for BTS Client step files (.xml, "Step File" version >= 17) -> StepRecords.

Port of the subset of Common.XmlStep (load) + Step.MergeWholePrt + Step.EncodeBts80 that
plain schedules use: CC/CV/CCCV charge and discharge, rest, cycle, end, with main
limits, per-step and whole-test protection/record settings. Anything else in the file
(conditions, aux, DBC, pulse, sim, ...) raises UnsupportedStepFile instead of being
dropped silently, so a schedule is either encoded completely or not at all.

Values are taken as written (version >= 17 files store BTS base units: ms, 0.1 mV, mA,
mAs); older files used scaled values and are refused.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .steps import FIELDS, STEP_TYPE, StepRecord

_FIELD_NAMES = {f.name for f in FIELDS}


class UnsupportedStepFile(ValueError):
    pass


# Limit/Main tag -> field (XmlStep.cs:1293-1316)
_LIMIT_MAIN = {"Curr": "limit_curr", "Volt": "limit_volt", "Time": "limit_time", "Cap": "limit_cap",
               "Pow": "limit_pow", "Stop_Curr": "cutoff_curr", "Stop_Volt": "cutoff_volt",
               "DV": "cutoff_dv", "Rate": "limit_rate", "Stop_Rate": "cutoff_rate"}
# Limit/Other tag -> field (XmlStep.cs:1255-1277)
_LIMIT_OTHER = {"Start_Step": "start_step", "Cycle_Count": "cycle_count", "Step_Range": "curr_range"}
# Protect/Main (XmlStep.cs:1964-2001): (child, attr-tag) -> field
_PRT_MAIN = {("Volt", "Upper"): "prt_volt_h", ("Volt", "Lower"): "prt_volt_l",
             ("Curr", "Upper"): "prt_curr_h", ("Curr", "Lower"): "prt_curr_l",
             ("Cap", "Upper"): "prt_cap_h", ("Bgfs", "Time"): "prt_bfgs_time",
             ("Bgfs", "Volt"): "prt_bfgs_volt"}
_PRT_MAIN_DIRECT = {"Delay_Time": "delay_time", "Plat_Volt1": "plat_volt1",
                    "Plat_Volt2": "plat_volt2", "Plat_Volt3": "plat_volt3",
                    "Remark": "remark"}       # step remark, XmlStep.cs:2083 (EncodeMapF10 bit 13)
# Record/Main (XmlStep.cs:1237-1242)
_REC_MAIN = {"Time": "record_time", "Volt": "record_volt", "Curr": "record_curr"}

_PRT_FIELDS = set(_PRT_MAIN.values()) | set(_PRT_MAIN_DIRECT.values())
_REC_FIELDS = set(_REC_MAIN.values())
_NO_WHOLE_PRT = {STEP_TYPE["end"], STEP_TYPE["cycle"], STEP_TYPE["pause"]}
_INT_FIELDS = {"limit_time", "record_time", "start_step", "cycle_count", "delay_time",
               "prt_bfgs_time", "param1", "param2"}


def _num(name: str, text: str):
    v = float(text)
    return int(round(v)) if name in _INT_FIELDS else v


def _val(el: ET.Element) -> str | None:
    v = el.get("Value")
    return v if v not in (None, "") else None


def _read_prt(node: ET.Element, where: str) -> dict:
    out: dict = {}
    for main in node:
        if main.tag != "Main":
            raise UnsupportedStepFile(f"{where}/Protect/{main.tag} not supported")
        for el in main:
            if el.tag in _PRT_MAIN_DIRECT:
                if _val(el) is not None:
                    out[_PRT_MAIN_DIRECT[el.tag]] = _val(el)
                continue
            for sub in el:
                key = (el.tag, sub.tag)
                if key not in _PRT_MAIN:
                    raise UnsupportedStepFile(f"{where}/Protect/Main/{el.tag}/{sub.tag} not supported")
                if _val(sub) is not None:
                    out[_PRT_MAIN[key]] = _val(sub)
            if not len(el) and el.tag not in _PRT_MAIN_DIRECT:
                raise UnsupportedStepFile(f"{where}/Protect/Main/{el.tag} not supported")
    return out


def _read_rec(node: ET.Element, where: str) -> dict:
    out: dict = {}
    for main in node:
        if main.tag != "Main":
            raise UnsupportedStepFile(f"{where}/Record/{main.tag} not supported")
        for el in main:
            if el.tag not in _REC_MAIN:
                raise UnsupportedStepFile(f"{where}/Record/Main/{el.tag} not supported")
            if _val(el) is not None:
                out[_REC_MAIN[el.tag]] = _val(el)
    return out


def _read_limit(node: ET.Element, where: str) -> dict:
    out: dict = {}
    for grp in node:
        table = {"Main": _LIMIT_MAIN, "Other": _LIMIT_OTHER}.get(grp.tag)
        if table is None:
            raise UnsupportedStepFile(f"{where}/Limit/{grp.tag} not supported")
        for el in grp:
            if el.tag not in table:
                raise UnsupportedStepFile(f"{where}/Limit/{grp.tag}/{el.tag} not supported")
            if _val(el) is not None:
                out[table[el.tag]] = _val(el)
    if "limit_time" in out and float(out["limit_time"]) < 1.0:   # XmlStep.cs:1299
        del out["limit_time"]
    return out


def load(path: str) -> tuple[list[StepRecord], dict]:
    """Parse a step file. Returns (records in EncodeBts80 order, head info)."""
    root = ET.parse(path).getroot()
    cfg = root.find("config")
    if cfg is None or cfg.get("type") != "Step File":
        raise UnsupportedStepFile("not a BTS step file")
    version = int(cfg.get("version", "0"))
    if version < 17:
        raise UnsupportedStepFile(f"step file version {version} < 17 (scaled units) not supported")

    head = cfg.find("Head_Info")
    info = {"version": version, "MultCap": None, "SpecificCap": None, "operator": None, "rate_type": None, "start_step": 1, "scale": "1"}
    for el in (head if head is not None else []):
        if el.tag == "Operate":
            info["operator"] = _val(el)
        elif el.tag == "RateType":
            info["rate_type"] = _val(el)
        elif el.tag == "Start_Step":
            info["start_step"] = int(el.get("Value", "1"))
            if el.get("Hide_Ctrl_Step", "0") != "0":
                raise UnsupportedStepFile("Hide_Ctrl_Step not supported")
        elif el.tag == "Scale":
            info["scale"] = _val(el)
        elif el.tag in ("Creator", "PN"):
            info[el.tag.lower()] = el.get("Value", "")    # start/barcode packets, not steps
        elif el.tag in ("MultCap", "SpecificCap"):
            info[el.tag] = _val(el)
        elif el.tag == "Remark":
            info["remark"] = el.get("Value", "")      # goes into the remark/start packets
        else:
            raise UnsupportedStepFile(f"Head_Info/{el.tag} not supported")

    whole: dict = {}
    for child in cfg:
        if child.tag in ("Head_Info", "Step_Info"):
            continue
        if child.tag == "Whole_Prt":
            for part in child:
                if part.tag == "Protect":
                    whole.update(_read_prt(part, "Whole_Prt"))
                elif part.tag == "Record":
                    whole.update(_read_rec(part, "Whole_Prt"))
                else:
                    raise UnsupportedStepFile(f"Whole_Prt/{part.tag} not supported")
        elif child.tag == "User_Info":
            pass                                          # GUI bookkeeping, not sent
        elif child.tag == "SMBUS":
            info_el = child.find("SMBUS_Info")
            if len(child) != 1 or info_el is None or info_el.get("Num", "0") != "0":
                raise UnsupportedStepFile("SMBUS settings not supported")
        else:
            raise UnsupportedStepFile(f"{child.tag} not supported")

    steps_el = cfg.find("Step_Info")
    if steps_el is None:
        raise UnsupportedStepFile("no Step_Info")
    records: list[StepRecord] = []
    step_index = 1
    for n, st in enumerate(steps_el, start=1):
        where = st.tag
        typ = int(st.get("Step_Type", "0"))
        if typ not in STEP_TYPE.values() or typ in (STEP_TYPE["ctrl"], 23):
            raise UnsupportedStepFile(f"{where}: step type {typ} not supported")
        fields: dict = {}
        for part in st:
            if part.tag == "Limit":
                fields.update(_read_limit(part, where))
            elif part.tag == "Protect":
                fields.update(_read_prt(part, where))
            elif part.tag == "Record":
                fields.update(_read_rec(part, where))
            else:
                raise UnsupportedStepFile(f"{where}/{part.tag} not supported")
        # Step.MergeSingleWholePrt (bResetStep=false): fill only what the step leaves empty
        if typ not in _NO_WHOLE_PRT:
            for k, v in whole.items():
                if k == "remark":
                    continue
                if k in _REC_FIELDS and typ == STEP_TYPE["cv"]:
                    continue
                fields.setdefault(k, v)
        # Step.EncodeBts80: param1 = operator, param2 = rate type, on every step
        if info["operator"] is not None:
            fields["param1"] = info["operator"]
        if info["rate_type"] is not None:
            fields["param2"] = info["rate_type"]
        # ... and NominalCapacity = MultCap, else SpecificCap (EncodeMapF7 bit 4)
        cap = info.get("MultCap") or info.get("SpecificCap")
        if cap is not None:
            fields["nominal_capacity"] = cap
        unknown = set(fields) - _FIELD_NAMES
        if unknown:
            raise UnsupportedStepFile(f"{where}: fields {sorted(unknown)} not supported")
        fields = {k: (v if k == "remark" else _num(k, v)) for k, v in fields.items()}
        records.append(StepRecord(typ, fields, step_index=step_index, step_id=n))
        if typ != STEP_TYPE["ctrl"] and typ < 31:
            step_index += 1
    return records, info
