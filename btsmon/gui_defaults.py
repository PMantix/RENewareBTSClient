"""Defaults the BTS GUI adds to a step file when it starts it (StepEdit.MergePrt,
Step/Steps/StepEdit.cs:4166-4236), for the settings found on this PC.

Order in the GUI, after XmlStep.LoadFile:
  1. Step.MergeWholePrt(sysSet)         -> done in stepfile.load (whole-test prt/record)
  2. Step.SetCCCVRange(sysSet, channel.ListParalRange)
       if sysSet.IsCCCVRange: CCCV chg/dchg and PCCCV steps get Prt.CurrRange = the
       smallest channel current range >= the step's limit current (Step.cs:2950-2985)
  3. Step.MergeAtlPrt(stepAtlPrt, sysSet, channel.ChgParalRange)   (Step.cs:1127-1205)
       with PrtWhenSingleStart = 0 the advanced protection is empty; but if
       sysSet.CurrAbsDefault parses, CC chg / CC dchg / CCCV chg steps without their own
       value get prtCurrAbs = (step's Prt.CurrRange, else the channel's charge range)
       * CurrAbsDefault / 100
  4. Step.MergeStepGlobalPrt()          -> global protection record, not handled here

Settings this module does not reproduce (advanced protection templates, special start
modes, split CCCV, CV minimum duration) make it refuse instead of guessing.
"""
from __future__ import annotations

import os

from .steps import STEP_TYPE, StepRecord

SYSCONFIG_PATH = os.path.join(os.path.expanduser("~"), "Documents", "NEWARE", "BTSClient",
                              "SysConfigParam.iconf")

_CCCV_RANGE_TYPES = {STEP_TYPE["cccv_chg"], STEP_TYPE["cccv_dchg"], STEP_TYPE["pcccv_chg"]}
_CURR_ABS_TYPES = {STEP_TYPE["cc_chg"], STEP_TYPE["cc_dchg"], STEP_TYPE["cccv_chg"]}


class UnsupportedSettings(ValueError):
    pass


def load_sysset(path: str = SYSCONFIG_PATH) -> dict:
    """The [sysSet] section of the GUI's SysConfigParam.iconf (UTF-16 INI), as strings.
    Read-only; the file belongs to the GUI."""
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    out: dict = {}
    section = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == "sysSet" and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def check_supported(sysset: dict) -> None:
    """Refuse settings whose start-time effects are not ported."""
    problems = []
    if sysset.get("StartModee", "0") != "0":
        problems.append(f"StartModee={sysset['StartModee']} (only normal=0 is ported)")
    if sysset.get("PrtWhenSingleStartt", "0") != "0":
        problems.append("PrtWhenSingleStartt != 0 (advanced protection template merge not ported)")
    if sysset.get("IsSplitCCCV", "False") == "True":
        problems.append("IsSplitCCCV=True not ported")
    if sysset.get("DefaultMinDuration", "").strip():
        problems.append("DefaultMinDuration set (CV minimum duration) not ported")
    if problems:
        raise UnsupportedSettings("; ".join(problems))


def _cccv_range(limit_curr: float, ranges: list[float]) -> float | None:
    """Step.SetCCCVRange(StepItem, listRange): smallest range >= limit current, or None."""
    if len(ranges) <= 1:
        return None
    best = None
    for r in sorted(ranges, reverse=True):
        if r >= limit_curr:
            best = r
        else:
            break
    return best


def apply(records: list[StepRecord], sysset: dict, chg_range_ma: float,
          ranges_ma: list[float], parallel: bool = False) -> list[StepRecord]:
    """Apply the GUI start defaults in place (and return the list).

    chg_range_ma / ranges_ma: the channel's ChgCurrRange and ListStepRange from device
    info (live feed `chl_ranges`). Positive ranges are plain mA (Unit.GetCurrRange)."""
    check_supported(sysset)
    if parallel:
        raise UnsupportedSettings("channel is in a parallel group (ListParalRange scaling not ported)")
    if chg_range_ma is None or chg_range_ma <= 0 or any(r <= 0 for r in ranges_ma):
        raise UnsupportedSettings(f"unexpected channel ranges {chg_range_ma} / {ranges_ma}")

    if sysset.get("IsCCCVRange", "False") == "True":
        for rec in records:
            lc = rec.fields.get("limit_curr")
            if rec.step_type in _CCCV_RANGE_TYPES and lc is not None:
                r = _cccv_range(float(lc), ranges_ma)
                if r is not None:
                    rec.fields["curr_range"] = float(r)

    try:
        pct = float(sysset.get("CurrAbsDefault", ""))
    except ValueError:
        pct = None
    if pct is not None:
        frac = pct / 100.0
        for rec in records:
            if rec.step_type in _CURR_ABS_TYPES and rec.fields.get("prt_curr_abs") is None:
                rng = rec.fields.get("curr_range")
                rec.fields["prt_curr_abs"] = float(rng if rng is not None else chg_range_ma) * frac
    return records
