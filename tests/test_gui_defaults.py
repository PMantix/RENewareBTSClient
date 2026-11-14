"""GUI start defaults (btsmon.gui_defaults) against a real GUI start logged by the server."""
import json
import os
from decimal import ROUND_HALF_UP, Decimal

import pytest

from btsmon import gui_defaults as G
from btsmon import stepfile
from btsmon import steps as S

DATA = os.path.join(os.path.dirname(__file__), "data")
SYSSET = {"StartModee": "0", "PrtWhenSingleStartt": "0", "IsSplitCCCV": "False",
          "IsCCCVRange": "True", "CurrAbsDefault": "100"}      # this PC's settings
DEV62 = (50.0, [1.0, 25.0, 50.0])                                # dev 62 device info


def _net_f4(v):
    """The GUI grid's display round trip for currents (double.ToString("f4"), .NET Framework)."""
    return float(Decimal("%.15g" % v).quantize(Decimal("0.0001"), ROUND_HALF_UP))


def test_hrc_schedule_matches_logged_gui_start():
    recs, _ = stepfile.load(os.path.join(DATA, "hrc_pr6_5-6.xml"))
    G.apply(recs, SYSSET, *DEV62)
    logged = {r["step_id"]: r for r in json.load(open(os.path.join(DATA, "hrc_pr6_5-6_logged.json")))["rows"]}
    assert len(recs) == len(logged)
    for r in recs:
        for k in ("limit_curr", "cutoff_curr"):
            if k in r.fields:
                r.fields[k] = _net_f4(r.fields[k])
        lg = logged[r.step_id]
        assert (r.step_type, r.step_index) == (lg["step_type"], lg["step_index"])
        assert S.logged_form(r) == (lg["bitmap"], lg["data"]), f"step {r.step_id}"


def test_cccv_range_and_curr_abs_rules():
    recs = [S.StepRecord(7, {"limit_curr": 5.4}), S.StepRecord(7, {"limit_curr": 27.0}),
            S.StepRecord(7, {"limit_curr": 60.0}), S.StepRecord(2, {"limit_curr": 5.4}),
            S.StepRecord(1, {"limit_curr": 5.4, "prt_curr_abs": 3.0}), S.StepRecord(4, {})]
    G.apply(recs, SYSSET, *DEV62)
    assert [r.fields.get("curr_range") for r in recs] == [25.0, 50.0, None, None, None, None]
    assert [r.fields.get("prt_curr_abs") for r in recs] == [25.0, 50.0, 50.0, 50.0, 3.0, None]


def test_settings_switches():
    recs = [S.StepRecord(7, {"limit_curr": 5.4})]
    G.apply(recs, dict(SYSSET, IsCCCVRange="False", CurrAbsDefault=""), *DEV62)
    assert recs[0].fields == {"limit_curr": 5.4}
    recs = [S.StepRecord(2, {"limit_curr": 5.4})]
    G.apply(recs, dict(SYSSET, CurrAbsDefault="80"), *DEV62)
    assert recs[0].fields["prt_curr_abs"] == 40.0


@pytest.mark.parametrize("change", [{"StartModee": "3"}, {"PrtWhenSingleStartt": "1"},
                                    {"IsSplitCCCV": "True"}, {"DefaultMinDuration": "1000"}])
def test_refuses_unported_settings(change):
    with pytest.raises(G.UnsupportedSettings):
        G.apply([], dict(SYSSET, **change), *DEV62)


def test_refuses_parallel_and_bad_ranges():
    with pytest.raises(G.UnsupportedSettings):
        G.apply([], SYSSET, *DEV62, parallel=True)
    with pytest.raises(G.UnsupportedSettings):
        G.apply([], SYSSET, 0.0, [])


def test_load_sysset_utf16(tmp_path):
    p = tmp_path / "SysConfigParam.iconf"
    p.write_bytes("﻿[SysUnit]\r\nCurr=3\r\n[sysSet]\r\nIsCCCVRange=True\r\nCurrAbsDefault=100\r\n[Mailinfo]\r\nX=1\r\n"
                  .encode("utf-16-le"))
    assert G.load_sysset(str(p)) == {"IsCCCVRange": "True", "CurrAbsDefault": "100"}
