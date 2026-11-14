"""Step codec vs. step records the server logged for real GUI starts (StartInfo logs)."""
import json
import os

import pytest

from btsmon import steps as S

ROWS = json.load(open(os.path.join(os.path.dirname(__file__), "data", "startinfo_steps.json")))["rows"]
STEP_ROWS = [r for r in ROWS if r["step_type"] != 254]


@pytest.mark.parametrize("r", STEP_ROWS, ids=lambda r: f"{r['dev_uid']}-{r['test_id']}-{r['step_id']}")
def test_roundtrip_logged(r):
    f = S.decode_logged(r["step_type"], r["bitmap_data"], r["step_data"])
    assert S.logged_form(S.StepRecord(r["step_type"], f)) == (r["bitmap_data"], r["step_data"])


def test_rest_step_test141_values():
    f = S.decode_logged(4, "8101E00400000000",
                        "04002A75150000000042000000690000000400401C460600401CC6043075000000000000")
    assert f == {"limit_time": 360_000_000, "param1": 66, "param2": 105, "prt_volt_h": 10000.0,
                 "prt_volt_l": -10000.0, "record_time": 30000}


def test_record_roundtrip():
    rec = S.StepRecord(4, {"limit_time": 60000, "param1": 66, "param2": 105, "record_time": 1000}, 1, 1)
    b = S.encode_record(rec)
    assert len(b) == struct_len(b) and b[-4:] == b"\x01\0\0\0"
    back, end = S.decode_record(b)
    assert end == len(b) and back.fields == rec.fields and back.step_type == 4


def struct_len(b):
    return int.from_bytes(b[:2], "little")


def test_rejects_unknown_field_and_bits():
    with pytest.raises(S.StepCodecError):
        S.encode_data(4, {"bogus": 1})
    with pytest.raises(S.StepCodecError):
        S.decode_data(4, [1 << 9, 1 << 30], b"\0" * 8)


def test_stepfile_test_rest_matches_test141():
    from btsmon import stepfile
    recs, info = stepfile.load(os.path.join(os.path.dirname(__file__), "data", "test_rest.xml"))
    logged = {1: ("8101E00400000000", "04005125020000000042000000690000000400401C460600401CC6043075000000000000"),
              2: ("8101E00400000000", "04002A75150000000042000000690000000400401C460600401CC6043075000000000000"),
              3: ("8000600000000000", "4200000069000000")}
    assert [r.step_index for r in recs] == [1, 2, 3]
    assert {r.step_id: S.logged_form(r) for r in recs} == logged


def test_stepfile_refuses_unknown(tmp_path):
    from btsmon import stepfile
    p = tmp_path / "x.xml"
    p.write_text('<root><config type="Step File" version="18"><Head_Info/><Step_Info Num="1">'
                 '<Step1 Step_ID="1" Step_Type="4"><Limit><Other><Cnd1 Value="1"/></Other></Limit></Step1>'
                 '</Step_Info></config></root>')
    with pytest.raises(stepfile.UnsupportedStepFile, match="Cnd1"):
        stepfile.load(str(p))
