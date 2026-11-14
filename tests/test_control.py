"""Offline tests for btsmon.control: guards, tokens, packets, and a full exchange against a
fake BtsServer on localhost (never the real one)."""
import json
import socket
import struct
import threading
import time

import pytest

from btsmon import control as C
from btsmon import protocol as P


class FakeFeed:
    def __init__(self, states):
        self.states = states          # channel -> dict (mutable)

    def channel(self, name):
        c = self.states.get(name)
        return dict(c, live=True, age_s=0.1) if c else None


@pytest.fixture
def allowlist(tmp_path, monkeypatch):
    p = tmp_path / "allow.json"
    p.write_text(json.dumps({"channels": {"62-1-1": {"dev_type": 25, "dev_id": 62, "unit": 1, "chl": 1,
                                                     "load": "none"}}}))
    monkeypatch.setattr(C, "ALLOWLIST_PATH", str(p))
    monkeypatch.setattr(C, "load_allowlist", lambda path=str(p): json.loads(p.read_text())["channels"])
    return p


def run_state(state, step=1, t=100.0):
    return {"work_state": state, "work_type": 0, "step_no": step, "step_time_s": t,
            "voltage_v": 0.445, "current_ma": 0.0}


def test_packets_match_live_verified_bytes():
    assert C.pkt_chl_cmd(0x000A, 25, 62, 1, 1).hex(" ") == \
        "ff ff ff ff ff ff ff ff 3e 01 1a 00 fe 0a 00 19 01 00 00 00 00 00 00 00 7b 5a"
    assert C.pkt_chl_cmd(0x000D, 25, 62, 1, 1).hex(" ") == \
        "ff ff ff ff ff ff ff ff 3e 01 1a 00 fe 0d 00 19 01 00 00 00 00 00 00 00 7e 5a"
    assert C.pkt_chl_cmd(0x0097, 25, 62, 1, 1).hex(" ") == \
        "ff ff ff ff ff ff ff ff 3e 01 1a 00 fe 97 00 19 01 00 00 00 00 00 00 00 08 5a"
    assert C.pkt_jump83(25, 62, 1, 1, 2).hex(" ") == \
        "ff ff ff ff ff ff ff ff 3e 01 1f 00 fe ec 00 0a 00 00 00 08 19 10 3e 18 01 20 01 28 02 25 5a"


def test_refuses_channel_not_in_allowlist(allowlist):
    ctl = C.Controller(FakeFeed({"35-4-1": run_state("running")}))
    with pytest.raises(C.ControlRefused, match="not in the control allowlist"):
        ctl.prepare("pause", "35-4-1")


def test_refuses_wrong_state_and_unknown_action(allowlist):
    ctl = C.Controller(FakeFeed({"62-1-1": run_state("idle")}))
    with pytest.raises(C.ControlRefused, match="needs 62-1-1 to be running"):
        ctl.prepare("pause", "62-1-1")
    with pytest.raises(C.ControlRefused, match="unknown action"):
        ctl.prepare("start", "62-1-1")
    with pytest.raises(C.ControlRefused, match="no fresh live reading"):
        C.Controller(FakeFeed({})).prepare("pause", "62-1-1")


def test_token_single_use_and_expiry(allowlist, monkeypatch):
    feed = FakeFeed({"62-1-1": run_state("running")})
    ctl = C.Controller(feed)
    p = ctl.prepare("pause", "62-1-1")
    assert p["bytes"].startswith("ff ff") and p["expected_after"] == "stopped"
    ctl._tokens[p["token"]]["expires"] = time.time() - 1
    with pytest.raises(C.ControlRefused, match="expired"):
        ctl.execute_token(p["token"])
    with pytest.raises(C.ControlRefused, match="unknown"):
        ctl.execute_token(p["token"])


def _fake_server(responses, received):
    """Accept one client; answer login, then answer the command with responses[cmdEx]."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        c, _ = srv.accept()
        buf = bytearray()
        c.settimeout(5)
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
                for f in P.split_frames(buf):
                    received.append(f)
                    if f[12] == 0x00:
                        c.sendall(P.frame(bytes([0x80, 0x00])))
                    elif f[12] == 0xFE:
                        cmd_ex = struct.unpack_from("<H", f, 13)[0]
                        c.sendall(responses[cmd_ex])
        except OSError:
            pass
        finally:
            c.close()
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_execute_pause_against_fake_server(allowlist, tmp_path):
    states = {"62-1-1": run_state("running")}
    feed = FakeFeed(states)
    resp = P.frame(bytes([0xFE, 0x00]) + struct.pack("<H", 0x800A) + bytes([25]) + struct.pack("<Q", 1), 62, 1)
    received = []
    port = _fake_server({0x000A: resp}, received)
    ctl = C.Controller(feed, port=port, log_dir=str(tmp_path))
    tok = ctl.prepare("pause", "62-1-1")["token"]
    threading.Timer(0.5, lambda: states["62-1-1"].update(work_state="stopped")).start()
    r = ctl.execute_token(tok)
    assert r.ok and r.response["result"] == 0 and r.after["work_state"] == "stopped"
    assert received[0] == P.pkt_login() and received[1] == C.pkt_chl_cmd(0x000A, 25, 62, 1, 1)
    assert list(tmp_path.glob("control_*_pause_62-1-1.log"))


def test_execute_rechecks_state_before_sending(allowlist, tmp_path):
    states = {"62-1-1": run_state("running")}
    ctl = C.Controller(FakeFeed(states), port=1, log_dir=str(tmp_path))
    tok = ctl.prepare("pause", "62-1-1")["token"]
    states["62-1-1"]["work_state"] = "idle"          # changed between prepare and execute
    with pytest.raises(C.ControlRefused, match="needs 62-1-1 to be running"):
        ctl.execute_token(tok)                       # port=1: would fail if it tried to connect


def test_expectations_must_match_the_channel(allowlist):
    feed = FakeFeed({"62-1-1": dict(run_state("running", step=2), test_id=142)})
    ctl = C.Controller(feed)
    ok = C.Expect("running", 0.3, 0.6, 142)
    assert ctl.prepare("pause", "62-1-1", expect=ok)["expected"]["test_id"] == 142
    for exp, msg in ((C.Expect("stopped", 0.3, 0.6, 142), "state is 'running'"),
                     (C.Expect("running", 3.0, 4.2, 142), "voltage is 0.445 V"),
                     (C.Expect("running", 0.3, 0.6, 141), "test id is 142"),
                     (C.Expect("running", 0.6, 0.3, 142), "min < max")):
        with pytest.raises(C.ControlRefused, match=msg):
            ctl.prepare("pause", "62-1-1", expect=exp)


def test_expectations_rechecked_before_sending(allowlist):
    states = {"62-1-1": dict(run_state("running"), test_id=142)}
    ctl = C.Controller(FakeFeed(states), port=1)
    tok = ctl.prepare("pause", "62-1-1", expect=C.Expect("running", 0.3, 0.6, 142))["token"]
    states["62-1-1"]["voltage_v"] = 3.7                 # something changed on the channel
    with pytest.raises(C.ControlRefused, match="voltage is 3.7 V"):
        ctl.execute_token(tok)                          # port=1: would fail if it tried to send
