"""Live, read-only realtime feed from BtsServer (TCP 8001).

A background thread logs in like BTS.exe, lists devices, asks each for its info and
subscribes (Plus SelectDev), then keeps the latest RTData83 per channel (~2 s updates).
It sends ONLY the read-only packets in btsmon.protocol (login, heartbeat, device list,
device info, select device); protocol.pkt_plus refuses anything else.

Observed safe on the live rig (docs/findings.md F-CS-8, F-CS-9). Reconnects with backoff
(>= 30 s). TX frames and non-realtime RX frames are logged to logs/live_<date>.log with
DB credentials redacted.

    python -m btsmon.live --seconds 20        # print live channels after 20 s
"""
from __future__ import annotations

import argparse
import os
import socket
import threading
import time
from datetime import datetime

from . import protocol as P

HEARTBEAT_S = 10
RECONNECT_MIN_S = 30
RECONNECT_MAX_S = 300
STALE_S = 10           # a reading older than this is not "live"


class LiveFeed:
    def __init__(self, host: str = "127.0.0.1", port: int = 8001, log_dir: str = "logs"):
        self.host, self.port, self.log_dir = host, port, log_dir
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self.channels: dict[tuple[int, int, int], dict] = {}   # (dev, unit, chl) -> reading
        self.devices: dict[int, dict] = {}                       # dev_id -> info
        self.server: dict = {}
        self.connected = False
        self.last_error: str | None = None
        self.sessions = 0

    # ---- public ------------------------------------------------------------------------
    def start(self) -> "LiveFeed":
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="btsmon-live", daemon=True)
            self._thread.start()
        return self

    def stop(self, timeout: float = 3.0) -> None:
        # The session loop wakes at least once per second (recv timeout) and then closes
        # the socket gracefully itself; don't shut it down from here.
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            chans = {f"{d}-{u}-{c}": dict(v, age_s=round(now - v["rx_time"], 1),
                                          live=(now - v["rx_time"]) < STALE_S)
                     for (d, u, c), v in sorted(self.channels.items())}
            return {"connected": self.connected, "server": dict(self.server),
                    "devices": {k: dict(v) for k, v in self.devices.items()},
                    "channels": chans, "last_error": self.last_error, "sessions": self.sessions}

    def channel(self, name: str) -> dict | None:
        try:
            d, u, c = (int(x) for x in name.split("-"))
        except ValueError:
            return None
        with self._lock:
            v = self.channels.get((d, u, c))
            if v is None:
                return None
            age = time.time() - v["rx_time"]
            return dict(v, age_s=round(age, 1), live=age < STALE_S)

    # ---- internals ---------------------------------------------------------------------
    def _log(self, text: str, raw: bytes = b"") -> None:
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            path = os.path.join(self.log_dir, f"live_{datetime.now():%Y%m%d}.log")
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now():%H:%M:%S.%f} {text}" + (f"\n    {raw.hex(' ')}" if raw else "") + "\n")
        except OSError:
            pass

    def _send(self, sock: socket.socket, data: bytes, what: str) -> None:
        self._log(f"TX {what}", data)
        sock.sendall(data)

    def _run(self) -> None:
        backoff = RECONNECT_MIN_S
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self._session()
            except Exception as e:  # noqa: BLE001 - keep the feed alive, record why
                if not self._stop.is_set():
                    self.last_error = f"{type(e).__name__}: {e}"
                    self._log(f"ERROR {self.last_error}")
            finally:
                self.connected = False
            if self._stop.is_set():
                break
            # long healthy session -> reset backoff
            backoff = RECONNECT_MIN_S if time.monotonic() - started > 600 else min(backoff * 2, RECONNECT_MAX_S)
            self._stop.wait(backoff)

    def _session(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=5)
        self._sock = sock
        self.sessions += 1
        buf = bytearray()
        try:
            sock.settimeout(1.0)
            self._log(f"connected {self.host}:{self.port} local {sock.getsockname()}")
            self._send(sock, P.pkt_login(), "login")
            hb, next_hb = 0, time.monotonic() + 1.5
            asked_list = False
            pending: list[tuple[float, bytes, str]] = []
            chunks: dict[tuple[int, int], bytearray] = {}
            while not self._stop.is_set():
                now = time.monotonic()
                if self.connected and not asked_list and now >= next_hb - 0.5:
                    self._send(sock, P.pkt_get_device_list(), "getdevlist")
                    asked_list = True
                if self.connected and now >= next_hb:
                    self._send(sock, P.pkt_heartbeat(hb), f"heartbeat {hb}")
                    hb, next_hb = hb + 1, now + HEARTBEAT_S
                while pending and now >= pending[0][0]:
                    _, data, what = pending.pop(0)
                    self._send(sock, data, what)
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    raise ConnectionError("server closed the connection")
                buf += chunk
                for raw in P.split_frames(buf):
                    self._handle(P.parse_frame(raw), pending, chunks)
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
                end = time.monotonic() + 1.0
                sock.settimeout(0.5)
                while time.monotonic() < end and sock.recv(65536):
                    pass
            except OSError:
                pass
            sock.close()
            self._sock = None
            self._log("closed")

    def _handle(self, f: P.Frame, pending: list, chunks: dict) -> None:
        if f.cmd == 0x80:
            self._log(f"RX login result={f.result}", f.raw)
            if f.result == 0:
                self.connected, self.last_error = True, None
            else:
                raise ConnectionError(f"login rejected, result {f.result}")
            return
        if f.cmd_ex == P.SVR_VERSION:
            self.server = P.parse_svr_version(f)
            self._log(f"RX server version {self.server}", P.redact_svr_version(f.raw))
            return
        if f.cmd_ex == P.RT_DATA_83:
            msg = P.decode(f.payload, P.RTDATA82_RESP)
            dev, unit, t = msg.get("DevID", f.dev_id), msg.get("UnitID", f.unit), time.time()
            with self._lock:
                for rt in msg.get("RTData83", []):
                    if rt.get("AuxChlID", 0):
                        continue
                    self.channels[(dev, unit, rt.get("ChlID"))] = dict(P.rt_to_channel(rt), rx_time=t)
            return
        if f.cmd_ex in P.PLUS_RESPONSES:
            key = (f.cmd_ex, f.dev_id)
            if f.sub_index == 0:
                chunks[key] = bytearray()
            chunks.setdefault(key, bytearray()).extend(f.payload)
            if f.sub_flag != 2:
                return
            data = bytes(chunks.pop(key))
            if f.cmd_ex == 0x8211:
                return
            self._log(f"RX plus 0x{f.cmd_ex:04X} dev={f.dev_id} result={f.result}", f.raw[:64])
            if f.cmd_ex == 0x821B:
                devs = P.decode(data, P.RESP_GET_DEVICE_LIST).get("Devs", [])
                t = time.monotonic()
                for i, d in enumerate(x for x in devs if x.get("OnLineStatus") == 1):
                    dev_id, dev_type = d.get("DevID"), d.get("DevType", P.DEV_TYPE_BTS83)
                    if dev_type != P.DEV_TYPE_BTS83:
                        self._log(f"skip device {dev_id}: devType {dev_type} not supported")
                        continue
                    with self._lock:
                        self.devices.setdefault(dev_id, {}).update(d)
                    pending.append((t + 0.5 + i, P.pkt_get_device_info(dev_id), f"getdevinfo {dev_id}"))
                    pending.append((t + 1.0 + i, P.pkt_select_dev(dev_id), f"selectdev {dev_id}"))
                pending.sort(key=lambda x: x[0])
            elif f.cmd_ex == 0x8201:
                info = P.decode(data, P.RESP_GET_DEVICE_INFO)
                di = info.get("DeviceInfo83", {})
                xwj = di.get("XwjInfo", [])
                with self._lock:
                    self.devices.setdefault(f.dev_id, {}).update({
                        "ip": info.get("IP"), "sn": di.get("SN"), "zwj_soft": di.get("SoftVersion"),
                        "units": sorted({c.get("UnitID") for c in di.get("ChlMap", [])}),
                        "channels": len(di.get("ChlMap", [])),
                        "max_current_ma": max((x.get("ChgRange", 0) for x in xwj), default=None),
                        "current_ranges_ma": xwj[0].get("CurrRange") if xwj else None,
                        "voltage_range_v": xwj[0].get("VolRange") if xwj else None,
                    })
            return
        # other pushes (0x80E4 status, 0x80BF, ...): log once in a while only
        if f.cmd_ex not in (0x80E4,):
            self._log(f"RX cmd=0x{f.cmd:02X} cmdEx={'' if f.cmd_ex is None else hex(f.cmd_ex)} len={len(f.raw)}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--seconds", type=float, default=20)
    a = ap.parse_args(argv)
    feed = LiveFeed(a.host, a.port).start()
    try:
        time.sleep(a.seconds)
    finally:
        feed.stop()
    s = feed.snapshot()
    print("server", s["server"], "connected-sessions", s["sessions"], "error", s["last_error"])
    for k, v in s["devices"].items():
        print("device", k, v)
    for name, c in s["channels"].items():
        if c["work_type"] or c["step_no"]:
            print(f"{name:<8} {c['work_state']:<8} V={c['voltage_v']:.4f} I={c['current_ma']:.4f}mA "
                  f"step={c['step_no']}/{c['step_type_code']} t={c['step_time_s'] / 3600:.2f}h "
                  f"Qc={c['charge_mah']:.3f} Qd={c['discharge_mah']:.3f} prt={c['protect_code']} age={c['age_s']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
