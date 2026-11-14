"""Start a step file on an allowlisted channel (btsmon.start), or just show the packets.

    python tools/start_test.py 62-1-1 path/to/schedule.xml            # dry run: print only
    python tools/start_test.py 62-1-1 path/to/schedule.xml --send     # really start

The dry run connects the read-only live feed (device info) and sends nothing else.
--send applies the guards (allowlist, channel idle on the live feed), then runs the start
transaction; a pause is sent automatically if Start was sent but not confirmed.
The start packets are Inferred from code: the first --send needs the user's go-ahead
with them watching the GUI (CLAUDE.md rules 8/9).
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from btsmon import gui_defaults, start  # noqa: E402
from btsmon.control import ControlRefused, load_allowlist  # noqa: E402
from btsmon.live import LiveFeed  # noqa: E402


def main(argv) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    name, path, send = argv[1], argv[2], "--send" in argv
    ch = load_allowlist().get(name)
    if ch is None:
        print(f"REFUSED: {name} is not in config/test_channels.json")
        return 2
    feed = LiveFeed().start()
    try:
        t_end = time.time() + 20
        while time.time() < t_end and not (feed.channel(name) or {}).get("live"):
            time.sleep(0.5)
        dev = feed.snapshot().get("devices", {}).get(ch["dev_id"], {})
        plan = start.build_plan(path, ch, dev, gui_defaults.load_sysset(), start.load_sysglobal())
        print(f"channel {plan.channel}  guid {plan.guid_hex}  {plan.info}")
        for r in plan.records:
            print(f"  step {r.step_index} {r.type_name}: {r.fields}")
        for st in plan.stages:
            print(f"  {st.name:11s} 0x{st.cmd_ex:04X} {len(st.packet):5d} B  {st.packet.hex(' ')}")
        print("  confirm     0x00E3 after the Start reply (test ids from the reply)")
        if not send:
            print("DRY RUN: nothing sent.")
            return 0
        try:
            start.check_start(name, feed)
        except ControlRefused as e:
            print(f"REFUSED: {e}. Nothing sent.")
            return 3
        os.makedirs("logs", exist_ok=True)
        with open(f"logs/start_{datetime.now():%Y%m%d_%H%M%S}_{name}.log", "w", encoding="utf-8") as lf:
            def out(s):
                print(s)
                lf.write(s + "\n")
                lf.flush()
            r = start.run_plan(plan, out=out)
            time.sleep(5)
            after = feed.channel(name)
            out(f"after: {after}")
        return 0 if r.ok else 1
    finally:
        feed.stop()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
