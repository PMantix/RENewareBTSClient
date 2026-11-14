"""CLI for the verified channel controls (pause/resume/jump/clear) via btsmon.control.

Same guards as the MCP tools: allowlist (config/test_channels.json), live-state check,
verification on the live feed, logs in logs/control_*.log.

    python tools/control_test.py pause  62-1-1
    python tools/control_test.py resume 62-1-1
    python tools/control_test.py jump   62-1-1 <step_no>
    python tools/control_test.py clear  62-1-1
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from btsmon.control import ControlRefused, Controller, load_allowlist  # noqa: E402
from btsmon.live import LiveFeed  # noqa: E402


def main(argv) -> int:
    action, name = argv[1], argv[2]
    step = int(argv[3]) if action == "jump" and len(argv) > 3 else None
    if name not in load_allowlist():
        print(f"REFUSED: {name} is not in config/test_channels.json")
        return 2
    feed = LiveFeed().start()
    try:
        t_end = time.time() + 20
        while time.time() < t_end and not (feed.channel(name) or {}).get("live"):
            time.sleep(0.5)
        try:
            r = Controller(feed).execute(action, name, step)
        except ControlRefused as e:
            print(f"REFUSED: {e}. Nothing sent.")
            return 3
        print("\n".join(r.log))
        return 0 if r.ok else 1
    finally:
        feed.stop()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
