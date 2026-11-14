"""Neware log codes (LogCode.csv shipped with BTS Client) and channel end-state logic.

LogCode.csv is read at runtime from the BTS install (UTF-16, columns: code, name,
protect code, protect item, event (zh), protect item (en), event (en), lamp, ...).
Lamp: -1 record, 0 tip, 1 warning, 2/3/4 error levels.
"""
from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass
from functools import lru_cache

from .ndc import LOG_CODE_FINISH, LOG_CODE_STATUS_CHANGED, LOG_CODE_STOP, LogEvent

DEFAULT_CSV = r"C:\Program Files (x86)\NEWARE\BTSClient80\LogCode.csv"
USER_CLEAR = 0xE4


@dataclass(frozen=True)
class LogCode:
    code: int
    name: str
    text: str
    lamp: int


@lru_cache(maxsize=4)
def load(path: str = DEFAULT_CSV) -> dict[int, LogCode]:
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("gbk", "replace")
    out: dict[int, LogCode] = {}
    for row in list(csv.reader(io.StringIO(text)))[1:]:
        try:
            code = int(row[0].strip(), 16)
        except (ValueError, IndexError):
            continue
        en = (row[6] if len(row) > 6 else "").strip() or (row[5] if len(row) > 5 else "").strip()
        try:
            lamp = int((row[7] if len(row) > 7 else "0").strip() or 0)
        except ValueError:
            lamp = 0
        out[code] = LogCode(code, row[1].strip(), en or row[1].strip(), lamp)
    return out


def describe(code: int, codes: dict[int, LogCode] | None = None) -> str:
    codes = load() if codes is None else codes
    c = codes.get(code)
    return f"0x{code:X} {c.text}" if c else f"0x{code:X}"


def end_state(events: list[LogEvent], codes: dict[int, LogCode] | None = None) -> tuple[str, str | None]:
    """Classify how a test ended from its log: finished / stopped / protect / cleared / unknown.

    Returns (state, reason). Only meaningful for a channel that is not live.
    """
    codes = load() if codes is None else codes
    sig = [e for e in events if e.code != LOG_CODE_STATUS_CHANGED]
    if sig and sig[-1].code == USER_CLEAR:
        # channel was cleared by a user; report what it was cleared from
        prev = next((e for e in reversed(sig) if e.code != USER_CLEAR), None)
        return "cleared", (f"after {describe(prev.code, codes)}" if prev else None)
    for ev in reversed(events):
        if ev.code in (LOG_CODE_STATUS_CHANGED, USER_CLEAR):
            continue
        if ev.code == LOG_CODE_FINISH:
            return "finished", None
        if ev.code == LOG_CODE_STOP:
            return "stopped", None
        c = codes.get(ev.code)
        if c is not None and c.lamp >= 1:
            return "protect", describe(ev.code, codes)
        # normal step-end codes (lamp -1/0): keep looking further back only if the
        # last record is just a step transition with no terminal event
        return "unknown", describe(ev.code, codes)
    return "unknown", None
