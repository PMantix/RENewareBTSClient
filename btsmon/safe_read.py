"""Read files that BtsServer is actively writing, without ever blocking it.

BtsServerNT keeps .ndc files open and appends to them during a test. A reader that
opens a file without FILE_SHARE_WRITE / FILE_SHARE_DELETE could make the server's next
open/write/rename fail. This module opens with *all* share flags, read-only access,
reads the whole file into memory and closes the handle immediately.

Never use plain open()/shutil on files under NdcFile/.
"""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

MAX_BYTES = 512 * 1024 * 1024  # refuse absurd sizes rather than exhaust memory

if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    _k32.ReadFile.restype = wintypes.BOOL
    _k32.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    _k32.GetFileSizeEx.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL


def read_shared(path: str | os.PathLike, max_bytes: int = MAX_BYTES) -> bytes:
    """Return the current contents of *path*, opened read-only with full sharing."""
    path = os.fspath(path)
    if sys.platform != "win32":  # tests / other OSes: plain read is non-blocking there
        with open(path, "rb") as f:
            return f.read(max_bytes)

    h = _k32.CreateFileW(path, GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), f"CreateFileW failed: {path}")
    try:
        size = ctypes.c_longlong(0)
        if not _k32.GetFileSizeEx(h, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), f"GetFileSizeEx failed: {path}")
        want = min(size.value, max_bytes)
        buf = ctypes.create_string_buffer(want)
        got_total = 0
        while got_total < want:
            got = wintypes.DWORD(0)
            chunk = min(want - got_total, 16 * 1024 * 1024)
            ptr = ctypes.byref(buf, got_total)
            if not _k32.ReadFile(h, ptr, chunk, ctypes.byref(got), None):
                raise OSError(ctypes.get_last_error(), f"ReadFile failed: {path}")
            if got.value == 0:  # file shrank while reading
                break
            got_total += got.value
        return buf.raw[:got_total]
    finally:
        _k32.CloseHandle(h)
