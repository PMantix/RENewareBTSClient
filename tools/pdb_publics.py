"""Minimal reader for public symbols (S_PUB32) in an MSF 7.0 PDB, no dependencies.

    python pdb_publics.py <file.pdb> <image.dll|exe> [regex]

Prints "RVA  name" for every public symbol (optionally filtered by regex), using the PE
section table to turn segment:offset into an RVA. Names are MSVC-decorated.
"""
from __future__ import annotations

import re
import struct
import sys

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"


class Msf:
    def __init__(self, data: bytes):
        if not data.startswith(MAGIC):
            raise ValueError("not an MSF 7.0 PDB")
        self.d = data
        (self.bs, _fpm, _nblocks, dir_bytes, _unk, dir_map_block) = struct.unpack_from("<6I", data, 32)
        n_dir_blocks = -(-dir_bytes // self.bs)
        # BlockMapAddr is a block holding the indices of the directory's blocks
        dir_blocks = struct.unpack_from(f"<{n_dir_blocks}I", data, dir_map_block * self.bs)
        dirdata = b"".join(self._blk(b) for b in dir_blocks)[:dir_bytes]
        n = struct.unpack_from("<I", dirdata)[0]
        sizes = struct.unpack_from(f"<{n}I", dirdata, 4)
        pos = 4 + 4 * n
        self.streams = []
        for s in sizes:
            if s == 0xFFFFFFFF:
                s = 0
            nb = -(-s // self.bs)
            blocks = struct.unpack_from(f"<{nb}I", dirdata, pos)
            pos += 4 * nb
            self.streams.append((s, blocks))

    def _blk(self, i: int) -> bytes:
        return self.d[i * self.bs:(i + 1) * self.bs]

    def stream(self, i: int) -> bytes:
        size, blocks = self.streams[i]
        return b"".join(self._blk(b) for b in blocks)[:size]


def publics(pdb_path: str):
    msf = Msf(open(pdb_path, "rb").read())
    dbi = msf.stream(3)
    # DBI header: sym record stream index is u16 at offset 20
    sym_stream = struct.unpack_from("<H", dbi, 20)[0]
    syms = msf.stream(sym_stream)
    pos = 0
    while pos + 4 <= len(syms):
        reclen, rectyp = struct.unpack_from("<HH", syms, pos)
        if reclen < 2:
            break
        if rectyp == 0x110E:  # S_PUB32
            _flags, off, seg = struct.unpack_from("<IIH", syms, pos + 4)
            name = syms[pos + 14:pos + 2 + reclen].split(b"\0", 1)[0].decode("latin1")
            yield seg, off, name
        pos += 2 + reclen


def section_rvas(image_path: str) -> list[int]:
    d = open(image_path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    sec = pe + 24 + opt
    return [struct.unpack_from("<I", d, sec + 40 * i + 12)[0] for i in range(nsec)]


def main(argv):
    pdb, img = argv[1], argv[2]
    pat = re.compile(argv[3]) if len(argv) > 3 else None
    rvas = section_rvas(img)
    for seg, off, name in publics(pdb):
        if pat and not pat.search(name):
            continue
        rva = rvas[seg - 1] + off if 0 < seg <= len(rvas) else None
        print(f"{rva:08X}  {name}" if rva is not None else f"--------  {name}")


if __name__ == "__main__":
    main(sys.argv)
