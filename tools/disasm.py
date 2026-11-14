"""Disassemble one function of a PE64 image by RVA, annotating calls with PDB publics.

    python disasm.py <image> <pdb> <rva-hex> [max_insns]

Needs a 64-bit Python with `capstone` (see vendor/tools/py64). Static only.
"""
from __future__ import annotations

import struct
import sys

import capstone

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from pdb_publics import publics, section_rvas  # noqa: E402


def load(image: str):
    d = open(image, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    base = struct.unpack_from("<Q", d, pe + 24 + 24)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + opt + 40 * i
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)
        secs.append((va, max(vsize, rawsize), rawptr))
    return d, base, secs


def read_rva(d, secs, rva, n):
    for va, size, raw in secs:
        if va <= rva < va + size:
            return d[raw + rva - va: raw + rva - va + n]
    raise ValueError(f"RVA {rva:X} not in image")


def main(argv):
    image, pdb, rva = argv[1], argv[2], int(argv[3], 16)
    maxn = int(argv[4]) if len(argv) > 4 else 400
    d, base, secs = load(image)
    rvas = section_rvas(image)
    names = {}
    for seg, off, name in publics(pdb):
        if 0 < seg <= len(rvas):
            names[rvas[seg - 1] + off] = name
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    end = min((a for a in names if a > rva), default=rva + 0x4000)
    code = read_rva(d, secs, rva, end - rva)
    n = 0
    for ins in md.disasm(code, rva):
        note = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            tgt = int(ins.op_str, 16)
            note = names.get(tgt, "")
        elif "rip +" in ins.op_str:
            try:
                disp = int(ins.op_str.split("rip + ")[1].split("]")[0], 16)
                note = names.get(ins.address + ins.size + disp, "")
            except ValueError:
                pass
        print(f"{ins.address:08X}  {ins.mnemonic:6} {ins.op_str:50} {note[:110]}")
        n += 1
        if n >= maxn:
            break


if __name__ == "__main__":
    main(sys.argv)
