"""Extract embedded FileDescriptorProto blobs (base64) from ILSpy-decompiled
Google.ProtocolBuffers C# sources and print them as .proto text.
Usage: python -I dump_protos.py <proto_src_dir> <out_dir>
"""
import base64, os, re, sys

def varint(b, i):
    r = s = 0
    while True:
        c = b[i]; i += 1
        r |= (c & 0x7F) << s; s += 7
        if c < 0x80:
            return r, i

def fields(b):
    i = 0
    out = []
    while i < len(b):
        k, i = varint(b, i)
        fn, wt = k >> 3, k & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            l, i = varint(b, i); v = b[i:i+l]; i += l
        elif wt == 1:
            v = b[i:i+8]; i += 8
        elif wt == 5:
            v = b[i:i+4]; i += 4
        else:
            raise ValueError(wt)
        out.append((fn, v))
    return out

TYPES = {1:'double',2:'float',3:'int64',4:'uint64',5:'int32',6:'fixed64',7:'fixed32',8:'bool',9:'string',
         10:'group',11:'message',12:'bytes',13:'uint32',14:'enum',15:'sfixed32',16:'sfixed64',17:'sint32',18:'sint64'}
LABELS = {1:'optional',2:'required',3:'repeated'}

def field_txt(b):
    d = {}
    for fn, v in fields(b):
        d.setdefault(fn, v)
    name = d.get(1, b'').decode(); num = d.get(3); lab = LABELS.get(d.get(4), '?'); t = d.get(5)
    tn = d.get(6, b'').decode()
    ty = tn if t in (11, 14) else TYPES.get(t, str(t))
    return f"  {lab} {ty} {name} = {num};"

def msg_txt(b, ind=''):
    lines = []
    fs = fields(b)
    name = next(v for f, v in fs if f == 1).decode()
    lines.append(f"{ind}message {name} {{")
    for f, v in fs:
        if f == 2:
            lines.append(ind + field_txt(v))
        elif f == 3:
            lines += msg_txt(v, ind + '  ')
        elif f == 4:
            lines += enum_txt(v, ind + '  ')
    lines.append(f"{ind}}}")
    return lines

def enum_txt(b, ind=''):
    fs = fields(b)
    name = next(v for f, v in fs if f == 1).decode()
    lines = [f"{ind}enum {name} {{"]
    for f, v in fs:
        if f == 2:
            d = dict(fields(v))
            lines.append(f"{ind}  {d.get(1,b'').decode()} = {d.get(2,0)};")
    lines.append(f"{ind}}}")
    return lines

def file_txt(b):
    fs = fields(b)
    lines = []
    for f, v in fs:
        if f == 1: lines.append(f"// file: {v.decode()}")
        elif f == 2: lines.append(f"package {v.decode()};")
        elif f == 3: lines.append(f'import "{v.decode()}";')
        elif f == 12: lines.append(f'syntax = "{v.decode()}";')
    for f, v in fs:
        if f == 4: lines += msg_txt(v)
        elif f == 5: lines += enum_txt(v)
    return '\n'.join(lines)

def main(src, out):
    os.makedirs(out, exist_ok=True)
    rx = re.compile(r'FromBase64String\((.*?)\), descriptorAssigner', re.S)
    n = 0
    for root, _, files in os.walk(src):
        for fn in files:
            if not fn.endswith('.cs'):
                continue
            p = os.path.join(root, fn)
            s = open(p, encoding='utf-8', errors='replace').read()
            for m in rx.finditer(s):
                b64 = ''.join(re.findall(r'"([^"]*)"', m.group(1)))
                blob = base64.b64decode(b64)
                txt = file_txt(blob)
                rel = os.path.relpath(p, src).replace(os.sep, '_')
                open(os.path.join(out, rel[:-3] + '.proto'), 'w', encoding='utf-8').write(
                    f"// extracted from {os.path.relpath(p, src)}\n" + txt + '\n')
                n += 1
    print('extracted', n)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
