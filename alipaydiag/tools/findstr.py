#!/usr/bin/env python3
"""在 Mach-O 里按关键字找 UTF-16LE / UTF-8 字符串，并给出所在 section。"""
import struct
import sys

PATH = sys.argv[1]
NEEDLES = [a.encode() for a in sys.argv[2:]]

data = open(PATH, 'rb').read()
magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from('<IIIIIIII', data, 0)
assert magic == 0xfeedfacf, hex(magic)
off = 32
sections = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off+8:off+24].rstrip(b'\0').decode()
        nsects = struct.unpack_from('<I', data, off+64)[0]
        soff = off + 72
        for _ in range(nsects):
            sectname = data[soff:soff+16].rstrip(b'\0').decode()
            seg2 = data[soff+16:soff+32].rstrip(b'\0').decode()
            addr, size, foff = struct.unpack_from('<QQI', data, soff+32)
            sections.append((seg2, sectname, addr, size, foff))
            soff += 80
    off += cmdsize

def section_of(fileoff):
    for seg, sect, addr, size, foff in sections:
        if foff and foff <= fileoff < foff + size:
            return f"{seg},{sect}"
    return "?"

for n in NEEDLES:
    # UTF-16LE
    i16 = 0
    while True:
        i = data.find(n.decode().encode('utf-16-le'), i16)
        if i < 0:
            break
        # 前后对齐到 2
        if i % 2 == 0:
            print(f"U16 {n.decode()} @ file 0x{i:x} {section_of(i)}")
        i16 = i + 1
    i8 = 0
    while True:
        i = data.find(n, i8)
        if i < 0:
            break
        print(f"UTF8 {n.decode()} @ file 0x{i:x} {section_of(i)}")
        i8 = i + 1
