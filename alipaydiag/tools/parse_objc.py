#!/usr/bin/env python3
"""极简 Mach-O ObjC 元数据解析：输出 类名 -> 方法名列表。
假设 __DATA_CONST 内指针为 dyld chained fixup 的 rebase 形式（无 bind）。"""
import struct
import sys

PATH = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else '/dev/stdout'
FILTER = sys.argv[3] if len(sys.argv) > 3 else None

d = open(PATH, 'rb').read()
magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from('<IIIIIIII', d, 0)
segments = []
off = 32
chained = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == 0x19:
        seg = d[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize, foff, fsize = struct.unpack_from('<QQQQ', d, off+24)
        segments.append((seg, vmaddr, vmsize, foff, fsize))
    elif cmd == 0x80000034:
        chained = struct.unpack_from('<IIII', d, off + 8)  # dataoff, datasize, ...
        chained = (chained[0], chained[1])
    off += cmdsize

BASE = 0x100000000  # arm64 常见基址，从 __TEXT vmaddr 取

def seg_of(vmaddr):
    for seg, va, vs, fo, fs in segments:
        if va <= vmaddr < va + vs:
            return seg, va, fo, fs
    return None

def vm2file(vmaddr):
    s = seg_of(vmaddr)
    if not s:
        return None
    seg, va, fo, fs = s
    delta = vmaddr - va
    if delta >= fs:
        return None
    return fo + delta

def decode_ptr(vmaddr_slot):
    """返回该 slot 解码后的目标 vmaddr；slot 必须是 8 字节对齐。"""
    fo = vm2file(vmaddr_slot)
    if fo is None:
        return None
    raw = struct.unpack_from('<Q', d, fo)[0]
    if raw == 0:
        return 0
    if (raw >> 63) == 0:
        # rebase: 低 36 位是目标相对 preferred base 的偏移（或绝对页偏移）
        target = raw & 0xFFFFFFFFF
        if target < BASE:
            target += BASE
        return target
    return None  # bind 等，跳过

def read_cstr(vmaddr):
    fo = vm2file(vmaddr)
    if fo is None:
        return None
    end = d.find(b'\0', fo)
    try:
        return d[fo:end].decode('utf-8', 'replace')
    except Exception:
        return None

# 找 __objc_classlist 段
classlist = None
for seg, va, vs, fo, fs in segments:
    pass

# 从 load commands 找 section
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == 0x19:
        segname = d[off+8:off+24].rstrip(b'\0').decode()
        nsects = struct.unpack_from('<I', d, off+64)[0]
        so = off + 72
        for _ in range(nsects):
            sectname = d[so:so+16].rstrip(b'\0').decode()
            seg2 = d[so+16:so+32].rstrip(b'\0').decode()
            addr, size, foff = struct.unpack_from('<QQI', d, so+32)
            if sectname == '__objc_classlist':
                classlist = (addr, size, foff)
            so += 80
    off += cmdsize

assert classlist, 'no __objc_classlist'
addr0, size0, foff0 = classlist
n = size0 // 8

def parse_class(cls_ptr):
    # class_t: isa, superclass, cache, vtable, data
    data_ptr = decode_ptr(cls_ptr + 32)
    if not data_ptr:
        return None
    data_ptr &= ~0x7
    fo = vm2file(data_ptr)
    if fo is None:
        return None
    rflags, instart, insize, reserved = struct.unpack_from('<IIII', d, fo)
    ivarlayout = decode_ptr(data_ptr + 16)
    name_ptr = decode_ptr(data_ptr + 24)
    base_methods = decode_ptr(data_ptr + 32)
    base_protocols = decode_ptr(data_ptr + 40)
    ivars = decode_ptr(data_ptr + 48)
    weaklayout = decode_ptr(data_ptr + 56)
    base_props = decode_ptr(data_ptr + 64)
    return dict(flags=rflags, name=read_cstr(name_ptr) if name_ptr else None,
                base_methods=base_methods, base_props=base_props)

def parse_relative_methods(mlist_ptr):
    fo = vm2file(mlist_ptr)
    if fo is None:
        return []
    entsize_flags, count = struct.unpack_from('<II', d, fo)
    relative = bool(entsize_flags & 0x80000000)
    entsize = entsize_flags & 0xFFFF
    out = []
    if relative and entsize == 12:
        for i in range(count):
            eo = fo + 8 + i*12
            name_off, types_off, imp_off = struct.unpack_from('<iii', d, eo)
            ref_slot = mlist_ptr + 8 + i*12 + name_off
            ref = decode_ptr(ref_slot)
            if not ref:
                continue
            nm = read_cstr(ref)
            if nm:
                out.append(nm)
    else:
        # 绝对指针数组
        for i in range(count):
            p = decode_ptr(mlist_ptr + 8 + i*entsize)
            if p:
                nm = read_cstr(p)
                if nm:
                    out.append(nm)
    return out

lines = []
for i in range(n):
    slot = addr0 + i*8
    cls = decode_ptr(slot)
    if not cls:
        continue
    info = parse_class(cls)
    if not info or not info['name']:
        continue
    name = info['name']
    if FILTER and FILTER.lower() not in name.lower():
        continue
    sels = parse_relative_methods(info['base_methods']) if info['base_methods'] else []
    lines.append(name)
    for s in sels:
        lines.append('    ' + s)

with open(OUT, 'w') as f:
    f.write('\n'.join(lines) + '\n')
print(f"classes={n} written={len(lines)}")
