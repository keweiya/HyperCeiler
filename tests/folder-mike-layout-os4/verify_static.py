#!/usr/bin/env python3
"""Read-only ELF/source audit. No compiler, assembler or executable artifact.

This mirrors conservative instruction normalization to audit real-image
uniqueness and negative controls; it does not execute the C++ resolver or ARM.
"""
from pathlib import Path
import argparse, re, struct

p = argparse.ArgumentParser()
p.add_argument('--elf', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
raw = a.elf.read_bytes()
assert raw[:6] == b'\x7fELF\x02\x01'
phoff = struct.unpack_from('<Q', raw, 32)[0]
phsize, phcount = struct.unpack_from('<HH', raw, 54)
assert phsize == 56 and 0 < phcount <= 64
ranges = []
for i in range(phcount):
    typ, flags, off, va, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', raw, phoff + i * phsize)
    if typ == 1 and flags & 1:
        assert not flags & 2 and va % 4 == 0 and filesz % 4 == 0
        ranges.append((va, struct.unpack_from('<' + 'I' * (filesz // 4), raw, off)))

header = (root/'app/src/main/cpp/targets/home/home_folder_mike_layout.h').read_text()
producer_hash = int(re.search(r'fingerprint != (0x[0-9a-f]+)ULL', header).group(1), 16)
getter_header = header[header.index('inline bool folder_mike_columns_site('):]
getter_hash = int(re.search(r'fingerprint != (0x[0-9a-f]+)ULL', getter_header).group(1), 16)

def sign(n, bits):
    return n - (1 << bits) if n & (1 << (bits - 1)) else n

def digest(words, producer):
    h = 1469598103934665603
    for i, w in enumerate(words):
        if w & 0xfc000000 == 0x94000000:
            w &= 0xfc000000
        elif producer and i in (17, 18, 43, 44):
            w &= ~0x003ffc00
        elif producer and w & 0xfc000000 == 0x14000000:
            target = i + sign(w & 0x3ffffff, 26)
            if not 0 <= target < len(words):
                w &= 0xfc000000
        h = ((h ^ w) * 1099511628211) & ((1 << 64) - 1)
    return h

def accept(words, producer):
    if len(words) != (217 if producer else 31):
        return False
    return digest(words, producer) == (producer_hash if producer else getter_hash)

found = {True: [], False: []}
for va, words in ranges:
    for i in range(len(words) - 1):
        if words[i:i+2] != (0xa9bf79fd, 0xaa0f03fd):
            continue
        for producer in (True, False):
            count = 217 if producer else 31
            candidate = words[i:i+count]
            if accept(candidate, producer):
                found[producer].append((va + i * 4, candidate))
assert len(found[True]) == len(found[False]) == 1, {k: len(v) for k,v in found.items()}
for producer in (True, False):
    va, words = found[producer][0]
    for i in range(len(words)):
        changed = list(words); changed[i] = 0xd503201f
        assert not accept(changed, producer), (producer, i)
    moved = [((w & 0xfc000000) | ((w + 1) & 0x3ffffff)) if w & 0xfc000000 == 0x94000000 else w for w in words]
    assert accept(moved, producer)
    print(f'PASS unique {"producer" if producer else "getter"}: VA={va:#x}, words={len(words)}, each-word NOP controls, BL relocation')
va, getter = found[False][0]
assert getter[27:] == (0x91001800, 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0)

asm = (root/'app/src/main/cpp/targets/home/home_layout_dart_arm64.S').read_text()
columns = asm[asm.index('hc_folder_mike_columns_entry:'):]
assert all(x in columns for x in ('hc_folder_mike_ready', 'hc_folder_mike_config',
    'ubfx x10, x9, #27, #3', 'cmp x10, #4', 'b.lo 1f', 'cmp x10, #6',
    'b.hi 1f', 'lsl x0, x10, #1', 'hc_folder_mike_columns_original'))
assert columns.index('dart_restore') < columns.index('mov x15, x29')
assert columns.count('dart_restore') == 2
hooks = (root/'app/src/main/cpp/targets/home/home_layout_hooks.cpp').read_text()
assert 'const uint64_t packed = __atomic_load_n(&hc_folder_mike_config' in hooks
assert 'home_layout::folder_mike_columns_site(fn.words, fn.va, offset)' in hooks
print('PASS static paired getter ABI: original ADD+epilogue, shared gate/config, 4..6 range and pass-through tail')
print('STATIC_ONLY: no C++/ARM execution, build, install, or device animation validation')
