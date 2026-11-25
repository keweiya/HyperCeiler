#!/usr/bin/env python3
"""Run the host audit of the HomeTweaks auto-close plan on a real launcher image."""
from pathlib import Path
import subprocess, sys, tempfile
root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'tests/home-layout-native'))
from dart_dump import Symbols
elf, mini = (Path(a).resolve() for a in sys.argv[1:3])
s = Symbols(mini)
def va(n): return s.by_name[n]
click, click_size = va('AppIconRemoteClick.handleRemoteClick')
close, close_size = va('FolderClingGetxController.handleFolderClingClose')
scroll = va('FolderGridViewGetxController.scrollNearestRow')[0]
rx = va('RxObjectMixin.value')[0]
registered = va('Inst|isRegistered')[0]
with tempfile.TemporaryDirectory(prefix='auto-close-') as tmp:
    exe = Path(tmp) / 't'
    subprocess.run(['g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-I',
        str(root / 'app/src/main/cpp'),
        str(Path(__file__).with_name('auto_close_test.cpp')), '-o', str(exe)], check=True)
    subprocess.run([str(exe), str(elf), f'{click:x}', f'{click_size:x}', f'{close:x}',
        f'{close_size:x}', f'{scroll:x}', f'{rx:x}', f'{registered:x}'], check=True)
