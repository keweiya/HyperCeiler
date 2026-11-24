#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
build="$(mktemp -d -t hc-mike-planner.XXXXXX)"
trap 'rm -rf "$build"' EXIT
cpp="$root/app/src/main/cpp"
tweaks="$cpp/targets/home/tweaks"
for name in xz_crc32 xz_crc64 xz_dec_lzma2 xz_dec_stream; do
    "${CC:-cc}" -std=c99 -O2 -I"$tweaks/xz" -c "$tweaks/xz/$name.c" -o "$build/$name.o"
done
"${CXX:-g++}" -std=c++20 -O2 -Wall -Wextra -Wno-misleading-indentation \
    -I"$cpp" -I"$root/tests/home-layout-native/stubs" \
    "$root/tests/folder-mike-layout-os4/planner_test.cpp" \
    "$tweaks/symtab.cpp" "$tweaks/scanner.cpp" "$tweaks/image.cpp" \
    "$tweaks/ht_plan.cpp" "$tweaks/blob.cpp" "$build/"*.o -o "$build/planner"
"$build/planner" "$@"
