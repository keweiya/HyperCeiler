#!/usr/bin/env python3
"""Negative wiring contracts: never mix producer layout with retired corrections."""
from pathlib import Path
root = Path(__file__).resolve().parents[2]
hooks = (root/'app/src/main/cpp/targets/home/home_layout_hooks.cpp').read_text()
planner = (root/'app/src/main/cpp/targets/home/tweaks/ht_plan.cpp').read_text()
startup = (root/'app/src/main/cpp/targets/home/home_startup.cpp').read_text()
entry = (root/'app/src/main/cpp/targets/home/hyperceiler_home.cpp').read_text()
def function(text, signature):
    a = text.index(signature); b = text.index('{', a); depth = 1; end = b+1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}'); end += 1
    return text[a:end]
assert 'return false;' in function(hooks, 'static bool folder_preview_requested(')
layout = function(hooks, 'bool bind_folder_layout() {')
assert '& 1)' in layout and 'if (i != 4 && i != 5 && i != 7) continue;' in layout
assert 'LocateFeature16Square' not in planner
assert 'kSitesPayloadVersion = 11' in planner
assert 'ReadFolderProducerOriginal' in planner
assert 'if (!top && !bottom && !side) return;' in function(hooks, 'extern "C" void hc_layout_folder_body(')
assert 'kFeatureFolderCols' not in function(hooks, 'home_layout_engine::Config make_layout_engine_config(')
first = function(hooks, 'void prime_home_folder_mike(')
assert 'bind_folder_mike()' in first and 'pair{kFolderMikeSlot, kFolderMikeColumnsSlot}' in first
assert 'SetInLoaderCallback(previous)' in first
assert 'nhk::slot_ready(g_slots[kFolderMikeColumnsSlot])' in first
assert first.index('ensure_slots_live') < first.index('__atomic_store_n(&hc_folder_mike_ready')
assert 'g_folder_mike_startup_window' in function(hooks, 'bool bind_folder_mike() {')
loader = function(entry, 'void on_library_loaded(')
assert loader.index('prime_home_folder_mike(') < loader.index('HomeLayoutEngineOnLibraryLoaded(')
assert 'RecentsAnimationRust | FolderColumns' in startup
print('PASS integration: producer startup, ready gate, no old full-width/preview/square mixture, HYOS old plan disabled')
