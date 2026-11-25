/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <cstdint>
#include <span>
#include <optional>
#include <array>
#include "home_dynamic_layout.h"
namespace home_layout {
constexpr const char* kFolderAutoClickSymbol = "AppIconRemoteClick.handleRemoteClick";
constexpr uint32_t kFolderAutoCloseMagic = 0x48434641;
constexpr uint32_t kFolderAutoCloseReplacement = 0xd503201f; // NOP, no Dart ABI crossing.
inline uint32_t auto_close_call(uint32_t pc, uint32_t w) {
    int32_t imm = int32_t(w << 6) >> 6;
    return uint32_t(int64_t(pc) + int64_t(imm) * 4);
}
// HomeTweaks 81 ("folderautoclose"): a click inside an open folder must run the
// launcher's own close-then-launch block, with the stock animated close. The stock
// code reaches that block only when two early tests already say "folder closed", so
// both are neutralised instead of replacing the close with a synchronous variant:
//   1. the mode gate reading the click model (fp spill -> RxObjectMixin.value),
//   2. the folder-open gate (registered controller -> Rx value in the heap),
//   3. inside the close routine, the grid re-scroll gate becomes an unconditional
//      branch, so closing no longer starts a second scroll animation.
// The launch continuation, the registration test and every blocked-launch guard are
// left untouched.
struct FolderAutoClosePlan {
    uint32_t mode_gate = 0;        // byte offset in the click body
    uint32_t open_gate = 0;        // byte offset in the click body
    uint32_t scroll_gate = 0;      // byte offset in the close body
    uint32_t scroll_branch = 0;    // replacement word: b <scroll continuation>
};
inline std::optional<FolderAutoClosePlan> resolve_folder_auto_close(
    std::span<const uint32_t> body, uint32_t va, uint32_t close, uint32_t rx, uint32_t registered,
    std::span<const uint32_t> close_body, uint32_t scroll) {
    if (body.size() < 8 || body[0] != 0xa9bf79fd || body[1] != 0xaa0f03fd) return {};
    size_t close_at = 0, close_count = 0;
    for (size_t i = 0; i < body.size(); ++i)
        if ((body[i] & 0xfc000000u) == 0x94000000u
            && auto_close_call(va + uint32_t(i * 4), body[i]) == close) {
            close_at = i; ++close_count;
        }
    // The close call carries the animated flag in x2 (add x2,x22,#0x20) and the
    // dispatch record in x4; a close invoked with any other shape is not this path.
    if (close_count != 1 || close_at < 4 || close_at + 1 > body.size()
        || body[close_at - 2] != 0x910082c2 || body[close_at - 1] != 0xf9403b64) return {};
    const uint32_t end = va + uint32_t((close_at + 1) * 4);
    unsigned registered_calls = 0;
    size_t mode = 0, open = 0; unsigned mode_hits = 0, open_hits = 0;
    for (size_t i = 2; i < close_at; ++i) {
        if ((body[i] & 0xfc000000u) == 0x94000000u
            && auto_close_call(va + uint32_t(i * 4), body[i]) == registered) ++registered_calls;
        // Every candidate gate is a TBNZ on the Rx result that jumps past the close.
        if ((body[i] & 0xfff80000u) != 0x37200000u || (body[i] & 31u) != 0u) continue;
        int32_t jump = int32_t(((body[i] >> 5) & 0x3fffu) << 18) >> 18;
        if (int64_t(va) + int64_t(i * 4) + int64_t(jump) * 4 != end) continue;
        if ((body[i - 1] & 0xfc000000u) != 0x94000000u
            || auto_close_call(va + uint32_t((i - 1) * 4), body[i - 1]) != rx) continue;
        // Mode gate: the tested value was spilled to the Dart frame by this caller.
        if ((body[i - 2] & 0xffe00fffu) == 0xf84003a1u && ((body[i - 2] >> 12) & 0x100)) {
            mode = i; ++mode_hits;
        // Open gate: the tested value is a heap field of the controller, loaded
        // through ldur w1,[x0,#imm] / add x1,x1,x28,lsl#32 just before Rx.
        } else if (body[i - 2] == 0x8b1c8021u
            && (body[i - 3] & 0xffe00c00u) == 0xb8400000u
            && (body[i - 3] & 31u) == 1u && ((body[i - 3] >> 5) & 31u) == 0u) {
            open = i; ++open_hits;
        }
    }
    // Each gate must be unique and in stock order: mode, then open registration,
    // then the open gate, then the close call.
    if (mode_hits != 1 || open_hits != 1 || registered_calls != 1 || !(mode < open && open < close_at)) return {};
    // Scroll gate: ldur w2,[x1,#imm] / add x2,x2,x28 / tbnz w2,#4 -> continuation,
    // immediately followed by the scroll routine. Only that branch is rewritten.
    size_t scroll_at = 0, scroll_hits = 0; uint32_t branch = 0;
    for (size_t i = 3; i < close_body.size(); ++i) {
        if ((close_body[i] & 0xfc000000u) != 0x94000000u
            || auto_close_call(close + uint32_t(i * 4), close_body[i]) != scroll) continue;
        if ((close_body[i - 1] & 0xfff80000u) != 0x37200000u
            || (close_body[i - 1] & 31u) != 2u) continue;
        int32_t jump = int32_t(((close_body[i - 1] >> 5) & 0x3fffu) << 18) >> 18;
        const int64_t pc = int64_t(close) + int64_t((i - 1) * 4);
        const int64_t target = pc + int64_t(jump) * 4;
        const int64_t delta = target - pc;
        if (close_body[i - 2] != 0x8b1c8042u
            || (close_body[i - 3] & 0xffe00c00u) != 0xb8400000u
            || (close_body[i - 3] & 31u) != 2u || ((close_body[i - 3] >> 5) & 31u) != 1u
            || delta <= 0 || (delta & 3) != 0 || delta > 0x7fffffc) return {};
        scroll_at = i - 1;
        branch = 0x14000000u | uint32_t(delta >> 2);
        ++scroll_hits;
    }
    if (scroll_hits != 1) return {};
    FolderAutoClosePlan plan;
    plan.mode_gate = uint32_t(mode * 4);
    plan.open_gate = uint32_t(open * 4);
    plan.scroll_gate = uint32_t(scroll_at * 4);
    plan.scroll_branch = branch;
    return plan;
}
template<class Read> bool read_folder_auto_close(Read read,bool& enabled,bool optional=true) {
    int32_t magic=0,flag=0;enabled=false;
    if(!read(magic))return optional;
    if(magic!=int32_t(kFolderAutoCloseMagic)||!read(flag)||(flag!=0&&flag!=1))return false;
    enabled=flag==1;return true;
}
} // namespace home_layout
