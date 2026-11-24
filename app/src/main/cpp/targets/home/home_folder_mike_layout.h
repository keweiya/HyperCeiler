/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <cmath>
#include <cstdint>
#include <span>

namespace home_layout {
// Pengeek FUN_0011be00. These are semantic scalar inputs, not Dart pointers.
// pad and jeejen are DISTINCT enum comparisons; neither denotes orientation.
struct FolderMikeInputs {
    double original_cell_width = 0;
    double screen_width_px = 0;
    double cell_width_px = 0;
    int64_t count_cell_x = 0; // unboxed GridConfig integer, NOT a tagged Smi
    bool is_pad = false;
    bool is_jeejen = false;
};
inline double mike_folder_cell_width(const FolderMikeInputs &v, int columns, bool full_width) {
    if (columns < 4) return v.original_cell_width;
    double gap = v.count_cell_x == 4 ? 8.0 : (v.is_jeejen ? 32.0 : 0.0);
    const unsigned base_columns = v.is_pad ? 4u : 3u;
    const double side = v.is_pad ? 4.0 : 12.0;
    double base_cell = v.original_cell_width;
    if (v.is_pad) gap = 0;
    else {
        base_cell = v.cell_width_px;
        if (v.is_jeejen) {
            const double cap = (v.screen_width_px - 26.0) / 3.0;
            // Preserve FCSEL's unordered arm, rather than using fmin.
            if (base_cell > cap) base_cell = cap;
        }
    }
    const double maximum = std::fma(side, -2.0, v.screen_width_px - 20.0);
    const double preferred = full_width ? maximum :
        std::fma(base_cell, double(base_columns), gap * double(base_columns - 1));
    // Native FCSEL chooses preferred for an unordered comparison.
    const double total = preferred > maximum ? maximum : preferred;
    const double result = std::fma(-gap, double(columns - 1), total) / double(columns);
    return std::isfinite(result) && result > 0 ? result : v.original_cell_width;
}

struct FolderMikeSite {
    uint32_t window = 0;       // byte offset from owning function, not absolute VA
    uint32_t continuation = 0; // absolute VA after four replay instructions
    int32_t config_slot = 0;
    int32_t width_slot = 0, height_slot = 0;
    int32_t width_field = 0, height_field = 0;
    int32_t condition_field = 0, device_kind_field = 0, launcher_mode_field = 0;
    int32_t screen_width_field = 0, cell_width_field = 0, count_cell_x_field = 0;
    uint32_t pad_pool = 0, jeejen_pool = 0;
};

// Conservative current-body contract, not a universal version recognizer.
// All 217 instructions are checked. Only BL targets, external tail B target,
// and the two enum-root pool immediates are relocatable. Local control flow,
// frame/register ABI, allocations, stores and all remaining pool operands stay exact.
// On the verified launcher this is FolderConfigHandler.handle @ 0x1ac1c44.
inline bool folder_mike_site(std::span<const uint32_t> body, uint32_t va, FolderMikeSite &out) {
    out = {};
    if (body.size() != 217 || va > UINT32_MAX - uint32_t(body.size() * 4)) return false;
    uint64_t fingerprint = 1469598103934665603ULL;
    for (size_t i = 0; i < body.size(); ++i) {
        uint32_t w = body[i];
        if ((w & 0xfc000000u) == 0x94000000u) w &= 0xfc000000u;
        else if (i == 17 || i == 18 || i == 43 || i == 44) w &= ~0x003ffc00u;
        else if ((w & 0xfc000000u) == 0x14000000u) {
            const int32_t delta = int32_t(w << 6) >> 6;
            const int64_t target = int64_t(i) + delta;
            if (target < 0 || target >= int64_t(body.size())) w &= 0xfc000000u;
        }
        fingerprint ^= w;
        fingerprint *= 1099511628211ULL;
    }
    if (fingerprint != 0xf8f60b3082ea688cULL) return false;
    // Explicit incoming-edge check for the four-instruction replay at +0x32c.
    constexpr uint32_t window = 0x32c;
    for (size_t i = 0; i < body.size(); ++i) {
        const uint32_t w = body[i]; int32_t delta = 0; bool branch = true;
        if ((w & 0x7c000000u) == 0x14000000u) delta = int32_t(w << 6) >> 6;
        else if ((w & 0xff000010u) == 0x54000000u || (w & 0x7e000000u) == 0x34000000u)
            delta = int32_t(w << 8) >> 13;
        else if ((w & 0x7e000000u) == 0x36000000u) delta = int32_t(w << 13) >> 18;
        else branch = false;
        const int64_t target = int64_t(i * 4) + int64_t(delta) * 4;
        if (branch && target > window && target < window + 16) return false;
    }
    const auto pool = [&](size_t i) {
        return ((body[i] >> 10) & 4095u) * 4096u + ((body[i + 1] >> 10) & 4095u) * 8u;
    };
    const auto imm9 = [](uint32_t w) { return int32_t(w << 11) >> 23; };
    FolderMikeSite f;
    f.window = window; f.continuation = va + window + 16;
    f.config_slot = imm9(body[8]);
    f.width_slot = imm9(body[window / 4]);
    f.width_field = imm9(body[window / 4 + 1]);
    f.height_slot = imm9(body[window / 4 + 2]);
    f.height_field = imm9(body[window / 4 + 3]);
    f.condition_field = 7; f.device_kind_field = 0x17; f.launcher_mode_field = 0x2f;
    f.screen_width_field = 0xb; f.cell_width_field = 0x2b; f.count_cell_x_field = 0x1b;
    f.pad_pool = pool(17); f.jeejen_pool = pool(43);
    if (!f.pad_pool || !f.jeejen_pool || f.pad_pool == f.jeejen_pool) return false;
    out = f; return true;
}
// Getter companion of the producer. Only BL displacements are relocatable;
// table/pool operands, device gate, local branches and final ADD/epilogue must
// retain the verified body. Caller installs the 16-byte window at +0x6c only.
inline bool folder_mike_columns_site(std::span<const uint32_t> body, uint32_t va,
                                     uint32_t &offset) {
    offset = 0;
    if (body.size() != 31 || va > UINT32_MAX - uint32_t(body.size() * 4)) return false;
    uint64_t fingerprint = 1469598103934665603ULL;
    for (uint32_t w : body) {
        if ((w & 0xfc000000u) == 0x94000000u) w &= 0xfc000000u;
        fingerprint ^= w;
        fingerprint *= 1099511628211ULL;
    }
    if (fingerprint != 0xa4dfbd0265312fe9ULL) return false;
    constexpr uint32_t tail[] = {0xf27c005f, 0x9a9f07e0, 0xd1000400, 0x927f0000,
        0x91001800, 0xaa1d03ef, 0xa8c179fd, 0xd65f03c0};
    for (size_t i = 0; i < 8; ++i) if (body[23 + i] != tail[i]) return false;
    offset = 0x6c;
    return true;
}
} // namespace home_layout
