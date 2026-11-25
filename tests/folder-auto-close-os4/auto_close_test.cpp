/* SPDX-License-Identifier: AGPL-3.0-or-later */
// Host audit of the HomeTweaks "auto close folder" plan against a real launcher
// image. Nothing here runs on the device; it proves the three source words and
// that the resolver refuses any altered click/close body.
#include "targets/home/home_folder_auto_close.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {
struct Image {
    std::vector<unsigned char> data;
    std::vector<std::pair<uint64_t, uint64_t>> loads; // vaddr, filesz
    bool open(const char *path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        data.assign(std::istreambuf_iterator<char>{in}, {});
        if (data.size() < 64 || std::memcmp(data.data(), "\x7f""ELF", 4) != 0) return false;
        uint64_t phoff = 0;
        std::memcpy(&phoff, data.data() + 32, 8);
        uint16_t phentsize = 0, phnum = 0;
        std::memcpy(&phentsize, data.data() + 54, 2);
        std::memcpy(&phnum, data.data() + 56, 2);
        for (uint16_t i = 0; i < phnum; ++i) {
            const unsigned char *p = data.data() + phoff + i * phentsize;
            uint32_t type = 0, flags = 0;
            uint64_t offset = 0, vaddr = 0, filesz = 0;
            std::memcpy(&type, p, 4); std::memcpy(&flags, p + 4, 4);
            std::memcpy(&offset, p + 8, 8); std::memcpy(&vaddr, p + 16, 8);
            std::memcpy(&filesz, p + 32, 8);
            if (type == 1 && flags == 5) loads.emplace_back(vaddr, filesz);
        }
        return !loads.empty();
    }
    std::vector<uint32_t> words(uint32_t va, size_t count) const {
        for (const auto &l : loads) {
            if (va < l.first || uint64_t(va) - l.first + count * 4 > l.second) continue;
            std::vector<uint32_t> out(count);
            std::memcpy(out.data(), data.data() + l.first + (va - l.first), count * 4);
            return out;
        }
        return {};
    }
};
} // namespace

int main(int argc, char **argv) {
    if (argc != 9) {
        std::fprintf(stderr, "usage: %s libapp.so click_va close_va scroll_va rx_va registered_va\n", argv[0]);
        return 2;
    }
    Image image;
    if (!image.open(argv[1])) { std::fprintf(stderr, "not an ELF\n"); return 2; }
    const auto hexarg = [](const char *s) { return uint32_t(std::strtoul(s, nullptr, 16)); };
    const uint32_t click = hexarg(argv[2]), click_size = hexarg(argv[3]);
    const uint32_t close = hexarg(argv[4]), close_size = hexarg(argv[5]);
    const uint32_t scroll = hexarg(argv[6]);
    const uint32_t rx = hexarg(argv[7]), registered = hexarg(argv[8]);
    assert(!(click_size % 4) && !(close_size % 4));
    const auto click_body = image.words(click, click_size / 4);
    const auto close_body = image.words(close, close_size / 4);
    assert(!click_body.empty() && !close_body.empty());
    auto plan = home_layout::resolve_folder_auto_close(click_body, click, close, rx, registered,
        close_body, scroll);
    assert(plan);
    std::printf("plan mode=%#x registered=%#x guard=%#x scroll=%#x branch=%#x\n",
        click + plan->mode_gate, click + plan->registered_gate, click + plan->open_guard,
        close + plan->scroll_gate, plan->scroll_branch);
    assert(click + plan->mode_gate == 0x1451218);
    assert(click + plan->registered_gate == 0x145124c);
    assert(click + plan->open_guard == 0x1451280);
    assert(close + plan->scroll_gate == 0x1933dc8);
    assert(plan->scroll_branch == 0x14000019);
    // The two words HomeTweaks NOPs must be the stock gates, and the
    // isFolderClingOpen guard must remain the untouched third gate.
    assert(click_body[plan->mode_gate / 4] == 0x372006c0);
    assert(click_body[plan->registered_gate / 4] == 0x37200520);
    assert(click_body[plan->open_guard / 4] == 0x37200380);
    assert(close_body[plan->scroll_gate / 4] == 0x37200322);
    assert(plan->scroll_gate != plan->registered_gate && plan->scroll_gate != plan->mode_gate);
    // Every single-word corruption of either owner body must be refused or move the plan.
    unsigned accepted = 0, refused = 0;
    for (size_t i = 0; i < click_body.size(); ++i) {
        auto altered = click_body; altered[i] ^= 1u;
        auto again = home_layout::resolve_folder_auto_close(altered, click, close, rx, registered,
            close_body, scroll);
        if (!again) { ++refused; continue; }
        ++accepted;
        assert(again->mode_gate == plan->mode_gate && again->registered_gate == plan->registered_gate
            && again->open_guard == plan->open_guard);
    }
    for (size_t i = 0; i < close_body.size(); ++i) {
        auto altered = close_body; altered[i] ^= 1u;
        auto again = home_layout::resolve_folder_auto_close(click_body, click, close, rx, registered,
            altered, scroll);
        if (!again) { ++refused; continue; }
        ++accepted;
        assert(again->scroll_gate == plan->scroll_gate);
    }
    // Removing the close call, or making the scroll call ambiguous, must be refused.
    auto no_close = click_body;
    for (size_t i = 0; i < no_close.size(); ++i)
        if ((no_close[i] & 0xfc000000u) == 0x94000000u
            && home_layout::auto_close_call(click + uint32_t(i * 4), no_close[i]) == close)
            no_close[i] = 0xd503201f;
    assert(!home_layout::resolve_folder_auto_close(no_close, click, close, rx, registered, close_body, scroll));
    // A second identical gate+call sequence must be refused as ambiguous.
    auto twice = close_body;
    for (size_t i = 3; i + 5 < twice.size(); ++i)
        if ((twice[i] & 0xfc000000u) == 0x94000000u
            && home_layout::auto_close_call(close + uint32_t(i * 4), twice[i]) == scroll) {
            for (size_t k = 0; k < 4; ++k) twice[i + 4 + k] = twice[i - 3 + k];
            // Re-encode the copy's BL for its own address; a verbatim copy would not
            // reach the scroll routine and would prove nothing.
            const int64_t delta = int64_t(scroll) - int64_t(close + uint32_t((i + 7) * 4));
            assert(delta % 4 == 0 && delta > 0 && delta <= 0x7fffffc);
            twice[i + 7] = 0x94000000u | uint32_t(delta >> 2);
            break;
        }
    assert(!home_layout::resolve_folder_auto_close(click_body, click, close, rx, registered, twice, scroll));
    std::printf("PASS auto-close plan: 3 sites, mutations accepted=%u refused=%u\n", accepted, refused);
    return 0;
}
