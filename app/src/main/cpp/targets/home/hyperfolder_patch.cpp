/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * HyperFolder: folder layout patches for the HyperOS 4 Flutter launcher.
 *
 * The launcher shipped with HyperOS 4 has no dex: the desktop UI is Dart AOT code inside
 * libapp.so. These three knobs therefore cannot be implemented with Java hooks; they are
 * done by rewriting the return value of the Dart accessors that feed the folder layout.
 *
 *   GridController.folderGridViewCol          -> number of icons per folder row (Smi)
 *   FolderClingWidget.getFolderClingWidth     -> width of the opened folder panel
 *   FolderHeaderWidget (title placement)      -> not implemented in this build
 *
 * Every site is validated against the image before it is touched: the .text marker at
 * 0x850000 of RELEASE-8.11.02.7755 must match, otherwise nothing is patched and the
 * failure is reported instead of corrupting an unknown build.
 */
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>

#include <cstdint>
#include <cstring>

namespace {

constexpr char kTag[] = "HyperCeilerHyperFolder";

/* Offsets of RELEASE-8.11.02.7755 (versionCode 811027755). */
constexpr uint64_t kFolderColsOff = 0x8e6e7c;   /* GridController.folderGridViewCol */
constexpr uint64_t kClingWidthOff = 0x8e6f3c;   /* FolderClingWidget.getFolderClingWidth */
constexpr uint64_t kTextVerifyOff = 0x850000;   /* .text start marker */
constexpr uint32_t kTextMarker = 0x00016940u;

struct PhdrInfo {
    uint64_t addr;
    const char* name;
    const void* phdr;
    uint16_t phnum;
};

uint64_t g_base = 0;
char g_name[192] = {0};

int phdr_cb(dl_phdr_info* info, size_t, void*) {
    if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') return 0;
    if (std::strstr(info->dlpi_name, "libapp.so") == nullptr) return 0;
    g_base = info->dlpi_addr;
    std::strncpy(g_name, info->dlpi_name, sizeof(g_name) - 1);
    return 1;
}

void cache_flush(void* start, void* end) {
    unsigned long ctr = 0;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    const unsigned long dline = 4UL << ((ctr >> 16) & 0xf);
    const unsigned long iline = 4UL << (ctr & 0xf);
    unsigned long a = reinterpret_cast<unsigned long>(start) & ~(dline - 1);
    for (; a < reinterpret_cast<unsigned long>(end); a += dline)
        __asm__ volatile("dc cvau, %0" ::"r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    a = reinterpret_cast<unsigned long>(start) & ~(iline - 1);
    for (; a < reinterpret_cast<unsigned long>(end); a += iline)
        __asm__ volatile("ic ivau, %0" ::"r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

bool patch_words(uint64_t addr, const uint32_t* words, int count, const char* what) {
    uint32_t old[4] = {0, 0, 0, 0};
    if (count > 4) count = 4;
    auto* p = reinterpret_cast<uint32_t*>(addr);
    for (int i = 0; i < count; ++i) old[i] = p[i];

    const uint64_t page = addr & ~0xFFFULL;
    const uint64_t end = (addr + static_cast<uint64_t>(count) * 4 + 0xFFFULL) & ~0xFFFULL;
    if (mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(end - page + 0x1000),
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, kTag, "%s: mprotect failed", what);
        return false;
    }
    std::memcpy(reinterpret_cast<void*>(addr), words, static_cast<size_t>(count) * 4);
    cache_flush(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(addr + count * 4));
    mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(end - page + 0x1000),
             PROT_READ | PROT_EXEC);

    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "%s @ %#llx: %08x->%08x %08x->%08x count=%d", what,
                        static_cast<unsigned long long>(addr), old[0], p[0],
                        count > 1 ? old[1] : 0, count > 1 ? p[1] : 0, count);
    return true;
}

}  // namespace

extern "C" void hpf_apply(int cols, int width, int title_center) {
    if (cols <= 0 && width == 0 && title_center == 0) {
        __android_log_print(ANDROID_LOG_INFO, kTag, "everything disabled, skip");
        return;
    }

    g_base = 0;
    g_name[0] = '\0';
    dl_iterate_phdr(phdr_cb, nullptr);
    if (g_base == 0) {
        __android_log_print(ANDROID_LOG_ERROR, kTag, "libapp.so not found, abort");
        return;
    }
    __android_log_print(ANDROID_LOG_INFO, kTag, "libapp=%s base=%#llx", g_name,
                        static_cast<unsigned long long>(g_base));

    auto* marker = reinterpret_cast<uint32_t*>(g_base + kTextVerifyOff);
    if (marker[0] != kTextMarker) {
        __android_log_print(ANDROID_LOG_ERROR, kTag,
                            "build mismatch: marker=%08x expect=%08x, abort", marker[0],
                            kTextMarker);
        return;
    }

    if (cols > 0) {
        if (cols > 12) cols = 12;
        const uint32_t insns[2] = {
            0xD2800000u | (static_cast<uint32_t>(cols * 2) << 5), /* mov x0, #cols*2 (Smi) */
            0xD65F03C0u,                                          /* ret */
        };
        patch_words(g_base + kFolderColsOff, insns, 2, "folderColumns");
    } else {
        __android_log_print(ANDROID_LOG_INFO, kTag, "folderColumns: disabled");
    }

    if (width != 0) {
        /* b <deviceScreenWidth branch at 0x8e7118> */
        const int64_t delta = static_cast<int64_t>(0x8e7118ULL - kClingWidthOff);
        const uint32_t insn = 0x14000000u | (static_cast<uint32_t>(delta >> 2) & 0x03FFFFFFu);
        patch_words(g_base + kClingWidthOff, &insn, 1, "clingWidth");
    } else {
        __android_log_print(ANDROID_LOG_INFO, kTag, "clingWidth: disabled");
    }

    if (title_center != 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "titleCenter: not implemented for this build, ignored");
    }
}
