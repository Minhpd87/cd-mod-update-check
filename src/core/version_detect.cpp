#include "version_detect.h"

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "../core/logger.h"
#include "../mem/scanner.h"
#include "../game/offsets.h"

#pragma comment(lib, "version.lib")

namespace trinity::core
{
    namespace
    {
        GameVersionInfo g_versionInfo{};
        bool            g_detected = false;

        void DetectVersion()
        {
            if (g_detected) return;
            g_detected = true;

            wchar_t exePath[MAX_PATH] = { 0 };
            if (GetModuleFileNameW(nullptr, exePath, MAX_PATH))
            {
                DWORD handle = 0;
                DWORD size = GetFileVersionInfoSizeW(exePath, &handle);
                if (size > 0)
                {
                    BYTE* buffer = new BYTE[size];
                    if (GetFileVersionInfoW(exePath, handle, size, buffer))
                    {
                        VS_FIXEDFILEINFO* pFileInfo = nullptr;
                        UINT len = 0;
                        if (VerQueryValueW(buffer, L"\\", reinterpret_cast<LPVOID*>(&pFileInfo), &len) && pFileInfo && len >= sizeof(VS_FIXEDFILEINFO))
                        {
                            g_versionInfo.major    = static_cast<uint16_t>(HIWORD(pFileInfo->dwFileVersionMS));
                            g_versionInfo.minor    = static_cast<uint16_t>(LOWORD(pFileInfo->dwFileVersionMS));
                            g_versionInfo.build    = static_cast<uint16_t>(HIWORD(pFileInfo->dwFileVersionLS));
                            g_versionInfo.revision = static_cast<uint16_t>(LOWORD(pFileInfo->dwFileVersionLS));

                            snprintf(g_versionInfo.rawVersionStr, sizeof(g_versionInfo.rawVersionStr),
                                     "%u.%u.%u.%u",
                                     g_versionInfo.major, g_versionInfo.minor,
                                     g_versionInfo.build, g_versionInfo.revision);
                        }
                    }
                    delete[] buffer;
                }
            }

            // In-Memory Binary Fingerprinting:
            // Pearl Abyss keeps the PE resource version static (1.0.0.2474) across multiple Steam updates.
            // We inspect the live machine code signatures in game memory to determine the exact Title Update.
            const bool hasModernDyeBatch = (mem::FindPattern(game::kSig_DyeApplyBatch) != 0);
            const bool hasLegacyDyeBatch = (mem::FindPattern(game::kSig_DyeApplyBatch_Legacy) != 0);

            // TU 2.00.00+: the PE revision moves per title update
            // (1.0.0.2474 = TU 1.18.02, 1.0.0.2625 = TU 2.00.00, 1.0.0.2658 = TU 2.00.01, 1.0.0.2692 = TU 2.00.02, 1.0.0.2760 = TU 2.01.00, 1.0.0.2944 = TU 2.03.00,
            //  1.0.0.3446 = TU 2.04.02, 1.0.0.3460+ = TU 2.04.03+ (displayed as the current 2.04.04)).
            if (g_versionInfo.revision >= 3460)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.04.04 (Active)");
            }
            else if (g_versionInfo.revision >= 3400)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.04.02 (Active)");
            }
            else if (g_versionInfo.revision >= 2900)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.03.00 (Active)");
            }
            else if (g_versionInfo.revision >= 2800)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.02.00 (Active)");
            }
            else if (g_versionInfo.revision >= 2750)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.01.00 (Active)");
            }
            else if (g_versionInfo.revision >= 2690)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.00.02 (Active)");
            }
            else if (g_versionInfo.revision >= 2650)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.00.01 (Active)");
            }
            else if (g_versionInfo.revision >= 2625)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus; // modern layout family
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 2.00.00 (Active)");
            }
            else if (hasModernDyeBatch)
            {
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus;
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 1.18.02 (Active)");
            }
            else if (hasLegacyDyeBatch)
            {
                g_versionInfo.tu = GameTU::TU_1_14;
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 1.14 - 1.15 (Legacy Compatible)");
            }
            else
            {
                // Fallback default
                g_versionInfo.tu = GameTU::TU_1_18_01_Plus;
                snprintf(g_versionInfo.displayStr, sizeof(g_versionInfo.displayStr),
                         "Crimson Desert TU 1.18.02 (Active)");
            }

            g_versionInfo.isSupported = true;
            LOG_OK("version: Game version detected: %s [PE: %s]", g_versionInfo.displayStr, g_versionInfo.rawVersionStr);
        }
    }

    const GameVersionInfo& GetGameVersion()
    {
        DetectVersion();
        return g_versionInfo;
    }

    const char* GetGameVersionDisplay()
    {
        return GetGameVersion().displayStr;
    }

    bool IsTU118OrNewer()
    {
        const GameVersionInfo& info = GetGameVersion();
        return info.tu == GameTU::TU_1_18 || info.tu == GameTU::TU_1_18_01_Plus || info.tu == GameTU::Unknown;
    }

    bool IsLegacyTU()
    {
        const GameVersionInfo& info = GetGameVersion();
        return info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15 || info.tu == GameTU::TU_1_16;
    }

    uintptr_t GetPlacementStride()
    {
        const GameVersionInfo& info = GetGameVersion();
        if (info.tu == GameTU::TU_1_13 || info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15)
            return 216; // 216 (0xD8) in TU 1.13 - 1.15
        return 0xE0;    // 224 (0xE0) in TU 1.16+
    }

    uintptr_t GetPlacementSlotIdxOffset()
    {
        const GameVersionInfo& info = GetGameVersion();
        if (info.tu == GameTU::TU_1_13 || info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15)
            return 208; // 208 (0xD0) in TU 1.13 - 1.15
        return 0xD8;    // 216 (0xD8) in TU 1.16+
    }

    uintptr_t GetSlotStride()
    {
        const GameVersionInfo& info = GetGameVersion();
        if (info.tu == GameTU::TU_1_13 || info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15)
            return 0xC0; // 192 bytes in TU 1.13 - 1.15
        return 0xC8;     // 200 bytes in TU 1.16+
    }

    uintptr_t GetItemValSocketOffset()
    {
        const GameVersionInfo& info = GetGameVersion();
        if (info.tu == GameTU::TU_1_13 || info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15 || info.tu == GameTU::TU_1_16)
            return 0x58; // Legacy offset in TU <= 1.16
        return 0x60;     // Modern offset in TU 1.17+
    }

    // TU 2.04.05+ (seen on PE 1.0.0.3576): ItemInfo gained _soundNameOnMaxCharged
    // at +0xE8, pushing every ItemDef field from +0xF8 onward down by 8 bytes
    // (_itemIconList 0x108->0x110, _cooltime 0x1D8->0x1E0, _itemGroupInfoList
    // 0x1F0->0x1F8, _respawnTimeSeconds 0x220->0x228, BucketType 0x240->0x248).
    // Recovered from the game's own ItemInfo deserializer in both builds.
    //
    // Detected from the live code rather than a PE revision cut-off: the game
    // reads BucketType with `movzx r32, word [r64+disp32]` all over the binary.
    // PE 3460 has 255 hits at +0x240 vs 8 at +0x248; PE 3576 has 11 vs 249.
    uintptr_t GetItemDefLayoutShift()
    {
        static uintptr_t s_shift = ~uintptr_t(0);
        if (s_shift != ~uintptr_t(0)) return s_shift;
        s_shift = 0;
        if (GetGameVersion().revision < 3400) return s_shift;

        const size_t oldHits = mem::FindAllMatches("0F B7 ?? 40 02 00 00", 512).size();
        const size_t newHits = mem::FindAllMatches("0F B7 ?? 48 02 00 00", 512).size();
        if (newHits > oldHits * 4 && newHits >= 32)
            s_shift = 8;
        LOG_INFO("version: ItemDef layout shift = +0x%llX (BucketType reads: +0x240 x%zu, +0x248 x%zu)",
                 static_cast<unsigned long long>(s_shift), oldHits, newHits);
        return s_shift;
    }

    uintptr_t GetItemDefMaxEnduranceOffset()
    {
        // _maxEndurance (u16) sits at +0x0E on TU 2.04 (PE 3460 and 3576 alike).
        if (GetGameVersion().revision >= 3400) return 0x0E;
        return 0x400; // pre-2.04 layout
    }

    uintptr_t GetItemDefBucketTypeOffset()
    {
        const GameVersionInfo& info = GetGameVersion();
        if (info.tu == GameTU::TU_1_13 || info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15 || info.tu == GameTU::TU_1_16)
            return 66; // Legacy bucket type offset 0x42 (66)
        if (info.revision >= 3400)
            return 0x240 + GetItemDefLayoutShift(); // TU 2.04: ItemDef re-laid out (+8 on 2.04.05+)
        if (info.revision >= 2625)
            return 0x428; // TU 2.00.00+: BucketType at +0x428 (confirmed from InvHolderInsert/CommitPlacement binary)
        return 0x418;  // Modern bucket type offset in TU 1.17 - 1.18.02
    }

    uintptr_t GetItemValWorkingSize()
    {
        const GameVersionInfo& info = GetGameVersion();
        if (info.tu == GameTU::TU_1_13 || info.tu == GameTU::TU_1_14 || info.tu == GameTU::TU_1_15)
            return 0xC0;  // 192 bytes buffer in 1.15
        return 0x108;     // 264 bytes buffer in 1.16+
    }

    // Live-verified on PE 1.0.0.3663 (2026-11-14): the per-table lookup became
    // `mov rcx,[rip+G] ; cmp r8d,[rcx+28h] ; mov rax,[rcx+20h] ; lea rdx,[r8+r8*2] ;
    // def = [rax+rdx*8+8]` (multichangeinfo: 20812 rows, iteminfo: 8379).
    bool IsRowRecordTableLayout() { return GetGameVersion().revision >= 3600; }
    uintptr_t GetTableCountOffset()  { return IsRowRecordTableLayout() ? 0x28 : 0x08; }
    uintptr_t GetTableRowsOffset()   { return IsRowRecordTableLayout() ? 0x20 : 0x58; }
    uintptr_t GetTableRowStride()    { return IsRowRecordTableLayout() ? 0x18 : 0x08; }
    uintptr_t GetTableRowDefOffset() { return IsRowRecordTableLayout() ? 0x08 : 0x00; }
}
