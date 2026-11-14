#pragma once
// Tracks Trinity's detached worker threads so a hot reload can wait for them
// before the core is unloaded (a detached thread still running core code after
// FreeLibrary would crash the game).
#include <Windows.h>
#include <atomic>
#include <thread>
#include <utility>

namespace trinity::bg
{
    inline std::atomic<long> g_running{0};
    inline std::atomic<bool> g_stopping{false};

    // True once shutdown began: long loops should bail out early.
    inline bool Stopping() { return g_stopping.load(std::memory_order_relaxed); }

    // std::thread(f).detach(), counted. Silently skips once stopping.
    template <typename F>
    inline void Spawn(F&& f)
    {
        if (Stopping()) return;
        g_running.fetch_add(1);
        try
        {
            std::thread([fn = std::forward<F>(f)]() mutable {
                fn();
                g_running.fetch_sub(1);
            }).detach();
        }
        catch (...)
        {
            g_running.fetch_sub(1);
        }
    }

    inline void BeginStop() { g_stopping.store(true); }

    inline bool WaitAll(DWORD timeoutMs)
    {
        const ULONGLONG t0 = GetTickCount64();
        while (g_running.load() != 0)
        {
            if (GetTickCount64() - t0 > timeoutMs) return false;
            Sleep(10);
        }
        return true;
    }
}
