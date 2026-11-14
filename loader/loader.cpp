// Trinity.asi - permanent loader for the reloadable mod core (Trinity_core.dll).
//
// What lives here (and why): only what the game holds pointers to for the
// whole session, so the core can be unloaded and replaced while playing.
//   * the factory CreateSwapChainForHwnd vtable patch
//   * WrappedIDXGISwapChain, the object the game presents through
//   * the game-window subclass
// Their events are forwarded to the core through host::OverlayCallbacks.
//
// Hot reload: the loader polls bin64\Trinity_core.dll. When the file changes
// (or Trinity_reload.txt appears) it stops the running core, frees it, copies
// the new file to Trinity_core.runN.dll and loads that copy - so the real
// Trinity_core.dll is never locked and can be overwritten at any time.
#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_5.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "core/host_api.h"

#pragma comment(lib, "dxgi.lib")

namespace
{
    using trinity::host::Api;
    using trinity::host::OverlayCallbacks;

    char g_dir[MAX_PATH]{}; // bin64 with trailing backslash

    // ---- tiny log (Trinity_loader.log) ------------------------------------
    CRITICAL_SECTION g_logLock;
    void Log(const char* fmt, ...)
    {
        char line[1024];
        SYSTEMTIME t; GetLocalTime(&t);
        int n = snprintf(line, sizeof(line), "%02u:%02u:%02u.%03u ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
        va_list ap; va_start(ap, fmt);
        n += vsnprintf(line + n, sizeof(line) - n - 2, fmt, ap);
        va_end(ap);
        if (n > static_cast<int>(sizeof(line)) - 3) n = sizeof(line) - 3;
        line[n++] = '\r'; line[n++] = '\n'; line[n] = 0;
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%sTrinity_loader.log", g_dir);
        EnterCriticalSection(&g_logLock);
        HANDLE f = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE)
        {
            DWORD w = 0;
            WriteFile(f, line, static_cast<DWORD>(n), &w, nullptr);
            CloseHandle(f);
        }
        LeaveCriticalSection(&g_logLock);
    }

    // ---- callback registration with in-flight drain ------------------------
    std::atomic<const OverlayCallbacks*> g_cb{nullptr};
    std::atomic<long> g_inflight{0};

    // Runs f(cb) if a core is attached. seq_cst: once SetOverlay(nullptr)
    // stores null and sees g_inflight == 0, no caller can still be inside.
    template <typename F>
    bool WithCb(F&& f)
    {
        g_inflight.fetch_add(1);
        const OverlayCallbacks* cb = g_cb.load();
        bool ran = false;
        if (cb) { f(cb); ran = true; }
        g_inflight.fetch_sub(1);
        return ran;
    }

    void ApiSetOverlay(const OverlayCallbacks* cb)
    {
        g_cb.store(cb);
        if (!cb)
        {
            const ULONGLONG t0 = GetTickCount64();
            while (g_inflight.load() != 0)
            {
                if (GetTickCount64() - t0 > 10000) { Log("WARN: overlay callbacks still in flight after 10 s"); break; }
                Sleep(1);
            }
        }
    }

    // ---- swapchain state ---------------------------------------------------
    std::atomic<bool> g_wrapperActive{false};
    HWND g_wrappedHwnd = nullptr;
    thread_local bool t_inSwapChainCreate = false;

    SRWLOCK g_queueLock = SRWLOCK_INIT;
    ID3D12CommandQueue* g_presentQueue = nullptr;
    std::atomic<int> g_colorSpace{-1};

    bool ApiWrapperActive() { return g_wrapperActive.load(); }
    ID3D12CommandQueue* ApiPresentQueue()
    {
        AcquireSRWLockShared(&g_queueLock);
        ID3D12CommandQueue* q = g_presentQueue;
        if (q) q->AddRef();
        ReleaseSRWLockShared(&g_queueLock);
        return q;
    }
    bool ApiColorSpace(DXGI_COLOR_SPACE_TYPE* out)
    {
        const int cs = g_colorSpace.load();
        if (cs < 0) return false;
        if (out) *out = static_cast<DXGI_COLOR_SPACE_TYPE>(cs);
        return true;
    }

    // ---- window subclass ---------------------------------------------------
    std::atomic<WNDPROC> g_origWndProc{nullptr};
    HWND g_subclassed = nullptr;

    LRESULT CALLBACK HostWndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
    {
        LRESULT r = 0;
        bool eaten = false;
        WithCb([&](const OverlayCallbacks* cb) {
            if (cb->wndFilter) eaten = cb->wndFilter(hwnd, msg, w, l, &r);
        });
        if (eaten) return r;
        const WNDPROC orig = g_origWndProc.load();
        return orig ? CallWindowProcW(orig, hwnd, msg, w, l) : DefWindowProcW(hwnd, msg, w, l);
    }

    void ApiSubclassWindow(HWND hwnd)
    {
        static SRWLOCK lock = SRWLOCK_INIT;
        AcquireSRWLockExclusive(&lock);
        if (!g_subclassed && hwnd)
        {
            g_origWndProc.store(reinterpret_cast<WNDPROC>(
                SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&HostWndProc))));
            g_subclassed = hwnd;
            Log("window %p subclassed (original proc %p)", hwnd, g_origWndProc.load());
        }
        ReleaseSRWLockExclusive(&lock);
    }

    Api g_api{};

    // ---- COM wrapper -------------------------------------------------------
    void ReleaseRefs(const char* why)
    {
        WithCb([&](const OverlayCallbacks* cb) { if (cb->releaseRefs) cb->releaseRefs(why); });
    }
    bool RenderBefore(IDXGISwapChain3* sc, UINT flags)
    {
        if (flags & DXGI_PRESENT_TEST) return false;
        bool drew = false;
        WithCb([&](const OverlayCallbacks* cb) { if (cb->render) drew = cb->render(sc, true); });
        return drew;
    }
    void AfterPresent(bool drew)
    {
        WithCb([&](const OverlayCallbacks* cb) { if (cb->postPresent) cb->postPresent(drew); });
    }
    bool PreResize()
    {
        bool ok = true;
        WithCb([&](const OverlayCallbacks* cb) { if (cb->preResize) ok = cb->preResize(); });
        return ok;
    }
    void PostResize(IDXGISwapChain3* sc)
    {
        WithCb([&](const OverlayCallbacks* cb) { if (cb->postResize) cb->postResize(sc); });
    }

    class WrappedIDXGISwapChain final : public IDXGISwapChain4
    {
    public:
        explicit WrappedIDXGISwapChain(IDXGISwapChain4* inner) : m_inner(inner) {}

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
        {
            if (!ppv) return E_POINTER;
            if (riid == __uuidof(IUnknown) || riid == __uuidof(IDXGIObject) ||
                riid == __uuidof(IDXGIDeviceSubObject) || riid == __uuidof(IDXGISwapChain) ||
                riid == __uuidof(IDXGISwapChain1) || riid == __uuidof(IDXGISwapChain2) ||
                riid == __uuidof(IDXGISwapChain3) || riid == __uuidof(IDXGISwapChain4))
            {
                AddRef();
                *ppv = static_cast<IDXGISwapChain4*>(this);
                return S_OK;
            }
            return m_inner->QueryInterface(riid, ppv);
        }
        ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_ref); }
        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG r = InterlockedDecrement(&m_ref);
            if (r == 0)
            {
                ReleaseRefs("swapchain released");
                m_inner->Release();
                delete this;
            }
            return r;
        }

        HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID n, UINT s, const void* d) override { return m_inner->SetPrivateData(n, s, d); }
        HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID n, const IUnknown* p) override { return m_inner->SetPrivateDataInterface(n, p); }
        HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID n, UINT* s, void* d) override { return m_inner->GetPrivateData(n, s, d); }
        HRESULT STDMETHODCALLTYPE GetParent(REFIID riid, void** pp) override { return m_inner->GetParent(riid, pp); }
        HRESULT STDMETHODCALLTYPE GetDevice(REFIID riid, void** pp) override { return m_inner->GetDevice(riid, pp); }

        HRESULT STDMETHODCALLTYPE Present(UINT syncInterval, UINT flags) override
        {
            const bool drew = RenderBefore(m_inner, flags);
            const HRESULT hr = m_inner->Present(syncInterval, flags);
            AfterPresent(drew);
            return hr;
        }
        HRESULT STDMETHODCALLTYPE GetBuffer(UINT i, REFIID riid, void** pp) override { return m_inner->GetBuffer(i, riid, pp); }
        HRESULT STDMETHODCALLTYPE SetFullscreenState(BOOL fs, IDXGIOutput* t) override { return m_inner->SetFullscreenState(fs, t); }
        HRESULT STDMETHODCALLTYPE GetFullscreenState(BOOL* fs, IDXGIOutput** t) override { return m_inner->GetFullscreenState(fs, t); }
        HRESULT STDMETHODCALLTYPE GetDesc(DXGI_SWAP_CHAIN_DESC* d) override { return m_inner->GetDesc(d); }
        HRESULT STDMETHODCALLTYPE ResizeBuffers(UINT bc, UINT w, UINT h, DXGI_FORMAT f, UINT fl) override
        {
            if (!PreResize()) return DXGI_ERROR_WAS_STILL_DRAWING;
            const HRESULT hr = m_inner->ResizeBuffers(bc, w, h, f, fl);
            if (SUCCEEDED(hr)) PostResize(m_inner);
            return hr;
        }
        HRESULT STDMETHODCALLTYPE ResizeTarget(const DXGI_MODE_DESC* p) override { return m_inner->ResizeTarget(p); }
        HRESULT STDMETHODCALLTYPE GetContainingOutput(IDXGIOutput** pp) override { return m_inner->GetContainingOutput(pp); }
        HRESULT STDMETHODCALLTYPE GetFrameStatistics(DXGI_FRAME_STATISTICS* p) override { return m_inner->GetFrameStatistics(p); }
        HRESULT STDMETHODCALLTYPE GetLastPresentCount(UINT* p) override { return m_inner->GetLastPresentCount(p); }

        HRESULT STDMETHODCALLTYPE GetDesc1(DXGI_SWAP_CHAIN_DESC1* p) override { return m_inner->GetDesc1(p); }
        HRESULT STDMETHODCALLTYPE GetFullscreenDesc(DXGI_SWAP_CHAIN_FULLSCREEN_DESC* p) override { return m_inner->GetFullscreenDesc(p); }
        HRESULT STDMETHODCALLTYPE GetHwnd(HWND* p) override { return m_inner->GetHwnd(p); }
        HRESULT STDMETHODCALLTYPE GetCoreWindow(REFIID riid, void** pp) override { return m_inner->GetCoreWindow(riid, pp); }
        HRESULT STDMETHODCALLTYPE Present1(UINT syncInterval, UINT flags, const DXGI_PRESENT_PARAMETERS* pp) override
        {
            const bool drew = RenderBefore(m_inner, flags);
            const HRESULT hr = m_inner->Present1(syncInterval, flags, pp);
            AfterPresent(drew);
            return hr;
        }
        BOOL    STDMETHODCALLTYPE IsTemporaryMonoSupported() override { return m_inner->IsTemporaryMonoSupported(); }
        HRESULT STDMETHODCALLTYPE GetRestrictToOutput(IDXGIOutput** pp) override { return m_inner->GetRestrictToOutput(pp); }
        HRESULT STDMETHODCALLTYPE SetBackgroundColor(const DXGI_RGBA* p) override { return m_inner->SetBackgroundColor(p); }
        HRESULT STDMETHODCALLTYPE GetBackgroundColor(DXGI_RGBA* p) override { return m_inner->GetBackgroundColor(p); }
        HRESULT STDMETHODCALLTYPE SetRotation(DXGI_MODE_ROTATION r) override { return m_inner->SetRotation(r); }
        HRESULT STDMETHODCALLTYPE GetRotation(DXGI_MODE_ROTATION* p) override { return m_inner->GetRotation(p); }

        HRESULT STDMETHODCALLTYPE SetSourceSize(UINT w, UINT h) override { return m_inner->SetSourceSize(w, h); }
        HRESULT STDMETHODCALLTYPE GetSourceSize(UINT* w, UINT* h) override { return m_inner->GetSourceSize(w, h); }
        HRESULT STDMETHODCALLTYPE SetMaximumFrameLatency(UINT m) override { return m_inner->SetMaximumFrameLatency(m); }
        HRESULT STDMETHODCALLTYPE GetMaximumFrameLatency(UINT* m) override { return m_inner->GetMaximumFrameLatency(m); }
        HANDLE  STDMETHODCALLTYPE GetFrameLatencyWaitableObject() override { return m_inner->GetFrameLatencyWaitableObject(); }
        HRESULT STDMETHODCALLTYPE SetMatrixTransform(const DXGI_MATRIX_3X2_F* p) override { return m_inner->SetMatrixTransform(p); }
        HRESULT STDMETHODCALLTYPE GetMatrixTransform(DXGI_MATRIX_3X2_F* p) override { return m_inner->GetMatrixTransform(p); }

        UINT    STDMETHODCALLTYPE GetCurrentBackBufferIndex() override { return m_inner->GetCurrentBackBufferIndex(); }
        HRESULT STDMETHODCALLTYPE CheckColorSpaceSupport(DXGI_COLOR_SPACE_TYPE c, UINT* s) override { return m_inner->CheckColorSpaceSupport(c, s); }
        HRESULT STDMETHODCALLTYPE SetColorSpace1(DXGI_COLOR_SPACE_TYPE c) override
        {
            const HRESULT hr = m_inner->SetColorSpace1(c);
            if (SUCCEEDED(hr))
            {
                g_colorSpace.store(static_cast<int>(c));
                WithCb([&](const OverlayCallbacks* cb) { if (cb->colorSpace) cb->colorSpace(c); });
            }
            return hr;
        }
        HRESULT STDMETHODCALLTYPE ResizeBuffers1(UINT bc, UINT w, UINT h, DXGI_FORMAT f, UINT fl, const UINT* nodeMask, IUnknown* const* pQueues) override
        {
            if (!PreResize()) return DXGI_ERROR_WAS_STILL_DRAWING;
            const HRESULT hr = m_inner->ResizeBuffers1(bc, w, h, f, fl, nodeMask, pQueues);
            if (SUCCEEDED(hr)) PostResize(m_inner);
            return hr;
        }
        HRESULT STDMETHODCALLTYPE SetHDRMetaData(DXGI_HDR_METADATA_TYPE t, UINT s, void* d) override { return m_inner->SetHDRMetaData(t, s, d); }

    private:
        IDXGISwapChain4* m_inner;
        LONG             m_ref = 1;
    };

    void ModuleOf(void* addr, char* out, size_t cap)
    {
        HMODULE m = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(addr), &m);
        char path[MAX_PATH] = "?";
        if (m) GetModuleFileNameA(m, path, MAX_PATH);
        const char* base = strrchr(path, '\\');
        strncpy_s(out, cap, base ? base + 1 : path, _TRUNCATE);
    }

    void WrapSwapChain(IDXGISwapChain1** pp, HWND hwnd)
    {
        if (!pp || !*pp) return;
        DXGI_SWAP_CHAIN_DESC1 d1 = {};
        if (SUCCEEDED((*pp)->GetDesc1(&d1)) && (d1.Width < 100 || d1.Height < 100))
            return;
        if (g_wrappedHwnd && hwnd && hwnd != g_wrappedHwnd)
            return;

        IDXGISwapChain4* inner = nullptr;
        if (FAILED((*pp)->QueryInterface(IID_PPV_ARGS(&inner))) || !inner)
            return;

        (*pp)->Release();
        auto* wrapper = new WrappedIDXGISwapChain(inner);
        *pp = static_cast<IDXGISwapChain1*>(wrapper);
        if (hwnd) g_wrappedHwnd = hwnd;

        char mod[MAX_PATH];
        ModuleOf((*reinterpret_cast<void***>(inner))[8], mod, sizeof(mod));
        Log("swapchain wrapped (%ux%u, %u buffers, flags 0x%X, inner Present in %s)",
            d1.Width, d1.Height, d1.BufferCount, d1.Flags, mod);
        g_wrapperActive.store(true);
        WithCb([](const OverlayCallbacks* cb) { if (cb->wrapped) cb->wrapped(); });
    }

    using CSFH_t = HRESULT (STDMETHODCALLTYPE*)(IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*,
                                                const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1**);
    CSFH_t oCreateSwapChainForHwnd = nullptr;

    HRESULT STDMETHODCALLTYPE hkCreateSwapChainForHwnd(
        IDXGIFactory2* self, IUnknown* device, HWND hwnd,
        const DXGI_SWAP_CHAIN_DESC1* desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fsDesc,
        IDXGIOutput* restrictOut, IDXGISwapChain1** ppSwapChain)
    {
        // Only the outermost (game-issued) creation is wrapped; nested ones are
        // Streamline rebuilding its chain during a Frame Generation toggle.
        // The core builds a throwaway swapchain on its own "TrinityDummyWnd"
        // window (to read vtable slots) - that one must never be wrapped or
        // pin its queue. Likewise ignore auxiliary windows once locked on.
        char cls[64] = {};
        if (hwnd) GetClassNameA(hwnd, cls, sizeof(cls));
        const bool mainWindow = strcmp(cls, "TrinityDummyWnd") != 0 &&
                                (!g_wrappedHwnd || !hwnd || hwnd == g_wrappedHwnd);
        const bool nested = t_inSwapChainCreate || !mainWindow;
        if (!nested) ReleaseRefs("swapchain recreation");
        const bool prevNested = t_inSwapChainCreate;
        t_inSwapChainCreate = true;
        const HRESULT hr = oCreateSwapChainForHwnd(self, device, hwnd, desc, fsDesc, restrictOut, ppSwapChain);
        t_inSwapChainCreate = prevNested;
        if (!nested)
        {
            if (SUCCEEDED(hr))
            {
                ID3D12CommandQueue* pq = nullptr;
                if (device && SUCCEEDED(device->QueryInterface(IID_PPV_ARGS(&pq))) && pq)
                {
                    AcquireSRWLockExclusive(&g_queueLock);
                    if (g_presentQueue) g_presentQueue->Release();
                    g_presentQueue = pq; // keeps the QI ref
                    ReleaseSRWLockExclusive(&g_queueLock);
                    WithCb([&](const OverlayCallbacks* cb) { if (cb->presentQueue) cb->presentQueue(pq); });
                }
                WrapSwapChain(ppSwapChain, hwnd);
            }
        }
        return hr;
    }

    void InstallSwapChainCreationPatch()
    {
        IDXGIFactory2* factory = nullptr;
        if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory))) || !factory)
        {
            if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))) || !factory)
            {
                Log("ERROR: no DXGI factory to patch - overlay over Frame Generation disabled");
                return;
            }
        }
        void** vt = *reinterpret_cast<void***>(factory);
        char mod[MAX_PATH];
        ModuleOf(vt[15], mod, sizeof(mod));
        DWORD old = 0;
        if (VirtualProtect(&vt[15], sizeof(void*), PAGE_EXECUTE_READWRITE, &old))
        {
            oCreateSwapChainForHwnd = reinterpret_cast<CSFH_t>(vt[15]);
            vt[15] = reinterpret_cast<void*>(&hkCreateSwapChainForHwnd);
            VirtualProtect(&vt[15], sizeof(void*), old, &old);
            Log("factory CreateSwapChainForHwnd patched (was in %s)", mod);
        }
        else Log("ERROR: VirtualProtect of CreateSwapChainForHwnd slot failed");
        factory->Release();
    }

    // ---- core load / reload ------------------------------------------------
    HMODULE g_core = nullptr;
    trinity::host::CoreStop_t g_coreStop = nullptr;
    int g_runSlot = 0;
    FILETIME g_coreStamp{};
    ULONGLONG g_coreSize = 0;

    bool StatCore(FILETIME* ft, ULONGLONG* size)
    {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%sTrinity_core.dll", g_dir);
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (!GetFileAttributesExA(path, GetFileExInfoStandard, &a)) return false;
        *ft = a.ftLastWriteTime;
        *size = (static_cast<ULONGLONG>(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
        return true;
    }

    void UnloadCore()
    {
        if (!g_core) return;
        Log("stopping core");
        bool safe = g_coreStop ? g_coreStop() : false;
        ApiSetOverlay(nullptr); // belt and braces; core already detached
        if (safe)
        {
            Sleep(1000); // let threads that just left core code finish returning
            FreeLibrary(g_core);
            Log("core unloaded");
        }
        else Log("WARN: core reported an unsafe stop - leaving it mapped (inert)");
        g_core = nullptr;
        g_coreStop = nullptr;
    }

    bool LoadCore()
    {
        char src[MAX_PATH];
        snprintf(src, sizeof(src), "%sTrinity_core.dll", g_dir);
        if (!StatCore(&g_coreStamp, &g_coreSize))
        {
            Log("ERROR: %s not found", src);
            return false;
        }

        // Copy to a run slot that is not mapped (a leaked old core may hold one).
        char run[MAX_PATH] = {};
        bool copied = false;
        for (int i = 0; i < 8 && !copied; ++i)
        {
            g_runSlot = (g_runSlot + 1) % 8;
            snprintf(run, sizeof(run), "%sTrinity_core.run%d.dll", g_dir, g_runSlot);
            copied = CopyFileA(src, run, FALSE) != 0;
        }
        if (!copied)
        {
            Log("ERROR: could not copy core to a run slot (error %lu)", GetLastError());
            return false;
        }

        HMODULE m = LoadLibraryA(run);
        if (!m)
        {
            Log("ERROR: LoadLibrary(%s) failed (error %lu)", run, GetLastError());
            return false;
        }
        auto start = reinterpret_cast<trinity::host::CoreStart_t>(GetProcAddress(m, "TrinityCoreStart"));
        auto stop  = reinterpret_cast<trinity::host::CoreStop_t>(GetProcAddress(m, "TrinityCoreStop"));
        if (!start || !stop)
        {
            Log("ERROR: %s has no TrinityCoreStart/Stop exports", run);
            FreeLibrary(m);
            return false;
        }
        ++g_api.loadCount;
        g_core = m;
        g_coreStop = stop;
        Log("starting core %s (load #%u)", run, g_api.loadCount);
        if (!start(&g_api))
        {
            Log("ERROR: core start failed");
            UnloadCore();
            return false;
        }
        Log("core running");
        return true;
    }

    DWORD WINAPI LoaderThread(LPVOID)
    {
        InstallSwapChainCreationPatch();
        LoadCore();

        char trigger[MAX_PATH];
        snprintf(trigger, sizeof(trigger), "%sTrinity_reload.txt", g_dir);
        FILETIME pendingFt{}; ULONGLONG pendingSize = 0; ULONGLONG pendingSince = 0;
        for (;;)
        {
            Sleep(500);
            bool reload = false;
            if (GetFileAttributesA(trigger) != INVALID_FILE_ATTRIBUTES)
            {
                DeleteFileA(trigger);
                Log("reload requested by Trinity_reload.txt");
                reload = true;
            }
            FILETIME ft{}; ULONGLONG size = 0;
            if (!reload && StatCore(&ft, &size) &&
                (CompareFileTime(&ft, &g_coreStamp) != 0 || size != g_coreSize))
            {
                // Wait until the file stops changing (copy finished) for 1 s.
                if (CompareFileTime(&ft, &pendingFt) != 0 || size != pendingSize)
                {
                    pendingFt = ft; pendingSize = size; pendingSince = GetTickCount64();
                }
                else if (GetTickCount64() - pendingSince >= 1000)
                {
                    Log("Trinity_core.dll changed - reloading");
                    reload = true;
                }
            }
            if (reload)
            {
                UnloadCore();
                LoadCore();
                pendingFt = {}; pendingSize = 0;
            }
        }
    }
}

extern "C" __declspec(dllexport) const trinity::host::Api* TrinityHostApi()
{
    return &g_api;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(module);

    char exe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    const char* exeName = strrchr(exe, '\\');
    exeName = exeName ? exeName + 1 : exe;
    if (_stricmp(exeName, "CrimsonDesert.exe") != 0) return TRUE; // crashpad etc.: stay inert

    GetModuleFileNameA(module, g_dir, MAX_PATH);
    if (char* slash = strrchr(g_dir, '\\')) slash[1] = 0;
    InitializeCriticalSection(&g_logLock);

    g_api.version        = trinity::host::kApiVersion;
    g_api.size           = sizeof(Api);
    g_api.setOverlay     = &ApiSetOverlay;
    g_api.wrapperActive  = &ApiWrapperActive;
    g_api.presentQueue   = &ApiPresentQueue;
    g_api.colorSpace     = &ApiColorSpace;
    g_api.subclassWindow = &ApiSubclassWindow;
    g_api.loadCount      = 0;

    Log("---- Trinity loader attached (pid %lu)", GetCurrentProcessId());
    if (HANDLE h = CreateThread(nullptr, 0, &LoaderThread, nullptr, 0, nullptr)) CloseHandle(h);
    return TRUE;
}
