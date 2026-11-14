#pragma once
// Interface between the permanent loader (Trinity.asi, loader/loader.cpp) and
// the reloadable mod core (Trinity_core.dll, everything under src/).
//
// The loader owns the only things the GAME keeps pointers to and that therefore
// can never be unloaded mid-session: the factory CreateSwapChainForHwnd vtable
// patch, the WrappedIDXGISwapChain object handed to the game, and the window
// subclass. It forwards their events to the core through OverlayCallbacks. To
// reload, the loader detaches the callbacks (waiting for in-flight calls to
// drain), calls TrinityCoreStop, frees the core and loads the new copy.
//
// A core built from this tree also still works stand-alone (renamed to
// Trinity.asi): it then finds no host and installs everything itself.
#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_5.h>
#include <cstdint>

namespace trinity::host
{
    constexpr uint32_t kApiVersion = 1;

    // All called with the loader's in-flight guard held; the loader never
    // calls them after SetOverlay(nullptr) has returned.
    struct OverlayCallbacks
    {
        // Draw the overlay into the game-facing swapchain before Present.
        bool (*render)(IDXGISwapChain3* sc, bool gameFacing);
        void (*postPresent)(bool drew);
        bool (*preResize)();                       // false -> fail the resize
        void (*postResize)(IDXGISwapChain3* sc);
        void (*colorSpace)(DXGI_COLOR_SPACE_TYPE cs);
        void (*releaseRefs)(const char* why);      // swapchain released / recreated
        void (*presentQueue)(ID3D12CommandQueue* q); // authoritative queue from creation
        void (*wrapped)();                         // a swapchain is now wrapped
        // Window messages: return true + *result to eat the message; false
        // lets the loader pass it on to the game's original window procedure.
        bool (*wndFilter)(HWND, UINT, WPARAM, LPARAM, LRESULT* result);
    };

    struct Api
    {
        uint32_t version;
        uint32_t size;
        // Register (non-null) or detach (null). Detaching blocks until no
        // callback is running any more.
        void (*setOverlay)(const OverlayCallbacks* cb);
        bool (*wrapperActive)();
        // AddRef'd present queue pinned at swapchain creation, or null.
        ID3D12CommandQueue* (*presentQueue)();
        // Last color space the game set; false if none seen yet.
        bool (*colorSpace)(DXGI_COLOR_SPACE_TYPE* out);
        // Subclass hwnd once (idempotent) so window messages reach wndFilter.
        void (*subclassWindow)(HWND hwnd);
        uint32_t loadCount; // 1 on first load, +1 per hot reload
    };

    using GetApi_t    = const Api* (*)();
    using CoreStart_t = bool (*)(const Api* api);
    using CoreStop_t  = bool (*)(); // false -> unsafe to FreeLibrary (leave it loaded)

    // Set by dllmain when running under the loader; null when stand-alone.
    const Api* Get();
    void Set(const Api* api);
}
