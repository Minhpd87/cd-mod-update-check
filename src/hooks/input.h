#pragma once
#include <Windows.h>

namespace trinity::input
{
    // Subclasses the game window so ImGui receives raw input and, while the
    // menu is open, the game does not.
    void Init(HWND hwnd);
    void Shutdown();
    // Menu input filter; true = message consumed (*result is the return value).
    bool Filter(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* result);
}
