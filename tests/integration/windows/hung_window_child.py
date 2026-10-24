"""Child process for the hung-window integration test.

Creates one visible (off-screen) top-level window, prints its handle and then never pumps
messages, so Windows comes to consider the window hung. Terminated by the test.
"""

import ctypes
import sys
import time
from ctypes import wintypes

WS_POPUP = 0x8000_0000
WS_VISIBLE = 0x1000_0000
OFF_SCREEN = -32_000
CLASS_NAME = "WindowsMedicHungTestWindow"
TITLE = "windows-medic hung test"

WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)


class WNDCLASSW(ctypes.Structure):
    _fields_ = (
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    )


def main() -> int:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.DefWindowProcW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = (
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    )

    def window_procedure(hwnd: int, message: int, wparam: int, lparam: int) -> int:
        return int(user32.DefWindowProcW(hwnd, message, wparam, lparam))

    window_proc = WNDPROC(window_procedure)
    window_class = WNDCLASSW()
    window_class.lpfnWndProc = window_proc
    window_class.hInstance = kernel32.GetModuleHandleW(None)
    window_class.lpszClassName = CLASS_NAME
    if not user32.RegisterClassW(ctypes.byref(window_class)):
        raise ctypes.WinError(ctypes.get_last_error())
    hwnd = user32.CreateWindowExW(
        0,
        CLASS_NAME,
        TITLE,
        WS_POPUP | WS_VISIBLE,
        OFF_SCREEN,
        OFF_SCREEN,
        1,
        1,
        None,
        None,
        window_class.hInstance,
        None,
    )
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    sys.stdout.write(f"{int(hwnd)}\n")
    sys.stdout.flush()
    time.sleep(120)  # never pump messages
    return 0


if __name__ == "__main__":
    sys.exit(main())
