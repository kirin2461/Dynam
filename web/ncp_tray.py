# -*- coding: utf-8 -*-
"""
ncp_tray.py — иконка NCP в системном трее Windows (чистый ctypes, без зависимостей).

Запускается из server.py только на Windows в frozen-режиме.
Любая ошибка → start_tray возвращает False, приложение продолжает без трея.
"""

import ctypes
from ctypes import wintypes
import sys
import threading

WM_USER = 0x0400
WM_TRAYICON = WM_USER + 1
WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
NIM_ADD = 0
NIM_DELETE = 2
NIF_ICON = 0x2
NIF_MESSAGE = 0x1
NIF_TIP = 0x4
IDI_APPLICATION = 32512
IMAGE_ICON = 0
LR_LOADFROMFILE = 0x10
MF_STRING = 0
TPM_BOTTOMALIGN = 0x20
TPM_LEFTALIGN = 0
TPM_RETURNCMD = 0x100
TPM_RIGHTBUTTON = 0x2
PM_REMOVE = 0x1

ID_OPEN = 1001
ID_QUIT = 1002


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeoutOrVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wintypes.HWND, wintypes.UINT,
                             wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
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
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class MSG(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND), ("message", wintypes.UINT),
                ("wParam", wintypes.WPARAM), ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD), ("pt", POINT)]


def start_tray(tooltip: str, on_open, on_quit) -> bool:
    """Запускает иконку трея в отдельном потоке. False при любой ошибке."""
    if sys.platform != "win32":
        return False
    try:
        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32
        kernel32 = ctypes.windll.kernel32

# Explicit 64-bit-safe prototypes (ctypes defaults to c_int and truncates
# pointers on Win64 -> OverflowError / corrupted HWND).
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                  wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = ctypes.c_ssize_t
user32.RegisterClassW.argtypes = [ctypes.c_void_p]
user32.RegisterClassW.restype = wintypes.ATOM if hasattr(wintypes, "ATOM") else ctypes.c_ushort
user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                   wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
user32.CreateWindowExW.restype = wintypes.HWND
user32.CreatePopupMenu.argtypes = []
user32.CreatePopupMenu.restype = wintypes.HMENU
user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
user32.AppendMenuW.restype = wintypes.BOOL
user32.GetCursorPos.argtypes = [ctypes.c_void_p]
user32.GetCursorPos.restype = wintypes.BOOL
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL
user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, wintypes.HWND, ctypes.c_void_p]
user32.TrackPopupMenu.restype = wintypes.BOOL
user32.DestroyMenu.argtypes = [wintypes.HMENU]
user32.DestroyMenu.restype = wintypes.BOOL
user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.PostQuitMessage.restype = None
user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
user32.LoadIconW.restype = wintypes.HICON if hasattr(wintypes, "HICON") else ctypes.c_void_p
user32.GetMessageW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL
user32.TranslateMessage.argtypes = [ctypes.c_void_p]
user32.TranslateMessage.restype = wintypes.BOOL
user32.DispatchMessageW.argtypes = [ctypes.c_void_p]
user32.DispatchMessageW.restype = ctypes.c_ssize_t
shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.c_void_p]
shell32.Shell_NotifyIconW.restype = wintypes.BOOL
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE


        state = {"hwnd": None, "nid": None}

        def _wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_TRAYICON:
                if lparam in (0x0202,):  # WM_LBUTTONUP
                    on_open()
                elif lparam in (0x0205,):  # WM_RBUTTONUP
                    menu = user32.CreatePopupMenu()
                    user32.AppendMenuW(menu, MF_STRING, ID_OPEN, "Открыть панель NCP")
                    user32.AppendMenuW(menu, MF_STRING, ID_QUIT, "Выход")
                    pt = POINT()
                    user32.GetCursorPos(ctypes.byref(pt))
                    user32.SetForegroundWindow(hwnd)
                    cmd = user32.TrackPopupMenu(
                        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                        pt.x, pt.y, 0, hwnd, None)
                    user32.DestroyMenu(menu)
                    if cmd == ID_OPEN:
                        on_open()
                    elif cmd == ID_QUIT:
                        on_quit()
                return 0
            if msg == WM_DESTROY:
                _remove_icon()
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        def _remove_icon():
            if state["nid"] is not None:
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(state["nid"]))
                state["nid"] = None

        wndproc = WNDPROC(_wnd_proc)

        def _run():
            hinst = kernel32.GetModuleHandleW(None)
            wc = WNDCLASSW()
            wc.lpfnWndProc = wndproc
            wc.hInstance = hinst
            wc.lpszClassName = "NCPTrayWindow"
            if not user32.RegisterClassW(ctypes.byref(wc)):
                return
            hwnd = user32.CreateWindowExW(0, "NCPTrayWindow", "NCP", 0,
                                          0, 0, 0, 0, None, None, hinst, None)
            if not hwnd:
                return
            state["hwnd"] = hwnd

            hicon = user32.LoadIconW(None, wintypes.LPCWSTR(IDI_APPLICATION))
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP
            nid.uCallbackMessage = WM_TRAYICON
            nid.hIcon = hicon
            nid.szTip = tooltip[:127]
            if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
                return
            state["nid"] = nid

            msg = MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return True
    except Exception:
        return False
