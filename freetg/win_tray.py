"""Zero-dependency native Win32 system tray, High-DPI helper, and dark titlebar styling."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import sys
import threading
from pathlib import Path
from typing import Callable, List, Optional, Tuple

MenuItem = Tuple[Optional[str], Optional[Callable[[], None]], bool]

if sys.platform == "win32":
    _user32 = ctypes.windll.user32
    _shell32 = ctypes.windll.shell32
    _kernel32 = ctypes.windll.kernel32
    try:
        _dwmapi = ctypes.windll.dwmapi
    except Exception:
        _dwmapi = None

    _LRESULT = ctypes.c_ssize_t
    _WNDPROC = ctypes.WINFUNCTYPE(_LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    _WM_NULL = 0x0000
    _WM_DESTROY = 0x0002
    _WM_CLOSE = 0x0010
    _WM_COMMAND = 0x0111
    _WM_LBUTTONUP = 0x0202
    _WM_LBUTTONDBLCLK = 0x0203
    _WM_RBUTTONUP = 0x0205
    _WM_CONTEXTMENU = 0x007B
    _WM_APP = 0x8000
    _WM_TRAY = _WM_APP + 17
    _WM_TRAY_CMD = _WM_APP + 18

    _IMAGE_ICON = 1
    _LR_LOADFROMFILE = 0x00000010
    _LR_DEFAULTSIZE = 0x00000040
    _IDI_APPLICATION = 32512

    _NIM_ADD = 0x00000000
    _NIM_MODIFY = 0x00000001
    _NIM_DELETE = 0x00000002
    _NIF_MESSAGE = 0x00000001
    _NIF_ICON = 0x00000002
    _NIF_TIP = 0x00000004
    _NIF_INFO = 0x00000010
    _NIIF_NONE = 0x00000000

    _TPM_RETURNCMD = 0x0100
    _TPM_RIGHTBUTTON = 0x0002
    _TPM_BOTTOMALIGN = 0x0020
    _MF_STRING = 0x0000
    _MF_SEPARATOR = 0x0800

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _NOTIFYICONDATAW(ctypes.Structure):
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
            ("uVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * 64),
            ("dwInfoFlags", wintypes.DWORD),
            ("guidItem", _GUID),
            ("hBalloonIcon", wintypes.HICON),
        ]

    class _WNDCLASSEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("style", wintypes.UINT),
            ("lpfnWndProc", _WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
            ("hIconSm", wintypes.HICON),
        ]

    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype = wintypes.HMODULE

    _user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.DefWindowProcW.restype = _LRESULT
    _user32.RegisterClassExW.argtypes = [ctypes.POINTER(_WNDCLASSEXW)]
    _user32.RegisterClassExW.restype = wintypes.ATOM
    _user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
    ]
    _user32.CreateWindowExW.restype = wintypes.HWND
    _user32.DestroyWindow.argtypes = [wintypes.HWND]
    _user32.DestroyWindow.restype = wintypes.BOOL
    _user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    _user32.GetMessageW.restype = wintypes.BOOL
    _user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.PostMessageW.restype = wintypes.BOOL
    _user32.PostQuitMessage.argtypes = [ctypes.c_int]
    _user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterWindowMessageW.restype = wintypes.UINT
    _user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    _user32.LoadImageW.restype = wintypes.HANDLE
    _user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadIconW.restype = wintypes.HICON
    _user32.DestroyIcon.argtypes = [wintypes.HICON]
    _user32.CreatePopupMenu.restype = wintypes.HMENU
    _user32.DestroyMenu.argtypes = [wintypes.HMENU]
    _user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT, wintypes.LPCWSTR]
    _user32.SetMenuDefaultItem.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT]
    _user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
    _user32.TrackPopupMenu.restype = wintypes.BOOL
    _user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW)]
    _shell32.Shell_NotifyIconW.restype = wintypes.BOOL


def enable_high_dpi() -> None:
    """Enable per-monitor v2 DPI awareness on Windows for sharp text and icons."""
    if sys.platform != "win32":
        return
    try:
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        _user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        _user32.SetProcessDPIAware()
    except Exception:
        pass


def apply_dark_titlebar(hwnd: int) -> None:
    """Enable native Windows 10/11 dark window titlebar for an HWND."""
    if sys.platform != "win32" or _dwmapi is None or not hwnd:
        return
    val = ctypes.c_int(1)
    for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (Win11 / Win10 1903+)
        try:
            _dwmapi.DwmSetWindowAttribute(
                wintypes.HWND(hwnd),
                ctypes.c_uint(attr),
                ctypes.byref(val),
                ctypes.sizeof(val),
            )
        except Exception:
            pass


def _load_hicon(icon_path: Optional[Path]) -> Tuple[int, bool]:
    if sys.platform != "win32":
        return 0, False
    if icon_path is not None and icon_path.exists():
        h = _user32.LoadImageW(
            None,
            str(icon_path),
            _IMAGE_ICON,
            0,
            0,
            _LR_LOADFROMFILE | _LR_DEFAULTSIZE,
        )
        if h:
            return int(h), True
    h_def = _user32.LoadIconW(None, ctypes.cast(_IDI_APPLICATION, wintypes.LPCWSTR))
    return int(h_def or 0), False


class Win32TrayIcon:
    """System tray icon running its own hidden message window on a background thread."""

    def __init__(
        self,
        icon_path: Optional[Path],
        tooltip: str,
        *,
        on_activate: Optional[Callable[[], None]] = None,
        menu_builder: Optional[Callable[[], List[MenuItem]]] = None,
    ) -> None:
        self._icon_path = icon_path
        self._tooltip = (tooltip or "FreeTG")[:127]
        self._on_activate = on_activate
        self._menu_builder = menu_builder
        self._hwnd: int = 0
        self._hicon: int = 0
        self._owns_icon: bool = False
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._pending_tip: Optional[str] = None
        self._pending_balloon: Optional[Tuple[str, str]] = None
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if sys.platform != "win32":
            self._ready.set()
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="freetg-win32-tray")
        self._thread.start()
        self._ready.wait(timeout=3.0)

    def set_tooltip(self, text: str) -> None:
        tip = (text or "FreeTG")[:127]
        with self._lock:
            self._tooltip = tip
            self._pending_tip = tip
        if sys.platform == "win32" and self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_TRAY_CMD, 1, 0)

    def show_notification(self, title: str, message: str) -> None:
        with self._lock:
            self._pending_balloon = ((title or "FreeTG")[:63], (message or "")[:255])
        if sys.platform == "win32" and self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_TRAY_CMD, 2, 0)

    def stop(self) -> None:
        self._stopped.set()
        if sys.platform == "win32" and self._hwnd:
            _user32.PostMessageW(self._hwnd, _WM_CLOSE, 0, 0)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1.5)

    def _add_nid(self) -> None:
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
        nid.uCallbackMessage = _WM_TRAY
        nid.hIcon = self._hicon
        nid.szTip = self._tooltip
        _shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid))

    def _modify_tip(self, tip: str) -> None:
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = _NIF_TIP
        nid.szTip = tip[:127]
        _shell32.Shell_NotifyIconW(_NIM_MODIFY, ctypes.byref(nid))

    def _modify_balloon(self, title: str, msg: str) -> None:
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = _NIF_INFO
        nid.szInfoTitle = title[:63]
        nid.szInfo = msg[:255]
        nid.dwInfoFlags = _NIIF_NONE
        _shell32.Shell_NotifyIconW(_NIM_MODIFY, ctypes.byref(nid))

    def _remove_nid(self) -> None:
        if not self._hwnd:
            return
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        _shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(nid))

    def _show_popup_menu(self) -> None:
        if self._menu_builder is None:
            return
        items = self._menu_builder()
        hmenu = _user32.CreatePopupMenu()
        if not hmenu:
            return
        callbacks: dict[int, Callable[[], None]] = {}
        try:
            cmd_id = 100
            default_id = None
            for label, cb, is_bold in items:
                if label is None:
                    _user32.AppendMenuW(hmenu, _MF_SEPARATOR, 0, None)
                else:
                    cid = cmd_id
                    cmd_id += 1
                    _user32.AppendMenuW(hmenu, _MF_STRING, cid, label)
                    if is_bold and default_id is None:
                        default_id = cid
                    if cb is not None:
                        callbacks[cid] = cb
            if default_id is not None:
                _user32.SetMenuDefaultItem(hmenu, default_id, 0)

            pt = wintypes.POINT()
            _user32.GetCursorPos(ctypes.byref(pt))
            _user32.SetForegroundWindow(self._hwnd)
            selected = int(
                _user32.TrackPopupMenu(
                    hmenu,
                    _TPM_RETURNCMD | _TPM_RIGHTBUTTON | _TPM_BOTTOMALIGN,
                    pt.x,
                    pt.y,
                    0,
                    self._hwnd,
                    None,
                )
            )
            _user32.PostMessageW(self._hwnd, _WM_NULL, 0, 0)
            if selected in callbacks:
                callbacks[selected]()
        finally:
            _user32.DestroyMenu(hmenu)

    def _run_loop(self) -> None:
        hinst = _kernel32.GetModuleHandleW(None)
        taskbar_msg = _user32.RegisterWindowMessageW("TaskbarCreated")
        self._hicon, self._owns_icon = _load_hicon(self._icon_path)

        def _wnd_proc(hwnd, msg, wparam, lparam):
            if msg == _WM_TRAY:
                ev = lparam & 0xFFFF
                if ev in (_WM_LBUTTONUP, _WM_LBUTTONDBLCLK):
                    if self._on_activate is not None:
                        self._on_activate()
                elif ev in (_WM_RBUTTONUP, _WM_CONTEXTMENU):
                    self._show_popup_menu()
                return 0
            if msg == _WM_TRAY_CMD:
                if wparam == 1:
                    with self._lock:
                        tip = self._pending_tip
                        self._pending_tip = None
                    if tip is not None:
                        self._modify_tip(tip)
                elif wparam == 2:
                    with self._lock:
                        bal = self._pending_balloon
                        self._pending_balloon = None
                    if bal is not None:
                        self._modify_balloon(bal[0], bal[1])
                return 0
            if taskbar_msg and msg == taskbar_msg:
                self._add_nid()
                return 0
            if msg == _WM_CLOSE:
                self._remove_nid()
                _user32.DestroyWindow(hwnd)
                return 0
            if msg == _WM_DESTROY:
                self._remove_nid()
                _user32.PostQuitMessage(0)
                return 0
            return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        wndproc_ref = _WNDPROC(_wnd_proc)
        cls_name = f"FreeTGTrayWnd_{id(self)}"
        wc = _WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(_WNDCLASSEXW)
        wc.lpfnWndProc = wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = cls_name
        _user32.RegisterClassExW(ctypes.byref(wc))

        hwnd = _user32.CreateWindowExW(
            0, cls_name, "FreeTG Tray", 0, 0, 0, 0, 0, None, None, hinst, None
        )
        self._hwnd = int(hwnd or 0)
        if self._hwnd:
            self._add_nid()
        self._ready.set()

        if self._hwnd:
            msg = wintypes.MSG()
            while not self._stopped.is_set():
                ret = _user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if ret <= 0:
                    break
                _user32.TranslateMessage(ctypes.byref(msg))
                _user32.DispatchMessageW(ctypes.byref(msg))
            self._remove_nid()
        if self._owns_icon and self._hicon:
            _user32.DestroyIcon(self._hicon)
            self._hicon = 0
        self._hwnd = 0
