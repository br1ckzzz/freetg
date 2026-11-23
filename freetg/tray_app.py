"""Lightweight tkinter + native Win32 System Tray UI and ProxyController for FreeTG."""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import queue
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from copy import deepcopy
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, List, Optional, Tuple
import webbrowser

from . import __version__
from .app_config import (
    APP_NAME,
    DEFAULT_CONFIG,
    FIRST_RUN_MARKER,
    LOG_FILE,
    ensure_dirs,
    get_link_host,
    load_config,
    resource_path,
    sanitize_worker_domain,
    save_config,
    set_autostart_enabled,
    set_verbose_logging,
    setup_logging,
    tg_proxy_url,
    to_freetg_config,
)
from .carousel import DcCarouselPool
from .crypto import (
    AES_BACKEND_NAME,
    PROTO_TAG_SECURE,
    encode_mtproto_reply,
    generate_relay_init,
    normalize_secret,
)
from .desync import (
    ZAPRET2_PROFILE_LABELS,
    ZAPRET2_PROFILE_ORDER,
    desync_manager,
    has_bundled_engine,
)
from .server import FreeTGProxyServer, _human_bytes
from .updater import UpdateInfo, check_for_update_sync
from .win_tray import Win32TrayIcon, apply_dark_titlebar, enable_high_dpi

log = logging.getLogger("freetg.tray")

_BG = "#0B1120"
_CARD_BG = "#121B2E"
_CARD_BORDER = "#1E2D45"
_INPUT_BG = "#0F172A"
_INPUT_BORDER = "#26354D"
_TEXT = "#E2E8F0"
_MUTED = "#94A3B8"
_DIM = "#64748B"
_ACCENT = "#10B981"
_ACCENT_HOVER = "#34D399"
_ACCENT_TEXT = "#052E16"
_BTN_BG = "#182338"
_BTN_HOVER = "#22304A"
_DANGER_BG = "#23141B"
_DANGER_FG = "#FCA5A5"

_PROXY_RESTART_KEYS = frozenset({
    "host",
    "port",
    "secret",
    "worker_domain",
    "mode",
    "bypass_mode",
    "desync_profile",
    "pool_size",
    "frag_tls",
    "builtin_desync",
    "auto_tune",
})

_mutex_handle: Optional[int] = None


def acquire_single_instance_mutex() -> bool:
    """Acquire a per-user Windows named mutex to enforce single instance."""
    global _mutex_handle
    if sys.platform != "win32":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, f"Local\\{APP_NAME}_SingleInstance")
        if not handle:
            return True
        if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return False
        _mutex_handle = int(handle)
        return True
    except Exception:
        return True


def release_single_instance_mutex() -> None:
    global _mutex_handle
    if sys.platform != "win32" or not _mutex_handle:
        return
    try:
        ctypes.windll.kernel32.CloseHandle(_mutex_handle)
    except Exception:
        pass
    _mutex_handle = None


def show_native_info(text: str, title: str = APP_NAME, error: bool = False) -> None:
    if sys.platform == "win32":
        flags = 0x10 if error else 0x40
        try:
            ctypes.windll.user32.MessageBoxW(None, text, title, flags)
            return
        except Exception:
            pass
    log.info("[%s] %s", title, text)


def _format_listen_error(host: str, port: int, exc: Exception) -> str:
    if isinstance(exc, OSError):
        errno = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if errno in (10048, 98, 48):
            return (
                f"Порт {host}:{port} уже занят другим приложением.\n\n"
                "Остановите другой процесс на этом порту и попробуйте другой порт в Настройках."
            )
        if errno in (10013, 13):
            return (
                f"Нет прав на прослушивание {host}:{port}.\n\n"
                "Выберите порт выше 1024 или запустите от имени администратора."
            )
    return f"Не удалось запустить прокси на {host}:{port}:\n{exc}"


def _open_tg_link(
    cfg: Dict[str, Any],
    tray: Optional[Win32TrayIcon] = None,
    root: Optional[tk.Misc] = None,
) -> None:
    url = tg_proxy_url(cfg)
    log.info("Opening Telegram proxy URL: %s", url)
    try:
        if sys.platform == "win32":
            os.startfile(url)
            return
        if webbrowser.open(url):
            return
    except Exception as exc:
        log.warning("Failed to open tg:// link (%r), copying to clipboard", exc)

    if root is not None:
        try:
            root.clipboard_clear()
            root.clipboard_append(url)
            root.update()
        except Exception:
            pass
    msg = f"Ссылка скопирована в буфер обмена. Вставьте её в Telegram («Избранное») и нажмите:\n{url}"
    if tray is not None:
        tray.show_notification(APP_NAME, msg)
    else:
        show_native_info(msg, APP_NAME)


def _apply_window_branding(win: tk.Wm, *, title: str) -> None:
    win.title(title)
    try:
        ico = resource_path("icon.ico")
        if sys.platform == "win32" and ico.exists():
            win.iconbitmap(default=str(ico))
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            win.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(win.winfo_id()) or win.winfo_id()
            apply_dark_titlebar(int(hwnd))
        except Exception:
            pass


def _load_logo_photo(master: Optional[tk.Misc] = None) -> Optional[tk.PhotoImage]:
    try:
        logo = resource_path("assets/logo.png")
        if logo.exists():
            pm = tk.PhotoImage(master=master, file=str(logo))
            w = pm.width()
            if w >= 96:
                factor = max(1, w // 48)
                pm = pm.subsample(factor, factor)
            return pm
    except Exception:
        pass
    return None


def _style_ttk(root: tk.Misc) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(
        "Dark.TCombobox",
        fieldbackground=_INPUT_BG,
        background=_BTN_BG,
        foreground="#F8FAFC",
        arrowcolor=_ACCENT_HOVER,
        bordercolor=_INPUT_BORDER,
        lightcolor=_INPUT_BORDER,
        darkcolor=_INPUT_BORDER,
        padding=4,
    )
    style.map(
        "Dark.TCombobox",
        fieldbackground=[("readonly", _INPUT_BG)],
        foreground=[("readonly", "#F8FAFC")],
        background=[("active", _BTN_HOVER)],
    )
    style.configure(
        "Dark.Vertical.TScrollbar",
        background=_BTN_BG,
        troughcolor=_BG,
        bordercolor=_BG,
        arrowcolor=_MUTED,
        gripcount=0,
    )
    root.option_add("*TCombobox*Listbox.background", _INPUT_BG)
    root.option_add("*TCombobox*Listbox.foreground", "#F8FAFC")
    root.option_add("*TCombobox*Listbox.selectBackground", "#059669")
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")


def _make_btn(
    parent: tk.Misc,
    text: str,
    command: Callable[[], None],
    *,
    primary: bool = False,
    danger: bool = False,
    image: Optional[tk.PhotoImage] = None,
) -> tk.Button:
    if primary:
        bg, fg, abg, afg, font = _ACCENT, _ACCENT_TEXT, _ACCENT_HOVER, _ACCENT_TEXT, ("Segoe UI", 9, "bold")
    elif danger:
        bg, fg, abg, afg, font = _DANGER_BG, _DANGER_FG, "#331822", _DANGER_FG, ("Segoe UI", 9)
    else:
        bg, fg, abg, afg, font = _BTN_BG, _TEXT, _BTN_HOVER, "#FFFFFF", ("Segoe UI", 9)
    kw: Dict[str, Any] = {
        "text": text,
        "command": command,
        "bg": bg,
        "fg": fg,
        "activebackground": abg,
        "activeforeground": afg,
        "disabledforeground": _DIM,
        "relief": "flat",
        "bd": 0,
        "highlightthickness": 1,
        "highlightbackground": _ACCENT if primary else ("#7F1D1D" if danger else "#2A3B58"),
        "padx": 11,
        "pady": 5,
        "cursor": "hand2",
        "font": font,
    }
    if image is not None:
        kw["image"] = image
        kw["compound"] = "left"
    return tk.Button(parent, **kw)


class _WrapFrame(tk.Frame):
    """Responsive flow container that wraps child buttons smoothly when window narrows."""

    def __init__(self, master: tk.Misc, *, bg: str = _CARD_BG, hgap: int = 8, vgap: int = 6) -> None:
        super().__init__(master, bg=bg, bd=0, highlightthickness=0)
        self._hgap = hgap
        self._vgap = vgap
        self._children: List[tk.Widget] = []
        self.bind("<Configure>", self._relayout)

    def add_widget(self, w: tk.Widget) -> tk.Widget:
        self._children.append(w)
        self.after_idle(self._relayout)
        return w

    def _relayout(self, _event=None) -> None:
        width = max(120, self.winfo_width())
        x = 0
        y = 0
        row_h = 0
        for w in self._children:
            if not getattr(w, "_wrap_visible", True):
                w.place_forget()
                continue
            rw = max(w.winfo_reqwidth(), 24)
            rh = max(w.winfo_reqheight(), 28)
            if x > 0 and x + rw > width:
                x = 0
                y += row_h + self._vgap
                row_h = 0
            w.place(x=x, y=y, width=rw, height=rh)
            x += rw + self._hgap
            row_h = max(row_h, rh)
        total_h = y + row_h if row_h > 0 else 1
        if int(self.cget("height") or 0) != total_h:
            self.configure(height=total_h)


class _ScrollableFrame(tk.Frame):
    """Vertical scrollable viewport adapted for dark cards without horizontal overflow."""

    def __init__(self, master: tk.Misc, *, bg: str = _BG) -> None:
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, bd=0, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview, style="Dark.Vertical.TScrollbar")
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vbar.pack(side="right", fill="y")

        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.canvas.bind("<Enter>", lambda _e: self.canvas.bind_all("<MouseWheel>", self._on_mousewheel))
        self.canvas.bind("<Leave>", lambda _e: self.canvas.unbind_all("<MouseWheel>"))

    def _on_canvas_resize(self, event) -> None:
        self.canvas.itemconfigure(self._win_id, width=max(100, event.width - 4))

    def _on_mousewheel(self, event) -> None:
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


class ProxyController:
    """Manages FreeTGProxyServer lifecycle inside a dedicated asyncio daemon thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._op_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._server: Optional[FreeTGProxyServer] = None
        self._last_error: Optional[str] = None
        self._autotune_thread: Optional[threading.Thread] = None
        self._watch_stop = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_cfg: Dict[str, Any] = {}

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive() and self._server is not None)

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    def start(
        self,
        cfg: Dict[str, Any],
        on_error: Optional[Callable[[str], None]] = None,
        *,
        stats_interval: float = 30.0,
        wait_ready: float = 10.0,
    ) -> Tuple[bool, Optional[str]]:
        with self._op_lock:
            return self._start_unlocked(
                cfg, on_error=on_error, stats_interval=stats_interval, wait_ready=wait_ready
            )

    def _start_unlocked(
        self,
        cfg: Dict[str, Any],
        on_error: Optional[Callable[[str], None]] = None,
        *,
        stats_interval: float = 30.0,
        wait_ready: float = 10.0,
    ) -> Tuple[bool, Optional[str]]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return True, None
            self._last_error = None

        bypass_mode = str(cfg.get("bypass_mode", "auto")).lower()
        desync_profile = str(cfg.get("desync_profile", "auto")).lower()
        if bypass_mode in ("windivert", "windivert1"):
            eng = "zapret1" if bypass_mode == "windivert1" else "zapret2"
            prof = ZAPRET2_PROFILE_ORDER[0] if desync_profile == "auto" else desync_profile
            if cfg.get("builtin_desync", True) and not desync_manager.is_external_winws_running():
                ok_w, err_w = desync_manager.start(
                    str(cfg.get("worker_domain", "")), profile=prof, engine=eng
                )
                if not ok_w and err_w:
                    log.warning("Failed to start forced %s bypass: %s", eng, err_w)
        elif bypass_mode in ("port80", "tls_frag", "direct") or not cfg.get("builtin_desync", True):
            desync_manager.stop()

        try:
            engine_cfg = to_freetg_config(cfg, stats_interval=stats_interval)
        except Exception as exc:
            err = f"Некорректная конфигурация прокси: {exc}"
            self._last_error = err
            if on_error:
                on_error(err)
            return False, err

        ready = threading.Event()
        start_error: Dict[str, Optional[str]] = {"msg": None}

        def _worker() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stop_ev = asyncio.Event()
            server = FreeTGProxyServer(engine_cfg)

            with self._lock:
                self._loop = loop
                self._stop_event = stop_ev
                self._server = server

            async def _runner() -> None:
                try:
                    await server.start()
                except Exception as exc:
                    err_msg = _format_listen_error(engine_cfg.host, engine_cfg.ports[0], exc)
                    start_error["msg"] = err_msg
                    self._last_error = err_msg
                    log.exception("Failed to start FreeTGProxyServer")
                    ready.set()
                    if on_error:
                        on_error(err_msg)
                    return

                ready.set()
                try:
                    await stop_ev.wait()
                finally:
                    await server.stop()

            try:
                loop.run_until_complete(_runner())
            except Exception as exc:
                err_msg = str(exc)
                if not ready.is_set():
                    start_error["msg"] = err_msg
                    ready.set()
                log.exception("Proxy thread exited unexpectedly")
            finally:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()
                with self._lock:
                    self._loop = None
                    self._stop_event = None
                    self._server = None

        thread = threading.Thread(target=_worker, daemon=True, name="freetg-proxy")
        with self._lock:
            self._thread = thread
        thread.start()

        if wait_ready > 0:
            ready.wait(timeout=wait_ready)
        if start_error["msg"]:
            return False, start_error["msg"]
        return True, None

    def stop(self, timeout: float = 5.0, *, stop_desync: bool = True) -> None:
        with self._op_lock:
            self._stop_unlocked(timeout=timeout, stop_desync=stop_desync)

    def _stop_unlocked(self, timeout: float = 5.0, *, stop_desync: bool = True) -> None:
        self.stop_zapret_watcher()
        with self._lock:
            loop = self._loop
            stop_ev = self._stop_event
            thread = self._thread

        if loop is not None and stop_ev is not None:
            try:
                loop.call_soon_threadsafe(stop_ev.set)
            except RuntimeError:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                log.warning("Proxy thread did not stop cleanly within %.1fs", timeout)

        with self._lock:
            self._thread = None
            self._server = None
            self._loop = None
            self._stop_event = None

        if stop_desync:
            desync_manager.stop()

    def restart(
        self,
        cfg: Dict[str, Any],
        on_error: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, Optional[str]]:
        with self._op_lock:
            log.info("Restarting FreeTG proxy...")
            self._stop_unlocked(timeout=5.0, stop_desync=False)
            time.sleep(0.25)
            return self._start_unlocked(cfg, on_error=on_error)

    def run_auto_tune_async(
        self,
        cfg: Dict[str, Any],
        on_notice: Optional[Callable[[Dict[str, Any], str], None]] = None,
    ) -> None:
        """Router-safe 4-stage probe: Direct 443 -> CF Port 80 -> TLS frag 443 -> zapret2 profiles."""
        if str(cfg.get("bypass_mode", "auto")).lower() != "auto":
            return
        if not cfg.get("auto_tune", True):
            return
        if self._autotune_thread is not None and self._autotune_thread.is_alive():
            return

        def _tune() -> None:
            with self._lock:
                srv = self._server
                loop = self._loop
            if srv is None or loop is None:
                return

            notes: List[str] = []

            async def _probe_once(*, use_frag: bool = False, prefer_port80: bool = False) -> Tuple[bool, int, Optional[str]]:
                probe_pool = DcCarouselPool(
                    worker_domain=srv.config.worker_domain,
                    mode=srv.config.mode,
                    pool_size=1,
                    frag_tls=use_frag,
                    prefer_port80_cf=prefer_port80,
                    allow_port80_fallback=False,
                    auto_tls_frag=False,
                )
                try:
                    await probe_pool.initialize()
                    deep_ok, sent_b, deep_err = await probe_pool.probe_deep_stream(dc=2, target_bytes=22000)
                    if not deep_ok:
                        return False, sent_b, deep_err
                    try:
                        _, err203 = await _probe_dc_via_worker(probe_pool, 203)
                    except Exception as exc203:
                        return False, sent_b, f"DC203: {exc203}"
                    if err203 is not None:
                        return False, sent_b, f"DC203: {err203}"
                    return True, sent_b, None
                finally:
                    await probe_pool.close()

            def _apply_live_flags(*, frag: bool, port80: bool) -> None:
                srv.carousel.frag_tls = frag
                srv.carousel.prefer_port80_cf = port80
                try:
                    loop.call_soon_threadsafe(srv.carousel._endpoint_cooldown.clear)
                    asyncio.run_coroutine_threadsafe(srv.carousel.flush_stream_idle(), loop)
                except RuntimeError:
                    pass

            probe_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(probe_loop)
            try:
                # 1. Direct Port 443 (works out-of-the-box with router zapret1/zapret2 or open CF)
                init_frag = bool(srv.carousel.frag_tls)
                ok443, sent_b, err443 = probe_loop.run_until_complete(
                    _probe_once(use_frag=init_frag, prefer_port80=False)
                )
                if ok443:
                    log.info("Auto-tune check passed on Port 443: %dB + DC203 OK", sent_b)
                    return

                # 2. CF Port 80 (driverless, safe alongside external/router zapret)
                log.warning("Port 443 check failed (%s at %dB); trying CF Port 80", err443, sent_b)
                ok80, sent80, err80 = probe_loop.run_until_complete(
                    _probe_once(use_frag=False, prefer_port80=True)
                )
                if ok80:
                    _apply_live_flags(frag=False, port80=True)
                    notes.append("включён режим CF Port 80 (без драйверов)")
                    log.info("Auto-tune switched to CF Port 80 (%dB OK)", sent80)
                else:
                    # 3. TLS TCP-segment frag on Port 443 (no driver needed)
                    log.warning("CF Port 80 failed (%s); trying TLS ClientHello frag on 443", err80)
                    ok_frag, sent_frag, err_frag = probe_loop.run_until_complete(
                        _probe_once(use_frag=True, prefer_port80=False)
                    )
                    if ok_frag:
                        _apply_live_flags(frag=True, port80=False)
                        notes.append("включена TLS-фрагментация (порт 443)")
                        log.info("Auto-tune enabled TCP-segment TLS frag (%dB OK)", sent_frag)
                    elif desync_manager.is_external_winws_running():
                        notes.append(
                            "обнаружен внешний zapret, но Cloudflare (443/80) недоступен; "
                            "добавьте домены .co.uk / IP CF в ваш zapret или отключите его"
                        )
                    elif cfg.get("builtin_desync", True):
                        # 4. Built-in zapret2 profiles (stops automatically if all profiles fail)
                        pref_prof = str(cfg.get("desync_profile", "auto")).lower()
                        profiles = (
                            list(ZAPRET2_PROFILE_ORDER)
                            if pref_prof == "auto"
                            else [pref_prof]
                        )
                        winws2_worked = False
                        last_w_err: Optional[str] = None
                        for prof in profiles:
                            ok_w, err_w = desync_manager.start(
                                srv.config.worker_domain, profile=prof, engine="zapret2"
                            )
                            if not ok_w:
                                last_w_err = err_w
                                break
                            re_ok, re_sent, re_err = probe_loop.run_until_complete(
                                _probe_once(use_frag=False, prefer_port80=False)
                            )
                            if re_ok:
                                winws2_worked = True
                                label = ZAPRET2_PROFILE_LABELS.get(prof, prof)
                                notes.append(f"активирован zapret2 ({label})")
                                _apply_live_flags(frag=False, port80=False)
                                log.info("Auto-tune activated zapret2 profile %s (%dB OK)", prof, re_sent)
                                break
                            log.warning("zapret2 profile %s did not pass: %s", prof, re_err)
                        if not winws2_worked:
                            desync_manager.stop()
                            if last_w_err:
                                notes.append(f"zapret2 не запущен: {last_w_err}")
                            else:
                                notes.append("все профили zapret2 не прошли проверку; обход остановлен")
            except Exception as exc:
                log.debug("Auto-tune check skipped: %r", exc)
            finally:
                probe_loop.close()

            if on_notice and notes:
                on_notice(dict(cfg), "Автоподбор обхода: " + "; ".join(notes))

        self._autotune_thread = threading.Thread(target=_tune, daemon=True, name="freetg-autotune")
        self._autotune_thread.start()

    def update_watch_config(self, cfg: Dict[str, Any]) -> None:
        self._watch_cfg = dict(cfg)

    def start_zapret_watcher(
        self,
        cfg: Dict[str, Any],
        on_notice: Optional[Callable[[Dict[str, Any], str], None]] = None,
    ) -> None:
        """Monitor external winws/winws2 so built-in zapret2 yields cleanly without WinDivert conflicts."""
        self.stop_zapret_watcher()
        self._watch_cfg = dict(cfg)
        self._watch_stop.clear()

        def _watch() -> None:
            was_external = desync_manager.is_external_winws_running()
            while not self._watch_stop.wait(3.0):
                if not self.is_running():
                    continue
                if desync_manager.yield_if_external_running():
                    was_external = True
                    if on_notice:
                        on_notice(
                            dict(self._watch_cfg),
                            "Обнаружен внешний zapret/zapret2 — встроенный модуль остановлен без сброса драйвера",
                        )
                    continue
                now_external = desync_manager.is_external_winws_running()
                if was_external and not now_external:
                    log.info("External zapret stopped; triggering auto-tune check")
                    if self._watch_cfg.get("auto_tune", True):
                        self.run_auto_tune_async(self._watch_cfg, on_notice=on_notice)
                was_external = now_external

        self._watch_thread = threading.Thread(target=_watch, daemon=True, name="freetg-zapret-watch")
        self._watch_thread.start()

    def stop_zapret_watcher(self) -> None:
        self._watch_stop.set()
        t = self._watch_thread
        if t is not None and t.is_alive() and threading.current_thread() is not t:
            t.join(timeout=1.0)
        self._watch_thread = None

    def get_status_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            srv = self._server
            running = bool(self._thread and self._thread.is_alive() and srv is not None)
        if not running or srv is None:
            return {"running": False, "err": self._last_error}
        st = srv.carousel.stats
        if desync_manager.is_external_winws_running():
            desync_label = "внешний zapret"
        elif desync_manager.is_running():
            eng = desync_manager.active_engine or "zapret2"
            prof = desync_manager.active_profile or ""
            desync_label = f"{eng} ({prof})" if prof else eng
        elif getattr(srv.carousel, "prefer_port80_cf", False):
            desync_label = "CF Port 80"
        elif srv.carousel.frag_tls:
            desync_label = "TLS-фраг"
        else:
            desync_label = "прямой"
        return {
            "running": True,
            "mode": srv.carousel.active_mode.upper(),
            "active_conns": srv._connections_active,
            "total_conns": srv._connections_total,
            "reqs_ok": st.requests_ok,
            "reqs_failed": st.requests_failed,
            "tx": _human_bytes(st.bytes_tx),
            "rx": _human_bytes(st.bytes_rx),
            "idle": srv.carousel.active_idle_count(),
            "desync": desync_label,
        }


async def _probe_dc_via_worker(pool: DcCarouselPool, dc: int) -> Tuple[int, Optional[str]]:
    """Send a genuine MTProto req_pq_multi packet through Worker and check resPQ."""
    nonce = os.urandom(16)
    msg_id = int(time.time() * (2**32)) & ~3
    req_body = struct.pack("<QQII", 0, msg_id, 20, 0xBE7E8EF1) + nonce

    sock = await pool.acquire_stream_socket(dc, False)
    try:
        init_bytes, tg_enc, tg_dec = generate_relay_init(PROTO_TAG_SECURE, dc)
        framed = encode_mtproto_reply(req_body, PROTO_TAG_SECURE)
        enc_framed = tg_enc.update(framed)
        if sock.is_cf_direct:
            await sock.send_ws(init_bytes)
            await sock.send_ws(enc_framed)
        else:
            await sock.send_ws(init_bytes + enc_framed)
        chunk = await sock.recv_ws(timeout=6.0)
        if not chunk:
            return dc, "соединение закрыто без ответа"
        plain = tg_dec.update(chunk)
        if b"\x63\x24\x16\x05" in plain:
            return dc, None
        return dc, f"неожиданный ответ ({len(plain)} Б)"
    finally:
        await sock.close()


async def test_worker_connectivity_async(
    worker_domain: str,
    mode: str,
    frag_tls: bool,
    *,
    bypass_mode: str = "auto",
    desync_profile: str = "auto",
    builtin_desync: bool = True,
    auto_tune: bool = True,
    controller: Optional[ProxyController] = None,
) -> Tuple[str, bool]:
    domain = sanitize_worker_domain(worker_domain)
    bmode = (bypass_mode or "auto").lower()
    dprof = (desync_profile or "auto").lower()
    target_label = domain if domain else "публичный пул CF (20 доменов)"

    async def _run_suite(
        use_frag: bool, prefer_port80: bool = False
    ) -> Tuple[bool, list, list, str, bool, int, Optional[str]]:
        pool = DcCarouselPool(
            worker_domain=domain,
            mode=mode,
            pool_size=1,
            frag_tls=use_frag,
            prefer_port80_cf=prefer_port80,
            allow_port80_fallback=False,
            auto_tls_frag=False,
        )
        try:
            await pool.initialize()
            dcs = (4, 203)
            results = await asyncio.gather(
                *(_probe_dc_via_worker(pool, dc) for dc in dcs),
                return_exceptions=True,
            )
            ok_dcs = []
            fail_lines = []
            for idx, res in enumerate(results):
                dc = dcs[idx]
                if isinstance(res, Exception):
                    fail_lines.append(f"DC{dc}: {res}")
                else:
                    dc_id, err = res
                    if err is None:
                        ok_dcs.append(f"DC{dc_id}")
                    else:
                        fail_lines.append(f"DC{dc_id}: {err}")

            deep_ok, deep_sent, deep_err = await pool.probe_deep_stream(dc=2, target_bytes=22000)
            if deep_ok:
                ok_dcs.insert(0, "DC2 (22 КБ ✓)")
            else:
                fail_lines.insert(0, f"DC2 (>16 КБ): {deep_err or 'обрыв'}")

            return (
                deep_ok and not fail_lines,
                ok_dcs,
                fail_lines,
                pool.active_mode.upper(),
                pool.frag_tls,
                deep_sent,
                deep_err,
            )
        finally:
            await pool.close()

    try:
        winws_note = ""
        if bmode == "port80":
            deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                False, prefer_port80=True
            )
            winws_note = ", CF Port 80 (без драйвера)"
        elif bmode == "tls_frag":
            deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                True, prefer_port80=False
            )
        elif bmode == "direct":
            deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                False, prefer_port80=False
            )
            if desync_manager.is_external_winws_running():
                winws_note = ", внешний zapret"
        elif bmode in ("windivert", "windivert1"):
            eng = "zapret1" if bmode == "windivert1" else "zapret2"
            if builtin_desync and not desync_manager.is_external_winws_running():
                profiles = (
                    list(ZAPRET2_PROFILE_ORDER)
                    if (eng == "zapret2" and dprof == "auto")
                    else [dprof]
                )
                deep_ok = False
                ok_dcs, fail_lines, mode_label, effective_frag, deep_err = [], [], mode.upper(), False, None
                for prof in profiles:
                    ok_w, err_w = desync_manager.start(domain, profile=prof, engine=eng)
                    if not ok_w:
                        return f"✗ {target_label}: {eng} не запущен — {err_w}", False
                    deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                        False, prefer_port80=False
                    )
                    winws_note = f", {eng} ({prof})" if eng == "zapret2" else ", zapret1 (winws.exe)"
                    if deep_ok:
                        break
                if not deep_ok:
                    desync_manager.stop()
            else:
                if desync_manager.is_external_winws_running():
                    winws_note = ", внешний zapret (встроенный отключён)"
                deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                    False, prefer_port80=False
                )
        else:
            # Cascade: 443 -> Port 80 -> TLS frag -> zapret2 profiles
            deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                False, prefer_port80=False
            )
            if not deep_ok:
                p80_res = await _run_suite(False, prefer_port80=True)
                if p80_res[0]:
                    deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = p80_res
                    winws_note = ", CF Port 80"
                else:
                    frag_res = await _run_suite(True, prefer_port80=False)
                    if frag_res[0]:
                        deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = frag_res
                    elif desync_manager.is_external_winws_running():
                        winws_note = ", внешний zapret активен (Cloudflare 443/80 не отвечает)"
                    elif builtin_desync and auto_tune:
                        profiles = list(ZAPRET2_PROFILE_ORDER) if dprof == "auto" else [dprof]
                        for prof in profiles:
                            ok_w, err_w = desync_manager.start(domain, profile=prof, engine="zapret2")
                            if not ok_w:
                                if err_w:
                                    fail_lines.append(f"zapret2: {err_w}")
                                break
                            z2_res = await _run_suite(False, prefer_port80=False)
                            if z2_res[0]:
                                deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = z2_res
                                winws_note = f", zapret2 ({prof})"
                                break
                        if not deep_ok:
                            desync_manager.stop()
            elif desync_manager.is_external_winws_running():
                winws_note = ", внешний zapret"
            elif desync_manager.is_running():
                winws_note = f", {desync_manager.active_engine or 'zapret2'}"

        frag_note = ", TLS-фраг вкл" if effective_frag else ""
        if deep_ok and len(ok_dcs) == 3:
            return (
                f"✓ Все датацентры ({', '.join(ok_dcs)}) работают: {target_label} "
                f"(режим {mode_label}{frag_note}{winws_note}).",
                effective_frag,
            )
        if ok_dcs:
            return (
                f"~ Частичный успех ({target_label}, режим {mode_label}{frag_note}{winws_note}):\n"
                f"✓ Доступны: {', '.join(ok_dcs)}\n"
                f"✗ Проблемы: {'; '.join(fail_lines)}",
                effective_frag,
            )
        return f"✗ {target_label} не проходит проверку:\n" + "\n".join(fail_lines), effective_frag
    except Exception as exc:
        return f"✗ Ошибка проверки {target_label}: {exc}", frag_tls


class FirstRunDialog:
    """Minimalist dark tkinter assistant with Automatic and Manual MTProto instructions."""

    def __init__(self, master: tk.Misc, cfg: Dict[str, Any]) -> None:
        self._cfg = cfg
        self.accepted = False
        self.dont_show_again = True

        self.win = tk.Toplevel(master)
        self.win.configure(bg=_BG)
        self.win.minsize(380, 460)
        self.win.geometry("500x540")
        _apply_window_branding(self.win, title=f"{APP_NAME} v{__version__} — Подключение Telegram")
        self._logo = _load_logo_photo(self.win)

        outer = tk.Frame(self.win, bg=_BG)
        outer.pack(fill="both", expand=True, padx=16, pady=14)

        # Header
        hdr = tk.Frame(outer, bg=_BG)
        hdr.pack(fill="x", pady=(0, 10))
        if self._logo is not None:
            tk.Label(hdr, image=self._logo, bg=_BG).pack(side="left", padx=(0, 12))
        title_col = tk.Frame(hdr, bg=_BG)
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(
            title_col,
            text=f"{APP_NAME} v{__version__}",
            bg=_BG, fg="#F8FAFC", font=("Segoe UI", 14, "bold"), anchor="w",
        ).pack(fill="x")
        worker_txt = self._cfg.get("worker_domain") or "Публичный пул Cloudflare (20+ доменов)"
        tk.Label(
            title_col,
            text=f"Прокси запущен • {worker_txt}",
            bg=_BG, fg=_ACCENT_HOVER, font=("Segoe UI", 9, "bold"), anchor="w", wraplength=380, justify="left",
        ).pack(fill="x")

        # Tabs switcher
        tab_bar = tk.Frame(outer, bg=_BG)
        tab_bar.pack(fill="x")
        card = tk.Frame(outer, bg=_CARD_BG, highlightbackground=_CARD_BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True)

        auto_page = tk.Frame(card, bg=_CARD_BG)
        manual_page = tk.Frame(card, bg=_CARD_BG)

        self._tab_btns: List[tk.Button] = []

        def _select_tab(idx: int) -> None:
            for i, btn in enumerate(self._tab_btns):
                if i == idx:
                    btn.configure(bg=_ACCENT, fg=_ACCENT_TEXT)
                else:
                    btn.configure(bg=_INPUT_BG, fg=_MUTED)
            if idx == 0:
                manual_page.pack_forget()
                auto_page.pack(fill="both", expand=True, padx=12, pady=12)
            else:
                auto_page.pack_forget()
                manual_page.pack(fill="both", expand=True, padx=12, pady=12)

        for i, lbl in enumerate(("Автоматически", "Вручную (пошагово)")):
            b = tk.Button(
                tab_bar, text=lbl, command=lambda idx=i: _select_tab(idx),
                relief="flat", bd=0, padx=14, pady=6, cursor="hand2", font=("Segoe UI", 9, "bold"),
            )
            b.pack(side="left", padx=(0, 4))
            self._tab_btns.append(b)

        link_host = get_link_host(str(cfg.get("host", "127.0.0.1")))
        port = str(cfg.get("port", 1080))
        try:
            clean_secret = normalize_secret(str(cfg.get("secret", ""))).hex()
        except Exception:
            clean_secret = str(cfg.get("secret", ""))
        prefixed_secret = f"dd{clean_secret}"
        url = tg_proxy_url(cfg)

        # Auto tab
        tk.Label(
            auto_page,
            text=(
                "Быстрое подключение в 1 клик:\n"
                "1. Нажмите зелёную кнопку ниже — откроется Telegram Desktop.\n"
                "2. В окне Telegram нажмите «Включить» (Enable proxy)."
            ),
            bg=_CARD_BG, fg="#CBD5E1", justify="left", anchor="w", wraplength=430, font=("Segoe UI", 10),
        ).pack(fill="x", pady=(0, 12))

        _make_btn(
            auto_page, "  Открыть в Telegram", lambda: _open_tg_link(self._cfg, root=self.win), primary=True
        ).pack(fill="x", ipady=4, pady=(0, 14))

        tk.Label(
            auto_page,
            text="Если Telegram не открылся автоматически — скопируйте ссылку в «Избранное»:",
            bg=_CARD_BG, fg=_MUTED, justify="left", anchor="w", wraplength=430, font=("Segoe UI", 9),
        ).pack(fill="x", pady=(0, 4))

        link_row = tk.Frame(auto_page, bg=_CARD_BG)
        link_row.pack(fill="x", pady=(0, 12))
        e_url = tk.Entry(
            link_row, bg=_INPUT_BG, fg="#F8FAFC", readonlybackground=_INPUT_BG,
            relief="flat", highlightthickness=1, highlightbackground=_INPUT_BORDER, font=("Segoe UI", 9),
        )
        e_url.insert(0, url)
        e_url.configure(state="readonly")
        e_url.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 6))
        copy_u_btn = _make_btn(link_row, "Копировать", lambda: self._copy_text(url, copy_u_btn))
        copy_u_btn.pack(side="right")

        tk.Label(
            auto_page,
            text="После закрытия окна FreeTG остаётся в системном трее рядом с часами.",
            bg=_CARD_BG, fg=_DIM, anchor="w", wraplength=430, font=("Segoe UI", 8),
        ).pack(fill="x", pady=(8, 0))

        # Manual tab
        tk.Label(
            manual_page,
            text=(
                "Пошаговое добавление в Telegram Desktop:\n"
                "1. Настройки → Продвинутые → Тип соединения\n"
                "2. Использовать собственный прокси → Добавить прокси → MTProto\n"
                "3. Вставьте три поля ниже и нажмите «Сохранить»:"
            ),
            bg=_CARD_BG, fg="#CBD5E1", justify="left", anchor="w", wraplength=430, font=("Segoe UI", 9),
        ).pack(fill="x", pady=(0, 10))

        for field_title, value in (
            ("Сервер:", link_host),
            ("Порт:", port),
            ("Ключ (dd...):", prefixed_secret),
        ):
            tk.Label(manual_page, text=field_title, bg=_CARD_BG, fg=_MUTED, font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x")
            row = tk.Frame(manual_page, bg=_CARD_BG)
            row.pack(fill="x", pady=(2, 8))
            ent = tk.Entry(
                row, bg=_INPUT_BG, fg="#F8FAFC", readonlybackground=_INPUT_BG,
                relief="flat", highlightthickness=1, highlightbackground=_INPUT_BORDER, font=("Segoe UI", 9),
            )
            ent.insert(0, value)
            ent.configure(state="readonly")
            ent.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 6))
            cb_btn = _make_btn(row, "Копировать", lambda v=value: None)
            cb_btn.configure(command=lambda v=value, b=cb_btn: self._copy_text(v, b))
            cb_btn.pack(side="right")

        _select_tab(0)

        # Footer
        footer = _WrapFrame(outer, bg=_BG)
        footer.pack(fill="x", pady=(10, 0))
        self._dont_show_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(
            footer, text="Больше не показывать при запуске", variable=self._dont_show_var,
            bg=_BG, fg=_TEXT, selectcolor=_INPUT_BG, activebackground=_BG, activeforeground=_TEXT,
            font=("Segoe UI", 9),
        )
        footer.add_widget(chk)
        footer.add_widget(_make_btn(footer, "Готово", self._on_finish, primary=True))
        self.win.protocol("WM_DELETE_WINDOW", self._on_finish)

    def _copy_text(self, text: str, btn: tk.Button) -> None:
        self.win.clipboard_clear()
        self.win.clipboard_append(text)
        self.win.update()
        btn.configure(text="Скопировано ✓")

    def _on_finish(self) -> None:
        self.dont_show_again = bool(self._dont_show_var.get())
        self.accepted = True
        self.win.destroy()


class UpdateDialog:
    """Modal notification showing available GitHub release details and download actions."""

    def __init__(
        self,
        master: tk.Misc,
        info: UpdateInfo,
        *,
        on_skip: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._info = info
        self._on_skip = on_skip

        self.win = tk.Toplevel(master)
        self.win.configure(bg=_BG)
        self.win.minsize(380, 300)
        self.win.geometry("460x340")
        _apply_window_branding(self.win, title=f"{APP_NAME} — Доступно обновление {info.tag}")
        self._logo = _load_logo_photo(self.win)

        outer = tk.Frame(self.win, bg=_BG)
        outer.pack(fill="both", expand=True, padx=16, pady=14)

        hdr = tk.Frame(outer, bg=_BG)
        hdr.pack(fill="x", pady=(0, 10))
        if self._logo is not None:
            tk.Label(hdr, image=self._logo, bg=_BG).pack(side="left", padx=(0, 12))
        col = tk.Frame(hdr, bg=_BG)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(
            col,
            text=f"Доступна новая версия {info.tag}",
            bg=_BG, fg="#F8FAFC", font=("Segoe UI", 12, "bold"), anchor="w",
        ).pack(fill="x")
        tk.Label(
            col,
            text=f"Текущая версия: v{__version__}",
            bg=_BG, fg=_ACCENT_HOVER, font=("Segoe UI", 9), anchor="w",
        ).pack(fill="x")

        card = tk.Frame(outer, bg=_CARD_BG, highlightbackground=_CARD_BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=(0, 12))
        tk.Label(
            card,
            text=info.notes_summary,
            bg=_CARD_BG, fg="#CBD5E1", justify="left", anchor="nw", wraplength=400,
            font=("Segoe UI", 9),
        ).pack(fill="both", expand=True, padx=12, pady=10)

        footer = _WrapFrame(outer, bg=_BG)
        footer.pack(fill="x")
        footer.add_widget(
            _make_btn(footer, "Открыть релиз", lambda: webbrowser.open(info.html_url), primary=True)
        )
        if info.download_url and info.download_url != info.html_url:
            footer.add_widget(
                _make_btn(footer, "Скачать FreeTG.exe", lambda: webbrowser.open(info.download_url))
            )
        footer.add_widget(_make_btn(footer, "Пропустить версию", self._handle_skip))
        footer.add_widget(_make_btn(footer, "Позже", self.win.destroy))

    def _handle_skip(self) -> None:
        if self._on_skip is not None:
            self._on_skip(self._info.tag)
        self.win.destroy()


class SettingsDialog:
    """Minimalist dark responsive Settings dialog using pure tkinter."""

    _BYPASS_ITEMS: List[Tuple[str, str]] = [
        ("auto", "Автоподбор (443 → Port 80 → TLS → zapret2)"),
        ("port80", "CF Port 80 (без TLS и без драйверов)"),
        ("windivert", "Встроенный zapret2 (winws2 + Lua)"),
        ("tls_frag", "Фрагментация TLS ClientHello (порт 443)"),
        ("direct", "Прямой / Роутер или внешний zapret (443)"),
    ]
    _PROFILE_ITEMS: List[Tuple[str, str]] = [
        ("auto", "Авто (перебор стратегий)"),
        ("z2_md5_disorder", "Профиль 1: md5 + multidisorder"),
        ("z2_autottl_fakedsplit", "Профиль 2: autottl + fakedsplit"),
        ("z2_disorder_only", "Профиль 3: только multidisorder (роутер/NAT)"),
    ]
    _MODE_ITEMS: List[Tuple[str, str]] = [
        ("auto", "Авто (V1 / V2)"),
        ("v1", "V1 — WebSocket стриминг"),
        ("v2", "V2 — Карусельный синк"),
    ]

    def __init__(
        self,
        master: tk.Misc,
        cfg: Dict[str, Any],
        controller: ProxyController,
        on_applied: Callable[[Dict[str, Any], bool], None],
        *,
        on_toggle_server: Optional[Callable[[], None]] = None,
        on_full_exit: Optional[Callable[[], None]] = None,
        on_open_guide: Optional[Callable[[], None]] = None,
        available_update: Optional[UpdateInfo] = None,
        on_open_update: Optional[Callable[[UpdateInfo], None]] = None,
        on_update_found: Optional[Callable[[UpdateInfo], None]] = None,
    ) -> None:
        self._cfg = deepcopy(cfg)
        self._controller = controller
        self._on_applied = on_applied
        self._on_toggle_server = on_toggle_server
        self._on_full_exit = on_full_exit
        self._on_open_guide = on_open_guide
        self._available_update = available_update
        self._on_open_update = on_open_update
        self._on_update_found = on_update_found
        self._testing = False
        self._checking_updates = False
        self._adv_open = False

        self._bypass_items = list(self._BYPASS_ITEMS)
        if has_bundled_engine("zapret1"):
            self._bypass_items.insert(
                3, ("windivert1", "Встроенный zapret1 (winws.exe — для теста A/B)")
            )

        self.win = tk.Toplevel(master)
        self.win.configure(bg=_BG)
        self.win.minsize(380, 440)
        self.win.geometry("510x580")
        _apply_window_branding(self.win, title=f"{APP_NAME} — Настройки")
        self._logo = _load_logo_photo(self.win)

        outer = tk.Frame(self.win, bg=_BG)
        outer.pack(fill="both", expand=True, padx=16, pady=12)

        # Header + Status
        hdr = tk.Frame(outer, bg=_BG)
        hdr.pack(fill="x", pady=(0, 8))
        if self._logo is not None:
            tk.Label(hdr, image=self._logo, bg=_BG).pack(side="left", padx=(0, 10))
        hdr_col = tk.Frame(hdr, bg=_BG)
        hdr_col.pack(side="left", fill="x", expand=True)
        tk.Label(
            hdr_col, text=f"{APP_NAME} v{__version__}", bg=_BG, fg="#F8FAFC",
            font=("Segoe UI", 13, "bold"), anchor="w",
        ).pack(fill="x")
        self._status_lbl = tk.Label(
            hdr_col, text="", bg=_BG, fg=_ACCENT_HOVER, font=("Segoe UI", 9), anchor="w",
            wraplength=390, justify="left",
        )
        self._status_lbl.pack(fill="x")

        # Update banner (hidden unless a newer GitHub release is available)
        self._upd_banner = tk.Frame(
            outer, bg="#064E3B", highlightbackground=_ACCENT, highlightthickness=1
        )
        self._upd_banner_lbl = tk.Label(
            self._upd_banner, text="", bg="#064E3B", fg="#ECFDF5", font=("Segoe UI", 9, "bold"), anchor="w"
        )
        self._upd_banner_lbl.pack(side="left", fill="x", expand=True, padx=(10, 6), pady=6)
        _make_btn(
            self._upd_banner, "Подробнее", self._open_update_banner, primary=True
        ).pack(side="right", padx=6, pady=4)
        if self._available_update is not None:
            self._show_update_banner(self._available_update)

        # Scroll body
        self._scroll = _ScrollableFrame(outer, bg=_BG)
        self._scroll.pack(fill="both", expand=True)
        body = self._scroll.inner

        # Card 1: MTProto
        c1 = self._make_card(body, "Подключение MTProto")
        self._lbl(c1, "Локальный адрес и порт:")
        addr_row = tk.Frame(c1, bg=_CARD_BG)
        addr_row.pack(fill="x", pady=(2, 8))
        self.host_var = tk.StringVar(value=str(self._cfg.get("host", "127.0.0.1")))
        self.port_var = tk.StringVar(value=str(self._cfg.get("port", 1080)))
        self._entry(addr_row, self.host_var).pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 6))
        tk.Spinbox(
            addr_row, from_=1, to=65535, textvariable=self.port_var, width=8,
            bg=_INPUT_BG, fg="#F8FAFC", buttonbackground=_BTN_BG, relief="flat",
            highlightthickness=1, highlightbackground=_INPUT_BORDER, font=("Segoe UI", 9),
        ).pack(side="right", ipady=4)

        self._lbl(c1, "Ключ доступа (Secret):")
        self.secret_var = tk.StringVar(value=str(self._cfg.get("secret", DEFAULT_CONFIG["secret"])))
        self._entry(c1, self.secret_var).pack(fill="x", ipady=4, pady=(2, 8))

        mt_btns = _WrapFrame(c1, bg=_CARD_BG)
        mt_btns.pack(fill="x")
        mt_btns.add_widget(
            _make_btn(mt_btns, "Открыть в Telegram", lambda: _open_tg_link(self._current_preview_config(), root=self.win))
        )
        mt_btns.add_widget(_make_btn(mt_btns, "Обновить ключ", lambda: self.secret_var.set(os.urandom(16).hex())))

        # Card 2: Cloudflare & Bypass
        c2 = self._make_card(body, "Cloudflare и обход ТСПУ")
        self._lbl(c2, "Свой Worker (опционально — пустое поле = публичный пул CF):")
        self.domain_var = tk.StringVar(value=str(self._cfg.get("worker_domain", "")))
        self._entry(c2, self.domain_var).pack(fill="x", ipady=4, pady=(2, 6))

        dom_btns = _WrapFrame(c2, bg=_CARD_BG)
        dom_btns.pack(fill="x", pady=(0, 8))
        self.test_btn = _make_btn(dom_btns, "Тест соединения", self._run_connectivity_test)
        dom_btns.add_widget(self.test_btn)
        dom_btns.add_widget(_make_btn(dom_btns, "Публичный пул (Авто)", lambda: self.domain_var.set("")))

        self._test_result_lbl = tk.Label(
            c2, text="", bg=_CARD_BG, fg=_MUTED, font=("Segoe UI", 9), anchor="w", justify="left", wraplength=420
        )

        self._lbl(c2, "Способ обхода:")
        self._bypass_combo = self._make_combo(c2, self._bypass_items, str(self._cfg.get("bypass_mode", "auto")).lower())
        self._bypass_combo.pack(fill="x", pady=(2, 8))

        self._lbl(c2, "Профиль zapret2 (Lua):")
        self._profile_combo = self._make_combo(c2, self._PROFILE_ITEMS, str(self._cfg.get("desync_profile", "auto")).lower())
        self._profile_combo.pack(fill="x", pady=(2, 8))

        self.auto_tune_var = tk.BooleanVar(value=bool(self._cfg.get("auto_tune", True)))
        self.autostart_var = tk.BooleanVar(value=bool(self._cfg.get("autostart", False)))
        self._check(c2, "Автоподбор обхода (443 → Port 80 → TLS → zapret2)", self.auto_tune_var).pack(anchor="w", pady=2)
        self._check(c2, "Запускать вместе с Windows", self.autostart_var).pack(anchor="w", pady=2)

        self._adv_toggle_btn = tk.Button(
            c2, text="Дополнительно ▸", command=self._toggle_advanced,
            bg=_CARD_BG, fg=_MUTED, activebackground=_CARD_BG, activeforeground=_ACCENT_HOVER,
            relief="flat", bd=0, anchor="w", cursor="hand2", font=("Segoe UI", 9, "bold"),
        )
        self._adv_toggle_btn.pack(anchor="w", pady=(6, 0))

        self._adv_frame = tk.Frame(c2, bg=_CARD_BG)
        self._lbl(self._adv_frame, "Режим работы (для своего Worker):")
        self._mode_combo = self._make_combo(self._adv_frame, self._MODE_ITEMS, str(self._cfg.get("mode", "auto")).lower())
        self._mode_combo.pack(fill="x", pady=(2, 6))

        pool_row = tk.Frame(self._adv_frame, bg=_CARD_BG)
        pool_row.pack(fill="x", pady=(0, 6))
        tk.Label(pool_row, text="Пул сокетов на DC:", bg=_CARD_BG, fg=_MUTED, font=("Segoe UI", 9)).pack(side="left")
        self.pool_var = tk.StringVar(value=str(self._cfg.get("pool_size", 3)))
        tk.Spinbox(
            pool_row, from_=0, to=10, textvariable=self.pool_var, width=6,
            bg=_INPUT_BG, fg="#F8FAFC", buttonbackground=_BTN_BG, relief="flat",
            highlightthickness=1, highlightbackground=_INPUT_BORDER, font=("Segoe UI", 9),
        ).pack(side="right", ipady=2)

        self.frag_var = tk.BooleanVar(value=bool(self._cfg.get("frag_tls", False)))
        self.builtin_desync_var = tk.BooleanVar(value=bool(self._cfg.get("builtin_desync", True)))
        self.check_updates_var = tk.BooleanVar(value=bool(self._cfg.get("check_updates", True)))
        self.verbose_var = tk.BooleanVar(value=bool(self._cfg.get("verbose", False)))
        self._check(self._adv_frame, "Фрагментация TLS ClientHello", self.frag_var).pack(anchor="w", pady=2)
        self._check(self._adv_frame, "Встроенный zapret2 (если 443 и Port 80 закрыты)", self.builtin_desync_var).pack(anchor="w", pady=2)
        self._check(self._adv_frame, "Проверять обновления на GitHub", self.check_updates_var).pack(anchor="w", pady=2)

        log_row = _WrapFrame(self._adv_frame, bg=_CARD_BG)
        log_row.pack(fill="x", pady=(4, 0))
        log_row.add_widget(self._check(log_row, "Подробный лог", self.verbose_var))
        self.log_mb_var = tk.StringVar(value=str(self._cfg.get("log_max_mb", 5)))
        mb_wrap = tk.Frame(log_row, bg=_CARD_BG)
        tk.Spinbox(
            mb_wrap, from_=1, to=100, textvariable=self.log_mb_var, width=5,
            bg=_INPUT_BG, fg="#F8FAFC", buttonbackground=_BTN_BG, relief="flat",
            highlightthickness=1, highlightbackground=_INPUT_BORDER, font=("Segoe UI", 9),
        ).pack(side="left", ipady=2)
        tk.Label(mb_wrap, text=" МБ", bg=_CARD_BG, fg=_MUTED, font=("Segoe UI", 9)).pack(side="left")
        log_row.add_widget(mb_wrap)
        log_row.add_widget(_make_btn(log_row, "Открыть логи", self._open_logs))
        self.check_upd_btn = _make_btn(log_row, "Проверить обновления", self._handle_check_updates)
        log_row.add_widget(self.check_upd_btn)

        # Responsive footer
        footer = _WrapFrame(outer, bg=_BG)
        footer.pack(fill="x", pady=(10, 0))
        self.toggle_srv_btn = _make_btn(footer, "Остановить сервер", self._handle_toggle_server)
        footer.add_widget(self.toggle_srv_btn)
        footer.add_widget(_make_btn(footer, "Инструкция", self._open_guide))
        footer.add_widget(_make_btn(footer, "Выгрузить", self._handle_full_exit, danger=True))
        footer.add_widget(_make_btn(footer, "Отмена", self.win.destroy))
        footer.add_widget(_make_btn(footer, "Сохранить", self._on_save, primary=True))

        self._refresh_status()
        self._schedule_refresh()

    @staticmethod
    def _make_card(parent: tk.Misc, title: str) -> tk.Frame:
        wrap = tk.Frame(parent, bg=_BG)
        wrap.pack(fill="x", pady=(0, 10))
        tk.Label(wrap, text=title, bg=_BG, fg=_ACCENT_HOVER, font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", pady=(0, 3))
        card = tk.Frame(wrap, bg=_CARD_BG, highlightbackground=_CARD_BORDER, highlightthickness=1)
        card.pack(fill="x")
        inner = tk.Frame(card, bg=_CARD_BG)
        inner.pack(fill="x", padx=12, pady=10)
        return inner

    @staticmethod
    def _lbl(parent: tk.Misc, text: str) -> None:
        tk.Label(parent, text=text, bg=_CARD_BG, fg=_MUTED, font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x")

    @staticmethod
    def _entry(parent: tk.Misc, var: tk.StringVar) -> tk.Entry:
        return tk.Entry(
            parent, textvariable=var, bg=_INPUT_BG, fg="#F8FAFC", insertbackground="#F8FAFC",
            relief="flat", highlightthickness=1, highlightbackground=_INPUT_BORDER, font=("Segoe UI", 9),
        )

    @staticmethod
    def _check(parent: tk.Misc, text: str, var: tk.BooleanVar) -> tk.Checkbutton:
        return tk.Checkbutton(
            parent, text=text, variable=var, bg=parent.cget("bg"), fg=_TEXT,
            selectcolor=_INPUT_BG, activebackground=parent.cget("bg"), activeforeground=_TEXT,
            font=("Segoe UI", 9),
        )

    @staticmethod
    def _make_combo(parent: tk.Misc, items: List[Tuple[str, str]], cur_val: str) -> ttk.Combobox:
        labels = [lbl for _, lbl in items]
        cb = ttk.Combobox(parent, values=labels, state="readonly", style="Dark.TCombobox", font=("Segoe UI", 9))
        idx = next((i for i, (k, _) in enumerate(items) if k == cur_val), 0)
        cb.current(idx)
        cb._data_keys = [k for k, _ in items]  # type: ignore[attr-defined]
        return cb

    @staticmethod
    def _combo_value(cb: ttk.Combobox) -> str:
        idx = cb.current()
        keys = getattr(cb, "_data_keys", [])
        if 0 <= idx < len(keys):
            return keys[idx]
        return keys[0] if keys else "auto"

    def _toggle_advanced(self) -> None:
        self._adv_open = not self._adv_open
        if self._adv_open:
            self._adv_frame.pack(fill="x", pady=(6, 0))
            self._adv_toggle_btn.configure(text="Дополнительно ▾")
        else:
            self._adv_frame.pack_forget()
            self._adv_toggle_btn.configure(text="Дополнительно ▸")

    def _schedule_refresh(self) -> None:
        if self.win.winfo_exists():
            self._refresh_status()
            self.win.after(2000, self._schedule_refresh)

    def _refresh_status(self) -> None:
        if not self.win.winfo_exists():
            return
        st = self._controller.get_status_snapshot()
        if st.get("running"):
            self._status_lbl.configure(
                fg=_ACCENT_HOVER,
                text=(
                    f"● Работает ({st['mode']}, {st.get('desync', 'прямой')}) • "
                    f"Подкл: {st['active_conns']} • ↑ {st['tx']} / ↓ {st['rx']}"
                ),
            )
            self.toggle_srv_btn.configure(text="Остановить сервер")
        else:
            err = st.get("err") or "остановлен"
            self._status_lbl.configure(fg="#F87171", text=f"● Остановлен ({err})")
            self.toggle_srv_btn.configure(text="Запустить сервер")

    def _handle_toggle_server(self) -> None:
        if self._on_toggle_server is not None:
            self.toggle_srv_btn.configure(state="disabled")
            self._on_toggle_server()
            self.win.after(800, lambda: self.win.winfo_exists() and (self.toggle_srv_btn.configure(state="normal"), self._refresh_status()))
        else:
            if self._controller.is_running():
                self._controller.stop(timeout=4.0, stop_desync=True)
            else:
                self._controller.start(self._cfg)
            self._refresh_status()

    def _open_guide(self) -> None:
        if self._on_open_guide is not None:
            self._on_open_guide()
        else:
            FirstRunDialog(self.win, self._current_preview_config())

    def _handle_full_exit(self) -> None:
        self.win.destroy()
        if self._on_full_exit is not None:
            self._on_full_exit()

    def _show_update_banner(self, info: UpdateInfo) -> None:
        self._available_update = info
        self._upd_banner_lbl.configure(text=f"★ Доступно обновление FreeTG {info.tag}")
        self._upd_banner.pack(fill="x", pady=(0, 8), before=self._scroll)

    def _open_update_banner(self) -> None:
        if self._available_update is None:
            return
        if self._on_open_update is not None:
            self._on_open_update(self._available_update)
        else:
            UpdateDialog(self.win, self._available_update)

    def _handle_check_updates(self) -> None:
        if self._checking_updates:
            return
        self._checking_updates = True
        self.check_upd_btn.configure(state="disabled", text="Проверка...")

        def _worker() -> None:
            info, err = check_for_update_sync(__version__)
            if self.win.winfo_exists():
                self.win.after(0, lambda: self._on_manual_update_result(info, err))

        threading.Thread(target=_worker, daemon=True, name="freetg-manual-upd").start()

    def _on_manual_update_result(self, info: Optional[UpdateInfo], err: Optional[str]) -> None:
        self._checking_updates = False
        if not self.win.winfo_exists():
            return
        self.check_upd_btn.configure(state="normal", text="Проверить обновления")
        if err:
            messagebox.showwarning(APP_NAME, f"Не удалось проверить обновления:\n{err}", parent=self.win)
            return
        if info is None:
            messagebox.showinfo(APP_NAME, f"Установлена актуальная версия (v{__version__}).", parent=self.win)
            return
        self._show_update_banner(info)
        if self._on_update_found is not None:
            self._on_update_found(info)
        if self._on_open_update is not None:
            self._on_open_update(info)
        else:
            UpdateDialog(self.win, info)

    def _open_logs(self) -> None:
        if LOG_FILE.exists():
            try:
                os.startfile(str(LOG_FILE))
                return
            except Exception as exc:
                messagebox.showerror(APP_NAME, f"Не удалось открыть лог:\n{exc}", parent=self.win)
        else:
            messagebox.showinfo(APP_NAME, "Файл логов ещё не создан.", parent=self.win)

    def _current_preview_config(self) -> Dict[str, Any]:
        c = dict(self._cfg)
        c["host"] = self.host_var.get().strip() or "127.0.0.1"
        try:
            c["port"] = int(self.port_var.get())
        except ValueError:
            c["port"] = int(self._cfg.get("port", 1080))
        c["secret"] = self.secret_var.get().strip() or DEFAULT_CONFIG["secret"]
        c["worker_domain"] = sanitize_worker_domain(self.domain_var.get())
        return c

    def _run_connectivity_test(self) -> None:
        if self._testing:
            return
        raw_domain = self.domain_var.get().strip()
        domain = sanitize_worker_domain(raw_domain)
        if raw_domain and not domain:
            messagebox.showwarning(
                APP_NAME,
                "Укажите корректный домен Cloudflare Worker (или оставьте пустым для авто-пула).",
                parent=self.win,
            )
            return
        self._testing = True
        self.test_btn.configure(state="disabled", text="Проверка...")
        self._test_result_lbl.configure(fg=_MUTED, text="Проверка >22 КБ через Cloudflare...")
        self._test_result_lbl.pack(fill="x", pady=(0, 8))

        bmode = self._combo_value(self._bypass_combo)
        dprof = self._combo_value(self._profile_combo)
        mode = self._combo_value(self._mode_combo)
        frag = bool(self.frag_var.get())
        b_desync = bool(self.builtin_desync_var.get())
        a_tune = bool(self.auto_tune_var.get())

        def _worker() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                msg, eff_frag = loop.run_until_complete(
                    test_worker_connectivity_async(
                        domain,
                        mode,
                        frag,
                        bypass_mode=bmode,
                        desync_profile=dprof,
                        builtin_desync=b_desync,
                        auto_tune=a_tune,
                        controller=self._controller,
                    )
                )
            except Exception as exc:
                msg, eff_frag = f"✗ Ошибка: {exc}", frag
            finally:
                loop.close()
            if self.win.winfo_exists():
                self.win.after(0, lambda: self._on_test_finished(msg, eff_frag))

        threading.Thread(target=_worker, daemon=True, name="freetg-test").start()

    def _on_test_finished(self, message: str, effective_frag: bool) -> None:
        self._testing = False
        if not self.win.winfo_exists():
            return
        self.test_btn.configure(state="normal", text="Тест соединения")
        if effective_frag and not self.frag_var.get():
            self.frag_var.set(True)
        color = _ACCENT_HOVER if message.startswith("✓") else ("#FBBF24" if message.startswith("~") else "#F87171")
        self._test_result_lbl.configure(fg=color, text=message)
        self._test_result_lbl.pack(fill="x", pady=(0, 8))

    def _on_save(self) -> None:
        host = self.host_var.get().strip()
        try:
            socket.inet_aton(host)
        except OSError:
            messagebox.showerror(APP_NAME, "Некорректный IPv4-адрес для локального прокси.", parent=self.win)
            return

        try:
            port = int(self.port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_NAME, "Порт должен быть от 1 до 65535.", parent=self.win)
            return

        try:
            secret = normalize_secret(self.secret_var.get()).hex()
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.win)
            return

        raw_domain = self.domain_var.get().strip()
        worker_domain = sanitize_worker_domain(raw_domain)
        if raw_domain and not worker_domain:
            messagebox.showwarning(
                APP_NAME,
                "Укажите корректный домен Cloudflare Worker или очистите поле для публичного пула.",
                parent=self.win,
            )
            return

        bypass_mode = self._combo_value(self._bypass_combo)
        if bypass_mode in ("windivert", "windivert1") and desync_manager.is_external_winws_running():
            if not messagebox.askyesno(
                APP_NAME,
                "В системе уже запущен внешний zapret/winws.\n"
                "Встроенный модуль автоматически уступит ему (иначе два WinDivert сломают друг друга).\n\n"
                "Сохранить настройку всё равно?",
                parent=self.win,
            ):
                return

        try:
            pool_size = max(0, min(10, int(self.pool_var.get())))
        except ValueError:
            pool_size = int(self._cfg.get("pool_size", 3))
        try:
            log_max_mb = max(0.5, min(100.0, round(float(self.log_mb_var.get()), 2)))
        except ValueError:
            log_max_mb = float(self._cfg.get("log_max_mb", 5))

        new_cfg: Dict[str, Any] = {
            "host": host,
            "port": port,
            "secret": secret,
            "worker_domain": worker_domain,
            "mode": self._combo_value(self._mode_combo),
            "bypass_mode": bypass_mode,
            "desync_profile": self._combo_value(self._profile_combo),
            "pool_size": pool_size,
            "frag_tls": bool(self.frag_var.get()),
            "builtin_desync": bool(self.builtin_desync_var.get()),
            "auto_tune": bool(self.auto_tune_var.get()),
            "verbose": bool(self.verbose_var.get()),
            "log_max_mb": log_max_mb,
            "autostart": bool(self.autostart_var.get()),
            "check_updates": bool(self.check_updates_var.get()),
            "skipped_update_tag": str(self._cfg.get("skipped_update_tag", "")),
        }

        if bool(new_cfg["autostart"]) != bool(self._cfg.get("autostart", False)) or new_cfg["autostart"]:
            ok, err = set_autostart_enabled(bool(new_cfg["autostart"]))
            if not ok:
                messagebox.showwarning(APP_NAME, f"Не удалось обновить автозапуск в реестре:\n{err}", parent=self.win)

        restart_needed = any(new_cfg.get(k) != self._cfg.get(k) for k in _PROXY_RESTART_KEYS)
        save_config(new_cfg)
        set_verbose_logging(bool(new_cfg["verbose"]))
        self._on_applied(new_cfg, restart_needed)
        self.win.destroy()


class FreeTGTrayApplication:
    """Lightweight tkinter + native Win32 Tray manager wrapping ProxyController."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        enable_high_dpi()
        self.cfg = cfg
        self.controller = ProxyController()
        self._ui_queue: queue.SimpleQueue[Callable[[], None]] = queue.SimpleQueue()
        self._exiting = False

        self.root = tk.Tk()
        self.root.withdraw()
        self.root.configure(bg=_BG)
        _style_ttk(self.root)

        self._settings_dlg: Optional[SettingsDialog] = None
        self._first_run_dlg: Optional[FirstRunDialog] = None
        self._update_dlg: Optional[UpdateDialog] = None
        self._available_update: Optional[UpdateInfo] = None

        ico_path = resource_path("icon.ico")
        self.tray = Win32TrayIcon(
            ico_path if ico_path.exists() else None,
            self._tooltip_text(),
            on_activate=lambda: self._post(self._open_settings),
            menu_builder=self._build_tray_menu,
        )

    def _post(self, fn: Callable[[], None]) -> None:
        self._ui_queue.put(fn)

    def _pump_ui_queue(self) -> None:
        if self._exiting:
            return
        while True:
            try:
                fn = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception:
                log.exception("UI callback failed")
        if not self._exiting:
            self.root.after(100, self._pump_ui_queue)

    def _tooltip_text(self) -> str:
        host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
        port = int(self.cfg.get("port", 1080))
        domain = self.cfg.get("worker_domain", "") or "публичный пул CF"
        state = "работает" if self.controller.is_running() else "остановлен"
        return f"{APP_NAME} v{__version__} — {state}\n{host}:{port} ({domain})"

    def _update_tooltip(self) -> None:
        self.tray.set_tooltip(self._tooltip_text())

    def _build_tray_menu(self):
        host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
        port = int(self.cfg.get("port", 1080))
        running = self.controller.is_running()
        items = [
            (f"Открыть в Telegram ({host}:{port})", lambda: self._post(lambda: _open_tg_link(self.cfg, self.tray, self.root)), True),
            ("Скопировать ссылку", lambda: self._post(self._on_copy_link), False),
        ]
        if self._available_update is not None:
            upd = self._available_update
            items.append((f"★ Обновление доступно ({upd.tag})...", lambda u=upd: self._post(lambda: self._open_update_dialog(u)), False))
        items.extend([
            (None, None, False),
            ("Остановить сервер" if running else "Запустить сервер", lambda: self._post(self._on_toggle_server_clicked), False),
            ("Перезапустить прокси", lambda: self._post(self._on_restart_clicked), False),
            ("Настройки...", lambda: self._post(self._open_settings), False),
            ("Инструкция подключения", lambda: self._post(lambda: self._open_first_run(force=True)), False),
            ("Проверить обновления", lambda: self._post(lambda: self._start_update_check(manual=True)), False),
            ("Открыть логи", lambda: self._post(self._on_open_logs), False),
            (None, None, False),
            ("Выход (выгрузить полностью)", lambda: self._post(self._on_exit), False),
        ])
        return items

    def _on_copy_link(self) -> None:
        url = tg_proxy_url(self.cfg)
        self.root.clipboard_clear()
        self.root.clipboard_append(url)
        self.root.update()
        self.tray.show_notification(APP_NAME, f"Ссылка скопирована:\n{url}")

    def _on_open_logs(self) -> None:
        if LOG_FILE.exists():
            try:
                os.startfile(str(LOG_FILE))
                return
            except Exception as exc:
                show_native_info(f"Не удалось открыть лог:\n{exc}", f"{APP_NAME} — Ошибка", error=True)
        else:
            show_native_info("Файл логов ещё не создан.", APP_NAME)

    def _on_toggle_server_clicked(self) -> None:
        if self.controller.is_running():
            threading.Thread(target=self._stop_server_background, daemon=True, name="proxy-stop").start()
        else:
            threading.Thread(target=self._start_server_background, daemon=True, name="proxy-start").start()

    def _stop_server_background(self) -> None:
        log.info("Stopping server by user request")
        self.controller.stop(timeout=4.0, stop_desync=True)
        self._post(lambda: self._on_restart_finished(False, "Сервер полностью остановлен"))

    def _start_server_background(self) -> None:
        ok, err = self.controller.start(
            self.cfg,
            on_error=lambda msg: self._post(lambda: show_native_info(msg, f"{APP_NAME} — Ошибка", error=True)),
        )
        self._post(lambda: self._on_restart_finished(ok, err or ""))

    def _on_restart_clicked(self) -> None:
        threading.Thread(target=self._restart_background, daemon=True, name="proxy-restart").start()

    def _restart_background(self) -> None:
        ok, err = self.controller.restart(
            self.cfg,
            on_error=lambda msg: self._post(lambda: show_native_info(msg, f"{APP_NAME} — Ошибка", error=True)),
        )
        self._post(lambda: self._on_restart_finished(ok, err or ""))

    def _on_restart_finished(self, ok: bool, err: str) -> None:
        self._update_tooltip()
        if ok:
            self.controller.run_auto_tune_async(
                self.cfg,
                on_notice=lambda new_cfg, msg: self._post(lambda: self._on_autotune_notice(new_cfg, msg)),
            )
            self.controller.start_zapret_watcher(
                self.cfg,
                on_notice=lambda new_cfg, msg: self._post(lambda: self._on_autotune_notice(new_cfg, msg)),
            )
            host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
            port = int(self.cfg.get("port", 1080))
            self.tray.show_notification(APP_NAME, f"Прокси запущен на {host}:{port}")
        elif err == "Сервер полностью остановлен":
            self.tray.show_notification(APP_NAME, "Сервер и встроенный zapret2 остановлены.")

    def _on_autotune_notice(self, new_cfg: object, msg: str) -> None:
        if isinstance(new_cfg, dict):
            self.cfg = new_cfg
            self.controller.update_watch_config(self.cfg)
        self._update_tooltip()
        self.tray.show_notification(APP_NAME, msg)

    def _open_settings(self) -> None:
        if self._settings_dlg is not None and self._settings_dlg.win.winfo_exists():
            self._settings_dlg.win.deiconify()
            self._settings_dlg.win.lift()
            self._settings_dlg.win.focus_force()
            return
        self.cfg["autostart"] = load_config().get("autostart", self.cfg.get("autostart", False))
        self._settings_dlg = SettingsDialog(
            self.root,
            self.cfg,
            self.controller,
            self._on_settings_applied,
            on_toggle_server=self._on_toggle_server_clicked,
            on_full_exit=self._on_exit,
            on_open_guide=lambda: self._open_first_run(force=True),
            available_update=self._available_update,
            on_open_update=self._open_update_dialog,
            on_update_found=self._set_available_update,
        )
        self._settings_dlg.win.lift()

    def _set_available_update(self, info: UpdateInfo) -> None:
        self._available_update = info

    def _skip_update_version(self, tag: str) -> None:
        self.cfg["skipped_update_tag"] = tag
        save_config(self.cfg)
        self._available_update = None

    def _open_update_dialog(self, info: UpdateInfo) -> None:
        if self._update_dlg is not None and self._update_dlg.win.winfo_exists():
            self._update_dlg.win.deiconify()
            self._update_dlg.win.lift()
            self._update_dlg.win.focus_force()
            return
        parent = (
            self._settings_dlg.win
            if (self._settings_dlg is not None and self._settings_dlg.win.winfo_exists())
            else self.root
        )
        self._update_dlg = UpdateDialog(parent, info, on_skip=self._skip_update_version)
        self._update_dlg.win.lift()

    def _start_update_check(self, *, manual: bool = False) -> None:
        def _worker() -> None:
            info, err = check_for_update_sync(__version__)
            self._post(lambda: self._on_update_checked(info, err, manual=manual))

        threading.Thread(target=_worker, daemon=True, name="freetg-update-check").start()

    def _on_update_checked(
        self, info: Optional[UpdateInfo], err: Optional[str], *, manual: bool
    ) -> None:
        if err:
            if manual:
                show_native_info(f"Не удалось проверить обновления:\n{err}", APP_NAME, error=True)
            return
        if info is None:
            if manual:
                show_native_info(f"Установлена актуальная версия FreeTG (v{__version__}).", APP_NAME)
            return
        if not manual and info.tag == self.cfg.get("skipped_update_tag", ""):
            return
        self._available_update = info
        if self._settings_dlg is not None and self._settings_dlg.win.winfo_exists():
            self._settings_dlg._show_update_banner(info)
        if manual:
            self._open_update_dialog(info)
        else:
            self.tray.show_notification(
                APP_NAME,
                f"Доступно обновление FreeTG {info.tag} (установлена v{__version__}). Откройте «Обновление» в меню трея.",
            )

    def _on_settings_applied(self, new_cfg: Dict[str, Any], restart_needed: bool) -> None:
        self.cfg = new_cfg
        self.controller.update_watch_config(self.cfg)
        self._update_tooltip()
        if restart_needed:
            self._on_restart_clicked()
        else:
            self.tray.show_notification(APP_NAME, "Настройки сохранены.")

    def _open_first_run(self, *, force: bool = False) -> None:
        ensure_dirs()
        if not force and FIRST_RUN_MARKER.exists():
            return
        if self._first_run_dlg is not None and self._first_run_dlg.win.winfo_exists():
            self._first_run_dlg.win.deiconify()
            self._first_run_dlg.win.lift()
            self._first_run_dlg.win.focus_force()
            return
        dlg = FirstRunDialog(self.root, self.cfg)
        self._first_run_dlg = dlg
        self.root.wait_window(dlg.win)
        if dlg.accepted and dlg.dont_show_again:
            try:
                FIRST_RUN_MARKER.touch()
            except OSError:
                pass

    def _on_exit(self) -> None:
        if self._exiting:
            return
        self._exiting = True
        log.info("Exiting FreeTG tray application")
        self.tray.stop()
        for dlg in (self._settings_dlg, self._first_run_dlg, self._update_dlg):
            if dlg is not None:
                try:
                    if dlg.win.winfo_exists():
                        dlg.win.destroy()
                except Exception:
                    pass
        threading.Thread(target=lambda: (time.sleep(2.0), os._exit(0)), daemon=True, name="force-exit").start()
        self.controller.stop(timeout=2.5, stop_desync=True)
        desync_manager.stop()
        release_single_instance_mutex()
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass

    def run(self) -> int:
        self.tray.start()
        ok, err = self.controller.start(
            self.cfg,
            on_error=lambda msg: self._post(lambda: show_native_info(msg, f"{APP_NAME} — Ошибка", error=True)),
        )
        self._update_tooltip()

        if ok:
            self.controller.run_auto_tune_async(
                self.cfg,
                on_notice=lambda new_cfg, msg: self._post(lambda: self._on_autotune_notice(new_cfg, msg)),
            )
            self.controller.start_zapret_watcher(
                self.cfg,
                on_notice=lambda new_cfg, msg: self._post(lambda: self._on_autotune_notice(new_cfg, msg)),
            )
            if not FIRST_RUN_MARKER.exists():
                self.root.after(250, lambda: self._open_first_run(force=True))
            else:
                host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
                port = int(self.cfg.get("port", 1080))
                self.tray.show_notification(APP_NAME, f"Прокси запущен: {host}:{port}")
        elif err:
            self.root.after(200, self._open_settings)

        if self.cfg.get("check_updates", True):
            self.root.after(4000, lambda: self._start_update_check(manual=False))

        self.root.after(100, self._pump_ui_queue)
        self.root.mainloop()
        self.tray.stop()
        self.controller.stop(timeout=3.0)
        desync_manager.stop()
        return 0


def run_tray_main() -> int:
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FreeTG.Proxy.App")
        except Exception:
            pass

    if not acquire_single_instance_mutex():
        show_native_info("Приложение FreeTG уже запущено, проверьте системный трей.", APP_NAME)
        return 0

    try:
        cfg = load_config()
        setup_logging(
            bool(cfg.get("verbose", False)),
            log_max_mb=float(cfg.get("log_max_mb", 5)),
        )
        save_config(cfg)
        log.info("Starting %s v%s (AES=%s, UI=tkinter)", APP_NAME, __version__, AES_BACKEND_NAME)
        tray_app = FreeTGTrayApplication(cfg)
        return tray_app.run()
    finally:
        release_single_instance_mutex()
