"""PyQt6 System Tray, Settings UI, and First-Run assistant for FreeTG."""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import socket
import struct
import sys
import threading
import time
import webbrowser
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from PyQt6.QtCore import QObject, QPoint, QRect, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QIcon, QPainter, QPainterPath, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLayoutItem,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSystemTrayIcon,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .app_config import (
    APP_NAME,
    CONFIG_FILE,
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
from .desync import desync_manager
from .server import FreeTGProxyServer, _human_bytes

log = logging.getLogger("freetg.tray")

_PROXY_RESTART_KEYS = frozenset({
    "host",
    "port",
    "secret",
    "worker_domain",
    "mode",
    "bypass_mode",
    "pool_size",
    "frag_tls",
    "builtin_desync",
    "auto_tune",
})

_APP_STYLESHEET = """
QDialog, QWidget {
    background-color: #0B1120;
    color: #E2E8F0;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QScrollArea, QScrollArea > QWidget > QWidget {
    background-color: transparent;
    border: none;
}
QGroupBox {
    background-color: #121B2E;
    border: 1px solid #1E2D45;
    border-radius: 10px;
    margin-top: 12px;
    padding: 14px 12px 10px 12px;
    font-weight: 600;
    color: #94A3B8;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    color: #34D399;
    font-size: 12px;
}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #0F172A;
    border: 1px solid #26354D;
    border-radius: 7px;
    padding: 6px 9px;
    min-height: 18px;
    color: #F8FAFC;
    selection-background-color: #10B981;
}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid #10B981;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #0F172A;
    border: 1px solid #26354D;
    selection-background-color: #059669;
    color: #F8FAFC;
}
QCheckBox {
    spacing: 8px;
    color: #E2E8F0;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #3B5275;
    background-color: #0F172A;
}
QCheckBox::indicator:checked {
    background-color: #10B981;
    border: 1px solid #10B981;
}
QPushButton {
    background-color: #182338;
    border: 1px solid #2A3B58;
    border-radius: 7px;
    padding: 6px 14px;
    min-height: 20px;
    color: #E2E8F0;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #22304A;
    border-color: #3B5275;
}
QPushButton:pressed {
    background-color: #131C2E;
}
QPushButton:disabled {
    color: #64748B;
    border-color: #1E293B;
}
QPushButton#primaryBtn {
    background-color: #10B981;
    border: 1px solid #10B981;
    color: #052E16;
    font-weight: 700;
}
QPushButton#primaryBtn:hover {
    background-color: #34D399;
    border-color: #34D399;
}
QPushButton#primaryBtn:pressed {
    background-color: #059669;
}
QPushButton#dangerBtn {
    background-color: #1E151B;
    border: 1px solid #7F1D1D;
    color: #FCA5A5;
}
QPushButton#dangerBtn:hover {
    background-color: #2C1820;
    border-color: #991B1B;
}
QPushButton#linkBtn {
    background-color: transparent;
    border: none;
    color: #94A3B8;
    padding: 4px 2px;
    text-align: left;
    font-weight: 600;
}
QPushButton#linkBtn:hover {
    color: #34D399;
}
QTabWidget::pane {
    border: 1px solid #1E2D45;
    border-radius: 9px;
    background-color: #121B2E;
    padding: 12px;
}
QTabBar::tab {
    background-color: #0F172A;
    border: 1px solid #1E2D45;
    border-bottom: none;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    padding: 7px 14px;
    margin-right: 4px;
    color: #94A3B8;
    font-weight: 600;
}
QTabBar::tab:selected {
    background-color: #10B981;
    border-color: #10B981;
    color: #052E16;
}
QMenu {
    background-color: #121B2E;
    border: 1px solid #26354D;
    padding: 4px;
    color: #E2E8F0;
}
QMenu::item {
    padding: 6px 18px 6px 14px;
    border-radius: 5px;
}
QMenu::item:selected {
    background-color: #10B981;
    color: #052E16;
}
QMenu::separator {
    height: 1px;
    background-color: #1E2D45;
    margin: 4px 8px;
}
"""


class _FlowLayout(QLayout):
    """Responsive wrapping layout so buttons stay cleanly sized at any width."""

    def __init__(self, parent: Optional[QWidget] = None, spacing: int = 8) -> None:
        super().__init__(parent)
        self._items: List[QLayoutItem] = []
        self.setSpacing(spacing)
        self.setContentsMargins(0, 0, 0, 0)

    def __del__(self) -> None:
        item = self.takeAt(0)
        while item is not None:
            item = self.takeAt(0)

    def addItem(self, item: QLayoutItem) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> Optional[QLayoutItem]:
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index: int) -> Optional[QLayoutItem]:
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self) -> Qt.Orientation:
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for item in self._items:
            w = item.widget()
            if w is not None and not w.isVisible():
                continue
            size = size.expandedTo(item.minimumSize())
        left, top, right, bottom = self.getContentsMargins()
        return size + QSize(left + right, top + bottom)

    def _do_layout(self, rect: QRect, test_only: bool) -> int:
        left, top, right, bottom = self.getContentsMargins()
        effective = rect.adjusted(left, top, -right, -bottom)
        x = effective.x()
        y = effective.y()
        line_height = 0
        spacing = max(6, self.spacing())

        for item in self._items:
            w = item.widget()
            if w is not None and not w.isVisible():
                continue
            hint = item.sizeHint().expandedTo(item.minimumSize())
            next_x = x + hint.width() + spacing
            if next_x - spacing > effective.right() and line_height > 0:
                x = effective.x()
                y = y + line_height + spacing
                next_x = x + hint.width() + spacing
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x = next_x
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + bottom


def _make_btn(
    text: str,
    *,
    object_name: Optional[str] = None,
    min_width: int = 0,
    tooltip: Optional[str] = None,
) -> QPushButton:
    btn = QPushButton(text)
    btn.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
    btn.setMinimumHeight(32)
    if min_width > 0:
        btn.setMinimumWidth(min_width)
    if object_name:
        btn.setObjectName(object_name)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn

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


def _show_message(
    parent: Optional[QWidget],
    text: str,
    title: str = APP_NAME,
    *,
    level: str = "info",
) -> None:
    """Display a branded message box using FreeTG's custom icon everywhere."""
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setWindowIcon(load_app_icon())
    box.setIconPixmap(load_logo_pixmap(44))
    box.setStyleSheet(_APP_STYLESHEET)
    box.setText(text)
    ok_btn = box.addButton("ОК", QMessageBox.ButtonRole.AcceptRole)
    if ok_btn is not None:
        ok_btn.setObjectName("primaryBtn")
        ok_btn.setMinimumHeight(30)
    box.exec()


def show_native_info(text: str, title: str = APP_NAME, error: bool = False) -> None:
    try:
        app = QApplication.instance()
        created = False
        if app is None:
            app = QApplication(sys.argv or [APP_NAME])
            app.setWindowIcon(load_app_icon())
            created = True
        _show_message(None, text, title, level="error" if error else "info")
        if created:
            app.quit()
        return
    except Exception:
        pass
    if sys.platform == "win32":
        flags = 0x10 if error else 0x40  # MB_ICONERROR / MB_ICONINFORMATION
        try:
            ctypes.windll.user32.MessageBoxW(None, text, title, flags)
            return
        except Exception:
            pass
    log.info("[%s] %s", title, text)


def _build_fallback_pixmap(size: int = 128) -> QPixmap:
    """Fallback vector icon drawn with Qt if bundled image assets are absent."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    p.setBrush(QColor("#0F172A"))
    p.setPen(QColor("#10B981"))
    margin = max(2, int(size * 0.04))
    radius = int(size * 0.22)
    p.drawRoundedRect(margin, margin, size - 2 * margin, size - 2 * margin, radius, radius)

    # Draw simplified green paper plane
    plane = QPainterPath()
    plane.moveTo(size * 0.20, size * 0.56)
    plane.lineTo(size * 0.80, size * 0.24)
    plane.lineTo(size * 0.56, size * 0.80)
    plane.lineTo(size * 0.44, size * 0.58)
    plane.closeSubpath()
    p.setBrush(QColor("#00E676"))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawPath(plane)
    p.end()
    return pm


def load_logo_pixmap(size: int = 64) -> QPixmap:
    for rel in ("assets/logo.png", "icon.ico"):
        path = resource_path(rel)
        if path.exists():
            pm = QPixmap(str(path))
            if not pm.isNull():
                return pm.scaled(
                    size,
                    size,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
    return _build_fallback_pixmap(size)


def load_app_icon() -> QIcon:
    for rel in ("icon.ico", "assets/icon.ico", "assets/logo.png"):
        path = resource_path(rel)
        if path.exists():
            icon = QIcon(str(path))
            if not icon.isNull():
                return icon
    return QIcon(_build_fallback_pixmap(64))


def _format_listen_error(host: str, port: int, exc: Exception) -> str:
    if isinstance(exc, OSError):
        errno = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if errno in (10048, 98, 48):
            return (
                f"Порт {host}:{port} уже занят другим приложением.\n\n"
                "Остановите другой процесс на этом порту (или старый скрипт) и попробуйте другой порт в Настройках."
            )
        if errno in (10013, 13):
            return (
                f"Нет прав на прослушивание {host}:{port}.\n\n"
                "Выберите порт выше 1024 или запустите от имени администратора."
            )
    return f"Не удалось запустить прокси на {host}:{port}:\n{exc}"


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
        if bypass_mode == "windivert":
            if cfg.get("builtin_desync", True) and not desync_manager.is_external_winws_running():
                ok_w, err_w = desync_manager.start(str(cfg.get("worker_domain", "")))
                if not ok_w and err_w:
                    log.warning("Failed to start forced WinDivert bypass: %s", err_w)
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
        """Probe TLS + 22KB stream and auto-enable TLS frag / CF Port 80 / built-in winws if TSPU blocks."""
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

            updated = False
            notes = []

            if srv.carousel.frag_tls:
                notes.append("включена фрагментация TLS")

            # Check deep stream (>22KB) on DC2 and verify DC203 using live carousel settings
            async def _probe_once(prefer_port80: bool = False) -> Tuple[bool, int, Optional[str]]:
                probe_pool = DcCarouselPool(
                    worker_domain=srv.config.worker_domain,
                    mode=srv.config.mode,
                    pool_size=1,
                    frag_tls=srv.carousel.frag_tls,
                    prefer_port80_cf=prefer_port80,
                )
                try:
                    await probe_pool.initialize()
                    if not prefer_port80 and probe_pool.frag_tls and not srv.carousel.frag_tls:
                        srv.carousel.frag_tls = True
                        notes.append("включена фрагментация TLS")
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

            probe_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(probe_loop)
            try:
                deep_ok, sent_b, deep_err = probe_loop.run_until_complete(_probe_once(prefer_port80=False))
                if not deep_ok:
                    log.warning(
                        "Deep 22KB check failed (%s at %dB); trying CF Port 80 (zero-zapret)",
                        deep_err,
                        sent_b,
                    )
                    p80_ok, p80_sent, p80_err = probe_loop.run_until_complete(
                        _probe_once(prefer_port80=True)
                    )
                    if p80_ok:
                        srv.carousel.prefer_port80_cf = True
                        try:
                            asyncio.run_coroutine_threadsafe(srv.carousel.flush_stream_idle(), loop)
                        except RuntimeError:
                            pass
                        notes.append("включён режим CF Port 80 (работает без zapret)")
                        updated = True
                        log.info(
                            "Auto-tune enabled CF Port 80 zero-zapret mode (%dB OK)",
                            p80_sent,
                        )
                    else:
                        log.warning(
                            "CF Port 80 check failed (%s at %dB); trying built-in winws bypass",
                            p80_err,
                            p80_sent,
                        )
                        if cfg.get("builtin_desync", True) and not desync_manager.is_external_winws_running():
                            ok_w, err_w = desync_manager.start(srv.config.worker_domain)
                            if ok_w:
                                re_ok, re_sent, re_err = probe_loop.run_until_complete(
                                    _probe_once(prefer_port80=False)
                                )
                                if re_ok:
                                    notes.append("активирован встроенный обход ТСПУ (WinDivert)")
                                    updated = True
                                    try:
                                        loop.call_soon_threadsafe(srv.carousel._endpoint_cooldown.clear)
                                    except RuntimeError:
                                        pass
                                else:
                                    log.warning(
                                        "Deep 22KB check still failed after built-in winws: %s",
                                        re_err,
                                    )
                            elif err_w:
                                notes.append(f"встроенный WinDivert не запущен: {err_w}")
                                updated = True
                else:
                    log.info("Auto-tune check passed: %dB transferred on single DC2 socket without freeze", sent_b)
            except Exception as exc:
                log.debug("Auto-tune check skipped: %r", exc)
            finally:
                probe_loop.close()

            if on_notice and (updated or notes):
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
        """Monitor external zapret/winws.exe so built-in WinDivert never runs alongside it."""
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
                            "Обнаружен внешний zapret — встроенный WinDivert автоматически отключён",
                        )
                    continue
                now_external = desync_manager.is_external_winws_running()
                if was_external and not now_external:
                    log.info("External zapret/winws.exe stopped; triggering auto-tune check")
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
            desync_label = "zapret"
        elif desync_manager.is_running():
            desync_label = "WinDivert"
        elif getattr(srv.carousel, "prefer_port80_cf", False):
            desync_label = "CF-Port80 (без zapret)"
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
    builtin_desync: bool = True,
    auto_tune: bool = True,
    controller: Optional[ProxyController] = None,
) -> Tuple[str, bool]:
    domain = sanitize_worker_domain(worker_domain)
    bmode = (bypass_mode or "auto").lower()
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
            winws_note = ", CF Port 80 (без zapret)"
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
        elif bmode == "windivert":
            if builtin_desync and not desync_manager.is_external_winws_running():
                ok_w, err_w = desync_manager.start(domain)
                if ok_w:
                    winws_note = ", встроенный WinDivert"
                elif err_w:
                    return f"✗ {target_label}: WinDivert не запущен — {err_w}", False
            elif desync_manager.is_external_winws_running():
                winws_note = ", внешний zapret"
            deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                False, prefer_port80=False
            )
        else:
            deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                frag_tls, prefer_port80=False
            )
            if not deep_ok:
                p80_res = await _run_suite(False, prefer_port80=True)
                if p80_res[0]:
                    deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = p80_res
                    winws_note = ", CF Port 80 (без zapret)"
                    if controller is not None:
                        with controller._lock:
                            live_srv = controller._server
                            live_loop = controller._loop
                        if live_srv is not None:
                            live_srv.carousel.prefer_port80_cf = True
                            if live_loop is not None:
                                try:
                                    asyncio.run_coroutine_threadsafe(
                                        live_srv.carousel.flush_stream_idle(), live_loop
                                    )
                                except RuntimeError:
                                    pass
                elif builtin_desync and auto_tune and not desync_manager.is_external_winws_running():
                    ok_w, err_w = desync_manager.start(domain)
                    if ok_w:
                        winws_note = ", встроенный WinDivert"
                        deep_ok, ok_dcs, fail_lines, mode_label, effective_frag, _, deep_err = await _run_suite(
                            effective_frag, prefer_port80=False
                        )
                    elif err_w:
                        fail_lines.append(f"WinDivert: {err_w}")
            elif desync_manager.is_external_winws_running():
                winws_note = ", внешний zapret"
            elif desync_manager.is_running():
                winws_note = ", встроенный WinDivert"

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


class _ConnectivityWorker(QThread):
    finished_result = pyqtSignal(str, bool)

    def __init__(
        self,
        domain: str,
        mode: str,
        frag_tls: bool,
        builtin_desync: bool,
        auto_tune: bool,
        bypass_mode: str = "auto",
        controller: Optional[ProxyController] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._domain = domain
        self._mode = mode
        self._frag_tls = frag_tls
        self._builtin_desync = builtin_desync
        self._auto_tune = auto_tune
        self._bypass_mode = bypass_mode
        self._controller = controller

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            msg, eff_frag = loop.run_until_complete(
                test_worker_connectivity_async(
                    self._domain,
                    self._mode,
                    self._frag_tls,
                    bypass_mode=self._bypass_mode,
                    builtin_desync=self._builtin_desync,
                    auto_tune=self._auto_tune,
                    controller=self._controller,
                )
            )
        except Exception as exc:
            msg, eff_frag = f"✗ Ошибка: {exc}", self._frag_tls
        finally:
            loop.close()
        self.finished_result.emit(msg, eff_frag)


def _open_tg_link(
    cfg: Dict[str, Any],
    parent_tray: Optional[QSystemTrayIcon] = None,
    icon: Optional[QIcon] = None,
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
        log.warning("Failed to open tg:// link directly (%r), copying to clipboard", exc)

    cb = QApplication.clipboard()
    if cb is not None:
        cb.setText(url)
    msg = (
        f"Ссылка скопирована в буфер обмена. Вставьте её в Telegram («Избранное») и нажмите:\n{url}"
    )
    if parent_tray is not None:
        parent_tray.showMessage(APP_NAME, msg, icon or load_app_icon(), 5000)
    else:
        _show_message(None, msg, APP_NAME)


class FirstRunDialog(QDialog):
    """Minimalist, responsive setup assistant with Automatic and Manual MTProto instructions."""

    def __init__(self, cfg: Dict[str, Any], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._cfg = cfg
        self.open_on_finish = False
        self.dont_show_again = True
        self.setWindowTitle(f"{APP_NAME} v{__version__} — Подключение Telegram")
        self.setWindowIcon(load_app_icon())
        self.setMinimumSize(380, 460)
        self.resize(500, 540)
        self.setSizeGripEnabled(True)
        self.setStyleSheet(_APP_STYLESHEET)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(12)

        # Branded header
        header = QHBoxLayout()
        header.setSpacing(12)
        logo_lbl = QLabel()
        logo_lbl.setPixmap(load_logo_pixmap(48))
        logo_lbl.setFixedSize(48, 48)
        header.addWidget(logo_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = QLabel(
            f"{APP_NAME} <span style='color:#94A3B8;font-size:12px;'>v{__version__}</span>"
        )
        title_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #F8FAFC;")
        worker_lbl_txt = (
            self._cfg.get("worker_domain") or "Публичный пул Cloudflare (20+ доменов)"
        )
        sub_lbl = QLabel(f"Прокси запущен • {worker_lbl_txt}")
        sub_lbl.setWordWrap(True)
        sub_lbl.setStyleSheet("font-size: 12px; color: #34D399; font-weight: 600;")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)
        header.addLayout(title_col, 1)
        outer.addLayout(header)

        # Scrollable main body
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body_widget = QWidget()
        body_layout = QVBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(10)

        link_host = get_link_host(str(cfg.get("host", "127.0.0.1")))
        port = str(cfg.get("port", 1080))
        try:
            clean_secret = normalize_secret(str(cfg.get("secret", ""))).hex()
        except Exception:
            clean_secret = str(cfg.get("secret", ""))
        prefixed_secret = f"dd{clean_secret}"
        url = tg_proxy_url(cfg)

        tabs = QTabWidget()

        # Tab 1: Automatic one-click setup
        auto_tab = QWidget()
        auto_layout = QVBoxLayout(auto_tab)
        auto_layout.setContentsMargins(6, 6, 6, 6)
        auto_layout.setSpacing(12)

        auto_intro = QLabel(
            "<b>Быстрое подключение в 1 клик</b><br>"
            "1. Нажмите зелёную кнопку ниже — откроется Telegram Desktop.<br>"
            "2. В окне Telegram нажмите <b>«Включить» (Enable proxy)</b>."
        )
        auto_intro.setWordWrap(True)
        auto_intro.setStyleSheet("color: #CBD5E1; line-height: 1.4;")
        auto_layout.addWidget(auto_intro)

        open_btn = _make_btn("Открыть в Telegram", object_name="primaryBtn")
        open_btn.setMinimumHeight(38)
        open_btn.setIcon(load_app_icon())
        open_btn.clicked.connect(lambda: _open_tg_link(self._cfg))
        auto_layout.addWidget(open_btn)

        fallback_lbl = QLabel(
            "<b>Если Telegram не открылся автоматически:</b><br>"
            "Скопируйте ссылку ниже, вставьте её в чат <b>«Избранное»</b> и нажмите на неё:"
        )
        fallback_lbl.setWordWrap(True)
        fallback_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
        auto_layout.addWidget(fallback_lbl)

        link_box = QHBoxLayout()
        link_box.setSpacing(6)
        link_edit = QLineEdit(url)
        link_edit.setReadOnly(True)
        link_edit.setMinimumWidth(100)
        copy_url_btn = _make_btn("Копировать")
        copy_url_btn.clicked.connect(lambda: self._copy_text(url, copy_url_btn))
        link_box.addWidget(link_edit, 1)
        link_box.addWidget(copy_url_btn)
        auto_layout.addLayout(link_box)

        tray_hint = QLabel(
            "После закрытия окна FreeTG остаётся в системном трее рядом с часами."
        )
        tray_hint.setWordWrap(True)
        tray_hint.setStyleSheet("font-size: 11px; color: #64748B;")
        auto_layout.addWidget(tray_hint)
        auto_layout.addStretch(1)
        tabs.addTab(auto_tab, "Автоматически")

        # Tab 2: Manual step-by-step setup
        manual_tab = QWidget()
        manual_layout = QVBoxLayout(manual_tab)
        manual_layout.setContentsMargins(6, 6, 6, 6)
        manual_layout.setSpacing(10)

        steps_lbl = QLabel(
            "<b>Пошаговое добавление в Telegram Desktop:</b><br>"
            "1. Откройте Telegram → <b>Настройки → Продвинутые → Тип соединения</b><br>"
            "2. Нажмите <b>Использовать собственный прокси → Добавить прокси</b><br>"
            "3. Выберите тип <b>MTProto</b> и скопируйте три поля ниже:<br>"
            "4. Нажмите <b>Сохранить</b> и убедитесь, что галочка прокси включена."
        )
        steps_lbl.setWordWrap(True)
        steps_lbl.setStyleSheet("color: #CBD5E1; line-height: 1.4;")
        manual_layout.addWidget(steps_lbl)

        for field_title, value in (
            ("Сервер:", link_host),
            ("Порт:", port),
            ("Ключ (dd...):", prefixed_secret),
        ):
            row_col = QVBoxLayout()
            row_col.setSpacing(3)
            lbl = QLabel(field_title)
            lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 600;")
            row_h = QHBoxLayout()
            row_h.setSpacing(6)
            edit = QLineEdit(value)
            edit.setReadOnly(True)
            edit.setMinimumWidth(90)
            c_btn = _make_btn("Копировать")
            c_btn.clicked.connect(lambda _chk=False, v=value, b=c_btn: self._copy_text(v, b))
            row_h.addWidget(edit, 1)
            row_h.addWidget(c_btn)
            row_col.addWidget(lbl)
            row_col.addLayout(row_h)
            manual_layout.addLayout(row_col)

        manual_layout.addStretch(1)
        tabs.addTab(manual_tab, "Вручную (пошагово)")

        body_layout.addWidget(tabs)
        scroll.setWidget(body_widget)
        outer.addWidget(scroll, 1)

        # Responsive footer
        footer = _FlowLayout(spacing=8)
        self.dont_show_cb = QCheckBox("Больше не показывать при запуске")
        self.dont_show_cb.setChecked(True)
        self.open_now_cb = self.dont_show_cb  # kept for compatibility
        footer.addWidget(self.dont_show_cb)

        done_btn = _make_btn("Готово", min_width=100)
        done_btn.clicked.connect(self._on_finish)
        footer.addWidget(done_btn)
        outer.addLayout(footer)

    @staticmethod
    def _copy_text(text: str, btn: QPushButton) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)
            btn.setText("Скопировано ✓")

    def _on_finish(self) -> None:
        self.dont_show_again = self.dont_show_cb.isChecked()
        self.accept()


class SettingsDialog(QDialog):
    """Minimalist, responsive GUI dialog for FreeTG proxy settings."""

    def __init__(
        self,
        cfg: Dict[str, Any],
        controller: ProxyController,
        on_applied: Callable[[Dict[str, Any], bool], None],
        parent: Optional[QWidget] = None,
        on_toggle_server: Optional[Callable[[], None]] = None,
        on_full_exit: Optional[Callable[[], None]] = None,
        on_open_guide: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(parent)
        self._cfg = deepcopy(cfg)
        self._controller = controller
        self._on_applied = on_applied
        self._on_toggle_server = on_toggle_server
        self._on_full_exit = on_full_exit
        self._on_open_guide = on_open_guide
        self._test_worker: Optional[_ConnectivityWorker] = None

        self.setWindowTitle(f"{APP_NAME} — Настройки")
        self.setWindowIcon(load_app_icon())
        self.setMinimumSize(380, 440)
        self.resize(510, 560)
        self.setSizeGripEnabled(True)
        self.setStyleSheet(_APP_STYLESHEET)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(10)

        # Compact Header + Live Status
        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(load_logo_pixmap(42))
        logo.setFixedSize(42, 42)
        hdr.addWidget(logo)

        hdr_text = QVBoxLayout()
        hdr_text.setSpacing(1)
        name_lbl = QLabel(
            f"{APP_NAME}  <span style='color:#94A3B8;font-size:12px;'>v{__version__}</span>"
        )
        name_lbl.setStyleSheet("font-size: 17px; font-weight: 700; color: #F8FAFC;")
        self._status_lbl = QLabel()
        self._status_lbl.setWordWrap(True)
        self._status_lbl.setStyleSheet("font-size: 12px; color: #34D399;")
        hdr_text.addWidget(name_lbl)
        hdr_text.addWidget(self._status_lbl)
        hdr.addLayout(hdr_text, 1)
        outer.addLayout(hdr)

        # Scrollable cards area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 2, 0)
        body.setSpacing(10)

        # Card 1: MTProto Listen settings
        mt_group = QGroupBox("Подключение MTProto")
        mt_layout = QVBoxLayout(mt_group)
        mt_layout.setSpacing(8)

        addr_lbl = QLabel("Локальный адрес и порт:")
        addr_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 600;")
        mt_layout.addWidget(addr_lbl)

        addr_row = QHBoxLayout()
        addr_row.setSpacing(6)
        self.host_edit = QLineEdit(str(self._cfg.get("host", "127.0.0.1")))
        self.host_edit.setMinimumWidth(110)
        self.host_edit.setToolTip("IP-адрес локального прокси (обычно 127.0.0.1)")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setMinimumWidth(78)
        self.port_spin.setValue(int(self._cfg.get("port", 1080)))
        addr_row.addWidget(self.host_edit, 1)
        addr_row.addWidget(self.port_spin)
        mt_layout.addLayout(addr_row)

        sec_lbl = QLabel("Ключ доступа (Secret):")
        sec_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 600;")
        mt_layout.addWidget(sec_lbl)

        self.secret_edit = QLineEdit(str(self._cfg.get("secret", DEFAULT_CONFIG["secret"])))
        self.secret_edit.setMinimumWidth(110)
        self.secret_edit.setPlaceholderText("32 hex-символа")
        mt_layout.addWidget(self.secret_edit)

        mt_btns = _FlowLayout(spacing=6)
        gen_secret_btn = _make_btn("Обновить ключ")
        gen_secret_btn.setToolTip("Сгенерировать новый случайный ключ")
        gen_secret_btn.clicked.connect(self._generate_secret)
        open_tg_btn = _make_btn("Открыть в Telegram")
        open_tg_btn.setIcon(load_app_icon())
        open_tg_btn.clicked.connect(lambda: _open_tg_link(self._current_preview_config()))
        mt_btns.addWidget(open_tg_btn)
        mt_btns.addWidget(gen_secret_btn)
        mt_layout.addLayout(mt_btns)
        body.addWidget(mt_group)

        # Card 2: Cloudflare & TSPU bypass (minimalist by default)
        cf_group = QGroupBox("Cloudflare и обход ТСПУ")
        cf_layout = QVBoxLayout(cf_group)
        cf_layout.setSpacing(8)

        dom_lbl = QLabel("Свой Worker (опционально — пустое поле = публичный пул CF):")
        dom_lbl.setWordWrap(True)
        dom_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 600;")
        cf_layout.addWidget(dom_lbl)

        self.domain_edit = QLineEdit(str(self._cfg.get("worker_domain", DEFAULT_CONFIG["worker_domain"])))
        self.domain_edit.setMinimumWidth(120)
        self.domain_edit.setPlaceholderText("Авто — публичный пул CF (20 доменов)")
        cf_layout.addWidget(self.domain_edit)

        bypass_lbl = QLabel("Способ обхода:")
        bypass_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: 600;")
        cf_layout.addWidget(bypass_lbl)

        self.bypass_combo = QComboBox()
        self.bypass_combo.addItem("Автоподбор (Port 443 / Port 80 / WinDivert)", "auto")
        self.bypass_combo.addItem("CF Port 80 (без TLS и без WinDivert)", "port80")
        self.bypass_combo.addItem("Встроенный WinDivert (winws.exe)", "windivert")
        self.bypass_combo.addItem("Фрагментация TLS ClientHello (порт 443)", "tls_frag")
        self.bypass_combo.addItem("Прямой / Внешний zapret (порт 443)", "direct")
        cur_bypass = str(self._cfg.get("bypass_mode", "auto")).lower()
        b_idx = self.bypass_combo.findData(cur_bypass)
        self.bypass_combo.setCurrentIndex(max(0, b_idx))
        cf_layout.addWidget(self.bypass_combo)

        dom_btns = _FlowLayout(spacing=6)
        self.test_btn = _make_btn("Тест соединения", min_width=120)
        self.test_btn.clicked.connect(self._run_connectivity_test)
        auto_dom_btn = _make_btn("Публичный пул (Авто)")
        auto_dom_btn.setToolTip("Очистить поле и использовать встроенные публичные домены Cloudflare")
        auto_dom_btn.clicked.connect(lambda: self.domain_edit.setText(""))
        dom_btns.addWidget(self.test_btn)
        dom_btns.addWidget(auto_dom_btn)
        cf_layout.addLayout(dom_btns)

        self._test_result_lbl = QLabel("")
        self._test_result_lbl.setWordWrap(True)
        self._test_result_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
        self._test_result_lbl.hide()
        cf_layout.addWidget(self._test_result_lbl)

        self.auto_tune_cb = QCheckBox("Автоподбор обхода (Port 80 / TLS / WinDivert)")
        self.auto_tune_cb.setChecked(bool(self._cfg.get("auto_tune", True)))
        cf_layout.addWidget(self.auto_tune_cb)

        self.autostart_cb = QCheckBox("Запускать вместе с Windows")
        self.autostart_cb.setChecked(bool(self._cfg.get("autostart", False)))
        cf_layout.addWidget(self.autostart_cb)

        # Collapsible advanced section
        self._adv_toggle_btn = _make_btn("Дополнительно ▸", object_name="linkBtn")
        self._adv_toggle_btn.clicked.connect(self._toggle_advanced)
        cf_layout.addWidget(self._adv_toggle_btn)

        self._adv_widget = QWidget()
        self._adv_widget.setVisible(False)
        adv_layout = QVBoxLayout(self._adv_widget)
        adv_layout.setContentsMargins(0, 4, 0, 0)
        adv_layout.setSpacing(8)

        adv_form = QFormLayout()
        adv_form.setSpacing(8)
        adv_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Авто (V1 / V2)", "auto")
        self.mode_combo.addItem("V1 — WebSocket стриминг", "v1")
        self.mode_combo.addItem("V2 — Карусельный синк", "v2")
        cur_mode = str(self._cfg.get("mode", "auto")).lower()
        idx = self.mode_combo.findData(cur_mode)
        self.mode_combo.setCurrentIndex(max(0, idx))
        adv_form.addRow("Режим работы:", self.mode_combo)

        self.pool_spin = QSpinBox()
        self.pool_spin.setRange(0, 10)
        self.pool_spin.setValue(int(self._cfg.get("pool_size", 3)))
        self.pool_spin.setToolTip("Прогретых сокетов на активный DC")
        adv_form.addRow("Пул сокетов на DC:", self.pool_spin)
        adv_layout.addLayout(adv_form)

        self.frag_cb = QCheckBox("Фрагментация TLS ClientHello")
        self.frag_cb.setChecked(bool(self._cfg.get("frag_tls", False)))
        adv_layout.addWidget(self.frag_cb)

        self.builtin_desync_cb = QCheckBox("Встроенный обход WinDivert (если Port 80 закрыт)")
        self.builtin_desync_cb.setChecked(bool(self._cfg.get("builtin_desync", True)))
        adv_layout.addWidget(self.builtin_desync_cb)

        log_row = _FlowLayout(spacing=8)
        self.verbose_cb = QCheckBox("Подробный лог (Debug)")
        self.verbose_cb.setChecked(bool(self._cfg.get("verbose", False)))
        log_row.addWidget(self.verbose_cb)

        self.log_mb_spin = QDoubleSpinBox()
        self.log_mb_spin.setRange(0.5, 100.0)
        self.log_mb_spin.setSingleStep(1.0)
        self.log_mb_spin.setSuffix(" МБ")
        self.log_mb_spin.setValue(float(self._cfg.get("log_max_mb", 5)))
        self.log_mb_spin.setFixedWidth(92)
        log_row.addWidget(self.log_mb_spin)

        logs_btn = _make_btn("Открыть логи")
        logs_btn.clicked.connect(self._open_logs)
        log_row.addWidget(logs_btn)
        adv_layout.addLayout(log_row)

        cf_layout.addWidget(self._adv_widget)
        body.addWidget(cf_group)
        body.addStretch(1)

        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        # Responsive footer buttons (auto-wrap when window narrows)
        footer = _FlowLayout(spacing=8)
        self.toggle_srv_btn = _make_btn("Остановить сервер")
        self.toggle_srv_btn.clicked.connect(self._handle_toggle_server)
        footer.addWidget(self.toggle_srv_btn)

        guide_btn = _make_btn("Инструкция")
        guide_btn.clicked.connect(self._open_guide)
        footer.addWidget(guide_btn)

        unload_btn = _make_btn(
            "Выгрузить",
            object_name="dangerBtn",
            tooltip="Остановить прокси, выгрузить WinDivert и закрыть FreeTG.exe",
        )
        unload_btn.clicked.connect(self._handle_full_exit)
        footer.addWidget(unload_btn)

        cancel_btn = _make_btn("Отмена")
        cancel_btn.clicked.connect(self.reject)
        footer.addWidget(cancel_btn)

        save_btn = _make_btn("Сохранить", object_name="primaryBtn", min_width=105)
        save_btn.clicked.connect(self._on_save)
        footer.addWidget(save_btn)
        outer.addLayout(footer)

        self._refresh_status()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_status)
        self._timer.start(2000)

    def _toggle_advanced(self) -> None:
        show = not self._adv_widget.isVisible()
        self._adv_widget.setVisible(show)
        self._adv_toggle_btn.setText("Дополнительно ▾" if show else "Дополнительно ▸")

    def _open_guide(self) -> None:
        if self._on_open_guide is not None:
            self._on_open_guide()
        else:
            FirstRunDialog(self._current_preview_config(), self).exec()

    def _handle_toggle_server(self) -> None:
        if self._on_toggle_server is not None:
            self.toggle_srv_btn.setEnabled(False)
            self._on_toggle_server()
            QTimer.singleShot(800, self._refresh_after_toggle)
        else:
            if self._controller.is_running():
                self._controller.stop(timeout=4.0, stop_desync=True)
            else:
                self._controller.start(self._cfg)
            self._refresh_status()

    def _refresh_after_toggle(self) -> None:
        self.toggle_srv_btn.setEnabled(True)
        self._refresh_status()

    def _handle_full_exit(self) -> None:
        self.close()
        if self._on_full_exit is not None:
            self._on_full_exit()

    def _refresh_status(self) -> None:
        st = self._controller.get_status_snapshot()
        if st.get("running"):
            self._status_lbl.setStyleSheet("font-size: 12px; color: #34D399;")
            self._status_lbl.setText(
                f"● Работает ({st['mode']}, {st.get('desync', 'прямой')}) • "
                f"Подкл: {st['active_conns']} • ↑ {st['tx']} / ↓ {st['rx']}"
            )
            self.toggle_srv_btn.setText("Остановить сервер")
        else:
            err = st.get("err") or "остановлен"
            self._status_lbl.setStyleSheet("font-size: 12px; color: #F87171;")
            self._status_lbl.setText(f"● Остановлен ({err})")
            self.toggle_srv_btn.setText("Запустить сервер")

    def _generate_secret(self) -> None:
        self.secret_edit.setText(os.urandom(16).hex())

    def _open_logs(self) -> None:
        if LOG_FILE.exists():
            try:
                os.startfile(str(LOG_FILE))
                return
            except Exception as exc:
                _show_message(self, f"Не удалось открыть лог:\n{exc}", APP_NAME, level="error")
        else:
            _show_message(self, "Файл логов ещё не создан.", APP_NAME)

    def _current_preview_config(self) -> Dict[str, Any]:
        c = dict(self._cfg)
        c["host"] = self.host_edit.text().strip() or "127.0.0.1"
        c["port"] = int(self.port_spin.value())
        c["secret"] = self.secret_edit.text().strip() or DEFAULT_CONFIG["secret"]
        c["worker_domain"] = sanitize_worker_domain(self.domain_edit.text())
        return c

    def _run_connectivity_test(self) -> None:
        if self._test_worker is not None and self._test_worker.isRunning():
            return
        raw_domain = self.domain_edit.text().strip()
        domain = sanitize_worker_domain(raw_domain)
        if raw_domain and not domain:
            _show_message(self, "Укажите корректный домен Cloudflare Worker (или оставьте пустым для авто-пула).", APP_NAME)
            return
        self.test_btn.setEnabled(False)
        self.test_btn.setText("Проверка...")
        self._test_result_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
        self._test_result_lbl.setText("Проверка >22 КБ через Cloudflare...")
        self._test_result_lbl.show()

        self._test_worker = _ConnectivityWorker(
            domain,
            str(self.mode_combo.currentData()),
            self.frag_cb.isChecked(),
            self.builtin_desync_cb.isChecked(),
            self.auto_tune_cb.isChecked(),
            bypass_mode=str(self.bypass_combo.currentData()),
            controller=self._controller,
            parent=self,
        )
        self._test_worker.finished_result.connect(self._on_test_finished)
        self._test_worker.start()

    def _on_test_finished(self, message: str, effective_frag: bool) -> None:
        self.test_btn.setEnabled(True)
        self.test_btn.setText("Тест соединения")
        if effective_frag and not self.frag_cb.isChecked():
            self.frag_cb.setChecked(True)
        color = "#34D399" if message.startswith("✓") else ("#FBBF24" if message.startswith("~") else "#F87171")
        self._test_result_lbl.setStyleSheet(f"font-size: 12px; color: {color};")
        self._test_result_lbl.setText(message)
        self._test_result_lbl.show()

    def _on_save(self) -> None:
        host = self.host_edit.text().strip()
        try:
            socket.inet_aton(host)
        except OSError:
            _show_message(self, "Некорректный IPv4-адрес для локального прокси.", APP_NAME, level="error")
            return

        port = int(self.port_spin.value())
        try:
            secret = normalize_secret(self.secret_edit.text()).hex()
        except ValueError as exc:
            _show_message(self, str(exc), APP_NAME, level="error")
            return

        raw_domain = self.domain_edit.text().strip()
        worker_domain = sanitize_worker_domain(raw_domain)
        if raw_domain and not worker_domain:
            _show_message(self, "Укажите корректный домен Cloudflare Worker или очистите поле для публичного пула.", APP_NAME)
            return

        new_cfg: Dict[str, Any] = {
            "host": host,
            "port": port,
            "secret": secret,
            "worker_domain": worker_domain,
            "mode": str(self.mode_combo.currentData()),
            "bypass_mode": str(self.bypass_combo.currentData()),
            "pool_size": int(self.pool_spin.value()),
            "frag_tls": self.frag_cb.isChecked(),
            "builtin_desync": self.builtin_desync_cb.isChecked(),
            "auto_tune": self.auto_tune_cb.isChecked(),
            "verbose": self.verbose_cb.isChecked(),
            "log_max_mb": round(float(self.log_mb_spin.value()), 2),
            "autostart": self.autostart_cb.isChecked(),
        }

        if bool(new_cfg["autostart"]) != bool(self._cfg.get("autostart", False)) or new_cfg["autostart"]:
            ok, err = set_autostart_enabled(bool(new_cfg["autostart"]))
            if not ok:
                _show_message(
                    self, f"Не удалось обновить автозапуск в реестре:\n{err}", APP_NAME
                )

        restart_needed = any(new_cfg.get(k) != self._cfg.get(k) for k in _PROXY_RESTART_KEYS)
        save_config(new_cfg)
        set_verbose_logging(bool(new_cfg["verbose"]))
        self._on_applied(new_cfg, restart_needed)
        self.accept()


class _UiBridge(QObject):
    error_signal = pyqtSignal(str)
    restarted_signal = pyqtSignal(bool, str)
    autotune_signal = pyqtSignal(object, str)


class FreeTGTrayApplication:
    """System tray manager wrapping QApplication, QSystemTrayIcon, and ProxyController."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.controller = ProxyController()
        self.app = QApplication(sys.argv)
        self.app.setApplicationName(APP_NAME)
        self.app.setQuitOnLastWindowClosed(False)
        self._app_icon = load_app_icon()
        self.app.setWindowIcon(self._app_icon)
        self.app.setStyleSheet(_APP_STYLESHEET)

        self.bridge = _UiBridge()
        self.bridge.error_signal.connect(self._show_error_dialog)
        self.bridge.restarted_signal.connect(self._on_restart_finished)
        self.bridge.autotune_signal.connect(self._on_autotune_notice)

        self._settings_dlg: Optional[SettingsDialog] = None
        self._first_run_dlg: Optional[FirstRunDialog] = None
        self._exiting = False

        self.tray = QSystemTrayIcon(self._app_icon, self.app)
        self.tray.activated.connect(self._on_tray_activated)
        self._open_tg_action: Optional[QAction] = None
        self._toggle_server_action: Optional[QAction] = None
        self._build_tray_menu()

    def _build_tray_menu(self) -> None:
        menu = QMenu()
        host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
        port = int(self.cfg.get("port", 1080))

        self._open_tg_action = QAction(self._app_icon, f"Открыть в Telegram ({host}:{port})", menu)
        font = self._open_tg_action.font()
        font.setBold(True)
        self._open_tg_action.setFont(font)
        self._open_tg_action.triggered.connect(lambda: _open_tg_link(self.cfg, self.tray, self._app_icon))
        menu.addAction(self._open_tg_action)

        copy_act = QAction("Скопировать ссылку", menu)
        copy_act.triggered.connect(self._on_copy_link)
        menu.addAction(copy_act)

        menu.addSeparator()

        self._toggle_server_action = QAction("Остановить сервер", menu)
        self._toggle_server_action.triggered.connect(self._on_toggle_server_clicked)
        menu.addAction(self._toggle_server_action)

        restart_act = QAction("Перезапустить прокси", menu)
        restart_act.triggered.connect(self._on_restart_clicked)
        menu.addAction(restart_act)

        settings_act = QAction("Настройки...", menu)
        settings_act.triggered.connect(self._open_settings)
        menu.addAction(settings_act)

        guide_act = QAction("Инструкция подключения", menu)
        guide_act.triggered.connect(lambda: self._open_first_run(force=True))
        menu.addAction(guide_act)

        logs_act = QAction("Открыть логи", menu)
        logs_act.triggered.connect(self._on_open_logs)
        menu.addAction(logs_act)

        menu.addSeparator()

        exit_act = QAction("Выход (выгрузить полностью)", menu)
        exit_act.triggered.connect(self._on_exit)
        menu.addAction(exit_act)

        self.tray.setContextMenu(menu)
        self._update_tooltip()

    def _update_tooltip(self) -> None:
        host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
        port = int(self.cfg.get("port", 1080))
        domain = self.cfg.get("worker_domain", "") or "публичный пул CF"
        running = self.controller.is_running()
        state = "работает" if running else "остановлен"
        self.tray.setToolTip(f"{APP_NAME} v{__version__} — {state}\n{host}:{port} ({domain})")
        if self._open_tg_action is not None:
            self._open_tg_action.setText(f"Открыть в Telegram ({host}:{port})")
        if self._toggle_server_action is not None:
            self._toggle_server_action.setText(
                "Остановить сервер" if running else "Запустить сервер"
            )

    def _show_error_dialog(self, msg: str) -> None:
        _show_message(None, msg, f"{APP_NAME} — Ошибка", level="error")

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.DoubleClick,
            QSystemTrayIcon.ActivationReason.Trigger,
        ):
            self._open_settings()

    def _on_copy_link(self) -> None:
        url = tg_proxy_url(self.cfg)
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(url)
            self.tray.showMessage(
                APP_NAME,
                f"Ссылка скопирована:\n{url}",
                self._app_icon,
                4000,
            )

    def _on_open_logs(self) -> None:
        if LOG_FILE.exists():
            try:
                os.startfile(str(LOG_FILE))
                return
            except Exception as exc:
                self._show_error_dialog(f"Не удалось открыть лог:\n{exc}")
        else:
            _show_message(None, "Файл логов ещё не создан.", APP_NAME)

    def _on_toggle_server_clicked(self) -> None:
        if self.controller.is_running():
            threading.Thread(
                target=self._stop_server_background, daemon=True, name="proxy-stop"
            ).start()
        else:
            threading.Thread(
                target=self._start_server_background, daemon=True, name="proxy-start"
            ).start()

    def _stop_server_background(self) -> None:
        log.info("Stopping server by user request")
        self.controller.stop(timeout=4.0, stop_desync=True)
        self.bridge.restarted_signal.emit(False, "Сервер полностью остановлен")

    def _start_server_background(self) -> None:
        ok, err = self.controller.start(
            self.cfg,
            on_error=lambda msg: self.bridge.error_signal.emit(msg),
        )
        self.bridge.restarted_signal.emit(ok, err or "")

    def _on_restart_clicked(self) -> None:
        threading.Thread(target=self._restart_background, daemon=True, name="proxy-restart").start()

    def _restart_background(self) -> None:
        ok, err = self.controller.restart(
            self.cfg,
            on_error=lambda msg: self.bridge.error_signal.emit(msg),
        )
        self.bridge.restarted_signal.emit(ok, err or "")

    def _on_restart_finished(self, ok: bool, err: str) -> None:
        self._update_tooltip()
        if ok:
            self.controller.run_auto_tune_async(
                self.cfg,
                on_notice=lambda new_cfg, msg: self.bridge.autotune_signal.emit(new_cfg, msg),
            )
            self.controller.start_zapret_watcher(
                self.cfg,
                on_notice=lambda new_cfg, msg: self.bridge.autotune_signal.emit(new_cfg, msg),
            )
            host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
            port = int(self.cfg.get("port", 1080))
            self.tray.showMessage(
                APP_NAME,
                f"Прокси запущен на {host}:{port}",
                self._app_icon,
                3000,
            )
        elif err == "Сервер полностью остановлен":
            self.tray.showMessage(
                APP_NAME,
                "Сервер и встроенный WinDivert остановлены.",
                self._app_icon,
                3000,
            )

    def _on_autotune_notice(self, new_cfg: object, msg: str) -> None:
        if isinstance(new_cfg, dict):
            self.cfg = new_cfg
            self.controller.update_watch_config(self.cfg)
        self._update_tooltip()
        self.tray.showMessage(
            APP_NAME,
            msg,
            self._app_icon,
            4500,
        )

    def _open_settings(self) -> None:
        if self._settings_dlg is not None and self._settings_dlg.isVisible():
            self._settings_dlg.raise_()
            self._settings_dlg.activateWindow()
            return
        self.cfg["autostart"] = load_config().get("autostart", self.cfg.get("autostart", False))
        dlg = SettingsDialog(
            self.cfg,
            self.controller,
            self._on_settings_applied,
            on_toggle_server=self._on_toggle_server_clicked,
            on_full_exit=self._on_exit,
            on_open_guide=lambda: self._open_first_run(force=True),
        )
        self._settings_dlg = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _on_settings_applied(self, new_cfg: Dict[str, Any], restart_needed: bool) -> None:
        self.cfg = new_cfg
        self.controller.update_watch_config(self.cfg)
        self._update_tooltip()
        if restart_needed:
            self._on_restart_clicked()
        else:
            self.tray.showMessage(
                APP_NAME,
                "Настройки сохранены.",
                self._app_icon,
                2500,
            )

    def _open_first_run(self, *, force: bool = False) -> None:
        ensure_dirs()
        if not force and FIRST_RUN_MARKER.exists():
            return
        if self._first_run_dlg is not None and self._first_run_dlg.isVisible():
            self._first_run_dlg.raise_()
            self._first_run_dlg.activateWindow()
            return
        dlg = FirstRunDialog(self.cfg)
        self._first_run_dlg = dlg
        if dlg.exec() == QDialog.DialogCode.Accepted:
            if getattr(dlg, "dont_show_again", True):
                try:
                    FIRST_RUN_MARKER.touch()
                except OSError:
                    pass
            if dlg.open_on_finish:
                _open_tg_link(self.cfg, self.tray, self._app_icon)

    def _on_exit(self) -> None:
        if self._exiting:
            return
        self._exiting = True
        log.info("Exiting FreeTG tray application")
        self.tray.hide()
        for dlg in (self._settings_dlg, self._first_run_dlg):
            if dlg is not None:
                try:
                    dlg.close()
                except Exception:
                    pass
        threading.Thread(
            target=lambda: (time.sleep(2.0), os._exit(0)),
            daemon=True,
            name="force-exit",
        ).start()
        self.controller.stop(timeout=2.5, stop_desync=True)
        desync_manager.stop()
        release_single_instance_mutex()
        self.app.quit()

    def run(self) -> int:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            log.warning("System tray reports unavailable; continuing anyway")

        self.tray.show()
        ok, err = self.controller.start(
            self.cfg,
            on_error=lambda msg: self.bridge.error_signal.emit(msg),
        )
        self._update_tooltip()

        if ok:
            self.controller.run_auto_tune_async(
                self.cfg,
                on_notice=lambda new_cfg, msg: self.bridge.autotune_signal.emit(new_cfg, msg),
            )
            self.controller.start_zapret_watcher(
                self.cfg,
                on_notice=lambda new_cfg, msg: self.bridge.autotune_signal.emit(new_cfg, msg),
            )
            if not FIRST_RUN_MARKER.exists():
                QTimer.singleShot(250, lambda: self._open_first_run(force=True))
            else:
                host = get_link_host(str(self.cfg.get("host", "127.0.0.1")))
                port = int(self.cfg.get("port", 1080))
                self.tray.showMessage(
                    APP_NAME,
                    f"Прокси запущен: {host}:{port}",
                    self._app_icon,
                    3000,
                )
        elif err:
            QTimer.singleShot(200, self._open_settings)

        exit_code = self.app.exec()
        self.controller.stop(timeout=3.0)
        desync_manager.stop()
        return exit_code


def run_tray_main() -> int:
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FreeTG.Proxy.App")
        except Exception:
            pass

    if not acquire_single_instance_mutex():
        show_native_info(
            "Приложение FreeTG уже запущено, проверьте системный трей.",
            APP_NAME,
        )
        return 0

    try:
        cfg = load_config()
        setup_logging(
            bool(cfg.get("verbose", False)),
            log_max_mb=float(cfg.get("log_max_mb", 5)),
        )
        save_config(cfg)
        log.info("Starting %s v%s (AES=%s)", APP_NAME, __version__, AES_BACKEND_NAME)
        tray_app = FreeTGTrayApplication(cfg)
        return tray_app.run()
    finally:
        release_single_instance_mutex()
