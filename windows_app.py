"""Desktop Windows entry point for FreeTG standalone executable and source mode."""

from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

from freetg import __version__
from freetg.app_config import APP_DIR, DEFAULT_CONFIG, ensure_dirs, load_config, resource_path, setup_logging
from freetg.crypto import AES_BACKEND_NAME
from freetg.tray_app import ProxyController, run_tray_main


def _safe_print(text: str) -> None:
    if sys.stdout is not None:
        try:
            print(text, flush=True)
        except Exception:
            pass


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def run_selftest() -> int:
    """Verify bundled crypto backend, assets, config, and local proxy startup/shutdown."""
    ensure_dirs()
    setup_logging(verbose=True, log_max_mb=2)
    logo_path = resource_path("assets/logo.png")
    icon_path = resource_path("icon.ico")

    test_cfg = dict(DEFAULT_CONFIG)
    test_port = _pick_free_port()
    test_cfg["host"] = "127.0.0.1"
    test_cfg["port"] = test_port
    test_cfg["pool_size"] = 0
    test_cfg["mode"] = "v1"
    test_cfg["builtin_desync"] = False
    test_cfg["auto_tune"] = False
    winws2_exe = resource_path("assets/winws/winws2.exe")
    lua_antidpi = resource_path("assets/winws/lua/zapret-antidpi.lua")
    winws1_exe = resource_path("assets/winws/winws.exe")

    controller = ProxyController()
    ok, err = controller.start(test_cfg, stats_interval=0, wait_ready=10.0)
    tcp_ok = False
    if ok:
        try:
            with socket.create_connection(("127.0.0.1", test_port), timeout=3.0) as sock:
                tcp_ok = True
        except OSError:
            tcp_ok = False
        finally:
            controller.stop(timeout=5.0)

    payload = {
        "status": "SELFTEST_OK" if (ok and tcp_ok) else "SELFTEST_FAILED",
        "version": __version__,
        "aes_backend": AES_BACKEND_NAME,
        "logo_exists": logo_path.exists(),
        "logo_path": str(logo_path),
        "icon_exists": icon_path.exists(),
        "icon_path": str(icon_path),
        "winws2_exists": winws2_exe.exists(),
        "winws2_lua_exists": lua_antidpi.exists(),
        "winws1_exists": winws1_exe.exists(),
        "bind_ok": ok,
        "tcp_ok": tcp_ok,
        "error": err,
    }
    try:
        (APP_DIR / "selftest.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        pass

    _safe_print(json.dumps(payload, ensure_ascii=False))
    return 0 if (ok and tcp_ok) else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return run_selftest()
    return run_tray_main()


if __name__ == "__main__":
    sys.exit(main())
