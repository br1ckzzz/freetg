"""Application configuration, rotating logging, resource lookup, and Windows autostart."""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
from copy import deepcopy
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .crypto import normalize_secret
from .server import DEFAULT_SECRET, DEFAULT_WORKER_DOMAIN, FreeTGConfig

if sys.platform == "win32":
    import winreg
else:  # pragma: no cover
    winreg = None

APP_NAME = "FreeTG"
PORTABLE_DIR_NAME = "FreeTG_data"
IS_FROZEN = bool(getattr(sys, "frozen", False))
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 1080,
    "secret": DEFAULT_SECRET,
    "worker_domain": DEFAULT_WORKER_DOMAIN,
    "mode": "auto",
    "bypass_mode": "auto",
    "desync_profile": "auto",
    "pool_size": 3,
    "frag_tls": False,
    "builtin_desync": True,
    "auto_tune": True,
    "verbose": False,
    "log_max_mb": 5,
    "autostart": False,
    "check_updates": True,
    "skipped_update_tag": "",
}

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_LOG_FMT = "%(asctime)s  %(levelname)-5s  %(name)s: %(message)s"


def resource_path(rel_path: str) -> Path:
    """Resolve bundled data paths in both PyInstaller frozen mode and source tree."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / rel_path
        if candidate.exists():
            return candidate
    if IS_FROZEN and sys.executable:
        candidate = Path(sys.executable).resolve().parent / rel_path
        if candidate.exists():
            return candidate
    return PROJECT_ROOT / rel_path


def _standard_app_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME


def _exe_dir() -> Optional[Path]:
    try:
        base = sys.executable if IS_FROZEN else sys.argv[0]
    except Exception:
        return None
    if not base:
        return None
    try:
        p = Path(base).resolve(strict=False)
    except OSError:
        p = Path(os.path.realpath(base))
    return p.parent if p.is_file() or p.suffix else p


def _migrate_into_portable(portable_dir: Path) -> None:
    try:
        if any(portable_dir.iterdir()):
            return
    except OSError:
        return
    std = _standard_app_dir()
    if not std.exists():
        return
    try:
        for src in std.iterdir():
            if ".log" in src.name or src.is_dir():
                continue
            try:
                shutil.copy2(src, portable_dir / src.name)
            except OSError:
                pass
    except OSError:
        pass


def _detect_portable() -> Optional[Path]:
    exe_dir = _exe_dir()
    if exe_dir is None:
        return None
    portable_dir = exe_dir / PORTABLE_DIR_NAME
    if "--portable" in sys.argv:
        try:
            portable_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
    if portable_dir.is_dir():
        _migrate_into_portable(portable_dir)
        return portable_dir
    return None


def _app_dir() -> Path:
    return _detect_portable() or _standard_app_dir()


APP_DIR = _app_dir()
CONFIG_FILE = APP_DIR / "config.json"
LOG_FILE = APP_DIR / "proxy.log"
FIRST_RUN_MARKER = APP_DIR / ".first_run_done"


def ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def parse_worker_domains(raw: str) -> list[str]:
    """Parse one or more optional Cloudflare Worker domains from user input."""
    text = (raw or "").replace(",", " ").replace(";", " ")
    seen = set()
    result = []
    for token in text.split():
        dom = token.strip()
        low = dom.lower()
        if low.startswith("https://"):
            dom = dom[8:]
        elif low.startswith("http://"):
            dom = dom[7:]
        dom = dom.split("/", 1)[0].strip().rstrip(".")
        key = dom.lower()
        if not dom or "." not in dom or key in seen:
            continue
        seen.add(key)
        result.append(dom)
    return result


def sanitize_worker_domain(raw: str) -> str:
    return ", ".join(parse_worker_domains(raw))


def load_config() -> Dict[str, Any]:
    ensure_dirs()
    cfg: Optional[Dict[str, Any]] = None
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key, default_val in DEFAULT_CONFIG.items():
                    data.setdefault(key, deepcopy(default_val))
                cfg = data
        except Exception:
            cfg = None
    if cfg is None:
        cfg = deepcopy(DEFAULT_CONFIG)
        cfg["secret"] = os.urandom(16).hex()
    cfg["autostart"] = is_autostart_enabled()
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_dirs()
    CONFIG_FILE.write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def to_freetg_config(cfg: Dict[str, Any], *, stats_interval: float = 30.0) -> FreeTGConfig:
    domain = sanitize_worker_domain(str(cfg.get("worker_domain", DEFAULT_WORKER_DOMAIN)))
    mode = str(cfg.get("mode", "auto")).lower()
    if mode not in ("auto", "v1", "v2"):
        mode = "auto"
    bypass_mode = str(cfg.get("bypass_mode", "auto")).lower()
    if bypass_mode not in ("auto", "port80", "windivert", "windivert1", "tls_frag", "direct"):
        bypass_mode = "auto"
    if bypass_mode == "port80":
        frag_tls = False
        prefer_port80_cf = True
        allow_port80_fallback = True
    elif bypass_mode == "tls_frag":
        frag_tls = True
        prefer_port80_cf = False
        allow_port80_fallback = False
    elif bypass_mode in ("windivert", "windivert1", "direct"):
        frag_tls = False
        prefer_port80_cf = False
        allow_port80_fallback = False
    else:
        frag_tls = bool(cfg.get("frag_tls", False))
        prefer_port80_cf = False
        allow_port80_fallback = True
    return FreeTGConfig(
        host=str(cfg.get("host", "127.0.0.1")).strip() or "127.0.0.1",
        ports=[int(cfg.get("port", 1080))],
        secret_hex=normalize_secret(str(cfg.get("secret", DEFAULT_SECRET))).hex(),
        worker_domain=domain,
        mode=mode,
        pool_size=max(0, min(10, int(cfg.get("pool_size", 3)))),
        frag_tls=frag_tls,
        prefer_port80_cf=prefer_port80_cf,
        allow_port80_fallback=allow_port80_fallback,
        auto_tls_frag=False,
        stats_interval=stats_interval,
        verbose=bool(cfg.get("verbose", False)),
    )


def get_link_host(host: str) -> str:
    cleaned = (host or "").strip()
    if not cleaned or cleaned in ("0.0.0.0", "::"):
        return "127.0.0.1"
    return cleaned


def tg_proxy_url(cfg: Dict[str, Any]) -> str:
    host = get_link_host(str(cfg.get("host", DEFAULT_CONFIG["host"])))
    port = int(cfg.get("port", DEFAULT_CONFIG["port"]))
    try:
        secret = normalize_secret(str(cfg.get("secret", DEFAULT_CONFIG["secret"]))).hex()
    except ValueError:
        secret = DEFAULT_SECRET
    return f"tg://proxy?server={host}&port={port}&secret=dd{secret}"


def set_verbose_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger().setLevel(level)
    logging.getLogger("freetg").setLevel(level)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def setup_logging(
    verbose: bool = False,
    log_max_mb: float = 5,
    *,
    to_console: Optional[bool] = None,
) -> None:
    ensure_dirs()
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    max_bytes = max(256 * 1024, int(float(log_max_mb or 5) * 1024 * 1024))
    fh = RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=max_bytes,
        backupCount=1,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(_LOG_FMT, datefmt="%Y-%m-%d %H:%M:%S"))
    root.addHandler(fh)

    if to_console is None:
        to_console = not IS_FROZEN
    if to_console and sys.stdout is not None:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-5s  %(message)s", datefmt="%H:%M:%S"))
        root.addHandler(ch)

    set_verbose_logging(verbose)


def autostart_command() -> str:
    """Return the Windows Run registry command string for FreeTG."""
    if IS_FROZEN:
        return f'"{Path(sys.executable).resolve()}"'
    exe_path = Path(sys.executable).resolve()
    pythonw = exe_path.with_name("pythonw.exe")
    launcher = pythonw if pythonw.exists() else exe_path
    script = (PROJECT_ROOT / "windows_app.py").resolve()
    return f'"{launcher}" "{script}"'


def is_autostart_enabled() -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_NAME)
        expected = autostart_command().strip().lower()
        return str(val).strip().lower() == expected
    except (FileNotFoundError, OSError):
        return False


def set_autostart_enabled(enabled: bool) -> Tuple[bool, Optional[str]]:
    if winreg is None:
        return False, "Registry autostart is only supported on Windows."
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            if enabled:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, autostart_command())
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
        return True, None
    except OSError as exc:
        return False, str(exc)
