"""Embedded zapret2 (winws2 + Lua) DPI desync manager with safe coexistence & cleanup."""

from __future__ import annotations

import atexit
import ctypes
import ctypes.wintypes as wintypes
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .app_config import APP_DIR, ensure_dirs, parse_worker_domains, resource_path, sanitize_worker_domain

log = logging.getLogger("freetg.desync")

_CF_BASE_IPS: Tuple[str, ...] = (
    "162.159.152.4",
    "162.159.135.42",
    "104.18.32.47",
    "141.101.90.96",
    "104.17.112.188",
    "104.21.61.51",
    "172.67.206.124",
)

_WINWS2_FILES: Tuple[str, ...] = (
    "winws2.exe",
    "WinDivert.dll",
    "WinDivert64.sys",
    "cygwin1.dll",
    "lua/zapret-lib.lua",
    "lua/zapret-antidpi.lua",
)

_WINWS1_FILES: Tuple[str, ...] = (
    "winws.exe",
    "WinDivert.dll",
    "WinDivert64.sys",
    "cygwin1.dll",
    "stun2.bin",
    "tls_clienthello_www_sferum_ru.bin",
)

ZAPRET2_PROFILE_ORDER: Tuple[str, ...] = (
    "z2_md5_disorder",
    "z2_autottl_fakedsplit",
    "z2_disorder_only",
)

ZAPRET2_PROFILE_LABELS: Dict[str, str] = {
    "z2_md5_disorder": "md5 + multidisorder",
    "z2_autottl_fakedsplit": "autottl + fakedsplit",
    "z2_disorder_only": "multidisorder (без фейков, для роутера/NAT)",
}

ZAPRET2_PROFILES: Dict[str, Tuple[str, ...]] = {
    "z2_md5_disorder": (
        "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6",
        "--lua-desync=multidisorder:pos=1,midsld",
    ),
    "z2_autottl_fakedsplit": (
        "--lua-desync=fake:blob=fake_default_tls:ip_autottl=-2,3-20:tcp_md5",
        "--lua-desync=fakedsplit:pos=1,midsld:ip_autottl=-2,3-20:tcp_md5",
    ),
    "z2_disorder_only": (
        "--lua-desync=multidisorder:pos=1,midsld",
    ),
}

WINWS_RUNTIME_DIR = APP_DIR / "winws_bin"
WINWS_PID_FILE = WINWS_RUNTIME_DIR / "winws.pid"
WINWS_STOP_FILE = WINWS_RUNTIME_DIR / "stop.signal"
WINWS_ARGS_JSON = WINWS_RUNTIME_DIR / "winws_args.json"
WINWS_WATCHDOG_PS1 = WINWS_RUNTIME_DIR / "run_winws_watchdog.ps1"

_WINWS_EXE_NAMES = frozenset({"winws.exe", "winws2.exe"})
_TH32CS_SNAPPROCESS = 0x00000002
_WAIT_TIMEOUT = 0x00000102
_STILL_ACTIVE = 259
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_FLAG_NO_UI = 0x00000400

_WATCHDOG_SCRIPT = r"""param(
    [int]$ParentPid,
    [string]$RuntimeDir,
    [string]$ExeName,
    [string]$PidFile,
    [string]$StopFile,
    [string]$ArgsJsonPath
)
$ErrorActionPreference = 'SilentlyContinue'
$exePath = Join-Path $RuntimeDir $ExeName

# Kill any stale own winws/winws2 left running from our runtime directory
Get-CimInstance Win32_Process -Filter "Name='winws.exe' OR Name='winws2.exe'" | ForEach-Object {
    if ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($RuntimeDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

$rawArgs = @(Get-Content -Raw -Encoding UTF8 $ArgsJsonPath | ConvertFrom-Json)
$quotedArgs = ($rawArgs | ForEach-Object {
    $s = [string]$_
    if ($s -match '[\s"]') { '"' + $s.Replace('"', '\"') + '"' } else { $s }
}) -join ' '
if (Test-Path $StopFile) { Remove-Item -Force $StopFile -ErrorAction SilentlyContinue }
if (Test-Path $PidFile) { Remove-Item -Force $PidFile -ErrorAction SilentlyContinue }

$proc = Start-Process -FilePath $exePath -ArgumentList $quotedArgs -WorkingDirectory $RuntimeDir -WindowStyle Hidden -PassThru
if (-not $proc) { exit 1 }
[System.IO.File]::WriteAllText($PidFile, [string]$proc.Id)

try {
    while (-not $proc.HasExited) {
        if (Test-Path $StopFile) { break }
        $parent = Get-Process -Id $ParentPid -ErrorAction SilentlyContinue
        if (-not $parent) { break }
        Start-Sleep -Milliseconds 350
        $proc.Refresh()
    }
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    $others = @(Get-CimInstance Win32_Process -Filter "Name='winws.exe' OR Name='winws2.exe'" | Where-Object {
        $_.ProcessId -ne $proc.Id
    })
    if ($others.Count -eq 0) {
        & sc.exe stop WinDivert 2>&1 | Out-Null
    }
    Remove-Item -Force $PidFile -ErrorAction SilentlyContinue
    Remove-Item -Force $StopFile -ErrorAction SilentlyContinue
}
"""


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def is_user_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _list_winws_pids() -> List[int]:
    """Return PIDs of all running winws.exe and winws2.exe processes."""
    if sys.platform != "win32":
        return []
    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value or not snap:
        return []
    pids: List[int] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() in _WINWS_EXE_NAMES:
                pids.append(int(entry.th32ProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return pids


def _quote_arg(arg: str) -> str:
    if not arg or any(ch in arg for ch in (" ", "\t", '"')):
        return '"' + arg.replace('"', '\\"') + '"'
    return arg


def _write_cf_lists(worker_domain: str, target_dir: Path) -> Tuple[Path, Path]:
    """Write cf_ipset.txt and cf_domains.txt inside target_dir for relative Cygwin-safe paths."""
    target_dir.mkdir(parents=True, exist_ok=True)
    ips: List[str] = list(_CF_BASE_IPS)
    seen_ips = set(ips)
    for dom in parse_worker_domains(worker_domain):
        try:
            for info in socket.getaddrinfo(dom, 443, family=socket.AF_INET):
                ip = info[4][0]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    ips.append(ip)
        except OSError:
            pass
    ipset_path = target_dir / "cf_ipset.txt"
    ipset_path.write_text("\n".join(ips) + "\n", encoding="ascii")

    domains = ["workers.dev", "co.uk"]
    for clean_dom in parse_worker_domains(worker_domain):
        low = clean_dom.lower()
        if not any(low == d or low.endswith("." + d) for d in domains):
            domains.append(low)
    domains_path = target_dir / "cf_domains.txt"
    domains_path.write_text("\n".join(domains) + "\n", encoding="ascii")
    return ipset_path, domains_path


def _stage_winws_files(engine: str = "zapret2") -> Tuple[Optional[Path], Optional[str]]:
    """Copy bundled zapret binaries and Lua modules into %APPDATA%\\FreeTG\\winws_bin."""
    ensure_dirs()
    src_dir = resource_path("assets/winws")
    required = _WINWS1_FILES if engine == "zapret1" else _WINWS2_FILES
    missing = [name for name in required if not (src_dir / name).exists()]
    if missing:
        return None, f"Отсутствуют файлы встроенного {engine}: {', '.join(missing)}"

    WINWS_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    for name in required:
        src = src_dir / name
        dst = WINWS_RUNTIME_DIR / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not dst.exists() or dst.stat().st_size != src.stat().st_size:
                shutil.copy2(src, dst)
        except OSError as exc:
            if not dst.exists():
                return None, f"Не удалось подготовить {name}: {exc}"
    return WINWS_RUNTIME_DIR, None


def has_bundled_engine(engine: str) -> bool:
    src_dir = resource_path("assets/winws")
    required = _WINWS1_FILES if engine == "zapret1" else _WINWS2_FILES
    return all((src_dir / name).exists() for name in required)


def _read_pid_file() -> Optional[int]:
    try:
        if WINWS_PID_FILE.exists():
            raw = WINWS_PID_FILE.read_text(encoding="ascii").strip()
            if raw.isdigit():
                return int(raw)
    except OSError:
        pass
    return None


def _normalize_profile(profile: str) -> str:
    p = (profile or "").strip().lower()
    if p in ZAPRET2_PROFILES:
        return p
    return ZAPRET2_PROFILE_ORDER[0]


def _build_zapret2_args(winws_dir: Path, worker_domain: str, profile: str) -> List[str]:
    _write_cf_lists(worker_domain, winws_dir)
    prof = _normalize_profile(profile)
    desync_calls = list(ZAPRET2_PROFILES[prof])

    return [
        "--wf-tcp-out=443",
        "--lua-init=@lua/zapret-lib.lua",
        "--lua-init=@lua/zapret-antidpi.lua",
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist=cf_domains.txt",
        "--out-range=-d10",
        "--payload=tls_client_hello",
        *desync_calls,
        "--new",
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--ipset=cf_ipset.txt",
        "--out-range=-d10",
        "--payload=tls_client_hello",
        *desync_calls,
    ]


def _build_zapret1_args(winws_dir: Path, worker_domain: str) -> List[str]:
    ipset_path, _ = _write_cf_lists(worker_domain, winws_dir)
    domains = ["workers.dev", "co.uk"]
    for clean_dom in parse_worker_domains(worker_domain):
        low = clean_dom.lower()
        if not any(low == d or low.endswith("." + d) for d in domains):
            domains.append(low)

    desync_opts = [
        "--dpi-desync", "fake,multisplit",
        "--dpi-desync-split-seqovl", "480",
        "--dpi-desync-split-pos", "1",
        "--dpi-desync-fooling", "ts",
        "--dpi-desync-repeats", "4",
        "--dpi-desync-split-seqovl-pattern", "stun2.bin",
        "--dpi-desync-fake-tls", "tls_clienthello_www_sferum_ru.bin",
    ]
    return [
        "--wf-tcp", "443",
        "--filter-tcp", "443",
        "--hostlist-domains", ",".join(domains),
        *desync_opts,
        "--new",
        "--filter-tcp", "443",
        "--ipset", ipset_path.name,
        *desync_opts,
    ]


class BuiltinDesyncManager:
    """Starts and cleanly unloads embedded zapret2 (winws2.exe) or zapret1 (winws.exe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._popen: Optional[subprocess.Popen] = None
        self._win_handle: Optional[int] = None
        self._pid: Optional[int] = None
        self._active_domain: Optional[str] = None
        self._active_profile: Optional[str] = None
        self._active_engine: Optional[str] = None

    @property
    def active_engine(self) -> Optional[str]:
        return self._active_engine

    @property
    def active_profile(self) -> Optional[str]:
        return self._active_profile

    def _own_winws_pids(self) -> set[int]:
        pids = set()
        if self._popen is not None and self._pid:
            pids.add(self._pid)
        file_pid = _read_pid_file()
        if file_pid:
            pids.add(file_pid)
        return pids

    def is_running(self) -> bool:
        with self._lock:
            return self._is_running_locked()

    def _is_running_locked(self) -> bool:
        if self._popen is not None:
            if self._popen.poll() is None:
                return True
            self._popen = None
            self._pid = None
        if self._win_handle:
            res = ctypes.windll.kernel32.WaitForSingleObject(self._win_handle, 0)
            if res == _WAIT_TIMEOUT:
                return True
            ctypes.windll.kernel32.CloseHandle(self._win_handle)
            self._win_handle = None
            self._pid = None
        file_pid = _read_pid_file()
        if file_pid and file_pid in _list_winws_pids():
            return True
        return False

    def is_external_winws_running(self) -> bool:
        with self._lock:
            running = self._is_running_locked()
            own_pids = self._own_winws_pids() if running else set()
        return any(pid not in own_pids for pid in _list_winws_pids())

    def _build_args(
        self, winws_dir: Path, worker_domain: str, *, profile: str, engine: str
    ) -> List[str]:
        if engine == "zapret1":
            return _build_zapret1_args(winws_dir, worker_domain)
        return _build_zapret2_args(winws_dir, worker_domain, profile)

    def start(
        self,
        worker_domain: str,
        *,
        profile: str = "z2_md5_disorder",
        engine: str = "zapret2",
    ) -> Tuple[bool, Optional[str]]:
        """Ensure DPI desync is active (yields if an external winws/winws2 is running)."""
        if sys.platform != "win32":
            return False, "Встроенный WinDivert доступен только на Windows."

        clean_domain = sanitize_worker_domain(worker_domain)
        eff_engine = "zapret1" if engine == "zapret1" else "zapret2"
        eff_profile = "z1_legacy" if eff_engine == "zapret1" else _normalize_profile(profile)
        exe_name = "winws.exe" if eff_engine == "zapret1" else "winws2.exe"

        if self.is_external_winws_running():
            log.info("External zapret/zapret2 process detected; skipping built-in launch")
            return True, "Используется внешний zapret"

        with self._lock:
            if self._is_running_locked():
                if (
                    clean_domain == self._active_domain
                    and eff_profile == self._active_profile
                    and eff_engine == self._active_engine
                ):
                    return True, None
                self._stop_locked()

            winws_dir, stage_err = _stage_winws_files(eff_engine)
            if winws_dir is None:
                return False, stage_err

            winws_exe = winws_dir / exe_name
            try:
                args = self._build_args(
                    winws_dir, clean_domain, profile=eff_profile, engine=eff_engine
                )
                if WINWS_STOP_FILE.exists():
                    WINWS_STOP_FILE.unlink()
                if WINWS_PID_FILE.exists():
                    WINWS_PID_FILE.unlink()
            except Exception as exc:
                return False, f"Не удалось подготовить параметры {exe_name}: {exc}"

            try:
                if is_user_admin():
                    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    proc = subprocess.Popen(
                        [str(winws_exe), *args],
                        cwd=str(winws_dir),
                        creationflags=flags,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    self._popen = proc
                    self._pid = int(proc.pid)
                    try:
                        WINWS_PID_FILE.write_text(str(self._pid), encoding="ascii")
                    except OSError:
                        pass
                    time.sleep(0.35)
                    if proc.poll() is not None:
                        rc = proc.returncode
                        self._popen = None
                        self._pid = None
                        return False, f"Встроенный {exe_name} завершился сразу (код {rc})"
                else:
                    WINWS_ARGS_JSON.write_text(
                        json.dumps(args, ensure_ascii=False), encoding="utf-8"
                    )
                    WINWS_WATCHDOG_PS1.write_text(_WATCHDOG_SCRIPT, encoding="utf-8")

                    ps_params = " ".join(
                        _quote_arg(p)
                        for p in (
                            "-NoProfile",
                            "-WindowStyle", "Hidden",
                            "-ExecutionPolicy", "Bypass",
                            "-File", str(WINWS_WATCHDOG_PS1),
                            "-ParentPid", str(os.getpid()),
                            "-RuntimeDir", str(winws_dir),
                            "-ExeName", exe_name,
                            "-PidFile", str(WINWS_PID_FILE),
                            "-StopFile", str(WINWS_STOP_FILE),
                            "-ArgsJsonPath", str(WINWS_ARGS_JSON),
                        )
                    )

                    sei = _SHELLEXECUTEINFOW()
                    sei.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
                    sei.fMask = _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_FLAG_NO_UI
                    sei.lpVerb = "runas"
                    sei.lpFile = "powershell.exe"
                    sei.lpParameters = ps_params
                    sei.lpDirectory = str(winws_dir)
                    sei.nShow = 0  # SW_HIDE

                    shell32 = ctypes.windll.shell32
                    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
                    shell32.ShellExecuteExW.restype = wintypes.BOOL
                    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
                        err_code = ctypes.windll.kernel32.GetLastError()
                        if err_code == 1223:  # ERROR_CANCELLED
                            return False, "Запрос прав администратора (UAC) для обхода ТСПУ отклонён пользователем."
                        return False, f"Не удалось запустить встроенный {exe_name} (ошибка Windows {err_code})"

                    if not sei.hProcess:
                        return False, f"ShellExecuteExW не вернул дескриптор watchdog {exe_name}"

                    kernel32 = ctypes.windll.kernel32
                    self._win_handle = int(sei.hProcess)
                    self._pid = int(kernel32.GetProcessId(sei.hProcess))

                    deadline = time.monotonic() + 4.0
                    while time.monotonic() < deadline:
                        if WINWS_PID_FILE.exists():
                            break
                        exit_code = wintypes.DWORD(0)
                        if kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code)):
                            if exit_code.value != _STILL_ACTIVE:
                                kernel32.CloseHandle(sei.hProcess)
                                self._win_handle = None
                                self._pid = None
                                return False, f"Встроенный {exe_name} watchdog завершился (код {exit_code.value})"
                        time.sleep(0.1)

                self._active_domain = clean_domain
                self._active_profile = eff_profile
                self._active_engine = eff_engine
                log.info(
                    "Started built-in %s (pid=%s, profile=%s, domain=%s)",
                    exe_name,
                    _read_pid_file(),
                    eff_profile,
                    clean_domain,
                )
                return True, None
            except Exception as exc:
                self._stop_locked()
                return False, f"Ошибка запуска встроенного {exe_name}: {exc}"

    def _stop_locked(self) -> None:
        winws_pid = _read_pid_file()
        had_anything = bool(self._popen or self._win_handle or winws_pid)

        try:
            if WINWS_RUNTIME_DIR.exists():
                WINWS_STOP_FILE.write_text("stop", encoding="ascii")
        except OSError:
            pass

        if self._popen is not None:
            try:
                if self._popen.poll() is None:
                    self._popen.terminate()
                    self._popen.wait(timeout=2.0)
            except Exception:
                try:
                    self._popen.kill()
                except Exception:
                    pass
            self._popen = None
            if is_user_admin():
                other_pids = [p for p in _list_winws_pids() if p != winws_pid]
                if not other_pids:
                    try:
                        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                        subprocess.run(
                            ["sc.exe", "stop", "WinDivert"],
                            creationflags=flags,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=2.0,
                        )
                    except Exception:
                        pass

        if self._win_handle or (winws_pid and winws_pid in _list_winws_pids()):
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if not WINWS_PID_FILE.exists() and (not winws_pid or winws_pid not in _list_winws_pids()):
                    break
                time.sleep(0.1)

        if self._win_handle:
            kernel32 = ctypes.windll.kernel32
            try:
                kernel32.WaitForSingleObject(self._win_handle, 500)
                kernel32.CloseHandle(self._win_handle)
            except Exception:
                pass
            self._win_handle = None

        for stale in (WINWS_PID_FILE, WINWS_STOP_FILE):
            try:
                if stale.exists():
                    stale.unlink()
            except OSError:
                pass

        if had_anything:
            log.info("Stopped built-in %s (pid=%s)", self._active_engine or "winws", winws_pid or self._pid)
        self._pid = None
        self._active_domain = None
        self._active_profile = None
        self._active_engine = None

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def yield_if_external_running(self) -> bool:
        """Stop built-in process if an external zapret/zapret2 process appears."""
        with self._lock:
            if not self._is_running_locked():
                return False
            own_pids = self._own_winws_pids()
        if any(pid not in own_pids for pid in _list_winws_pids()):
            log.info("External zapret/zapret2 detected; stopping built-in %s", self._active_engine or "winws")
            self.stop()
            return True
        return False


desync_manager = BuiltinDesyncManager()
atexit.register(desync_manager.stop)
