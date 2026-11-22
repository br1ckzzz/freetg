"""Embedded WinDivert / winws DPI desync manager with clean full-unload watchdog."""

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
from typing import List, Optional, Tuple

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

_WINWS_FILES: Tuple[str, ...] = (
    "winws.exe",
    "WinDivert.dll",
    "WinDivert64.sys",
    "cygwin1.dll",
    "stun2.bin",
    "tls_clienthello_www_sferum_ru.bin",
)

WINWS_RUNTIME_DIR = APP_DIR / "winws_bin"
WINWS_PID_FILE = WINWS_RUNTIME_DIR / "winws.pid"
WINWS_STOP_FILE = WINWS_RUNTIME_DIR / "stop.signal"
WINWS_ARGS_JSON = WINWS_RUNTIME_DIR / "winws_args.json"
WINWS_WATCHDOG_PS1 = WINWS_RUNTIME_DIR / "run_winws_watchdog.ps1"

_TH32CS_SNAPPROCESS = 0x00000002
_WAIT_TIMEOUT = 0x00000102
_STILL_ACTIVE = 259
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_FLAG_NO_UI = 0x00000400

_WATCHDOG_SCRIPT = r"""param(
    [int]$ParentPid,
    [string]$RuntimeDir,
    [string]$PidFile,
    [string]$StopFile,
    [string]$ArgsJsonPath
)
$ErrorActionPreference = 'SilentlyContinue'
$exePath = Join-Path $RuntimeDir 'winws.exe'

# Kill any stale winws.exe left running from our runtime directory
Get-CimInstance Win32_Process -Filter "Name='winws.exe'" | ForEach-Object {
    if ($_.ExecutablePath -and $_.ExecutablePath.Equals($exePath, [System.StringComparison]::OrdinalIgnoreCase)) {
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
    & sc.exe stop WinDivert 2>&1 | Out-Null
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
            if entry.szExeFile.lower() == "winws.exe":
                pids.append(int(entry.th32ProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return pids


def _quote_arg(arg: str) -> str:
    if not arg or any(ch in arg for ch in (' ', '\t', '"')):
        return '"' + arg.replace('"', '\\"') + '"'
    return arg


def _write_cf_ipset(worker_domain: str) -> Path:
    ensure_dirs()
    ips: List[str] = list(_CF_BASE_IPS)
    seen = set(ips)
    for dom in parse_worker_domains(worker_domain):
        try:
            for info in socket.getaddrinfo(dom, 443, family=socket.AF_INET):
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        except OSError:
            pass
    ipset_path = APP_DIR / "cf_ipset.txt"
    ipset_path.write_text("\n".join(ips) + "\n", encoding="ascii")
    return ipset_path


def _stage_winws_files() -> Tuple[Optional[Path], Optional[str]]:
    """Copy bundled winws/WinDivert binaries out of _MEIPASS into %APPDATA%\\FreeTG\\winws_bin."""
    ensure_dirs()
    src_dir = resource_path("assets/winws")
    missing = [name for name in _WINWS_FILES if not (src_dir / name).exists()]
    if missing:
        return None, f"Отсутствуют файлы встроенного winws: {', '.join(missing)}"

    WINWS_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    for name in _WINWS_FILES:
        src = src_dir / name
        dst = WINWS_RUNTIME_DIR / name
        try:
            if not dst.exists() or dst.stat().st_size != src.stat().st_size:
                shutil.copy2(src, dst)
        except OSError as exc:
            # If destination is currently locked by an active winws.exe already staged there,
            # reuse it cleanly rather than failing.
            if not dst.exists():
                return None, f"Не удалось подготовить {name}: {exc}"
    return WINWS_RUNTIME_DIR, None


def _read_pid_file() -> Optional[int]:
    try:
        if WINWS_PID_FILE.exists():
            raw = WINWS_PID_FILE.read_text(encoding="ascii").strip()
            if raw.isdigit():
                return int(raw)
    except OSError:
        pass
    return None


class BuiltinDesyncManager:
    """Starts and cleanly unloads the bundled winws.exe / WinDivert bypass."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._popen: Optional[subprocess.Popen] = None
        self._win_handle: Optional[int] = None
        self._pid: Optional[int] = None  # direct winws PID or elevated watchdog PID
        self._active_domain: Optional[str] = None

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
        for pid in _list_winws_pids():
            if pid not in own_pids:
                return True
        return False

    def _build_args(self, winws_dir: Path, worker_domain: str) -> List[str]:
        ipset_path = _write_cf_ipset(worker_domain)
        stun2 = winws_dir / "stun2.bin"
        sferum = winws_dir / "tls_clienthello_www_sferum_ru.bin"

        domains = ["workers.dev", "co.uk", "eu.cc"]
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
            "--dpi-desync-split-seqovl-pattern", str(stun2),
            "--dpi-desync-fake-tls", str(sferum),
        ]

        return [
            "--wf-tcp", "443",
            "--filter-tcp", "443",
            "--hostlist-domains", ",".join(domains),
            *desync_opts,
            "--new",
            "--filter-tcp", "443",
            "--ipset", str(ipset_path),
            *desync_opts,
        ]

    def start(self, worker_domain: str) -> Tuple[bool, Optional[str]]:
        """Ensure winws DPI desync is active (either external zapret or bundled winws.exe)."""
        if sys.platform != "win32":
            return False, "Встроенный WinDivert доступен только на Windows."

        clean_domain = sanitize_worker_domain(worker_domain)

        if self.is_external_winws_running():
            log.info("External zapret/winws.exe detected; skipping built-in winws launch")
            return True, "Используется внешний winws.exe (zapret)"

        with self._lock:
            if self._is_running_locked():
                if clean_domain == self._active_domain:
                    return True, None
                self._stop_locked()

            winws_dir, stage_err = _stage_winws_files()
            if winws_dir is None:
                return False, stage_err

            winws_exe = winws_dir / "winws.exe"
            try:
                args = self._build_args(winws_dir, clean_domain)
                if WINWS_STOP_FILE.exists():
                    WINWS_STOP_FILE.unlink()
                if WINWS_PID_FILE.exists():
                    WINWS_PID_FILE.unlink()
            except Exception as exc:
                return False, f"Не удалось подготовить параметры winws: {exc}"

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
                        return False, f"Встроенный winws.exe завершился сразу (код {rc})"
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
                        return False, f"Не удалось запустить встроенный winws.exe (ошибка Windows {err_code})"

                    if not sei.hProcess:
                        return False, "ShellExecuteExW не вернул дескриптор watchdog winws.exe"

                    kernel32 = ctypes.windll.kernel32
                    self._win_handle = int(sei.hProcess)
                    self._pid = int(kernel32.GetProcessId(sei.hProcess))

                    # Wait briefly (up to 4s) for elevated watchdog to write winws.pid
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
                                return False, f"Встроенный winws watchdog завершился (код {exit_code.value})"
                        time.sleep(0.1)

                self._active_domain = clean_domain
                log.info(
                    "Started built-in winws.exe (winws_pid=%s, watchdog_pid=%s, domain=%s)",
                    _read_pid_file(),
                    self._pid,
                    clean_domain,
                )
                return True, None
            except Exception as exc:
                self._stop_locked()
                return False, f"Ошибка запуска встроенного winws.exe: {exc}"

    def _stop_locked(self) -> None:
        winws_pid = _read_pid_file()
        had_anything = bool(self._popen or self._win_handle or winws_pid)

        # Signal elevated watchdog to terminate winws.exe + unload WinDivert cleanly
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

        # Wait up to 2.0s for the elevated watchdog to stop winws.exe & remove winws.pid
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
            log.info("Stopped built-in winws.exe (pid=%s)", winws_pid or self._pid)
        self._pid = None
        self._active_domain = None

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def yield_if_external_running(self) -> bool:
        """Stop built-in winws.exe if an external zapret/winws.exe process is active."""
        with self._lock:
            if not self._is_running_locked():
                return False
            own_pids = self._own_winws_pids()
        if any(pid not in own_pids for pid in _list_winws_pids()):
            log.info("External zapret/winws.exe started; stopping built-in winws.exe")
            self.stop()
            return True
        return False


desync_manager = BuiltinDesyncManager()
atexit.register(desync_manager.stop)
