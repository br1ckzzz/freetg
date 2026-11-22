# -*- mode: python ; coding: utf-8 -*-
import os
import sys

_libcrypto = os.path.join(sys.base_prefix, 'DLLs', 'libcrypto-3.dll')
_binaries = [(_libcrypto, '.')] if os.path.exists(_libcrypto) else []

a = Analysis(
    ['windows_app.py'],
    pathex=[],
    binaries=_binaries,
    datas=[('icon.ico', '.'), ('assets/logo.png', 'assets'), ('assets/winws', 'assets/winws')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='FreeTG',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
