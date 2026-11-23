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
    excludes=[
        'PyQt6',
        'PyQt5',
        'PySide6',
        'PIL',
        'Pillow',
        'pytest',
        'unittest',
        'pydoc',
        'doctest',
        'xmlrpc',
        'lib2to3',
        'setuptools',
        'pkg_resources',
        'distutils',
        'sqlite3',
    ],
    noarchive=False,
    optimize=0,
)

# Drop root-level duplicate cygwin1.dll (staged safely inside assets/winws/)
a.binaries = [b for b in a.binaries if os.path.basename(b[0]).lower() != 'cygwin1.dll']

# Drop bulky non-runtime Tcl/Tk tzdata & demo files
a.datas = [
    d for d in a.datas
    if not any(seg in d[0].replace('\\', '/').lower() for seg in ('/tzdata/', '/demos/', '/msgs/', '/images/'))
    or d[0].replace('\\', '/').lower().startswith('assets/')
]

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
