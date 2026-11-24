# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：小酱代理 单文件 exe（带自定义图标）。

    python -m PyInstaller --noconfirm --clean localproxy.spec
产物：dist/LocalProxy.exe
    - 图标 = assets/app.ico
    - 带控制台（CLI 可用）；双击不带参数时自动隐藏黑框、只显示图形界面
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve()
ICON = ROOT / "assets" / "app.ico"

# cryptography 是本地 CA 用到的，PyInstaller 的 hook 偶尔漏 Rust 扩展，这里显式收一遍
hidden = collect_submodules("cryptography")
data = (
    [(str(ICON), "assets"),
     (str(ROOT / "assets" / "app-256.png"), "assets"),
     (str(ROOT / "assets" / "about.json"), "assets"),
     (str(ROOT / "assets" / "i18n.json"), "assets"),
     (str(ROOT / "assets" / "sponsor-qr.png"), "assets")]
    + collect_data_files("cryptography")
)

a = Analysis(
    [str(ROOT / "run_localproxy.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=data,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "unittest", "pydoc_data", "lib2to3",
        "numpy", "pandas", "PIL", "lxml", "openpyxl", "docx", "pptx",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="FURINA-GITHUB-PROXY",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    icon=str(ICON),
    version=str(ROOT / "tools" / "version_app.txt"),
)
