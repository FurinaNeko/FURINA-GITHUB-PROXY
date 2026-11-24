# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：小酱代理 安装程序（单文件、自带运行时、无需管理员）。

前置：必须先打好 dist/LocalProxy.exe
    python -m PyInstaller --noconfirm --clean installer.spec
产物：dist/LocalProxy-Setup.exe
    - 图标与软件图标一致（assets/app.ico）
    - 双击打开安装界面；`--silent` 静默安装
"""

from pathlib import Path

ROOT = Path(SPECPATH).resolve()
ICON = ROOT / "assets" / "app.ico"
PAYLOAD = ROOT / "dist" / "FURINA-GITHUB-PROXY.exe"

if not PAYLOAD.exists():
    raise SystemExit("缺少 dist/FURINA-GITHUB-PROXY.exe，先执行 scripts\\build-exe.ps1")

datas = [
    (str(PAYLOAD), "payload"),
    (str(ICON), "payload/assets"),
    (str(ROOT / "assets" / "app-256.png"), "payload/assets"),
    (str(ROOT / "assets" / "about.json"), "payload/assets"),
    (str(ROOT / "assets" / "i18n.json"), "payload/assets"),
    (str(ROOT / "assets" / "sponsor-qr.png"), "payload/assets"),
    (str(ROOT / "README.md"), "payload"),
    (str(ROOT / "scripts" / "apply-hosts.ps1"), "payload/scripts"),
]

a = Analysis(
    [str(ROOT / "installer" / "installer.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=["tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["numpy", "pandas", "PIL", "lxml", "openpyxl", "cryptography"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="FURINA-GITHUB-PROXY-Setup",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # 图形安装器，不要黑框
    disable_windowed_traceback=False,
    icon=str(ICON),
    version=None,
    uac_admin=False,        # 按用户安装，不弹 UAC
)
