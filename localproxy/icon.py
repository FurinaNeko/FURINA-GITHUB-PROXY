"""给程序窗口挂上自定义图标（Windows）。

两条路径：
  1. 直接 python 跑：调用 Win32 给控制台窗口发 WM_SETICON；
  2. PyInstaller 打包：exe 资源里已经嵌入生成好的 assets/app.ico。
另外设置 AppUserModelID，让任务栏把窗口归到自己的图标组，而不是 python.exe。
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path

APP_ID = "localproxy.app.1"

WM_SETICON = 0x0080
ICON_SMALL = 0
ICON_BIG = 1
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
LR_DEFAULTSIZE = 0x0040


def resource_path(rel: str) -> Path:
    """兼容源码运行与 PyInstaller 解包目录。"""
    candidates = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidates.append(Path(base) / rel)
    here = Path(__file__).resolve().parent
    candidates.append(here.parent / rel)      # 仓库根目录 / assets/app.ico
    candidates.append(here / rel)
    candidates.append(Path.cwd() / rel)
    for item in candidates:
        if item.exists():
            return item
    return candidates[-1]


def icon_path() -> Path:
    import os

    override = os.environ.get("LOCALPROXY_ICON")
    if override and Path(override).exists():
        return Path(override)
    return resource_path("assets/app.ico")


def apply_icon(path: str | Path | None = None, verbose: bool = False) -> bool:
    """把窗口图标换成自定义 ico；失败不抛异常（图标只是装饰）。"""
    if not sys.platform.startswith("win"):
        return False
    target = Path(path) if path else icon_path()
    if not target.exists():
        if verbose:
            print(f"[icon] 找不到图标文件：{target}")
        return False
    try:
        user32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        shell32 = ctypes.windll.shell32

        shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [ctypes.c_wchar_p]
        shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
        shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)

        user32.LoadImageW.restype = ctypes.c_void_p
        user32.LoadImageW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint,
            ctypes.c_int, ctypes.c_int, ctypes.c_uint,
        ]
        user32.SendMessageW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p,
        ]
        user32.SendMessageW.restype = ctypes.c_void_p
        k32.GetConsoleWindow.restype = ctypes.c_void_p

        hwnd = k32.GetConsoleWindow()
        flags = LR_LOADFROMFILE | LR_DEFAULTSIZE
        big = user32.LoadImageW(None, str(target), IMAGE_ICON, 0, 0, flags)
        small = user32.LoadImageW(None, str(target), IMAGE_ICON, 16, 16,
                                  LR_LOADFROMFILE)
        if not hwnd:
            if verbose:
                print("[icon] 没有控制台窗口，图标已交给 exe 资源")
            return False
        if big:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, big)
        if small:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small)
        # 顺带改窗口标题栏大字标
        k32.SetConsoleTitleW("localproxy — 本地代理")
        if verbose:
            print(f"[icon] 已应用 {target}")
        return True
    except Exception as exc:  # noqa: BLE001
        if verbose:
            print(f"[icon] 应用失败：{exc}")
        return False


def describe() -> dict:
    p = icon_path()
    return {"app_id": APP_ID, "path": str(p), "exists": p.exists(), "platform": sys.platform}


if __name__ == "__main__":
    print(describe())
    print("applied:", apply_icon(verbose=True))
