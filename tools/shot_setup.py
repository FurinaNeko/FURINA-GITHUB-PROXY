import sys, time
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
import ctypes
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    ctypes.windll.user32.SetProcessDPIAware()

import tkinter as tk
import installer.installer as inst

root = tk.Tk(); root.geometry("800x700+40+40")
tr = inst.Tr("zh-CN")
gui = inst.SetupGui(root, inst.Installer(Path("dist"), inst.Log()), {
    "dir": r"C:\Users\FWZ\AppData\Local\Programs\FURINA-GITHUB-PROXY",
    "desktop": True, "ca": True, "hosts": False, "autostart": False,
    "start": False, "no_popup": True}, tr)

def shot():
    from PIL import ImageGrab
    root.lift(); root.attributes("-topmost", True); root.update(); time.sleep(0.7); root.update()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    ImageGrab.grab(bbox=(x, y, x + root.winfo_width(), y + root.winfo_height())).save("docs/setup-zh.png")
    root.destroy()

root.after(1100, shot); root.mainloop(); print("ok")
