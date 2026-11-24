"""FURINA-GITHUB-PROXY 安装程序（自带运行时的单文件 exe）。

设计目标：干净的 Windows 10/11 x64 上双击即装，不需要 Python、不需要 pip、
默认按用户安装到 %LOCALAPPDATA%，不弹 UAC。

命令行：
    FURINA-GITHUB-PROXY-Setup.exe                  # 图形界面
    ... --silent                                   # 静默安装（默认选项）
    ... --silent --dir D:\\Apps\\FURINA-GITHUB-PROXY
    ... --silent --uninstall
    ... --silent --ca --hosts --autostart
    ... --lang zh-CN --silent                      # 指定界面语言
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import winreg
from datetime import datetime
from pathlib import Path

APP_NAME = "FURINA-GITHUB-PROXY"
EXE_NAME = "FURINA-GITHUB-PROXY.exe"
DEFAULT_VERSION = "1.0.0"
AUTHOR_QQ = "2252296536"
GITHUB_URL = "https://github.com/FurinaNeko/FURINA-GITHUB-PROXY"
GITHUB_USER = "https://github.com/FurinaNeko"

UNINSTALL_KEY = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{APP_NAME}"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

FALLBACK_APP = {
    "title": "FURINA-GITHUB-PROXY {version} Setup",
    "headline": "FURINA-GITHUB-PROXY",
    "subtitle": "Local SOCKS5/HTTP proxy + GitHub & HuggingFace acceleration",
    "dir": "Install folder", "browse": "Browse…", "options": "Options",
    "opt_desktop": "Create a desktop shortcut",
    "opt_ca": "Install the root CA into CurrentUser → Trusted Root",
    "opt_hosts": "Write system hosts (administrator; removed on uninstall)",
    "opt_autostart": "Start with Windows", "opt_start": "Launch after installation",
    "install": "Install", "uninstall": "Uninstall", "exit": "Exit",
    "done": "—— finished ——", "failed": "—— not completed, see the log ——",
    "language": "Language", "link": "GitHub",
    "log_welcome": "Setup {version}\nDefault folder: {dir}",
    "mkdir_ok": "Folder created: {path}",
    "mkdir_fail": "Cannot create folder: {error}",
    "support_title": "Installation complete",
    "support_head": "Installation complete — thanks!",
    "support_qq": "Author QQ: {qq}", "support_tip": "",
    "support_github": "GitHub", "support_copy": "Copy QQ {qq}",
    "support_copied": "Copied ✓", "support_close": "Close",
}

TEMPLATE_CONFIG = {
    "log_level": "info",
    "ui": {"language": "en"},
    "listeners": {
        "socks5": {"enabled": True, "host": "127.0.0.1", "port": 7890},
        "http": {"enabled": True, "host": "127.0.0.1", "port": 7891},
        "api": {"enabled": True, "host": "127.0.0.1", "port": 7892},
    },
    "dns": {"mode": "doh", "doh_url": "https://1.1.1.1/dns-query",
            "cache_ttl": 300, "timeout": 3},
    "timeouts": {"connect": 8, "handshake": 10, "idle": 300},
    "health": {"interval": 30, "timeout": 4, "fail_threshold": 2, "cooldown": 20},
    "accelerator": {
        "enabled": False, "mode": "mitm", "host": "127.0.0.1", "port": 443,
        "ca_dir": "certs", "upstream_verify": True, "upstream_port": 443,
        "ip_overrides": {}, "strip_csp": True,
    },
    "upstreams": [
        {"name": "direct", "type": "direct"},
        {"name": "socks-local", "type": "socks5", "server": "127.0.0.1", "port": 1080},
        {"name": "http-local", "type": "http", "server": "127.0.0.1", "port": 10809},
    ],
    "groups": {
        "PROXY": {"type": "latency", "members": ["socks-local", "http-local", "direct"]},
    },
    "rules": [
        "DOMAIN-SUFFIX,github.com,PROXY",
        "DOMAIN-SUFFIX,githubusercontent.com,PROXY",
        "DOMAIN-SUFFIX,githubassets.com,PROXY",
        "DOMAIN-SUFFIX,ghcr.io,PROXY",
        "DOMAIN-SUFFIX,huggingface.co,PROXY",
        "DOMAIN-SUFFIX,hf.co,PROXY",
        "DOMAIN,cas-bridge.xethub.hf.co,PROXY",
        "DOMAIN,cas-server.huggingface.co,PROXY",
        "DOMAIN,cdn-lfs.huggingface.co,PROXY",
        "DOMAIN-SUFFIX,pypi.org,PROXY",
        "DOMAIN-SUFFIX,pythonhosted.org,PROXY",
        "DOMAIN-SUFFIX,npmjs.org,PROXY",
        "DOMAIN-SUFFIX,googleapis.com,PROXY",
        "DOMAIN-SUFFIX,gstatic.com,PROXY",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "FINAL,DIRECT",
    ],
    "final": "DIRECT",
}


# --------------------------------------------------------------------------
# 路径 / 元信息 / 语言
# --------------------------------------------------------------------------

def payload_root() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "payload"
    return Path(__file__).resolve().parent.parent


def default_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / APP_NAME


def state_dir() -> Path:
    path = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def _read_json(path: Path, fallback: dict) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                return {**fallback, **data}
    except Exception:  # noqa: BLE001
        pass
    return dict(fallback)


def about() -> dict:
    return _read_json(payload_root() / "assets" / "about.json", {
        "name": APP_NAME, "display_name": APP_NAME, "version": DEFAULT_VERSION,
        "author_qq": AUTHOR_QQ, "project_url": GITHUB_URL, "github_url": GITHUB_USER,
    })


def catalog() -> dict:
    return _read_json(payload_root() / "assets" / "i18n.json", {
        "languages": [{"code": "en", "label": "English"}],
        "installer": {"en": FALLBACK_APP},
    })


class Tr:
    """安装器自己的小翻译器（不依赖 localproxy 包）。"""

    def __init__(self, lang: str = "en"):
        self.cat = catalog()
        self.langs = list(self.cat.get("languages") or [{"code": "en", "label": "English"}])
        section = self.cat.get("installer") or {}
        codes = set(section)
        self.lang = lang if lang in codes else "en"
        self.table = section.get(self.lang) or {}
        self.fallback = section.get("en") or FALLBACK_APP

    def set_language(self, lang: str) -> None:
        self.__init__(lang)

    def __call__(self, key: str, **kw) -> str:
        text = self.table.get(key) or self.fallback.get(key) or FALLBACK_APP.get(key, key)
        if kw:
            try:
                return text.format(**kw)
            except (KeyError, IndexError, ValueError):
                return text
        return text


def load_language() -> str:
    data = _read_json(state_dir() / "installer.json", {"language": "en"})
    return str(data.get("language") or "en")


def save_language(lang: str) -> None:
    try:
        (state_dir() / "installer.json").write_text(
            json.dumps({"language": lang}, ensure_ascii=False, indent=2),
            encoding="utf-8")
    except OSError:
        pass


class Log:
    def __init__(self):
        self.lines: list[str] = []
        self.file = state_dir() / "install.log"

    def __call__(self, message: str) -> None:
        self.lines.append(message)
        try:
            print(message, flush=True)
        except Exception:  # noqa: BLE001
            pass
        try:
            with self.file.open("a", encoding="utf-8") as fh:
                fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")
        except OSError:
            pass


# --------------------------------------------------------------------------
# 安装 / 卸载
# --------------------------------------------------------------------------

class Installer:
    def __init__(self, target: Path, log: Log):
        self.target = Path(target)
        self.log = log
        self.exe = self.target / EXE_NAME

    def install(self, *, desktop: bool = True, ca: bool = True, hosts: bool = False,
                autostart: bool = False, start_now: bool = False) -> bool:
        src = payload_root()
        if not (src / EXE_NAME).exists():
            self.log(f"payload missing: {src / EXE_NAME}")
            return False

        self.target.mkdir(parents=True, exist_ok=True)
        self.log(f"install dir: {self.target}")
        self._copy(src / EXE_NAME, self.exe)
        (self.target / "assets").mkdir(exist_ok=True)
        for name in ("app.ico", "app-256.png", "about.json", "i18n.json"):
            if (src / "assets" / name).exists():
                self._copy(src / "assets" / name, self.target / "assets" / name)
        if (src / "README.md").exists():
            self._copy(src / "README.md", self.target / "README.md")
        (self.target / "scripts").mkdir(exist_ok=True)
        if (src / "scripts" / "apply-hosts.ps1").exists():
            self._copy(src / "scripts" / "apply-hosts.ps1",
                       self.target / "scripts" / "apply-hosts.ps1")

        cfg = self.target / "config.json"
        if cfg.exists():
            self.log("keeping existing config.json")
        else:
            cfg.write_text(json.dumps(TEMPLATE_CONFIG, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
            self.log("wrote default config.json")

        self._shortcut(desktop)
        self._registry(autostart)
        if ca:
            self._install_ca()
        if hosts:
            self._apply_hosts()
        if start_now:
            self._start()
        self.log("install done")
        return True

    def _copy(self, src: Path, dst: Path) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(3):
            try:
                shutil.copy2(src, dst)
                return
            except PermissionError:
                if attempt == 2:
                    raise
                subprocess.run(["taskkill", "/f", "/im", EXE_NAME],
                               capture_output=True, check=False)

    def _shortcut(self, desktop: bool) -> None:
        title = about().get("display_name") or APP_NAME
        folders = [Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu"
                   / "Programs" / APP_NAME]
        if desktop:
            desk = Path(os.environ.get("USERPROFILE", Path.home())) / "Desktop"
            if desk.exists():
                folders.append(desk)
        for folder in folders:
            folder.mkdir(parents=True, exist_ok=True)
            lnk = folder / f"{title}.lnk"
            try:
                _make_lnk(lnk, target=self.exe, args="run -c config.json",
                          workdir=self.target,
                          icon=self.target / "assets" / "app.ico",
                          description=f"{title} · local SOCKS5/HTTP proxy")
                self.log(f"shortcut: {lnk}")
            except Exception as exc:  # noqa: BLE001
                self.log(f"shortcut failed ({lnk}): {exc}")

    def _registry(self, autostart: bool) -> None:
        size = sum(f.stat().st_size for f in self.target.rglob("*") if f.is_file())
        meta = about()
        exe_path = Path(sys.argv[0]).resolve() if getattr(sys, "frozen", False) else Path(sys.argv[0])
        uninstall_cmd = f'"{exe_path}" --uninstall'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ,
                              meta.get("display_name") or APP_NAME)
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ,
                              meta.get("version") or DEFAULT_VERSION)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ,
                              meta.get("author") or "FurinaNeko")
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(self.target))
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ,
                              str(self.target / "assets" / "app.ico"))
            winreg.SetValueEx(key, "URLInfoAbout", 0, winreg.REG_SZ,
                              meta.get("project_url") or GITHUB_URL)
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall_cmd)
            winreg.SetValueEx(key, "QuietUninstallString", 0, winreg.REG_SZ,
                              uninstall_cmd + " --silent")
            winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, int(size // 1024))
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
        self.log("registered in Apps & features")

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
            if autostart:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ,
                                  f'"{self.exe}" run -c config.json')
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass

    def _install_ca(self) -> None:
        try:
            init = subprocess.run([str(self.exe), "cert", "init", "-c", "config.json"],
                                  cwd=self.target, capture_output=True, text=True, timeout=180)
            if init.returncode != 0:
                self.log("CA init failed: " + (init.stderr or init.stdout).strip()[:200])
                return
            trust = subprocess.run([str(self.exe), "cert", "trust", "-c", "config.json"],
                                   cwd=self.target, capture_output=True, text=True, timeout=180)
            out = (trust.stdout or trust.stderr).strip().splitlines()
            self.log("CA: " + (out[-1] if out else "done"))
        except Exception as exc:  # noqa: BLE001
            self.log(f"CA error: {exc}")

    def _apply_hosts(self) -> None:
        script = self.target / "scripts" / "apply-hosts.ps1"
        if not script.exists():
            self.log("apply-hosts.ps1 missing, skipped")
            return
        ok = _shell_runas("powershell.exe",
                          f'-NoProfile -ExecutionPolicy Bypass -File "{script}" -Apply')
        self.log(f"hosts: {'submitted' if ok else 'cancelled'}")

    def _start(self) -> None:
        try:
            subprocess.Popen([str(self.exe), "run", "-c", "config.json"],
                             cwd=self.target, close_fds=True)
            self.log("launched app")
        except Exception as exc:  # noqa: BLE001
            self.log(f"launch failed: {exc}")

    def uninstall(self, remove_ca: bool = True) -> bool:
        self.log(f"uninstall: {self.target}")
        if remove_ca and self.exe.exists():
            try:
                subprocess.run([str(self.exe), "cert", "untrust", "-c", "config.json"],
                               cwd=self.target, capture_output=True, text=True, timeout=90)
                self.log("root CA removed from trust store")
            except Exception:  # noqa: BLE001
                pass

        title = about().get("display_name") or APP_NAME
        for folder in (
            Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu"
            / "Programs" / APP_NAME,
            Path(os.environ.get("USERPROFILE", Path.home())) / "Desktop",
        ):
            for name in (f"{title}.lnk", f"{APP_NAME}.lnk"):
                lnk = folder / name
                try:
                    if lnk.exists():
                        lnk.unlink()
                        self.log(f"removed {lnk}")
                except OSError:
                    pass

        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY)
            self.log("removed from Apps & features")
        except FileNotFoundError:
            pass
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteValue(key, APP_NAME)
        except FileNotFoundError:
            pass

        subprocess.run(["taskkill", "/f", "/im", EXE_NAME], capture_output=True, check=False)
        if self.target.exists():
            for item in sorted(self.target.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                try:
                    item.unlink() if item.is_file() else item.rmdir()
                except OSError:
                    pass
            try:
                self.target.rmdir()
                self.log("install dir removed")
            except OSError:
                self.log(f"install dir not fully removed: {self.target}")
        self.log("uninstall done")
        return True


# --------------------------------------------------------------------------
# Windows 辅助
# --------------------------------------------------------------------------

def _make_lnk(lnk: Path, *, target: Path, args: str, workdir: Path, icon: Path,
              description: str) -> None:
    if sys.platform != "win32":
        raise OSError("Windows only")
    script = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');"
        "$s.TargetPath='{target}';$s.Arguments='{args}';$s.WorkingDirectory='{wd}';"
        "$s.IconLocation='{icon}';$s.Description='{desc}';$s.Save()"
    ).format(
        lnk=str(lnk).replace("'", "''"), target=str(target).replace("'", "''"),
        args=args.replace("'", "''"), wd=str(workdir).replace("'", "''"),
        icon=str(icon).replace("'", "''"), desc=description.replace("'", "''"),
    )
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not lnk.exists():
        raise OSError((proc.stderr or proc.stdout or "create failed").strip()[:200])


def _shell_runas(exe: str, args: str) -> bool:
    import ctypes

    if sys.platform != "win32":
        return False
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1) > 32


def open_url(url: str) -> None:
    try:
        import webbrowser

        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# “支持作者”弹窗
# --------------------------------------------------------------------------

def show_support_dialog(tr: Tr, parent=None, shot: str | None = None) -> None:
    meta = about()
    qq = str(meta.get("author_qq") or AUTHOR_QQ)
    url = str(meta.get("project_url") or GITHUB_URL)
    try:
        import tkinter as tk

        own_root = parent is None
        win = tk.Tk() if own_root else tk.Toplevel(parent)
        win.title(tr("support_title"))
        win.configure(bg="#FFF7F9")
        win.resizable(False, False)
        assets = payload_root() / "assets"
        if (assets / "app.ico").exists():
            try:
                win.iconbitmap(default=str(assets / "app.ico"))
            except Exception:  # noqa: BLE001
                pass
        if (assets / "app-256.png").exists():
            try:
                img = tk.PhotoImage(file=str(assets / "app-256.png")).subsample(5, 5)
                holder = tk.Label(win, image=img, bg="#FFF7F9")
                holder.image = img
                holder.pack(pady=(18, 6))
            except Exception:  # noqa: BLE001
                pass

        tk.Label(win, text=tr("support_head"), bg="#FFF7F9", fg="#3A2E33",
                 font=("Microsoft YaHei UI", 12, "bold"),
                 wraplength=420, justify="center").pack(pady=(4, 6))
        qq_label = tk.Label(win, text=tr("support_qq", qq=qq), bg="#FFF7F9",
                            fg="#E2728C", cursor="hand2",
                            font=("Microsoft YaHei UI", 15, "bold"))
        qq_label.pack(pady=(0, 4))
        qq_label.bind("<Button-1>", lambda _e: open_qq_chat(qq))
        if tr("support_tip"):
            tk.Label(win, text=tr("support_tip"), bg="#FFF7F9", fg="#8A7A80",
                     font=("Microsoft YaHei UI", 9)).pack()
        link = tk.Label(win, text=f"{tr('support_github')}: {url}", bg="#FFF7F9",
                        fg="#1F6FEB", cursor="hand2",
                        font=("Microsoft YaHei UI", 9, "underline"))
        link.pack(pady=(6, 0))
        link.bind("<Button-1>", lambda _e, u=url: open_url(u))

        row = tk.Frame(win, bg="#FFF7F9")
        row.pack(pady=16)

        def copy_qq():
            win.clipboard_clear()
            win.clipboard_append(qq)
            btn.config(text=tr("support_copied"))

        btn = tk.Button(row, text=tr("support_copy", qq=qq), command=copy_qq, relief="flat",
                        bg="#E2728C", fg="white", activebackground="#C4556E",
                        activeforeground="white", font=("Microsoft YaHei UI", 10, "bold"),
                        padx=16, pady=5, borderwidth=0, cursor="hand2")
        btn.pack(side="left", padx=6)
        tk.Button(row, text=tr("support_close"), command=win.destroy, relief="flat",
                  bg="#F1E4E8", fg="#3A2E33", font=("Microsoft YaHei UI", 10),
                  padx=16, pady=5, borderwidth=0, cursor="hand2").pack(side="left", padx=6)

        win.update_idletasks()
        width = max(win.winfo_reqwidth(), 440)
        height = win.winfo_reqheight()
        win.geometry(f"{width}x{height}+{(win.winfo_screenwidth() - width) // 2}"
                     f"+{(win.winfo_screenheight() - height) // 3}")
        win.lift()
        win.attributes("-topmost", True)
        win.after(400, lambda: win.attributes("-topmost", False))
        if shot:
            def grab():
                try:
                    from PIL import ImageGrab

                    win.update()
                    x, y = win.winfo_rootx(), win.winfo_rooty()
                    ImageGrab.grab(bbox=(x, y, x + win.winfo_width(),
                                         y + win.winfo_height())).save(shot)
                finally:
                    win.destroy()

            win.after(900, grab)
        if own_root:
            win.mainloop()
    except Exception:  # noqa: BLE001
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None, f"{tr('support_head')}\r\n\r\n{tr('support_qq', qq=qq)}\r\n{url}",
                tr("support_title"), 0x40)
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------
# 赞助按钮（彩色循环渐变文字）+ 赞助二维码弹窗
# --------------------------------------------------------------------------

def make_sponsor_button(parent, text: str, command, bg: str = "#FFF7F9"):
    """安装器版彩虹文字：逐字符上色 + 定时推进色相。"""
    import colorsys
    import tkinter as tk
    from tkinter import font as tkfont

    class Rainbow(tk.Canvas):
        def __init__(self):
            super().__init__(parent, bd=0, highlightthickness=0, bg=bg, cursor="hand2")
            self._font = tkfont.Font(font=("Microsoft YaHei UI", 10, "bold"))
            self._hue = 0.0
            self._alive = True
            widths = [self._font.measure(ch) for ch in text]
            height = self._font.metrics("linespace") + 10
            self.configure(width=sum(widths) + 14, height=height)
            x = 7
            self._items = []
            for ch, w in zip(text, widths):
                self._items.append(self.create_text(
                    x, height // 2, text=ch, anchor="w",
                    font=("Microsoft YaHei UI", 10, "bold"), fill="#E2728C"))
                x += w
            self.bind("<Button-1>", lambda _e: command())
            self._tick()

        def _tick(self):
            if not self._alive:
                return
            try:
                for index, item in enumerate(self._items):
                    r, g, b = colorsys.hsv_to_rgb((self._hue + index * 0.055) % 1.0, 0.62, 0.95)
                    self.itemconfig(item, fill=f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}")
                self._hue = (self._hue + 0.012) % 1.0
                self.after(90, self._tick)
            except tk.TclError:
                self._alive = False

        def destroy(self):
            self._alive = False
            try:
                super().destroy()
            except tk.TclError:
                pass

    return Rainbow()


def open_qq_chat(qq: str) -> None:
    """QQ 超链接：先试 tencent:// 拉起客户端，再退到网页版。"""
    try:
        os.startfile(f"tencent://message/?uin={qq}&Site=&Menu=yes")
        return
    except Exception:  # noqa: BLE001
        pass
    open_url(f"https://wpa.qq.com/msgrd?v=3&uin={qq}&site=qq&menu=yes")


def show_sponsor_dialog(tr, parent=None) -> None:
    """赞助页：显示微信收款二维码。"""
    meta = about()
    qq = str(meta.get("author_qq") or AUTHOR_QQ)
    try:
        import tkinter as tk

        own = parent is None
        win = tk.Tk() if own else tk.Toplevel(parent)
        win.title(tr("sponsor_title"))
        win.configure(bg="#FFF7F9")
        win.resizable(False, False)
        assets = payload_root() / "assets"
        if (assets / "app.ico").exists():
            try:
                win.iconbitmap(default=str(assets / "app.ico"))
            except Exception:  # noqa: BLE001
                pass
        if (assets / "sponsor-qr.png").exists():
            try:
                raw = tk.PhotoImage(file=str(assets / "sponsor-qr.png"))
                factor = max(1, round(raw.width() / 250))
                img = raw.subsample(factor, factor)
                holder = tk.Label(win, image=img, bg="#FFF7F9")
                holder.image = img
                holder.pack(padx=18, pady=(16, 8))
            except Exception:  # noqa: BLE001
                pass
        tk.Label(win, text=tr("sponsor_head"), bg="#FFF7F9", fg="#3A2E33",
                 font=("Microsoft YaHei UI", 13, "bold")).pack(pady=(0, 4))
        tk.Label(win, text=tr("sponsor_hint"), bg="#FFF7F9", fg="#8A7A80",
                 font=("Microsoft YaHei UI", 9)).pack(pady=(0, 6))
        link = tk.Label(win, text=f"QQ: {qq}", bg="#FFF7F9", fg="#1F6FEB",
                        cursor="hand2", font=("Microsoft YaHei UI", 9, "underline"))
        link.pack()
        link.bind("<Button-1>", lambda _e: open_qq_chat(qq))
        tk.Button(win, text=tr("sponsor_close"), command=win.destroy, relief="flat",
                  bg="#F1E4E8", fg="#3A2E33", font=("Microsoft YaHei UI", 10),
                  padx=18, pady=4, borderwidth=0,
                  cursor="hand2").pack(pady=14)
        win.update_idletasks()
        w = max(win.winfo_reqwidth(), 320)
        h = win.winfo_reqheight()
        win.geometry(f"{w}x{h}+{(win.winfo_screenwidth() - w) // 2}"
                     f"+{(win.winfo_screenheight() - h) // 3}")
        win.lift()
        win.attributes("-topmost", True)
        win.after(600, lambda: win.attributes("-topmost", False))
        if own:
            win.mainloop()
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# 图形界面
# --------------------------------------------------------------------------

class SetupGui:
    def __init__(self, root, installer: Installer, defaults: dict, tr: Tr):
        self.root = root
        self.installer = installer
        self.defaults = defaults
        self.tr = tr
        self.path_var = None
        self.log_text = None
        self._result = None
        self.build()

    # ------------------------------------------------------------------ 构建
    def build(self):
        import tkinter as tk
        import tkinter.ttk as ttk
        from tkinter import filedialog

        tr = self.tr
        root = self.root
        meta = about()
        root.title(tr("title", version=meta.get("version") or DEFAULT_VERSION))
        root.geometry("800x700")
        root.minsize(760, 660)
        root.configure(bg="#FFF7F9")
        root.columnconfigure(0, weight=1)

        assets = payload_root() / "assets"
        self._logo = None
        if (assets / "app.ico").exists():
            try:
                root.iconbitmap(default=str(assets / "app.ico"))
            except Exception:  # noqa: BLE001
                pass
        if (assets / "app-256.png").exists():
            try:
                self._logo = tk.PhotoImage(file=str(assets / "app-256.png")).subsample(4, 4)
                root.iconphoto(True, self._logo)
            except Exception:  # noqa: BLE001
                self._logo = None

        # ---- 页头（grid：左图标 / 中标题 / 右语言+赞助）
        head = tk.Frame(root, bg="#FFF7F9")
        head.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 0))
        head.columnconfigure(1, weight=1)
        if self._logo is not None:
            tk.Label(head, image=self._logo, bg="#FFF7F9").grid(
                row=0, column=0, rowspan=3, sticky="nw", padx=(0, 12))

        tk.Label(head, text=tr("headline"), bg="#FFF7F9", fg="#3A2E33",
                 font=("Microsoft YaHei UI", 15, "bold")).grid(row=0, column=1, sticky="w")
        tk.Label(head, text=tr("subtitle"), bg="#FFF7F9", fg="#8A7A80",
                 font=("Microsoft YaHei UI", 9), wraplength=380, justify="left").grid(
                     row=1, column=1, sticky="w")
        short_link = (meta.get("project_url") or GITHUB_URL).replace("https://github.com/", "")
        self.link_label = tk.Label(
            head, text=short_link, bg="#FFF7F9", fg="#1F6FEB", cursor="hand2",
            font=("Microsoft YaHei UI", 9, "underline"))
        self.link_label.grid(row=2, column=1, sticky="w", pady=(2, 0))
        self.link_label.bind(
            "<Button-1>", lambda _e: open_url(meta.get("project_url") or GITHUB_URL))

        side = tk.Frame(head, bg="#FFF7F9")
        side.grid(row=0, column=2, rowspan=3, sticky="ne", padx=(10, 0))
        lang_row = tk.Frame(side, bg="#FFF7F9")
        lang_row.pack(anchor="e")
        tk.Label(lang_row, text=tr("language"), bg="#FFF7F9", fg="#8A7A80",
                 font=("Microsoft YaHei UI", 9)).pack(side="left", padx=(0, 6))
        self.lang_var = tk.StringVar(
            value=next((x["label"] for x in tr.langs if x["code"] == tr.lang), "English"))
        combo = ttk.Combobox(lang_row, values=[x["label"] for x in tr.langs],
                             state="readonly", width=9, textvariable=self.lang_var)
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", self._on_language)
        make_sponsor_button(
            side, f"♥ {tr('sponsor')}", lambda: show_sponsor_dialog(tr, root)).pack(
                anchor="e", pady=(6, 0))

        # ---- 安装目录
        row = ttk.Frame(root)
        row.grid(row=1, column=0, sticky="ew", padx=16, pady=10)
        ttk.Label(row, text=tr("dir")).pack(side="left")
        self.path_var = tk.StringVar(value=str(self.defaults["dir"]))
        self.dir_entry = ttk.Entry(row, textvariable=self.path_var, width=1)
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=8)
        # 改完路径（回车 / 失焦）就自动建目录，避免点安装才发现路径不存在
        self.dir_entry.bind("<Return>", self._ensure_dir)
        self.dir_entry.bind("<FocusOut>", self._ensure_dir)

        def browse():
            # mustexist=False：允许在“选择文件夹”对话框里直接新建
            chosen = filedialog.askdirectory(initialdir=self.path_var.get(),
                                             mustexist=False, title=tr("dir"))
            if chosen:
                self.path_var.set(chosen)
                self._ensure_dir()

        ttk.Button(row, text=tr("browse"), command=browse).pack(side="left")

        # ---- 选项
        opts = ttk.LabelFrame(root, text=tr("options"))
        opts.grid(row=2, column=0, sticky="ew", padx=16)
        self.v_desktop = tk.BooleanVar(value=self.defaults["desktop"])
        self.v_ca = tk.BooleanVar(value=self.defaults["ca"])
        self.v_hosts = tk.BooleanVar(value=self.defaults["hosts"])
        self.v_auto = tk.BooleanVar(value=self.defaults["autostart"])
        self.v_start = tk.BooleanVar(value=self.defaults["start"])
        for idx, (text, var) in enumerate((
            (tr("opt_desktop"), self.v_desktop),
            (tr("opt_ca"), self.v_ca),
            (tr("opt_hosts"), self.v_hosts),
            (tr("opt_autostart"), self.v_auto),
            (tr("opt_start"), self.v_start),
        )):
            ttk.Checkbutton(opts, text=text, variable=var).grid(
                row=idx, column=0, sticky="w", padx=10, pady=2)

        # ---- 日志
        self.log_text = tk.Text(root, height=7, wrap="word", font=("Consolas", 9),
                                bg="#FFFFFF", fg="#3A2E33", relief="flat",
                                highlightbackground="#F0D3DB", highlightthickness=1)
        self.log_text.grid(row=3, column=0, sticky="nsew", padx=16, pady=10)
        root.rowconfigure(3, weight=1)

        # ---- 按钮
        btns = ttk.Frame(root)
        btns.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 14))
        self.btn_install = ttk.Button(btns, text=tr("install"),
                                      command=lambda: self.task("install"))
        self.btn_install.pack(side="right", padx=4)
        self.btn_uninstall = ttk.Button(btns, text=tr("uninstall"),
                                        command=lambda: self.task("uninstall"))
        self.btn_uninstall.pack(side="right", padx=4)
        ttk.Button(btns, text=tr("exit"), command=root.destroy).pack(side="right", padx=4)

        self._write(tr("log_welcome", version=meta.get("version") or DEFAULT_VERSION,
                       dir=self.defaults["dir"]))
        self._write(f"{meta.get('name')} · QQ {meta.get('author_qq')} · "
                    f"{meta.get('project_url')}")

    def _ensure_dir(self, _event=None) -> None:
        """把路径输入框里的目录建出来（改路径时自动新建文件夹）。"""
        raw = (self.path_var.get() or "").strip().strip('"')
        if not raw:
            return
        path = Path(raw)
        try:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                self._write(self.tr("mkdir_ok", path=path))
            self.path_var.set(str(path))
        except OSError as exc:
            self._write(self.tr("mkdir_fail", error=exc))

    def _write(self, message: str):
        if self.log_text is not None:
            self.log_text.insert("end", message + "\n")
            self.log_text.see("end")

    # ------------------------------------------------------------------ 语言
    def _on_language(self, _event=None):
        label = self.lang_var.get()
        code = next((x["code"] for x in self.tr.langs if x["label"] == label), "en")
        if code == self.tr.lang:
            return
        self.tr.set_language(code)
        save_language(code)
        self.rebuild()

    def rebuild(self):
        saved = self.log_text.get("1.0", "end").rstrip("\n") if self.log_text else ""
        for child in list(self.root.winfo_children()):
            child.destroy()
        self.build()
        if saved:
            self.log_text.delete("1.0", "end")
            self.log_text.insert("end", saved + "\n")

    # ------------------------------------------------------------------ 动作
    def task(self, kind: str):
        """后台线程只写结果，UI 更新一律回到主线程做（Tk 不是线程安全的）。"""
        import threading

        # Tk 变量只能在主线程读，先全部取出来再交给工作线程
        opts = {
            "dir": Path(self.path_var.get()),
            "desktop": bool(self.v_desktop.get()),
            "ca": bool(self.v_ca.get()),
            "hosts": bool(self.v_hosts.get()),
            "autostart": bool(self.v_auto.get()),
            "start": bool(self.v_start.get()),
        }
        self.btn_install.config(state="disabled")
        self.btn_uninstall.config(state="disabled")
        self._write("…")
        self._result = None

        def work():
            try:
                inst = Installer(opts["dir"], Log())
                if kind == "install":
                    ok = inst.install(
                        desktop=opts["desktop"], ca=opts["ca"], hosts=opts["hosts"],
                        autostart=opts["autostart"], start_now=opts["start"],
                    )
                else:
                    ok = inst.uninstall(remove_ca=opts["ca"])
                self._result = (bool(ok), "")
            except Exception as exc:  # noqa: BLE001
                self._result = (False, str(exc))

        threading.Thread(target=work, daemon=True).start()
        self.root.after(200, self._poll_result)

    def _poll_result(self):
        if self._result is None:
            self.root.after(200, self._poll_result)
            return
        ok, error = self._result
        self._result = None
        self.finish(ok, error)

    def finish(self, ok: bool, error: str = ""):
        self.btn_install.config(state="normal")
        self.btn_uninstall.config(state="normal")
        self._write(self.tr("done") if ok else f"{self.tr('failed')} {error}")
        if ok and not self.defaults.get("no_popup"):
            show_support_dialog(self.tr, self.root)


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="FURINA-GITHUB-PROXY-Setup")
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--dir", default="")
    parser.add_argument("--lang", default="")
    parser.add_argument("--no-desktop", action="store_true")
    parser.add_argument("--ca", dest="ca", action="store_true", default=None)
    parser.add_argument("--no-ca", dest="ca", action="store_false")
    parser.add_argument("--hosts", action="store_true")
    parser.add_argument("--autostart", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--no-popup", action="store_true")
    parser.add_argument("--gui-selftest", default="", metavar="DIR",
                        help="无人值守跑一遍图形界面安装流程（用于打包后自检）")
    args = parser.parse_args(argv)

    target = Path(args.dir) if args.dir else default_dir()
    log = Log()
    lang = args.lang or load_language()
    tr = Tr(lang)

    if args.uninstall:
        inst = Installer(target, log)
        return 0 if inst.uninstall(remove_ca=True if args.ca is None else args.ca) else 1

    if args.silent:
        inst = Installer(target, log)
        ok = inst.install(
            desktop=not args.no_desktop,
            ca=True if args.ca is None else args.ca,
            hosts=args.hosts, autostart=args.autostart, start_now=args.start,
        )
        if ok and not args.no_popup:
            show_support_dialog(tr)
        return 0 if ok else 1

    import tkinter as tk

    defaults = {
        "dir": target, "desktop": not args.no_desktop,
        "ca": True if args.ca is None else args.ca,
        "hosts": args.hosts, "autostart": args.autostart, "start": args.start,
        "no_popup": args.no_popup,
    }
    import tkinter as tk

    root = tk.Tk()
    gui = SetupGui(root, Installer(target, log), defaults, tr)

    if args.gui_selftest:
        import tkinter.ttk as ttk

        report = state_dir() / "selftest.log"
        lines = [f"frozen={getattr(sys, 'frozen', False)}",
                 f"ttk.Combobox={hasattr(ttk, 'Combobox')}"]

        def poll(tries=0):
            text = gui.log_text.get("1.0", "end")
            done = any(k in text for k in ("finished", "not completed", "—— 完成 ——", "未成功"))
            if not done and tries < 300:
                root.after(200, poll, tries + 1)
                return
            ok = "finished" in text or "—— 完成 ——" in text
            lines.append(f"gui_install={'OK' if ok else 'FAILED'}")
            lines.append("tail=" + " | ".join(text.strip().splitlines()[-3:]))
            report.write_text("\n".join(lines), encoding="utf-8")
            root.destroy()

        def start():
            gui.task("install")
            poll()

        root.after(400, start)
        root.mainloop()
        return 0

    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
