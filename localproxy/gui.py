"""FURINA-GITHUB-PROXY 图形界面（纯 tkinter，零第三方依赖）。

功能：
  * 一键启动 / 停止本地代理（SOCKS5 + HTTP + 指标 API）
  * 实时查看上游健康度、延迟、累计流量
  * 开关 Windows 系统代理、复制代理地址、连通性自检
  * 本地 CA 管理（本机签发证书 + hosts 指向本机实现加速）
  * 多语言：默认英语，设置里可切 简体中文 / 日本語 / Русский

asyncio 事件循环跑在后台线程，UI 通过 run_coroutine_threadsafe 与它交互，
网络 IO 永远不会卡界面。
"""

from __future__ import annotations

import asyncio
import colorsys
import json
import logging
import os
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from . import __version__
from .about import AUTHOR_QQ, GITHUB_URL, GITHUB_USER_URL
from .config import Config, ConfigError
from .i18n import DEFAULT_LANG, language_label, languages, Translator
from .icon import resource_path

ACCENT = "#E2728C"
ACCENT_DARK = "#C4556E"
BG = "#FFF7F9"
CARD = "#FFFFFF"
BORDER = "#F0D3DB"
TEXT = "#3A2E33"
MUTED = "#8A7A80"
OK = "#2E9E6B"
BAD = "#C9485B"
LINK = "#1F6FEB"
LINK_HOVER = "#3B82F6"
FONT = "Microsoft YaHei UI"


def hsv_hex(hue: float, sat: float = 0.62, val: float = 0.95) -> str:
    r, g, b = colorsys.hsv_to_rgb(hue % 1.0, sat, val)
    return f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"


class RainbowText(tk.Canvas):
    """彩色循环渐变的可点击文字。

    Tk 的 Label 只能整段一个颜色，所以用 Canvas 逐字符上色，
    每 90 ms 把色相往前推一点，就得到滚动的彩虹渐变。
    """

    def __init__(self, parent, text: str, command=None, bg: str = BG,
                 font_desc=(FONT, 10, "bold"), speed: float = 0.012):
        super().__init__(parent, bd=0, highlightthickness=0, bg=bg, cursor="hand2")
        self._font = tkfont.Font(font=font_desc)
        self._speed = speed
        self._hue = 0.0
        self._alive = True
        widths = [self._font.measure(ch) for ch in text]
        height = self._font.metrics("linespace") + 10
        self.configure(width=sum(widths) + 14, height=height)
        x = 7
        self._items = []
        for ch, w in zip(text, widths):
            self._items.append(self.create_text(
                x, height // 2, text=ch, anchor="w", font=font_desc, fill=ACCENT))
            x += w
        if command is not None:
            self.bind("<Button-1>", lambda _e: command())
        self._tick()

    def _tick(self):
        if not self._alive:
            return
        try:
            for index, item in enumerate(self._items):
                self.itemconfig(item, fill=hsv_hex(self._hue + index * 0.055))
            self._hue = (self._hue + self._speed) % 1.0
            self.after(90, self._tick)
        except tk.TclError:
            self._alive = False

    def destroy(self):
        self._alive = False
        try:
            super().destroy()
        except tk.TclError:
            pass


# --------------------------------------------------------------------------
# 后台事件循环 / 日志桥
# --------------------------------------------------------------------------

class AsyncBridge:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, name="localproxy-loop", daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def call(self, coro, timeout: float = 15.0):
        return self.submit(coro).result(timeout)

    def shutdown(self):
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:  # noqa: BLE001
            pass


class QueueLog(logging.Handler):
    def __init__(self, q: "queue.Queue[tuple[str, int]]"):
        super().__init__(level=logging.INFO)
        self.q = q
        self.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record):
        try:
            self.q.put((self.format(record), record.levelno))
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------
# 主窗口
# --------------------------------------------------------------------------

class App:
    def __init__(self, root: tk.Tk, cfg_path: Path, cfg: Config,
                 smoke_shot: str | None = None, smoke_tab: int = 0):
        self.root = root
        self.cfg_path = cfg_path
        self.cfg = cfg
        self.tr = Translator("app", self._initial_language(cfg))
        self.bridge = AsyncBridge()
        self.server = None
        self.ports: dict[str, int] = {}
        self.logq: "queue.Queue[tuple[str, int]]" = queue.Queue()
        self._running = False
        self._lat_result = None
        self._checking = False
        self._check_result = None
        self._smoke_shot = smoke_shot
        self._smoke_tab = smoke_tab

        self._setup_window()
        self._setup_logging()
        self._build_ui()
        self._refresh_all()
        self.root.after(400, self._pump_logs)
        self.root.after(1200, self._poll_stats)
        self.root.after(1500, self._poll_daemon)

    def _poll_daemon(self):
        self._refresh_daemon()
        self.root.after(4000, self._poll_daemon)
        if smoke_shot:
            self.root.after(600, lambda: self._select_tab(smoke_tab))
            if smoke_tab == 1:
                self.root.after(900, self.run_latency)
                self.root.after(3200, lambda: self._take_shot(smoke_shot))
            else:
                self.root.after(1900, lambda: self._take_shot(smoke_shot))
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    @staticmethod
    def _initial_language(cfg: Config) -> str:
        lang = str((cfg.ui or {}).get("language") or DEFAULT_LANG)
        codes = {item.get("code") for item in languages()}
        return lang if lang in codes else DEFAULT_LANG

    # ------------------------------------------------------------------ 外观
    def _setup_window(self):
        self.root.title(f"{self.tr('title')} {__version__}  ·  {self.tr('subtitle', version='', config='').strip(' ·')}")
        self.root.geometry("1040x720")
        self.root.minsize(980, 660)
        self.root.configure(bg=BG)
        ico = resource_path("assets/app.ico")
        if ico.exists():
            try:
                self.root.iconbitmap(default=str(ico))
            except Exception:  # noqa: BLE001
                pass
        png = resource_path("assets/app-256.png")
        if png.exists():
            try:
                self._logo = tk.PhotoImage(file=str(png))
                self._logo_small = self._logo.subsample(4, 4)
                self.root.iconphoto(True, self._logo)
            except Exception:  # noqa: BLE001
                self._logo = None
        else:
            self._logo = None

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=(FONT, 9), background=BG, foreground=TEXT)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Value.TLabel", background=CARD, foreground=TEXT,
                        font=(FONT, 13, "bold"))
        style.configure("Small.TLabel", background=CARD, foreground=MUTED,
                        font=(FONT, 8))
        style.configure("Title.TLabel", background=BG, foreground=TEXT,
                        font=(FONT, 14, "bold"))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED)
        style.configure("Accent.TButton", font=(FONT, 10, "bold"))
        style.configure("Treeview", background=CARD, fieldbackground=CARD, rowheight=24)
        style.configure("Treeview.Heading", font=(FONT, 9, "bold"))
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 6), font=(FONT, 9))

    def _setup_logging(self):
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
        root_logger.addHandler(QueueLog(self.logq))

    # ------------------------------------------------------------------ 布局
    def _build_ui(self):
        tr = self.tr
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=18, pady=(16, 6))
        header.columnconfigure(1, weight=1)
        if getattr(self, "_logo_small", None) is not None:
            ttk.Label(header, image=self._logo_small, background=BG).grid(
                row=0, column=0, rowspan=3, sticky="nw", padx=(0, 12))
        ttk.Label(header, text=tr("title"), style="Title.TLabel").grid(
            row=0, column=1, sticky="w")
        ttk.Label(
            header,
            text=tr("subtitle", version=__version__, config=self.cfg_path.name),
            style="Sub.TLabel", wraplength=470, justify="left",
        ).grid(row=1, column=1, sticky="w")
        self._make_link(header, GITHUB_URL.replace("https://", ""), GITHUB_URL).grid(
            row=2, column=1, sticky="w", pady=(3, 0))

        controls = ttk.Frame(header)
        controls.grid(row=0, column=2, rowspan=3, sticky="ne", padx=(12, 0))
        self.badge = tk.Label(controls, text=tr("status_stopped"), bg="#F1E4E8", fg=BAD,
                              font=(FONT, 10, "bold"), padx=14, pady=5)
        self.badge.pack(side="right")
        ttk.Button(controls, text=f"⚙  {tr('settings')}",
                   command=self.open_settings).pack(side="right", padx=(0, 8))
        self.sponsor_btn = RainbowText(controls, f"♥ {tr('sponsor')}",
                                       command=self.open_sponsor, bg=BG)
        self.sponsor_btn.pack(side="right", padx=(0, 6))

        cards = ttk.Frame(self.root)
        cards.pack(fill="x", padx=18, pady=6)
        self.card_socks = self._card(cards, tr("card_socks"))
        self.card_http = self._card(cards, tr("card_http"))
        self.card_traffic = self._card(cards, tr("card_traffic"))
        self.card_rules = self._card(cards, tr("card_rules"))

        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=18, pady=4)
        self.btn_run = ttk.Button(bar, text=tr("start"), style="Accent.TButton",
                                  command=self.toggle_run)
        self.btn_run.pack(side="left", padx=(0, 8))
        self.btn_sys = ttk.Button(bar, text=tr("sysproxy"), command=self.toggle_sysproxy)
        self.btn_sys.pack(side="left", padx=4)
        self.btn_copy = ttk.Button(bar, text=tr("copy_addr"), command=self.copy_proxy)
        self.btn_copy.pack(side="left", padx=4)
        self.btn_check = ttk.Button(bar, text=tr("selfcheck"), command=self.self_check)
        self.btn_check.pack(side="left", padx=4)
        self.btn_cfg = ttk.Button(bar, text=tr("open_config"), command=self.open_config)
        self.btn_cfg.pack(side="left", padx=4)
        self.daemon_btn = ttk.Button(bar, text=tr("daemon_off"),
                                     command=self.toggle_daemon)
        self.daemon_btn.pack(side="left", padx=4)


        footer = ttk.Frame(self.root)
        footer.pack(side="bottom", fill="x", padx=18, pady=(0, 10))
        self._qq_link(footer, tr("footer_author", qq=AUTHOR_QQ)).pack(side="left")
        ttk.Button(footer, text=tr("footer_copy_qq"), command=self.copy_qq).pack(
            side="left", padx=8)
        self._make_link(footer, tr("footer_github"), GITHUB_USER_URL).pack(
            side="left", padx=8)
        self.msg = ttk.Label(footer, text="", style="Sub.TLabel")
        self.msg.pack(side="right")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=18, pady=(8, 4))
        self._build_upstreams_tab(self.nb)
        self._build_latency_tab(self.nb)
        self._build_accel_tab(self.nb)
        self._build_log_tab(self.nb)

    def _card(self, parent, title: str) -> ttk.Label:
        frame = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=6)
        tk.Label(frame, text=title, bg=CARD, fg=MUTED, font=(FONT, 8)).pack(
            anchor="w", padx=12, pady=(4, 0))
        value = ttk.Label(frame, text="—", style="Value.TLabel")
        value.pack(anchor="w", padx=12, pady=(0, 4))
        return value

    def _build_upstreams_tab(self, nb):
        tr = self.tr
        frame = ttk.Frame(nb)
        nb.add(frame, text=tr("tab_upstreams"))
        cols = ("name", "type", "state", "latency", "connects", "last")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=6)
        for key, label, width in (
            ("name", tr("col_name"), 150), ("type", tr("col_type"), 90),
            ("state", tr("col_state"), 100), ("latency", tr("col_latency"), 90),
            ("connects", tr("col_connects"), 90), ("last", tr("col_last"), 320),
        ):
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=4, pady=6)
        ttk.Label(frame, text=tr("tip_upstreams"), style="Sub.TLabel").pack(
            anchor="w", padx=6, pady=(0, 4))

    def _build_latency_tab(self, nb):
        tr = self.tr
        frame = ttk.Frame(nb)
        nb.add(frame, text=tr("tab_latency"))
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=4, pady=(8, 4))
        ttk.Button(bar, text=tr("lat_run"), command=self.run_latency).pack(side="left", padx=4)
        ttk.Label(bar, text=tr("lat_hint"), style="Sub.TLabel").pack(side="left", padx=8)
        cols = ("site", "direct", "proxy", "state")
        self.lat_tree = ttk.Treeview(frame, columns=cols, show="headings", height=8)
        for key, label, width in (("site", tr("lat_site"), 300),
                                  ("direct", tr("lat_direct"), 110),
                                  ("proxy", tr("lat_proxy"), 110),
                                  ("state", tr("lat_state"), 120)):
            self.lat_tree.heading(key, text=label)
            self.lat_tree.column(key, width=width, anchor="w")
        self.lat_tree.pack(fill="both", expand=True, padx=4, pady=4)

    def run_latency(self):
        """延迟检测跑到后台事件循环里，结果用轮询回填，绝不跨线程碰 Tk。"""
        from .latency import DEFAULT_SITES, matrix

        sites = list(DEFAULT_SITES)
        self.lat_tree.delete(*self.lat_tree.get_children())
        for site in sites:
            self.lat_tree.insert("", "end",
                                 values=(site, "…", "…", self.tr("lat_running")))
        self._lat_result = None
        cfg = self.cfg

        async def job():
            # 只写字段，不碰 Tk（跨线程）
            self._lat_result = await matrix(sites, proxy_port=cfg.socks5.port,
                                            count=2, concurrency=8, timeout=5.0)

        self.bridge.submit(job())
        self.root.after(500, self._poll_latency)

    def _poll_latency(self):
        rows = getattr(self, "_lat_result", None)
        if rows is None:
            self.root.after(500, self._poll_latency)
            return
        self._lat_result = None
        tr = self.tr
        self.lat_tree.delete(*self.lat_tree.get_children())
        for row in rows:
            direct = f"{row['direct']:.0f}" if row.get("direct") else "—"
            proxy = f"{row['proxy']:.0f}" if row.get("proxy") else "—"
            state = tr("lat_ok") if (row.get("direct_ok") or row.get("proxy_ok")) \
                else tr("lat_fail")
            self.lat_tree.insert("", "end",
                                 values=(row["host"], direct, proxy, state))

    def _build_accel_tab(self, nb):
        tr = self.tr
        frame = ttk.Frame(nb)
        nb.add(frame, text=tr("tab_accel"))

        info = tk.Frame(frame, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        info.pack(fill="x", padx=4, pady=(8, 6))
        tk.Label(info, text=tr("accel_title"), bg=CARD, fg=TEXT,
                 font=(FONT, 9, "bold")).pack(anchor="w", padx=12, pady=(6, 1))
        tk.Label(info, text=tr("accel_body"), bg=CARD, fg=MUTED, justify="left",
                 font=(FONT, 8)).pack(anchor="w", padx=12, pady=(0, 4))
        self.accel_state = tk.Label(info, text="", bg=CARD, fg=TEXT, justify="left",
                                    font=("Consolas", 8))
        self.accel_state.pack(anchor="w", padx=12, pady=(0, 6))

        row = ttk.Frame(frame)
        row.pack(fill="x", padx=4, pady=4)
        ttk.Button(row, text=tr("accel_gen"), command=self.ca_init).pack(side="left", padx=3)
        ttk.Button(row, text=tr("accel_trust"), command=self.ca_trust).pack(side="left", padx=3)
        ttk.Button(row, text=tr("accel_untrust"), command=self.ca_untrust).pack(side="left", padx=3)
        ttk.Button(row, text=tr("accel_open"), command=self.open_certs).pack(side="left", padx=3)
        ttk.Button(row, text=tr("accel_hosts"), command=self.make_hosts).pack(side="left", padx=3)
        self.accel_btn = ttk.Button(row, text="", command=self.toggle_accel)
        self.accel_btn.pack(side="left", padx=3)
        ttk.Label(frame, text=tr("accel_hint"), style="Sub.TLabel").pack(
            anchor="w", padx=6, pady=(2, 0))

    def _build_log_tab(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text=self.tr("tab_logs"))
        self.log_text = tk.Text(frame, wrap="word", font=("Consolas", 9), bg="#2A2226",
                                fg="#F2E6EA", insertbackground="#F2E6EA", relief="flat")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=6)
        self.log_text.tag_configure("warn", foreground="#FFB4A2")
        self.log_text.tag_configure("err", foreground="#FF8095")
        ttk.Button(frame, text=self.tr("log_clear"),
                   command=lambda: self.log_text.delete("1.0", "end")).pack(
            anchor="e", padx=4, pady=(0, 6))

    # ------------------------------------------------------------------ 链接
    def _make_link(self, parent, text: str, url: str):
        label = tk.Label(parent, text=text, fg=LINK, bg=BG, cursor="hand2",
                         font=(FONT, 8, "underline"))
        label.bind("<Button-1>", lambda _event, u=url: self.open_url(u))
        label.bind("<Enter>", lambda _event: label.config(fg=LINK_HOVER))
        label.bind("<Leave>", lambda _event: label.config(fg=LINK))
        return label

    def _qq_link(self, parent, text: str):
        """作者 QQ 也做成可点击链接。"""
        label = tk.Label(parent, text=text, fg=LINK, bg=BG, cursor="hand2",
                         font=(FONT, 9, "underline"))
        label.bind("<Button-1>", lambda _e: self.open_qq())
        label.bind("<Enter>", lambda _e: label.config(fg=LINK_HOVER))
        label.bind("<Leave>", lambda _e: label.config(fg=LINK))
        return label

    def open_qq(self) -> None:
        """优先用 tencent:// 直接拉起 QQ 会话，失败再退到 web 版。"""
        try:
            os.startfile(f"tencent://message/?uin={AUTHOR_QQ}&Site=&Menu=yes")
            self._say(f"QQ: {AUTHOR_QQ}", 5000)
            return
        except Exception:  # noqa: BLE001
            pass
        self.open_url(
            f"https://wpa.qq.com/msgrd?v=3&uin={AUTHOR_QQ}&site=qq&menu=yes")

    def open_sponsor(self) -> None:
        """赞助页：展示微信收款二维码。"""
        tr = self.tr
        win = tk.Toplevel(self.root)
        win.title(tr("sponsor_title"))
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self.root)
        ico = resource_path("assets/app.ico")
        if ico.exists():
            try:
                win.iconbitmap(default=str(ico))
            except Exception:  # noqa: BLE001
                pass

        png = resource_path("assets/sponsor-qr.png")
        if png.exists():
            try:
                raw = tk.PhotoImage(file=str(png))
                factor = max(1, round(raw.width() / 250))
                img = raw.subsample(max(1, factor), max(1, factor))
                holder = tk.Label(win, image=img, bg=BG)
                holder.image = img
                holder.pack(padx=18, pady=(16, 8))
            except Exception:  # noqa: BLE001
                pass

        tk.Label(win, text=tr("sponsor_head"), bg=BG, fg=TEXT,
                 font=(FONT, 13, "bold")).pack(pady=(0, 4))
        tk.Label(win, text=tr("sponsor_hint"), bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(pady=(0, 6))
        self._qq_link(win, tr("sponsor_qq", qq=AUTHOR_QQ)).pack()
        tk.Button(win, text=tr("sponsor_close"), command=win.destroy, relief="flat",
                  bg="#F1E4E8", fg=TEXT, font=(FONT, 10), padx=18, pady=4,
                  borderwidth=0, cursor="hand2").pack(pady=14)
        win.update_idletasks()
        w = max(win.winfo_reqwidth(), 320)
        h = win.winfo_reqheight()
        win.geometry(f"{w}x{h}+{(win.winfo_screenwidth() - w) // 2}"
                     f"+{(win.winfo_screenheight() - h) // 3}")
        win.lift()
        win.attributes("-topmost", True)
        win.after(600, lambda: win.attributes("-topmost", False))

    def open_url(self, url: str) -> None:
        try:
            import webbrowser

            webbrowser.open(url)
            self._say(self.tr("msg_opened", url=url), 5000)
        except Exception as exc:  # noqa: BLE001
            logging.getLogger("localproxy").warning("open url failed: %s", exc)
            self._say(self.tr("msg_open_failed", error=exc), 6000)

    # ------------------------------------------------------------------ 语言
    def rebuild(self) -> None:
        """语言切换后重建界面（比重排每个控件更稳）。"""
        saved = ""
        if getattr(self, "log_text", None) is not None:
            try:
                saved = self.log_text.get("1.0", "end").rstrip("\n")
            except Exception:  # noqa: BLE001
                saved = ""
        for child in list(self.root.winfo_children()):
            child.destroy()
        self._build_ui()
        if saved:
            self.log_text.insert("end", saved + "\n")
        self._refresh_all()
        if self._running:
            self.btn_run.config(text=self.tr("stop"))
            if self.cfg.accel.enabled:
                self.badge.config(text=self.tr("status_running_accel"),
                                  bg="#E4F4EC", fg=OK)
            else:
                self.badge.config(
                    text=self.tr("status_running", port=self.ports.get("socks5", "-")),
                    bg="#E4F4EC", fg=OK)

    def open_settings(self) -> None:
        tr = self.tr
        win = tk.Toplevel(self.root)
        win.title(tr("settings_title"))
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self.root)
        ico = resource_path("assets/app.ico")
        if ico.exists():
            try:
                win.iconbitmap(default=str(ico))
            except Exception:  # noqa: BLE001
                pass

        tk.Label(win, text=tr("settings_language"), bg=BG, fg=TEXT,
                 font=(FONT, 10, "bold")).grid(row=0, column=0, padx=16, pady=(18, 6),
                                               sticky="w")
        choices = languages()
        labels = [item["label"] for item in choices]
        current = self.tr.lang
        combo = ttk.Combobox(win, values=labels, state="readonly", width=24)
        try:
            combo.current([c["code"] for c in choices].index(current))
        except ValueError:
            combo.current(0)
        combo.grid(row=0, column=1, padx=16, pady=(18, 6))
        tk.Label(win, text=tr("settings_hint"), bg=BG, fg=MUTED,
                 font=(FONT, 9)).grid(row=1, column=0, columnspan=2, padx=16, sticky="w")

        row = tk.Frame(win, bg=BG)
        row.grid(row=2, column=0, columnspan=2, pady=16)

        def apply():
            code = choices[combo.current()]["code"]
            win.destroy()
            if code != self.tr.lang:
                self.set_language(code)

        tk.Button(row, text=tr("settings_ok"), command=apply, relief="flat",
                  bg=ACCENT, fg="white", activebackground=ACCENT_DARK,
                  activeforeground="white", font=(FONT, 10, "bold"), padx=16, pady=4,
                  borderwidth=0, cursor="hand2").pack(side="left", padx=6)
        tk.Button(row, text=tr("settings_cancel"), command=win.destroy, relief="flat",
                  bg="#F1E4E8", fg=TEXT, font=(FONT, 10), padx=16, pady=4,
                  borderwidth=0, cursor="hand2").pack(side="left", padx=6)

    def set_language(self, code: str) -> None:
        self.tr.set_language(code)
        self._save_language(self.tr.lang)
        self.rebuild()
        self._say(self.tr("msg_language", label=language_label(self.tr.lang)), 5000)

    def _save_language(self, code: str) -> None:
        raw: dict = {}
        if self.cfg_path.exists():
            try:
                raw = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
            except Exception:  # noqa: BLE001
                raw = {}
        else:
            raw = json.loads(json.dumps(self.cfg.raw))
        raw.setdefault("ui", {})["language"] = code
        try:
            self.cfg_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n",
                                     encoding="utf-8")
            self.cfg = Config.load(self.cfg_path)
        except (OSError, ConfigError) as exc:
            logging.getLogger("localproxy").warning("saving language failed: %s", exc)

    # ------------------------------------------------------------------ 刷新
    def _refresh_all(self):
        tr = self.tr
        cfg = self.cfg
        self.card_socks.config(text=f"127.0.0.1:{cfg.socks5.port}" if cfg.socks5.enabled
                               else "off")
        self.card_http.config(text=f"127.0.0.1:{cfg.http.port}" if cfg.http.enabled
                              else "off")
        self.card_rules.config(text=f"{len(cfg.engine.rules)} · {cfg.final}")
        self.accel_btn.config(text=tr("accel_disable") if cfg.accel.enabled
                              else tr("accel_enable"))
        self.badge.config(text=tr("status_stopped") if not self._running
                          else self.badge.cget("text"))
        self.accel_state.config(text="\n".join(self._accel_lines()))
        if not self._running:
            self._fill_tree_idle()

    def _accel_lines(self) -> list[str]:
        tr = self.tr
        cfg = self.cfg
        mode = tr("accel_mode_mitm") if cfg.accel.mode == "mitm" else tr("accel_mode_sni")
        state = tr("accel_on") if cfg.accel.enabled else tr("accel_off")
        lines = [f"{tr('accel_status')}: {state} / {mode} / 127.0.0.1:{cfg.accel.port}"]
        try:
            from .ca import CAStore

            store = CAStore(cfg.accel.ca_dir, cfg.accel.ca_common_name,
                            cfg.accel.ca_organization)
            if not store.exists():
                lines.append(f"{tr('accel_ca')}: {tr('accel_ca_missing')}")
                return lines
            info = store.describe()
            trusted = tr("accel_trusted") if info["trusted"] else tr("accel_untrusted")
            lines += [
                f"{tr('accel_ca')}: {info['subject']}",
                f"{tr('accel_valid', date=info['not_after'])} · {trusted}",
                f"{tr('accel_fp')}: {info['fingerprint_sha1']}",
                f"{tr('accel_dir')}: {info['dir']} · {tr('accel_leaves', count=info['leaves'])}",
            ]
        except ImportError:
            lines.append("cryptography not available in this build")
        except Exception as exc:  # noqa: BLE001
            lines.append(str(exc))
        return lines

    def _fill_tree_idle(self):
        tr = self.tr
        self.tree.delete(*self.tree.get_children())
        for name, spec in self.cfg.upstreams.items():
            self.tree.insert("", "end", values=(name, spec.type, tr("state_idle"), "—", 0, ""))

    def _pump_logs(self):
        try:
            while True:
                text, level = self.logq.get_nowait()
                tag = "err" if level >= logging.ERROR else ("warn" if level >= logging.WARNING else "")
                self.log_text.insert("end", text + "\n", tag)
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.root.after(400, self._pump_logs)

    def _poll_stats(self):
        if self.server is not None:
            try:
                snap = self.bridge.call(self._snapshot(), 5)
            except Exception:  # noqa: BLE001
                snap = None
            if snap:
                self._apply_snapshot(snap)
        self.root.after(1200, self._poll_stats)

    async def _snapshot(self):
        return self.server.snapshot() if self.server else None

    def _apply_snapshot(self, snap: dict):
        tr = self.tr
        traffic = snap.get("traffic", {})
        self.card_traffic.config(text=f"↑{traffic.get('up', '0B')}  ↓{traffic.get('down', '0B')}")
        rows = []
        for up in snap.get("upstreams", []):
            state = tr("state_available") if up["healthy"] else tr("state_cooldown")
            if up["healthy"] and up["fails"]:
                state = tr("state_degraded")
            lat = f"{up['latency_ms']:.0f} ms" if up["latency_ms"] else "—"
            rows.append((up["name"], up["type"], state, lat, up["connects"],
                         (up["last_error"] or "")[:120]))
        existing = self.tree.get_children()
        if len(existing) == len(rows):
            for item, row in zip(existing, rows):
                self.tree.item(item, values=row)
        else:
            self.tree.delete(*existing)
            for row in rows:
                self.tree.insert("", "end", values=row)
        if snap.get("accelerator"):
            self.badge.config(text=tr("status_running_accel"), bg="#E4F4EC", fg=OK)
        elif self._running:
            stats = snap.get("stats", {})
            self.badge.config(text=tr("status_running", port=self.ports.get("socks5", "-")),
                              bg="#E4F4EC", fg=OK)

    def _say(self, text: str, ms: int = 4000):
        self.msg.config(text=text)
        self.root.after(ms, lambda: self.msg.config(text=""))

    # ------------------------------------------------------------------ 运行
    def toggle_run(self):
        self.stop_proxy() if self._running else self.start_proxy()

    def start_proxy(self):
        if self._running:
            return

        async def boot():
            from .server import ProxyServer

            self.server = ProxyServer(self.cfg)
            return await self.server.start()

        try:
            self.ports = self.bridge.call(boot(), 20)
        except Exception as exc:  # noqa: BLE001
            self.server = None
            logging.getLogger("localproxy").error("start failed: %s", exc)
            messagebox.showerror(self.tr("title"),
                                 self.tr("msg_start_failed", error=exc))
            return
        self._running = True
        self.btn_run.config(text=self.tr("stop"))
        if self.cfg.accel.enabled:
            self.badge.config(text=self.tr("status_running_accel"), bg="#E4F4EC", fg=OK)
        else:
            self.badge.config(text=self.tr("status_running",
                                           port=self.ports.get("socks5", "-")),
                              bg="#E4F4EC", fg=OK)
        self._say(self.tr("msg_started"))

    def stop_proxy(self):
        if not self._running or self.server is None:
            return
        try:
            self.bridge.call(self.server.close(), 15)
        except Exception as exc:  # noqa: BLE001
            logging.getLogger("localproxy").warning("stop failed: %s", exc)
        self._running = False
        self.server = None
        self.btn_run.config(text=self.tr("start"))
        self.badge.config(text=self.tr("status_stopped"), bg="#F1E4E8", fg=BAD)
        self._say(self.tr("msg_stopped"))

    def toggle_sysproxy(self):
        from .cli import apply_system_proxy, system_proxy_status

        enable, _server = system_proxy_status()
        port = self.ports.get("http") or self.cfg.http.port
        ok, msg = apply_system_proxy(f"127.0.0.1:{port}", not bool(enable))
        self._say(msg, 5000)
        logging.getLogger("localproxy").info("system proxy: %s", msg)

    def toggle_daemon(self):
        """一键在后台常驻（无窗口）与停止之间切换。"""
        from . import daemon

        st = daemon.status()
        if st.get("running"):
            out = daemon.stop()
            self._say(self.tr("daemon_stopped", pid=out.get("pid") or "-"), 8000)
        else:
            info = daemon.start(str(self.cfg_path))
            self._say(self.tr("daemon_started", pid=info.get("pid"),
                              port=info.get("socks5_port")), 9000)
        self._refresh_daemon()

    def _refresh_daemon(self):
        from . import daemon

        try:
            running = bool(daemon.status().get("running"))
        except Exception:  # noqa: BLE001
            running = False
        btn = getattr(self, "daemon_btn", None)
        if btn is not None:
            btn.config(text=self.tr("daemon_on") if running
                       else self.tr("daemon_off"))

    def copy_proxy(self):
        port = self.ports.get("http") or self.cfg.http.port
        socks = self.ports.get("socks5") or self.cfg.socks5.port
        text = f"http://127.0.0.1:{port}  |  socks5://127.0.0.1:{socks}"
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._say(self.tr("msg_copied", text=text))

    def copy_qq(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(AUTHOR_QQ)
        self._say(self.tr("msg_copied_qq", qq=AUTHOR_QQ))

    def self_check(self):
        from .cli import _verify
        from .resolver import Resolver
        from .router import Router

        if getattr(self, "_checking", False):
            return
        self._checking = True
        self._check_result = None
        self.btn_check.config(state="disabled", text=self.tr("lat_running"))
        self._say(self.tr("msg_checking"), 8000)

        def work():
            async def run():
                router = Router(self.cfg, Resolver(self.cfg.dns))
                await asyncio.gather(
                    *(u.probe() for u in router.upstreams.values()),
                    return_exceptions=True)
                # 三个目标并发测，谁先通就算通过：单个站点卡住不再拖累整体
                hosts = ("raw.githubusercontent.com", "api.github.com", "github.com")
                results = await asyncio.gather(
                    *(_verify(router, h, 443, timeout=10) for h in hosts),
                    return_exceptions=True)
                clean = [r for r in results if isinstance(r, dict)]
                for res in clean:
                    if res.get("ok"):
                        res["tried"] = [f"{r['host']}: {r.get('error') or '-'}"
                                        for r in clean if not r.get("ok")]
                        return res
                errors = [f"{r.get('host')}: {r.get('error') or '-'}" for r in clean]
                return {"ok": False,
                        "error": " | ".join(errors) or "全部目标均无响应"}

            try:
                # 首次连接要等 DoH / 占位上游失败，30s 不够，放宽到 120s
                self._check_result = self.bridge.call(run(), 120)
            except Exception as exc:  # noqa: BLE001
                self._check_result = {"ok": False,
                                      "error": f"{type(exc).__name__}: {exc}"}

        threading.Thread(target=work, daemon=True).start()
        self.root.after(500, self._poll_check)

    def _poll_check(self):
        """结果只回填 UI：切到日志页 + 弹窗 + 底部常驻提示，确保看得见。"""
        res = getattr(self, "_check_result", None)
        if res is None:
            if getattr(self, "_checking", False):
                self.root.after(500, self._poll_check)
            return
        self._check_result = None
        self._checking = False
        self.btn_check.config(state="normal", text=self.tr("selfcheck"))

        tr = self.tr
        if res.get("ok"):
            msg = (f"{res.get('host', '')} · "
                   + tr("probe_ok", upstream=res.get("upstream") or "-",
                        policy=res.get("policy") or "-",
                        ms=f"{res.get('ms', 0):.0f}"))
            if res.get("tried"):
                msg += f"（{'; '.join(res['tried'])[:120]}）"
        else:
            msg = tr("probe_fail",
                     error=(res.get("error") or res.get("status") or "-")[:300])
        logger = logging.getLogger("localproxy")
        logger.info(msg) if res.get("ok") else logger.warning(msg)
        self._say(msg, 20000)
        try:
            self.nb.select(len(self.nb.tabs()) - 1)  # 日志页在最后
        except Exception:  # noqa: BLE001
            pass
        dialog = messagebox.showinfo if res.get("ok") else messagebox.showwarning
        try:
            dialog(tr("selfcheck"), msg)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ 证书
    def _store(self):
        from .ca import CAStore

        return CAStore(self.cfg.accel.ca_dir, self.cfg.accel.ca_common_name,
                       self.cfg.accel.ca_organization)

    def ca_init(self):
        try:
            store = self._store()
            store.ensure()
            logging.getLogger("localproxy").info("CA created: %s", store.ca_cert_path)
            self._refresh_all()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(self.tr("title"), str(exc))

    def ca_trust(self):
        try:
            ok, msg = self._store().trust()
        except Exception as exc:  # noqa: BLE001
            ok, msg = False, str(exc)
        self._say(msg, 6000)
        logging.getLogger("localproxy").info("%s", msg)
        self._refresh_all()
        if not ok:
            messagebox.showwarning(self.tr("title"), msg)

    def ca_untrust(self):
        try:
            ok, msg = self._store().untrust()
        except Exception as exc:  # noqa: BLE001
            ok, msg = False, str(exc)
        self._say(msg, 6000)
        self._refresh_all()

    def open_certs(self):
        path = Path(self.cfg.accel.ca_dir)
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)  # noqa: S606

    def open_config(self):
        os.startfile(self.cfg_path)  # noqa: S606

    def make_hosts(self):
        from .ca import ensure_hosts_snippet
        from .presets import ACCEL_HOSTS

        snippet = ensure_hosts_snippet(
            ACCEL_HOSTS, path=str(Path(self.cfg.accel.ca_dir) / "hosts-snippet.txt"))
        logging.getLogger("localproxy").info("hosts snippet: %s", snippet)
        self._say(self.tr("msg_hosts"), 7000)

    def toggle_accel(self):
        raw: dict = {}
        if self.cfg_path.exists():
            try:
                raw = json.loads(self.cfg_path.read_text(encoding="utf-8-sig"))
            except Exception:  # noqa: BLE001
                raw = {}
        else:
            raw = json.loads(json.dumps(self.cfg.raw))
        accel = raw.setdefault("accelerator", {})
        accel["enabled"] = not bool(accel.get("enabled", self.cfg.accel.enabled))
        self.cfg_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n",
                                 encoding="utf-8")
        try:
            self.cfg = Config.load(self.cfg_path)
        except ConfigError as exc:
            messagebox.showerror(self.tr("title"), str(exc))
            return
        self._refresh_all()
        self._say(self.tr("msg_saved_restart") if self._running
                  else self.tr("msg_saved_start"), 6000)

    # ------------------------------------------------------------------ 收尾
    def _select_tab(self, index: int):
        try:
            self.nb.select(index)
        except Exception:  # noqa: BLE001
            pass

    def _take_shot(self, path: str):
        try:
            from PIL import ImageGrab

            self.root.deiconify()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.focus_force()
            self.root.update()
            time.sleep(0.6)
            self.root.update()
            x, y = self.root.winfo_rootx(), self.root.winfo_rooty()
            ImageGrab.grab(bbox=(x, y, x + self.root.winfo_width(),
                                 y + self.root.winfo_height())).save(path)
        finally:
            self.root.destroy()

    def _on_close(self):
        if self._running and self.server is not None:
            try:
                self.bridge.call(self.server.close(), 10)
            except Exception:  # noqa: BLE001
                pass
        self.bridge.shutdown()
        self.root.destroy()


# --------------------------------------------------------------------------
# 启动
# --------------------------------------------------------------------------

def load_config(path: str | Path) -> tuple[Path, Config]:
    p = Path(path)
    if p.exists():
        return p, Config.load(p)
    for candidate in (Path.cwd() / "config.json", Path(sys.argv[0]).resolve().parent / "config.json"):
        if candidate.exists():
            return candidate, Config.load(candidate)
    from .config import EXAMPLE_CONFIG

    return p, Config.from_dict(EXAMPLE_CONFIG, source="<builtin>")


def enable_dpi_awareness() -> None:
    """缩放屏上按物理像素绘制，界面才不发虚。"""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:  # noqa: BLE001
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001
        pass


def hide_console() -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:  # noqa: BLE001
        pass


def launch(config: str = "config.json", smoke_shot: str | None = None,
           smoke_tab: int = 0, lang: str | None = None) -> int:
    enable_dpi_awareness()
    path, cfg = load_config(config)
    if lang:
        cfg.ui = dict(cfg.ui or {})
        cfg.ui["language"] = lang
    root = tk.Tk()
    App(root, path, cfg, smoke_shot=smoke_shot, smoke_tab=smoke_tab)
    root.mainloop()
    return 0


def about_text() -> str:
    from .about import ABOUT

    return (f"{ABOUT['name']} {__version__}\n{ABOUT['tagline']}\n"
            f"GitHub: {ABOUT['project_url']}\nQQ: {ABOUT['author_qq']}")


if __name__ == "__main__":
    raise SystemExit(launch())
