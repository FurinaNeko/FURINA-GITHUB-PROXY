"""命令行入口：run / check / gen-config / rules / sysproxy。"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import ssl
import sys
import time
from pathlib import Path

from . import __version__, presets
from .config import Config, ConfigError
from .netutil import encode_addr, encode_reply, read_head, read_addr
from .resolver import Resolver
from .router import Router
from .server import ProxyServer

LOG_FORMAT = "%(asctime)s %(levelname)-5s %(name)-18s %(message)s"

CHECK_TARGETS = [
    ("github.com", 443),
    ("api.github.com", 443),
    ("raw.githubusercontent.com", 443),
    ("codeload.github.com", 443),
    ("objects.githubusercontent.com", 443),
    ("huggingface.co", 443),
    ("cdn-lfs.huggingface.co", 443),
    ("cdn-lfs-us-1.huggingface.co", 443),
    ("cas-bridge.xethub.hf.co", 443),
    ("files.pythonhosted.org", 443),
    ("registry.npmjs.org", 443),
]


# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------

def setup_logging(level: str) -> None:
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    logging.basicConfig(level=numeric, format=LOG_FORMAT, datefmt="%H:%M:%S")
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

async def _run(cfg: Config, restart: bool = False) -> None:
    if restart:
        # 看护模式：代理异常退出后 3 秒自动拉起（后台常驻用）
        while True:
            try:
                await _run_once(cfg)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logging.getLogger("localproxy").error("代理退出，3 秒后重启：%s", exc)
                await asyncio.sleep(3)
                continue
            return
    await _run_once(cfg)


async def _run_once(cfg: Config) -> None:
    server = ProxyServer(cfg)
    ports = await server.start()
    banner = [
        f"localproxy {__version__}  配置：{cfg.source}",
        f"  SOCKS5  : 127.0.0.1:{ports.get('socks5', '-')}" if cfg.socks5.enabled else "  SOCKS5  : 关闭",
        f"  HTTP    : 127.0.0.1:{ports.get('http', '-')}" if cfg.http.enabled else "  HTTP    : 关闭",
        f"  指标 API: http://127.0.0.1:{ports['api']}/metrics" if ports.get("api") else "  指标 API: 关闭",
        f"  规则    : {len(cfg.engine.rules)} 条，final={cfg.final}",
        f"  上游    : {', '.join(f'{n}({s.type})' for n, s in cfg.upstreams.items())}",
    ]
    if cfg.accel.enabled:
        banner.append(
            f"  加速器  : {cfg.accel.mode} 模式 → 127.0.0.1:{ports.get('accel', cfg.accel.port)}"
            f"（CA: {cfg.accel.ca_dir}）"
        )
    banner.append("  按 Ctrl+C 停止")
    print("\n".join(banner), flush=True)
    try:
        await server.serve_forever()
    finally:
        await server.close()


def cmd_run(args) -> int:
    cfg = _load(args)
    setup_logging(args.log_level or cfg.log_level)
    try:
        asyncio.run(_run(cfg, restart=bool(getattr(args, "restart", False))))
    except KeyboardInterrupt:
        print("\n已停止。")
    return 0


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------

async def _check(cfg: Config) -> int:
    resolver = Resolver(cfg.dns)
    router = Router(cfg, resolver)
    ok_count = 0

    print(f"\n[1/3] 上游探测（{len(router.upstreams)} 个）")
    await asyncio.gather(*(up.probe() for up in router.upstreams.values()))
    for up in router.upstreams.values():
        state = "可用" if up.healthy else "不可用"
        if up.healthy and up.fails:
            state = "降级"
        lat = f"{up.latency * 1000:.0f}ms" if up.latency else "-"
        note = up.last_error if up.fails else ""
        print(f"  {up.name:<14} {up.type:<7} {up.spec.masked():<34} {state:<4} {lat:>7}  {note}")

    print(f"\n[2/3] 目标站点验证（经选路拨号 + TLS 握手 + HTTP 头）")
    sem = asyncio.Semaphore(4)

    async def one(host: str, port: int):
        async with sem:
            return await _verify(router, host, port)

    results = await asyncio.gather(*(one(h, p) for h, p in CHECK_TARGETS))
    for res in results:
        if res["ok"]:
            ok_count += 1
            print(
                f"  {res['host']:<32} {res['policy']:<8} {res['upstream']:<12} "
                f"{res['ms']:>7.0f}ms  {res['status']}"
            )
        else:
            print(f"  {res['host']:<32} {res['policy']:<8} 失败  {res['error'][:90]}")

    print(f"\n[3/3] 本机代理自测（127.0.0.1 上真实跑一次 SOCKS5 + HTTP 隧道）")
    self_ok = await _self_test(cfg)
    ok_count += 1 if self_ok else 0

    total = len(results) + 1
    print(f"\n结果：{ok_count}/{total} 通过")
    return 0 if ok_count == total else 1


async def _verify(router: Router, host: str, port: int,
                  timeout: float = 15.0) -> dict:
    started = time.monotonic()
    policy = "?"
    try:
        policy = await router.decide(host, port)
        reader, writer, policy, up = await router.dial(host, port, policy)
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "policy": policy, "upstream": "-", "ok": False,
                "error": str(exc) or type(exc).__name__, "ms": 0.0, "status": ""}
    try:
        ctx = ssl.create_default_context()
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
        writer.write(
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: localproxy-check/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        head, _ = await asyncio.wait_for(read_head(reader, 32768), timeout)
        status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        return {
            "host": host,
            "policy": policy,
            "upstream": up.name,
            "ok": status.upper().startswith("HTTP/"),
            "error": "" if status.upper().startswith("HTTP/") else status,
            "ms": (time.monotonic() - started) * 1000,
            "status": status,
        }
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "policy": policy, "upstream": up.name, "ok": False,
                "error": str(exc) or type(exc).__name__,
                "ms": (time.monotonic() - started) * 1000, "status": ""}
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def _self_test(cfg: Config) -> bool:
    raw = json.loads(json.dumps(_jsonable(cfg.raw)))
    raw["listeners"] = {
        "socks5": {"enabled": True, "host": "127.0.0.1", "port": 0},
        "http": {"enabled": True, "host": "127.0.0.1", "port": 0},
        "api": {"enabled": False, "host": "127.0.0.1", "port": 0},
    }
    raw["health"] = {"interval": 0}
    try:
        local = Config.from_dict(raw, source="<self-test>")
    except ConfigError as exc:
        print(f"  自测配置构建失败：{exc}")
        return False
    server = ProxyServer(local)
    ports = await server.start()
    all_ok = True
    for label, port in (("SOCKS5", ports.get("socks5")), ("HTTP", ports.get("http"))):
        if not port:
            continue
        try:
            status = await _probe_through(port, "github.com", 443, label)
            print(f"  经 {label} 127.0.0.1:{port} 访问 github.com:443 -> {status}")
        except Exception as exc:  # noqa: BLE001
            all_ok = False
            print(f"  经 {label} 127.0.0.1:{port} 访问 github.com:443 -> 失败：{exc}")
    await server.close()
    return all_ok


async def _probe_through(proxy_port: int, host: str, port: int, kind: str) -> str:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", proxy_port, limit=2**20), 10
    )
    try:
        if kind == "SOCKS5":
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            ver, method = await reader.readexactly(2)
            if ver != 5 or method != 0:
                raise ConnectionError("SOCKS5 协商失败")
            writer.write(b"\x05\x01\x00" + encode_addr(host, port))
            await writer.drain()
            ver, rep, _, atyp = await reader.readexactly(4)
            if rep != 0:
                raise ConnectionError(f"SOCKS5 CONNECT 失败 rep={rep}")
            # 消费 BND.ADDR + BND.PORT
            if atyp == 0x01:
                await reader.readexactly(4 + 2)
            elif atyp == 0x04:
                await reader.readexactly(16 + 2)
            elif atyp == 0x03:
                ln = (await reader.readexactly(1))[0]
                await reader.readexactly(ln + 2)
            else:
                raise ConnectionError(f"SOCKS5 应答 ATYP 异常 0x{atyp:02x}")
        else:
            authority = f"{host}:{port}"
            writer.write(
                f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
            )
            await writer.drain()
            head, _ = await read_head(reader, 8192)
            if b" 200 " not in head.split(b"\r\n", 1)[0] + b" ":
                raise ConnectionError(head.split(b"\r\n", 1)[0].decode("latin-1"))
        ctx = ssl.create_default_context()
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
        writer.write(
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: localproxy-check/1.0\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        await writer.drain()
        head, _ = await asyncio.wait_for(read_head(reader, 32768), timeout)
        return head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


def cmd_check(args) -> int:
    cfg = _load(args)
    setup_logging(args.log_level or "warning")
    return asyncio.run(_check(cfg))


# --------------------------------------------------------------------------
# gen-config
# --------------------------------------------------------------------------

def cmd_gen_config(args) -> int:
    preset = args.preset or "dev"
    try:
        rules = presets.get(preset)
    except KeyError as exc:
        print(exc, file=sys.stderr)
        return 2

    doc = {
        "log_level": "info",
        "listeners": {
            "socks5": {"enabled": True, "host": "127.0.0.1", "port": 7890},
            "http": {"enabled": True, "host": "127.0.0.1", "port": 7891},
            "api": {"enabled": True, "host": "127.0.0.1", "port": 7892},
        },
        "dns": {"mode": "doh", "doh_url": "https://dns.alidns.com/dns-query",
                "cache_ttl": 300, "timeout": 5},
        "timeouts": {"connect": 8, "handshake": 10, "idle": 300},
        "health": {"interval": 30, "timeout": 4, "fail_threshold": 2, "cooldown": 20},
        "accelerator": {
            "enabled": False,
            "mode": "mitm",
            "host": "127.0.0.1",
            "port": 443,
            "ca_dir": "certs",
            "upstream_verify": True,
            "upstream_port": 443,
            "ip_overrides": {},
            "strip_csp": True,
        },
        "upstreams": [
            {"name": "trojan-main", "type": "trojan",
             "server": args.node_host, "port": args.node_port,
             "password": args.node_password,
             "tls": {"sni": args.node_sni or args.node_host, "insecure": False,
                     "alpn": ["http/1.1"], "probe_target": "github.com:443"}},
            {"name": "socks-local", "type": "socks5", "server": "127.0.0.1", "port": 1080,
             "username": "", "password": ""},
            {"name": "http-local", "type": "http", "server": "127.0.0.1", "port": 10809,
             "username": "", "password": ""},
            {"name": "direct", "type": "direct"},
        ],
        "groups": {
            "PROXY": {"type": "latency",
                      "members": ["trojan-main", "socks-local", "http-local", "direct"]},
            "STABLE": {"type": "fallback", "members": ["trojan-main", "socks-local"]},
        },
        "rules": rules,
        "final": "DIRECT",
    }
    out = Path(args.out)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"已生成 {out}（预置规则集：{preset}，共 {len(rules)} 条）")
    print("下一步：把 upstreams 里的 NODE_HOST / NODE_PASSWORD / NODE_SNI 换成本机可用的真实节点，")
    print(f"然后运行：python -m localproxy check -c {out}")
    return 0


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

def cmd_rules(args) -> int:
    cfg = _load(args)
    if args.test:
        async def run():
            resolver = Resolver(cfg.dns)
            for item in args.test:
                host, _, port = item.partition(":")
                policy = await cfg.engine.match(host, int(port or 443), resolver)
                print(f"{item:<44} -> {policy}")
        asyncio.run(run())
        return 0
    for idx, rule in enumerate(cfg.engine.rules, 1):
        print(f"{idx:>3}  {rule.raw}")
    print(f"    final -> {cfg.final}")
    return 0


# --------------------------------------------------------------------------
# sysproxy（Windows 系统代理）
# --------------------------------------------------------------------------

def system_proxy_status() -> tuple[int, str]:
    """读当前用户的 WinINET 代理设置。"""
    if not sys.platform.startswith("win"):
        return 0, ""
    import winreg

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        return int(enable), str(server)
    except FileNotFoundError:
        return 0, ""


def apply_system_proxy(server: str, enable: bool) -> tuple[bool, str]:
    """开关 WinINET（Edge / Chrome / 系统组件共用）代理，并立即通知生效。"""
    if not sys.platform.startswith("win"):
        return False, "该功能仅支持 Windows；其他系统请设置 http_proxy/https_proxy"
    import ctypes
    import winreg

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            if enable:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(
                    key, "ProxyOverride", 0, winreg.REG_SZ,
                    "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;"
                    "172.19.*;172.2*;172.30.*;172.31.*;192.168.*",
                )
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    except OSError as exc:
        return False, f"写注册表失败：{exc}"

    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:  # noqa: BLE001
        pass
    return True, (f"已开启系统代理：{server}" if enable else "已关闭系统代理")


def cmd_sysproxy(args) -> int:
    if args.action == "status":
        enable, server = system_proxy_status()
        print(f"ProxyEnable = {enable}\nProxyServer = {server}")
        return 0
    if args.action == "off":
        ok, msg = apply_system_proxy("", False)
        print(msg)
        return 0 if ok else 2
    target = args.server
    if not target:
        cfg = _load(args)
        port = cfg.http.port if args.scheme == "http" else cfg.socks5.port
        target = f"127.0.0.1:{port}"
        if args.scheme == "socks":
            target = f"socks={target}"
    ok, msg = apply_system_proxy(target, True)
    print(msg)
    return 0 if ok else 2


# --------------------------------------------------------------------------
# 公共
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# cert（本地 CA）
# --------------------------------------------------------------------------

def cmd_cert(args) -> int:
    from .ca import CAError, CAStore

    cfg = _load(args)
    store = CAStore(cfg.accel.ca_dir, cfg.accel.ca_common_name, cfg.accel.ca_organization)
    action = args.cert_action
    try:
        if action == "init":
            store.ensure(force=args.force)
            print(json.dumps(store.describe(), ensure_ascii=False, indent=2))
            print(f"\n根证书 PEM：{store.ca_cert_path}")
            print(f"根证书 CER：{store.ca_der_path}（双击即可导入）")
            print("导入当前用户信任区：python -m localproxy cert trust")
        elif action == "status":
            print(json.dumps(store.describe(), ensure_ascii=False, indent=2))
        elif action == "export":
            target = store.export_to(args.out or "certs/MyCA.cer")
            print(f"已导出：{target}")
            bundle = store.export_to("certs/ca-bundle.pem")
            print(f"PEM 信任包：{bundle}")
        elif action == "trust":
            ok, msg = store.trust()
            print(msg)
            return 0 if ok else 1
        elif action == "untrust":
            ok, msg = store.untrust()
            print(msg)
            return 0 if ok else 1
        elif action == "issue":
            hosts = args.hosts or presets.ACCEL_HOSTS
            for host in hosts:
                cert, key = store.issue(host, days=int(args.days), force=args.force)
                print(f"  {host:<40} {cert.name}")
        elif action == "leaves":
            rows = store.list_leaves()
            if not rows:
                print("还没有签发任何域名证书")
            for row in rows:
                print(f"  {row['subject']:<52} 到期 {row['not_after']}  {row['file']}")
    except CAError as exc:
        print(f"证书操作失败：{exc}", file=sys.stderr)
        return 1
    return 0


# --------------------------------------------------------------------------
# accel（hosts 加速）
# --------------------------------------------------------------------------

def cmd_accel(args) -> int:
    from .ca import CAError, ensure_hosts_snippet
    from .accelerator import Accelerator

    cfg = _load(args)
    action = args.accel_action

    if action == "hosts":
        path = ensure_hosts_snippet(presets.ACCEL_HOSTS, path=args.out or "certs/hosts-snippet.txt")
        print(f"hosts 片段已生成：{path}")
        print(path.read_text(encoding="utf-8"))
        if args.apply:
            print("写入系统 hosts 需要管理员权限，执行：")
            print("  powershell -ExecutionPolicy Bypass -File scripts\\apply-hosts.ps1 -Apply")
        return 0

    if action == "probe":
        async def run():
            resolver = Resolver(cfg.dns)
            router = Router(cfg, resolver)
            accel = Accelerator(cfg, router)
            host = args.host or "github.com"
            rows = await accel.probe(host, int(args.port or cfg.accel.upstream_port))
            print(f"{host} 的候选 IP（真 TLS 握手测延迟）：")
            for row in rows:
                if row["ok"]:
                    print(f"  {row['ip']:<40} {row['ms']:>7.0f}ms  alpn={row.get('alpn')}")
                else:
                    print(f"  {row['ip']:<40} 失败  {row['error'][:70]}")
            fast = [r for r in rows if r["ok"]]
            if fast:
                best = min(fast, key=lambda r: r["ms"])
                print(f"\n最快：{best['ip']}（{best['ms']:.0f}ms）")
                print(f'可写入配置： "ip_overrides": {{"{host}": ["{best["ip"]}"]}}')
        asyncio.run(run())
        return 0

    if action == "status":
        try:
            store = CAStore(cfg.accel.ca_dir, cfg.accel.ca_common_name,
                            cfg.accel.ca_organization)
            info = store.describe()
        except CAError as exc:
            print(f"CA 不可用：{exc}")
            info = {"exists": False}
        info["accelerator"] = {
            "enabled": cfg.accel.enabled,
            "mode": cfg.accel.mode,
            "listen": f"{cfg.accel.host}:{cfg.accel.port}",
            "upstream_verify": cfg.accel.upstream_verify,
            "ip_overrides": cfg.accel.ip_overrides,
        }
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0

    print("未知 accel 动作", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------
# daemon（后台常驻）/ selftest（代理可用性）
# --------------------------------------------------------------------------

def cmd_daemon(args) -> int:
    from . import daemon

    action = args.daemon_action
    if action == "start":
        info = daemon.start(args.config)
        if info.get("already"):
            print(f"已在后台运行：PID {info['pid']}（配置 {info.get('config')}）")
        else:
            state = "就绪" if info.get("ready") else "启动中"
            print(f"已后台启动：PID {info['pid']}  SOCKS5 127.0.0.1:{info.get('socks5_port')}  {state}")
            print(f"日志：{daemon.log_file()}")
        return 0
    if action == "stop":
        out = daemon.stop()
        print("已停止" if out.get("stopped") else "当前没有在跑的代理")
        return 0
    if action == "restart":
        daemon.stop()
        info = daemon.start(args.config)
        print(f"已重启：PID {info.get('pid')}")
        return 0
    info = daemon.status()
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0 if info.get("running") else 1


def cmd_selftest(args) -> int:
    from . import daemon

    cfg = _load(args)
    setup_logging("warning")
    result = asyncio.run(daemon.selftest(
        cfg, start_if_down=not args.no_start, target=args.target))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"目标 {result['target']} · 配置 {result['config']}")
        for item in result["checks"]:
            mark = "PASS" if item["ok"] else "FAIL"
            extra = item.get("status") or item.get("error") or ""
            print(f"  [{mark}] {item['name']:<14} {item['ms']:>7.0f}ms  {extra[:80]}")
        print("结论：" + ("代理可用" if result["ok"] else "代理不可用"))
    return 0 if result["ok"] else 1


def cmd_latency(args) -> int:
    from . import latency

    cfg = _load(args)
    setup_logging("warning")
    sites = args.hosts or latency.DEFAULT_SITES
    paths = tuple(p.strip() for p in (args.paths or "direct,proxy").split(",") if p.strip())
    rows = asyncio.run(latency.matrix(
        sites, proxy_port=cfg.socks5.port, count=args.count, paths=paths,
        concurrency=args.concurrency))
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print(latency.format_table(rows, paths))
    return 0 if any(r.get("direct") or r.get("proxy") for r in rows) else 1


def _load(args) -> Config:
    path = args.config
    try:
        return Config.load(path)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        raise SystemExit(2)


def _jsonable(value):
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def cmd_gui(args) -> int:
    from .gui import hide_console, launch

    hide_console()
    return launch(args.config, smoke_shot=getattr(args, "smoke_shot", None))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="localproxy",
        description=f"localproxy / 小酱代理 {__version__} —— 本地 SOCKS5/HTTP 代理，"
                    "多上游分流（GitHub / HuggingFace 等）",
    )
    parser.add_argument("--version", action="version", version=f"localproxy {__version__}")
    parser.add_argument("--no-icon", action="store_true", help="不修改窗口图标（调试用）")
    parser.add_argument("-c", "--config", default="config.json",
                        help="配置文件路径（默认 config.json）")
    parser.add_argument("--smoke-shot", default=None, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_gui = sub.add_parser("gui", help="打开图形界面（不带参数双击 exe 也是它）")
    p_gui.add_argument("-c", "--config", default="config.json")
    p_gui.add_argument("--smoke-shot", default=None, help=argparse.SUPPRESS)
    p_gui.set_defaults(func=cmd_gui)

    p_run = sub.add_parser("run", help="启动代理服务（命令行/后台）")
    p_run.add_argument("-c", "--config", default="config.json")
    p_run.add_argument("--log-level")
    p_run.add_argument("--restart", action="store_true", help="崩溃后自动重启（后台常驻）")
    p_run.set_defaults(func=cmd_run)

    p_daemon = sub.add_parser("daemon", help="后台常驻：start/stop/restart/status")
    p_daemon.add_argument("daemon_action", choices=["start", "stop", "restart", "status"])
    p_daemon.add_argument("-c", "--config", default="config.json")
    p_daemon.set_defaults(func=cmd_daemon)

    p_self = sub.add_parser("selftest", help="自动测试本地代理是否可用")
    p_self.add_argument("-c", "--config", default="config.json")
    p_self.add_argument("--target", default="github.com")
    p_self.add_argument("--no-start", action="store_true", help="不自动拉起后台代理")
    p_self.add_argument("--json", action="store_true")
    p_self.set_defaults(func=cmd_selftest)

    p_lat = sub.add_parser("latency", help="网站延迟检测（直连 / 经代理）")
    p_lat.add_argument("-c", "--config", default="config.json")
    p_lat.add_argument("--hosts", nargs="*", help="自定义站点，默认内置开发站点清单")
    p_lat.add_argument("--paths", default="direct,proxy",
                       help="direct / proxy / direct,proxy")
    p_lat.add_argument("--count", type=int, default=3, help="每个站点采样次数")
    p_lat.add_argument("--concurrency", type=int, default=4)
    p_lat.add_argument("--json", action="store_true")
    p_lat.set_defaults(func=cmd_latency)

    p_check = sub.add_parser("check", help="连通性自检（含真实 TLS 握手）")
    p_check.add_argument("-c", "--config", default="config.json")
    p_check.add_argument("--log-level")
    p_check.set_defaults(func=cmd_check)

    p_gen = sub.add_parser("gen-config", help="生成配置模板")
    p_gen.add_argument("-o", "--out", default="config.json")
    p_gen.add_argument("--preset", default="dev", choices=sorted(presets.PRESETS))
    p_gen.add_argument("--node-host", default="NODE_HOST")
    p_gen.add_argument("--node-port", type=int, default=443)
    p_gen.add_argument("--node-password", default="NODE_PASSWORD")
    p_gen.add_argument("--node-sni", default="")
    p_gen.set_defaults(func=cmd_gen_config)

    p_rules = sub.add_parser("rules", help="打印或测试规则")
    p_rules.add_argument("-c", "--config", default="config.json")
    p_rules.add_argument("--test", nargs="*", help="例如 --test github.com huggingface.co:443")
    p_rules.set_defaults(func=cmd_rules)

    p_cert = sub.add_parser("cert", help="本地 CA：生成 / 导出 / 导入信任 / 签发域名证书")
    p_cert.add_argument("cert_action",
                        choices=["init", "status", "export", "trust", "untrust",
                                 "issue", "leaves"])
    p_cert.add_argument("-c", "--config", default="config.json")
    p_cert.add_argument("--force", action="store_true", help="强制重建/重签")
    p_cert.add_argument("--out", default="", help="export 的目标路径")
    p_cert.add_argument("--hosts", nargs="*", help="issue 指定域名，默认用内置加速名单")
    p_cert.add_argument("--days", type=int, default=397)
    p_cert.set_defaults(func=cmd_cert)

    p_accel = sub.add_parser("accel", help="hosts 加速：生成 hosts 片段 / 探测最快 IP / 查看状态")
    p_accel.add_argument("accel_action", choices=["hosts", "probe", "status"])
    p_accel.add_argument("-c", "--config", default="config.json")
    p_accel.add_argument("--host", help="probe 的目标域名")
    p_accel.add_argument("--port", type=int, default=0)
    p_accel.add_argument("--out", default="")
    p_accel.add_argument("--apply", action="store_true")
    p_accel.set_defaults(func=cmd_accel)

    p_sys = sub.add_parser("sysproxy", help="设置/关闭 Windows 系统代理")
    p_sys.add_argument("action", choices=["on", "off", "status"])
    p_sys.add_argument("-c", "--config", default="config.json")
    p_sys.add_argument("--scheme", choices=["http", "socks"], default="http")
    p_sys.add_argument("--server", default="")
    p_sys.set_defaults(func=cmd_sysproxy)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        return cmd_gui(args)
    if not getattr(args, "no_icon", False):
        from .icon import apply_icon

        apply_icon()
    return args.func(args)
