"""后台常驻：把代理丢到后台跑起来，带崩溃自动重启与 PID 管理。

设计（Windows 友好，不需要管理员、不装服务）：
  * daemon start  → Popen(DETACHED_PROCESS) 起一个 `run --restart` 子进程，
                    主进程立刻返回，控制台可以关掉；
  * run --restart → 内部看护循环，代理异常退出 3 秒后自动拉起；
  * daemon stop   → 读 PID 文件，taskkill /T 整棵进程树；
  * daemon status → tasklist 校验 PID 是否还活着。

开机自启由安装器写 HKCU\\...\\Run = "<exe> daemon start"，同样不需要管理员。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR_NAME = "FURINA-GITHUB-PROXY"
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def _listen_port(config: str | Path, key: str = "socks5") -> int:
    """从配置文件里读监听端口，读不出来就用默认值。"""
    default = {"socks5": 7890, "http": 7891, "api": 7892}[key]
    try:
        raw = json.loads(Path(config).read_text(encoding="utf-8-sig"))
        return int(((raw.get("listeners") or {}).get(key) or {}).get("port", default))
    except Exception:  # noqa: BLE001
        return default


def state_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or str(Path.home())
    path = Path(base) / STATE_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def pid_file() -> Path:
    return state_dir() / "proxy.pid"


def log_file() -> Path:
    return state_dir() / "proxy.log"


def info_file() -> Path:
    return state_dir() / "proxy.json"


def _launcher() -> tuple[list[str], str]:
    """返回 (可执行前缀, 说明)。冻结版直接用 exe，源码版用 python -m localproxy。"""
    if getattr(sys, "frozen", False):
        return [sys.executable], "exe"
    return [sys.executable, "-m", "localproxy"], "python"


def read_pid() -> int | None:
    try:
        data = json.loads(info_file().read_text(encoding="utf-8"))
        return int(data.get("pid")) if data.get("pid") else None
    except Exception:  # noqa: BLE001
        pass
    try:
        return int(pid_file().read_text(encoding="utf-8").strip())
    except Exception:  # noqa: BLE001
        return None


def is_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if sys.platform.startswith("win"):
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                             capture_output=True, text=True)
        return str(pid) in (out.stdout or "")
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def status() -> dict:
    pid = read_pid()
    alive = is_alive(pid)
    data: dict = {"running": alive, "pid": pid if alive else None}
    try:
        data.update(json.loads(info_file().read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001
        pass
    data["log"] = str(log_file())
    return data


def start(config: str = "config.json", extra: list[str] | None = None) -> dict:
    """后台启动；已在跑就直接返回当前状态。"""
    current = status()
    if current.get("running"):
        current["already"] = True
        return current

    cmd_prefix, _kind = _launcher()
    cmd = cmd_prefix + ["run", "-c", config, "--restart"] + list(extra or [])
    state_dir().mkdir(parents=True, exist_ok=True)
    log = log_file().open("ab")
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": log,
        "stderr": log,
        "close_fds": True,
        "cwd": str(Path(config).resolve().parent) if Path(config).parent else os.getcwd(),
    }
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(cmd, **kwargs)
    log.close()
    pid_file().write_text(str(proc.pid), encoding="utf-8")

    # 等端口真的能连上（最多 8 秒），否则后台进程可能起不来
    port = _listen_port(config, "socks5")
    ready = False
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                ready = True
                break
        except OSError:
            time.sleep(0.2)

    info = {"pid": proc.pid, "config": str(Path(config).resolve()),
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ready": ready, "socks5_port": port, "cmd": " ".join(cmd)}
    info_file().write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    info["running"] = is_alive(proc.pid)
    return info


def stop() -> dict:
    pid = read_pid()
    if not pid or not is_alive(pid):
        for path in (pid_file(), info_file()):
            try:
                path.unlink()
            except OSError:
                pass
        return {"stopped": False, "reason": "not running"}
    if sys.platform.startswith("win"):
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        os.kill(pid, 15)
    for _ in range(25):
        if not is_alive(pid):
            break
        time.sleep(0.2)
    for path in (pid_file(), info_file()):
        try:
            path.unlink()
        except OSError:
            pass
    return {"stopped": True, "pid": pid}


def tail_log(lines: int = 30) -> str:
    try:
        content = log_file().read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except OSError:
        return ""


# --------------------------------------------------------------------------
# 代理可用性自测
# --------------------------------------------------------------------------

async def probe_via_socks5(proxy_port: int, host: str, port: int, timeout: float = 25.0) -> dict:
    import asyncio
    import ssl

    from .netutil import encode_addr, read_head

    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", proxy_port, limit=2**20), timeout)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"连不上本地 SOCKS5 {proxy_port}：{exc}", "ms": 0}
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        _, method = await asyncio.wait_for(reader.readexactly(2), timeout)
        if method != 0:
            return {"ok": False, "error": "SOCKS5 协商失败（本地代理未开启免认证）", "ms": 0}
        writer.write(b"\x05\x01\x00" + encode_addr(host, port))
        await writer.drain()
        _, rep, _, atyp = await asyncio.wait_for(reader.readexactly(4), timeout)
        if rep != 0:
            return {"ok": False, "error": f"SOCKS5 CONNECT 被拒（rep={rep}）", "ms": 0}
        if atyp == 0x01:
            await reader.readexactly(6)
        elif atyp == 0x04:
            await reader.readexactly(18)
        else:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln + 2)
        ctx = ssl.create_default_context()
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
        writer.write(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fgp-selftest\r\n"
                     "Connection: close\r\n\r\n".encode())
        await writer.drain()
        head, _ = await asyncio.wait_for(read_head(reader, 32768), timeout)
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        return {"ok": line.upper().startswith("HTTP/"), "status": line,
                "ms": (time.monotonic() - started) * 1000}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "ms": (time.monotonic() - started) * 1000}
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def probe_via_http(proxy_port: int, host: str, port: int, timeout: float = 25.0) -> dict:
    import asyncio
    import ssl

    from .netutil import read_head

    started = time.monotonic()
    authority = f"{host}:{port}"
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", proxy_port, limit=2**20), timeout)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"连不上本地 HTTP 代理 {proxy_port}：{exc}", "ms": 0}
    try:
        writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        await writer.drain()
        head, _ = await asyncio.wait_for(read_head(reader, 8192), timeout)
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        if " 200 " not in line + " ":
            return {"ok": False, "error": f"HTTP 代理拒绝 CONNECT：{line}", "ms": 0}
        ctx = ssl.create_default_context()
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
        writer.write(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fgp-selftest\r\n"
                     "Connection: close\r\n\r\n".encode())
        await writer.drain()
        head2, _ = await asyncio.wait_for(read_head(reader, 32768), timeout)
        line2 = head2.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        return {"ok": line2.upper().startswith("HTTP/"), "status": line2,
                "ms": (time.monotonic() - started) * 1000}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "ms": (time.monotonic() - started) * 1000}
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def probe_http_forward(proxy_port: int, api_port: int, timeout: float = 8.0) -> dict:
    """走 HTTP 代理发一个普通请求（不带 CONNECT），验证绝对 URI 转发。"""
    import asyncio

    from .netutil import read_head

    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", proxy_port), timeout)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "ms": 0}
    try:
        writer.write(f"GET http://127.0.0.1:{api_port}/health HTTP/1.1\r\n"
                     f"Host: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        head, _ = await asyncio.wait_for(read_head(reader, 8192), timeout)
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        return {"ok": " 200 " in line + " ", "status": line,
                "ms": (time.monotonic() - started) * 1000}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "ms": (time.monotonic() - started) * 1000}
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def selftest(config, start_if_down: bool = True, target: str = "github.com") -> dict:
    """跑三项检查：SOCKS5 隧道 / HTTP CONNECT / HTTP 明文转发。"""
    import asyncio

    cfg = config
    result = {"config": str(cfg.source), "target": target, "checks": []}
    ports = {"socks5": cfg.socks5.port, "http": cfg.http.port, "api": cfg.api.port}

    if start_if_down:
        st = status()
        if not st.get("running"):
            spawned = start(str(cfg.source) if Path(cfg.source).exists() else "config.json")
            result["spawned"] = spawned.get("pid")
            await asyncio.sleep(1.5)
            ports = {"socks5": cfg.socks5.port, "http": cfg.http.port, "api": cfg.api.port}

    checks = [
        ("socks5", await probe_via_socks5(ports["socks5"], target, 443)),
        ("http-connect", await probe_via_http(ports["http"], target, 443)),
        ("http-forward", await probe_http_forward(ports["http"], ports["api"])),
    ]
    result["checks"] = [{"name": name, **data} for name, data in checks]
    result["ok"] = all(item["ok"] for item in result["checks"])
    return result
