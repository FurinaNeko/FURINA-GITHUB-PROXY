"""本地 HTTP 代理：CONNECT 隧道 + 绝对 URI 正向代理。

浏览器 / git / curl 配置 http_proxy 后都会走这里：
  * CONNECT host:443   -> 建隧道，交给上游
  * GET http://host/x  -> 改写成源站请求转发
一条连接处理一个请求（Connection: close），客户端会自动重连，行为简单可控。
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
from urllib.parse import urlsplit

from .netutil import (
    header_get,
    parse_head,
    push_back,
    read_head,
    relay,
)

log = logging.getLogger("localproxy.http")

HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
}


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, srv) -> None:
    peer = _peer(writer)
    srv.stats["http_total"] += 1
    try:
        head, rest = await asyncio.wait_for(read_head(reader), 30)
        try:
            start, headers = parse_head(head)
            method, target, version = start.split(" ", 2)
        except ValueError as exc:
            await _error(writer, 400, "Bad Request", "请求行无法解析")
            raise ConnectionError("请求行无法解析") from exc

        if not _check_auth(headers, srv.cfg.http):
            await _error(
                writer, 407, "Proxy Authentication Required",
                "需要代理认证",
                extra='Proxy-Authenticate: Basic realm="localproxy"\r\n',
            )
            srv.stats["http_failed"] += 1
            srv.log_route(peer, target, 0, "-", "-", False, "407 需要认证")
            return

        if method.upper() == "CONNECT":
            await _tunnel(reader, writer, srv, peer, target, rest)
        else:
            await _forward(reader, writer, srv, peer, method, target, version, headers, rest)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
        log.debug("HTTP 会话结束 %s：%s", peer, exc)
    except Exception as exc:  # noqa: BLE001
        log.debug("HTTP 会话异常 %s：%r", peer, exc)
        await _error(writer, 502, "Bad Gateway", str(exc))
    finally:
        _close(writer)


async def _tunnel(reader, writer, srv, peer, target, rest) -> None:
    host, port = _split_authority(target, 443)
    try:
        u_reader, u_writer, policy, up = await srv.router.dial(host, port)
    except Exception as exc:  # noqa: BLE001
        srv.stats["http_failed"] += 1
        srv.log_route(peer, host, port, "-", "-", False, str(exc))
        await _error(writer, 502, "Bad Gateway", str(exc))
        return

    srv.stats["http_ok"] += 1
    srv.log_route(peer, host, port, policy, up.name, True, "")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    if rest:
        u_writer.write(rest)
        await u_writer.drain()
    up_bytes, down_bytes = await relay(
        reader, writer, u_reader, u_writer, srv.cfg.timeout("idle", 300)
    )
    srv.add_traffic(up_bytes, down_bytes)


async def _forward(reader, writer, srv, peer, method, target, version, headers, rest) -> None:
    parts = urlsplit(target)
    if not parts.scheme:
        await _error(writer, 400, "Bad Request", "非代理请求：缺少绝对 URI")
        return
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        await _error(writer, 400, "Bad Request", f"不支持的协议 {scheme}")
        return

    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    try:
        u_reader, u_writer, policy, up = await srv.router.dial(host, port)
    except Exception as exc:  # noqa: BLE001
        srv.stats["http_failed"] += 1
        srv.log_route(peer, host, port, "-", "-", False, str(exc))
        await _error(writer, 502, "Bad Gateway", str(exc))
        return

    if scheme == "https":
        # 明文代理端口上的 https:// 绝对 URI 很罕见，交给上层 CONNECT 更稳妥
        u_writer.close()
        await _error(writer, 400, "Bad Request", "https 请使用 CONNECT")
        return

    out = [f"{method} {path} HTTP/1.1"]
    has_host = False
    for name, value in headers:
        low = name.lower()
        if low in HOP_BY_HOP:
            continue
        if low == "host":
            has_host = True
        out.append(f"{name}: {value}")
    if not has_host:
        out.append(f"Host: {parts.netloc}")
    out.append("Connection: close")
    u_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
    if rest:
        u_writer.write(rest)
    await u_writer.drain()

    try:
        r_head, r_rest = await asyncio.wait_for(read_head(u_reader), 60)
    except Exception as exc:  # noqa: BLE001
        u_writer.close()
        srv.stats["http_failed"] += 1
        srv.log_route(peer, host, port, policy, up.name, False, f"响应头读取失败：{exc}")
        await _error(writer, 502, "Bad Gateway", "上游响应头读取失败")
        return

    start_line = r_head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    writer.write(r_head)
    if r_rest:
        writer.write(r_rest)
    await writer.drain()

    srv.stats["http_ok"] += 1
    srv.log_route(peer, host, port, policy, up.name, True, start_line)

    up_bytes = len(rest)
    down_bytes = len(r_rest)
    try:
        while True:
            chunk = await asyncio.wait_for(u_reader.read(65536), 300)
            if not chunk:
                break
            down_bytes += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        pass
    finally:
        u_writer.close()
    srv.add_traffic(up_bytes, down_bytes)


# --------------------------------------------------------------------------
# 辅助
# --------------------------------------------------------------------------

def _check_auth(headers, listener) -> bool:
    if not listener.needs_auth:
        return True
    value = header_get(headers, "Proxy-Authorization")
    if not value:
        return False
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        raw = base64.b64decode(token.strip()).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return False
    user, _, pwd = raw.partition(":")
    return hmac.compare_digest(user, listener.username) and hmac.compare_digest(
        pwd, listener.password
    )


def _split_authority(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        end = target.find("]")
        host = target[1:end]
        rest = target[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if ":" in target:
        host, _, port_text = target.rpartition(":")
        if port_text.isdigit():
            return host, int(port_text)
    return target, default_port


async def _error(writer, code: int, reason: str, detail: str, extra: str = "") -> None:
    body = f"localproxy: {detail}\n".encode("utf-8")
    head = (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{extra}"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    try:
        writer.write(head + body)
        await writer.drain()
    except Exception:  # noqa: BLE001
        pass


def _peer(writer) -> str:
    info = writer.get_extra_info("peername")
    return f"{info[0]}:{info[1]}" if info else "?"


def _close(writer) -> None:
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
