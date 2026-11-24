"""加速器：把 github.com / huggingface.co 在 hosts 里指到本机，由本进程接管。

两种模式：

  sni   —— 纯 TCP 透传：只窥探 ClientHello 里的 SNI，选好上游后原样转发，
           证书仍是服务器真证书，客户端零配置。
  mitm  —— 本地 CA 签发证书就地终止 TLS，
           可在 HTTP 层改写请求/响应头；需要把 certs/MyCA.cer 装进信任区。

上游怎么走仍然由规则决定：命中 PROXY 组就走 SOCKS5/Trojan 隧道，命中 DIRECT 就直连
（可用 accelerator.ip_overrides 指定“能连通的 IP”，加速效果主要来自这一步）。
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time

from .ca import CAStore
from .netutil import header_get, parse_head, read_head, relay

log = logging.getLogger("localproxy.accel")

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
}

# 这两类响应头会让浏览器绕过本地代理（h3/alt-svc）或拦下被改写的资源（CSP）
DROP_RESPONSE_HEADERS = {
    "alt-svc",
    "content-security-policy",
    "content-security-policy-report-only",
}

MAX_HELLO = 32768


# --------------------------------------------------------------------------
# ClientHello 解析
# --------------------------------------------------------------------------

def _decode_name(raw: bytes) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def parse_client_hello(data: bytes) -> str | None:
    """从 TLS ClientHello 里取 server_name；解析失败返回 None（绝不抛异常）。"""
    try:
        if len(data) < 6 or data[0] != 0x16:
            return None
        record_len = int.from_bytes(data[3:5], "big")
        body = data[5:5 + record_len]
        if len(body) < 4 or body[0] != 0x01:
            return None
        hs_len = int.from_bytes(body[1:4], "big")
        hs = body[4:4 + hs_len]
        pos = 2 + 32  # legacy_version + random
        if len(hs) < pos + 1:
            return None
        sid_len = hs[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(hs[pos:pos + 2], "big")
        pos += 2 + cs_len
        comp_len = hs[pos]
        pos += 1 + comp_len
        if pos + 2 > len(hs):
            return None
        ext_total = int.from_bytes(hs[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(hs))
        while pos + 4 <= end:
            etype = int.from_bytes(hs[pos:pos + 2], "big")
            elen = int.from_bytes(hs[pos + 2:pos + 4], "big")
            start = pos + 4
            if etype == 0x0000:  # server_name
                blob = hs[start:start + elen]
                if len(blob) < 5:
                    return None
                name_type = blob[2]
                nlen = int.from_bytes(blob[3:5], "big")
                if name_type != 0:
                    return None
                return _decode_name(blob[5:5 + nlen]) or None
            pos = start + elen
        return None
    except Exception:  # noqa: BLE001
        return None


async def read_client_hello(reader: asyncio.StreamReader, limit: int = MAX_HELLO) -> bytes:
    """读满一条 TLS handshake 记录（透传模式要先看清 SNI 再决定去哪）。"""
    header = await asyncio.wait_for(reader.readexactly(5), 15)
    if header[0] != 0x16:
        raise ConnectionError(f"不是 TLS 握手（type=0x{header[0]:02x}）")
    length = int.from_bytes(header[3:5], "big")
    if length > limit:
        raise ConnectionError(f"ClientHello 过大：{length}")
    return header + await asyncio.wait_for(reader.readexactly(length), 15)


# --------------------------------------------------------------------------
# 加速器
# --------------------------------------------------------------------------

class Accelerator:
    def __init__(self, cfg, router):
        self.cfg = cfg
        self.router = router
        spec = cfg.accel
        self.spec = spec
        self.store = CAStore(spec.ca_dir, spec.ca_common_name, spec.ca_organization)
        self.servers: list[asyncio.AbstractServer] = []
        self.ports: dict[str, int] = {}
        self._ctx: ssl.SSLContext | None = None
        self.stats = {"total": 0, "ok": 0, "failed": 0, "up_bytes": 0, "down_bytes": 0}

    # ------------------------------------------------------------------ 生命周期
    async def start(self) -> dict[str, int]:
        spec = self.spec
        if spec.mode == "mitm":
            self.store.ensure()
            ctx = self.store.base_context()
        else:
            ctx = None
        srv = await asyncio.start_server(
            self._handler_for(spec.mode),
            spec.host,
            spec.port,
            ssl=ctx,
            limit=2**20,
            reuse_address=True,
        )
        self.servers.append(srv)
        port = int(srv.sockets[0].getsockname()[1])
        self.ports["accel"] = port
        log.info(
            "加速器已启动：%s://%s:%d  模式 %s",
            "https" if spec.mode == "mitm" else "tcp", spec.host, port, spec.mode,
        )
        return self.ports

    async def close(self) -> None:
        for srv in self.servers:
            srv.close()
        for srv in self.servers:
            try:
                await asyncio.wait_for(srv.wait_closed(), 3)
            except Exception:  # noqa: BLE001
                pass

    def _handler_for(self, mode: str):
        if mode == "mitm":
            return self._handle_mitm
        return self._handle_passthrough

    def snapshot(self) -> dict:
        return {
            "mode": self.spec.mode,
            "listen": f"{self.spec.host}:{self.ports.get('accel', self.spec.port)}",
            "ca": self.store.describe(),
            "stats": dict(self.stats),
            "ip_overrides": self.spec.ip_overrides,
        }

    # ------------------------------------------------------------------ 上游
    def upstream_context(self) -> ssl.SSLContext:
        if self._ctx is not None:
            return self._ctx
        spec = self.spec
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        if not spec.upstream_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif spec.upstream_ca:
            ctx.load_verify_locations(cafile=spec.upstream_ca)
        self._ctx = ctx
        return ctx

    async def dial(self, host: str, port: int):
        """按规则选路；命中 DIRECT 且配了 ip_overrides 时用指定 IP。"""
        policy = await self.router.decide(host, port)
        overrides = self.spec.ip_overrides.get(host) or self.spec.ip_overrides.get(f"*.{host}")
        if overrides and policy.upper() == "DIRECT":
            if isinstance(overrides, str):
                overrides = [overrides]
            last: Exception | None = None
            for ip in overrides:
                try:
                    u_reader, u_writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, limit=2**20), 10
                    )
                    return u_reader, u_writer, "DIRECT", f"ip:{ip}"
                except Exception as exc:  # noqa: BLE001
                    last = exc
            if last:
                log.debug("ip_overrides 全部失败 %s：%s", host, last)
        return await self.router.dial(host, port, policy)

    # ------------------------------------------------------------------ 透传模式
    async def _handle_passthrough(self, reader, writer) -> None:
        peer = _peer(writer)
        self.stats["total"] += 1
        try:
            hello = await read_client_hello(reader)
            sni = parse_client_hello(hello)
            if not sni:
                log.debug("SNI 解析失败，断开 %s", peer)
                self.stats["failed"] += 1
                return
            port = self.spec.upstream_port
            u_reader, u_writer, policy, tag = await self.dial(sni, port)
            u_writer.write(hello)
            await u_writer.drain()
            self.stats["ok"] += 1
            log.info("[ACC] %-16s %-36s %-8s %s", peer, f"{sni}:{port}", policy, tag)
            up, down = await relay(reader, writer, u_reader, u_writer,
                                   self.cfg.timeout("idle", 300))
            self.stats["up_bytes"] += up
            self.stats["down_bytes"] += down
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            log.debug("透传会话结束 %s：%s", peer, exc)
        except Exception:  # noqa: BLE001
            log.debug("透传会话异常", exc_info=True)
        finally:
            _close(writer)

    # ------------------------------------------------------------------ 证书模式
    async def _handle_mitm(self, reader, writer) -> None:
        peer = _peer(writer)
        self.stats["total"] += 1
        try:
            sslobj = writer.get_extra_info("ssl_object")
            sni = self.store.pop_sni(sslobj)
            head, rest = await asyncio.wait_for(read_head(reader, 65536), 30)
            start, headers = parse_head(head)
            try:
                method, target, version = start.split(" ", 2)
            except ValueError:
                await self._error(writer, 400, "请求行无法解析")
                self.stats["failed"] += 1
                return

            host_header = header_get(headers, "host") or ""
            host, port = split_host(host_header or sni or "", self.spec.upstream_port)
            if not host:
                await self._error(writer, 400, "缺少 Host 且无法从 SNI 推断目标")
                self.stats["failed"] += 1
                return

            await self._proxy_http(reader, writer, peer, method, target, version,
                                   headers, rest, host, port)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            log.debug("证书会话结束 %s：%s", peer, exc)
        except Exception:  # noqa: BLE001
            log.debug("证书会话异常", exc_info=True)
            await self._error(writer, 502, "本地加速器内部错误")
        finally:
            _close(writer)

    async def _proxy_http(self, reader, writer, peer, method, target, version,
                          headers, rest, host, port) -> None:
        upstream_port = self.spec.upstream_port
        try:
            u_reader, u_writer, policy, tag = await self.dial(host, upstream_port)
        except Exception as exc:  # noqa: BLE001
            self.stats["failed"] += 1
            log.warning("[ACC] %-16s %-36s 失败 %s", peer, f"{host}:{upstream_port}", exc)
            await self._error(writer, 502, f"上游不可达：{exc}")
            return

        try:
            ctx = self.upstream_context()
            await asyncio.wait_for(
                u_writer.start_tls(ctx, server_hostname=host), 15
            )
        except Exception as exc:  # noqa: BLE001
            _close(u_writer)
            self.stats["failed"] += 1
            log.warning("[ACC] %s 上游 TLS 失败：%s", host, exc)
            await self._error(writer, 502, f"上游 TLS 失败：{exc}")
            return

        path = target if target.startswith("/") else _origin_form(target)
        out = [f"{method} {path} {version}"]
        for name, value in headers:
            low = name.lower()
            if low in HOP_BY_HOP or low == "host":
                continue
            out.append(f"{name}: {value}")
        out.append(f"Host: {host}")
        out.append("Connection: close")
        out.append("X-Localproxy-Accel: 1")
        u_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        if rest:
            u_writer.write(rest)
        await u_writer.drain()

        try:
            r_head, r_rest = await asyncio.wait_for(read_head(u_reader, 65536), 60)
        except Exception as exc:  # noqa: BLE001
            _close(u_writer)
            self.stats["failed"] += 1
            await self._error(writer, 502, f"上游响应头读取失败：{exc}")
            return

        status = r_head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        writer.write(_filter_response_head(r_head, self.spec.strip_csp))
        if r_rest:
            writer.write(r_rest)
        await writer.drain()

        self.stats["ok"] += 1
        log.info("[ACC] %-16s %-36s %-8s %-12s %s", peer, f"{host}:{upstream_port}",
                 policy, tag, status.strip())

        down = len(r_rest)
        try:
            while True:
                chunk = await asyncio.wait_for(u_reader.read(65536), 300)
                if not chunk:
                    break
                down += len(chunk)
                writer.write(chunk)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            pass
        finally:
            _close(u_writer)
        self.stats["down_bytes"] += down

    async def _error(self, writer, code: int, detail: str) -> None:
        body = f"localproxy accel: {detail}\n".encode("utf-8")
        head = (
            f"HTTP/1.1 {code} {'Bad Gateway' if code == 502 else 'Bad Request'}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            writer.write(head + body)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ 自检
    async def probe(self, host: str, port: int | None = None) -> list[dict]:
        """给 `localproxy accel probe` 用：逐个 IP 做真 TLS 握手测延迟。"""
        port = port or self.spec.upstream_port
        try:
            ips = await self.router.resolver.resolve(host)
        except Exception as exc:  # noqa: BLE001
            return [{"ip": "-", "ok": False, "error": str(exc), "ms": 0.0}]
        out = []
        for ip in ips:
            started = time.monotonic()
            try:
                ctx = self.upstream_context()
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host, limit=2**16),
                    10,
                )
                alpn = w.get_extra_info("ssl_object").selected_alpn_protocol()
                w.close()
                out.append({"ip": ip, "ok": True, "ms": (time.monotonic() - started) * 1000,
                            "alpn": alpn})
            except Exception as exc:  # noqa: BLE001
                out.append({"ip": ip, "ok": False, "error": str(exc),
                            "ms": (time.monotonic() - started) * 1000})
        return out


# --------------------------------------------------------------------------
# 辅助
# --------------------------------------------------------------------------

def split_host(value: str, default_port: int) -> tuple[str, int]:
    value = (value or "").strip()
    if not value:
        return "", default_port
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return value[1:], default_port
        host = value[1:end]
        rest = value[end + 1:]
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
    host, sep, tail = value.rpartition(":")
    if sep and tail.isdigit():
        return host, int(tail)
    return value, default_port


def _origin_form(target: str) -> str:
    if "://" not in target:
        return target
    rest = target.split("://", 1)[1]
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


def _filter_response_head(head: bytes, strip_csp: bool) -> bytes:
    if not strip_csp:
        return head
    text = head.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = text.split("\r\n")
    kept = [lines[0]]
    for line in lines[1:]:
        name = line.split(":", 1)[0].strip().lower()
        if name in DROP_RESPONSE_HEADERS:
            continue
        kept.append(line)
    return ("\r\n".join(kept) + "\r\n\r\n").encode("latin-1")


def _peer(writer) -> str:
    info = writer.get_extra_info("peername")
    return f"{info[0]}:{info[1]}" if info else "?"


def _close(writer) -> None:
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
