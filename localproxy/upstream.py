"""上游连接器：direct / http(CONNECT) / socks5 / trojan(TLS)，含健康检查与故障切换。

每个上游维护自己的健康状态（延迟 EWMA、失败计数、冷却期），
Router 选路时先取健康的、延迟最低的，失败立刻换下一个。
"""

from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import time

from .config import Config, UpstreamSpec
from .netutil import encode_addr, read_head
from .resolver import Resolver, open_any

log = logging.getLogger("localproxy.upstream")

SOCKS5_ERRORS = {
    1: "通用失败",
    2: "规则不允许",
    3: "网络不可达",
    4: "主机不可达",
    5: "连接被拒绝",
    6: "TTL 过期",
    7: "命令不支持",
    8: "地址类型不支持",
}


class UpstreamError(Exception):
    """上游握手 / 连接失败。"""


class Upstream:
    def __init__(self, spec: UpstreamSpec, resolver: Resolver, cfg: Config):
        self.spec = spec
        self.name = spec.name
        self.type = spec.type
        self.resolver = resolver
        self.cfg = cfg
        # 健康状态
        self.healthy = True
        self.latency: float | None = None      # 健康探测得到的延迟
        self.ewma: float | None = None         # 真实建连耗时（拨号时统计）
        self.fails = 0
        self.checks = 0
        self.blocked_until = 0.0
        self.last_error = ""
        self.last_ok = 0.0
        self.connects = 0

    # ------------------------------------------------------------------ 描述
    def __repr__(self) -> str:
        return f"<Upstream {self.name} {self.type}>"

    def describe(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "address": self.spec.masked(),
            "healthy": self.healthy,
            "latency_ms": round(self.latency * 1000, 1) if self.latency else None,
            "ewma_ms": round(self.ewma * 1000, 1) if self.ewma else None,
            "fails": self.fails,
            "checks": self.checks,
            "connects": self.connects,
            "last_error": self.last_error,
            "cooldown_s": max(0.0, round(self.blocked_until - time.monotonic(), 1)),
        }

    # ------------------------------------------------------------------ 参数
    @property
    def timeout(self) -> float:
        if self.spec.connect_timeout:
            return float(self.spec.connect_timeout)
        return self.cfg.timeout("connect", 8.0)

    def _resolve_locally(self) -> bool:
        if self.spec.resolve_locally is not None:
            return bool(self.spec.resolve_locally)
        return str(self.cfg.dns.get("mode", "system")).lower() == "doh"

    # ------------------------------------------------------------------ 连接
    async def connect(self, host: str, port: int):
        timeout = self.timeout
        try:
            if self.type == "direct":
                return await self._connect_direct(host, port, timeout)
            if self.type == "http":
                return await self._connect_http(host, port, timeout)
            if self.type == "socks5":
                return await self._connect_socks5(host, port, timeout)
            if self.type == "trojan":
                return await self._connect_trojan(host, port, timeout)
        except asyncio.TimeoutError as exc:
            raise UpstreamError(f"{self.name}: 握手超时（>{timeout}s）") from exc
        except UpstreamError:
            raise
        except (OSError, ConnectionError) as exc:
            raise UpstreamError(f"{self.name}: {exc}") from exc
        raise UpstreamError(f"{self.name}: 未知上游类型 {self.type}")

    async def _open(self, host: str, port: int, timeout: float):
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=2**20), timeout
        )

    async def _connect_direct(self, host: str, port: int, timeout: float):
        if self._resolve_locally():
            ips = await self.resolver.resolve(host)
            return await open_any(ips, port, timeout)
        return await self._open(host, port, timeout)

    async def _connect_http(self, host: str, port: int, timeout: float):
        reader, writer = await self._open(self.spec.server, self.spec.port, timeout)
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        auth = ""
        if self.spec.username:
            token = base64.b64encode(
                f"{self.spec.username}:{self.spec.password}".encode()
            ).decode()
            auth = f"Proxy-Authorization: Basic {token}\r\n"
        req = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"{auth}"
            "Proxy-Connection: keep-alive\r\n"
            "User-Agent: localproxy/1.0\r\n\r\n"
        )
        writer.write(req.encode("latin-1"))
        await asyncio.wait_for(writer.drain(), timeout)

        head, rest = await asyncio.wait_for(read_head(reader), timeout)
        status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split()
        code = 0
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        if code != 200:
            writer.close()
            raise UpstreamError(f"{self.name}: HTTP 上游拒绝 CONNECT（{status_line}）")
        if rest:
            _push_back(reader, rest)
        return reader, writer

    async def _connect_socks5(self, host: str, port: int, timeout: float):
        reader, writer = await self._open(self.spec.server, self.spec.port, timeout)
        use_auth = bool(self.spec.username)
        greeting = b"\x05\x02\x00\x02" if use_auth else b"\x05\x01\x00"
        writer.write(greeting)
        await asyncio.wait_for(writer.drain(), timeout)

        ver, method = await asyncio.wait_for(reader.readexactly(2), timeout)
        if ver != 5:
            writer.close()
            raise UpstreamError(f"{self.name}: 不是 SOCKS5 服务（ver={ver}）")
        if method == 0xFF:
            writer.close()
            raise UpstreamError(f"{self.name}: 上游不接受任何认证方式")
        if method == 0x02:
            if not use_auth:
                writer.close()
                raise UpstreamError(f"{self.name}: 上游要求用户名密码，但配置里没有")
            user = self.spec.username.encode("utf-8")
            pwd = self.spec.password.encode("utf-8")
            writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
            await asyncio.wait_for(writer.drain(), timeout)
            _, status = await asyncio.wait_for(reader.readexactly(2), timeout)
            if status != 0:
                writer.close()
                raise UpstreamError(f"{self.name}: SOCKS5 认证失败")

        writer.write(b"\x05\x01\x00" + encode_addr(host, port))
        await asyncio.wait_for(writer.drain(), timeout)
        _, rep, _, atyp = await asyncio.wait_for(reader.readexactly(4), timeout)
        if rep != 0:
            writer.close()
            raise UpstreamError(
                f"{self.name}: SOCKS5 连接 {host}:{port} 失败 —— "
                f"{SOCKS5_ERRORS.get(rep, f'错误码 {rep}')}"
            )
        # 吃掉 BND.ADDR + BND.PORT
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout)
        elif atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout)
        elif atyp == 0x03:
            ln = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
            await asyncio.wait_for(reader.readexactly(ln + 2), timeout)
        else:
            writer.close()
            raise UpstreamError(f"{self.name}: SOCKS5 应答 ATYP 异常 0x{atyp:02x}")
        return reader, writer

    def _tls_context(self) -> ssl.SSLContext:
        cfg = self.spec.tls or {}
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        if cfg.get("insecure"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if cfg.get("ca_file"):
            ctx.load_verify_locations(cafile=cfg["ca_file"])
        alpn = cfg.get("alpn") or ["http/1.1"]
        try:
            ctx.set_alpn_protocols(list(alpn))
        except NotImplementedError:
            pass
        return ctx

    async def _connect_trojan(self, host: str, port: int, timeout: float):
        import hashlib

        cfg = self.spec.tls or {}
        sni = str(cfg.get("sni") or cfg.get("server_name") or self.spec.server)
        ctx = self._tls_context()
        reader, writer = await self._open(self.spec.server, self.spec.port, timeout)
        try:
            await asyncio.wait_for(
                writer.start_tls(ctx, server_hostname=sni), self.cfg.timeout("handshake", 10.0)
            )
        except Exception:
            writer.close()
            raise
        digest = hashlib.sha224(self.spec.password.encode("utf-8")).hexdigest().encode()
        header = digest + b"\r\n" + b"\x01" + encode_addr(host, port) + b"\r\n"
        writer.write(header)
        await asyncio.wait_for(writer.drain(), timeout)
        return reader, writer

    # ------------------------------------------------------------------ 健康
    async def probe(self) -> float | None:
        """轻量探测：TCP（或 TLS）握手延迟。direct 不探测。"""
        self.checks += 1
        if self.type == "direct":
            anchor = str(self.cfg.health.get("direct_probe") or "223.5.5.5:443")
            host, _, port_text = anchor.rpartition(":")
            started = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, int(port_text or 443), limit=2**16),
                    float(self.cfg.health.get("timeout", 4.0)))
                writer.close()
                elapsed = time.monotonic() - started
                self.latency = (elapsed if self.latency is None
                                else self.latency * 0.7 + elapsed * 0.3)
            except Exception:  # noqa: BLE001
                pass
            self.healthy = True
            return self.latency
        health_timeout = float(self.cfg.health.get("timeout", 4.0))
        probe_target = (self.spec.tls or {}).get("probe_target")
        started = time.monotonic()
        try:
            if probe_target and ":" in str(probe_target):
                p_host, p_port = str(probe_target).rsplit(":", 1)
                reader, writer = await self.connect(p_host, int(p_port))
                ctx = ssl.create_default_context()
                await asyncio.wait_for(
                    writer.start_tls(ctx, server_hostname=p_host), health_timeout
                )
                writer.close()
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.spec.server, self.spec.port, limit=2**16),
                    health_timeout,
                )
                if self.type == "trojan":
                    sni = str(
                        (self.spec.tls or {}).get("sni")
                        or (self.spec.tls or {}).get("server_name")
                        or self.spec.server
                    )
                    await asyncio.wait_for(
                        writer.start_tls(self._tls_context(), server_hostname=sni),
                        health_timeout,
                    )
                writer.close()
            elapsed = time.monotonic() - started
            self.latency = elapsed if self.latency is None else self.latency * 0.7 + elapsed * 0.3
            self.healthy = True
            self.fails = 0
            self.last_ok = time.monotonic()
            self.last_error = ""
            return elapsed
        except Exception as exc:  # noqa: BLE001
            self.fails += 1
            self.last_error = str(exc)
            if self.fails >= int(self.cfg.health.get("fail_threshold", 2)):
                self.healthy = False
                self.blocked_until = time.monotonic() + float(
                    self.cfg.health.get("cooldown", 20.0)
                )
            log.debug("探测 %s 失败：%s", self.name, exc)
            return None

    def mark_failure(self, reason: str) -> None:
        self.fails += 1
        self.last_error = reason
        if self.fails >= int(self.cfg.health.get("fail_threshold", 2)):
            self.healthy = False
            self.blocked_until = time.monotonic() + float(
                self.cfg.health.get("cooldown", 20.0)
            )

    def record_connect(self, seconds: float) -> None:
        """用真实拨号耗时更新 EWMA —— 比健康探测更贴近用户实际感受。"""
        self.ewma = seconds if self.ewma is None else self.ewma * 0.7 + seconds * 0.3

    def mark_success(self) -> None:
        self.fails = 0
        self.healthy = True
        self.last_ok = time.monotonic()


def _push_back(reader: asyncio.StreamReader, data: bytes) -> None:
    """把已经读进内存的剩余字节塞回流读取缓冲。"""
    feed = getattr(reader, "feed_data", None)
    if feed is not None:
        feed(data)
    else:  # 理论上不会发生
        log.warning("StreamReader 不支持 feed_data，丢弃 %d 字节", len(data))
