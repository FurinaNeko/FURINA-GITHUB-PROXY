"""服务编排：起监听、维护统计、提供 /health /metrics 接口。"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import suppress

from . import httpproxy, socks5
from .config import Config
from .netutil import human_bytes, read_head
from .resolver import Resolver
from .router import Router

log = logging.getLogger("localproxy.server")


class ProxyServer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.resolver = Resolver(cfg.dns)
        self.router = Router(cfg, self.resolver)
        self.started_at = time.time()
        self.stats = {
            "socks5_total": 0,
            "socks5_ok": 0,
            "socks5_failed": 0,
            "http_total": 0,
            "http_ok": 0,
            "http_failed": 0,
            "up_bytes": 0,
            "down_bytes": 0,
            "routes": 0,
        }
        self._servers: list[asyncio.AbstractServer] = []
        self._conns: set[asyncio.StreamWriter] = set()
        self._stop = asyncio.Event()
        self._health_task: asyncio.Task | None = None
        self.accel = None
        self.ports: dict[str, int] = {}

    # ------------------------------------------------------------------ 生命周期
    async def start(self) -> dict[str, int]:
        cfg = self.cfg
        if cfg.socks5.enabled:
            srv = await asyncio.start_server(
                lambda r, w: self._serve(socks5.handle, r, w),
                cfg.socks5.host,
                cfg.socks5.port,
                limit=2**20,
                reuse_address=True,
            )
            self._servers.append(srv)
            self.ports["socks5"] = _port_of(srv)
        if cfg.http.enabled:
            srv = await asyncio.start_server(
                lambda r, w: self._serve(httpproxy.handle, r, w),
                cfg.http.host,
                cfg.http.port,
                limit=2**20,
                reuse_address=True,
            )
            self._servers.append(srv)
            self.ports["http"] = _port_of(srv)
        if cfg.api.enabled:
            srv = await asyncio.start_server(
                self._api_handler, cfg.api.host, cfg.api.port, limit=2**18
            )
            self._servers.append(srv)
            self.ports["api"] = _port_of(srv)

        self._health_task = asyncio.create_task(self._health())
        if cfg.accel.enabled:
            from .accelerator import Accelerator

            self.accel = Accelerator(cfg, self.router)
            self.ports.update(await self.accel.start())
        return self.ports

    async def _health(self) -> None:
        with suppress(asyncio.CancelledError):
            await self.router.start_health_loop(self._stop)

    async def _serve(self, handler, reader, writer) -> None:
        """登记活跃连接，便于停机时主动断开（否则 Ctrl+C 会卡在长连接上）。"""
        self._conns.add(writer)
        try:
            await handler(reader, writer, self)
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001
            log.debug("连接处理异常", exc_info=True)
        finally:
            self._conns.discard(writer)
            with suppress(Exception):
                writer.close()

    async def serve_forever(self) -> None:
        await self._stop.wait()

    def request_stop(self) -> None:
        self._stop.set()

    async def close(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self.accel is not None:
            with suppress(Exception):
                await self.accel.close()
        for srv in self._servers:
            srv.close()
        for writer in list(self._conns):
            transport = getattr(writer, "transport", None)
            if transport is not None:
                with suppress(Exception):
                    transport.abort()
        if self._servers:
            await asyncio.gather(
                *(asyncio.wait_for(srv.wait_closed(), timeout) for srv in self._servers),
                return_exceptions=True,
            )
        if self._health_task:
            self._health_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await self._health_task

    # ------------------------------------------------------------------ 统计
    def add_traffic(self, up: int, down: int) -> None:
        self.stats["up_bytes"] += up
        self.stats["down_bytes"] += down

    def log_route(self, peer: str, host: str, port: int, policy: str, upstream: str,
                  ok: bool, detail: str) -> None:
        self.stats["routes"] += 1
        mark = "OK " if ok else "FAIL"
        target = f"{host}:{port}" if port else host
        if ok:
            log.info("[%s] %-16s %-42s %-8s %-12s", mark, peer, target, policy, upstream)
        else:
            log.warning("[%s] %-16s %-42s %-8s %s", mark, peer, target, policy, detail)

    def snapshot(self) -> dict:
        return {
            "version": 1,
            "uptime_s": round(time.time() - self.started_at, 1),
            "listen": self.ports,
            "stats": dict(self.stats),
            "traffic": {
                "up": human_bytes(self.stats["up_bytes"]),
                "down": human_bytes(self.stats["down_bytes"]),
            },
            "upstreams": self.router.snapshot(),
            "dns": {"mode": self.resolver.mode, "cache": len(self.resolver._cache)},
            "accelerator": self.accel.snapshot() if self.accel else None,
        }

    # ------------------------------------------------------------------ 指标接口
    async def _api_handler(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
        try:
            head, _ = await asyncio.wait_for(read_head(reader, 8192), 10)
            line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = line.split()
            path = (parts[1] if len(parts) > 1 else "/").split("?")[0]
            if path in ("/", "/health", "/stats", "/metrics"):
                payload = json.dumps(self.snapshot(), ensure_ascii=False, indent=2)
                code, reason = 200, "OK"
            elif path == "/rules":
                payload = json.dumps(
                    [r.raw for r in self.cfg.engine.rules], ensure_ascii=False, indent=2
                )
                code, reason = 200, "OK"
            else:
                payload = json.dumps({"error": "not found"}, ensure_ascii=False)
                code, reason = 404, "Not Found"
            body = payload.encode("utf-8")
            writer.write(
                (
                    f"HTTP/1.1 {code} {reason}\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("latin-1")
                + body
            )
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            with suppress(Exception):
                writer.close()


def _port_of(srv: asyncio.AbstractServer) -> int:
    for sock in srv.sockets or []:
        try:
            return int(sock.getsockname()[1])
        except Exception:  # noqa: BLE001
            continue
    return 0
