"""域名解析：系统解析器 / DoH(JSON API)，带 TTL 缓存。

为什么需要 DoH：直连时代理会把域名交给系统解析器，一旦 DNS 被污染，
拿到的 IP 就是错的；DoH 通过固定 IP 的 HTTPS 查询，绕开本地 DNS。
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
import urllib.parse
import urllib.request

log = logging.getLogger("localproxy.dns")

DOH_TIMEOUT = 5.0


class ResolveError(Exception):
    pass


class Resolver:
    def __init__(self, dns_cfg: dict | None = None):
        cfg = dns_cfg or {}
        self.mode = str(cfg.get("mode", "system")).lower()
        self.doh_url = str(cfg.get("doh_url") or "https://1.1.1.1/dns-query")
        self.cache_ttl = float(cfg.get("cache_ttl", 300))
        self.timeout = float(cfg.get("timeout", DOH_TIMEOUT))
        self._cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._neg_cache: dict[tuple[str, int], float] = {}
        self._doh_fails = 0
        self._doh_warned = False
        self._doh_block_until = 0.0
        self.hits = 0
        self.misses = 0

    # ---------------------------------------------------------------- 公共
    def clear_cache(self) -> None:
        self._cache.clear()
        self._neg_cache.clear()

    async def resolve(self, host: str) -> list[str]:
        """返回 A + AAAA 地址列表（A 在前）。A/AAAA 并发查，避免串行等两次超时。"""
        host = host.strip().strip("[]").rstrip(".").lower()
        if not host:
            raise ResolveError("空主机名")
        try:
            import ipaddress

            ipaddress.ip_address(host)
            return [host]  # 已经是字面量 IP
        except ValueError:
            pass

        loop = asyncio.get_running_loop()
        now = time.monotonic()
        results: list[str] = []
        pending: list[tuple[int, asyncio.Future]] = []

        for rtype in (1, 28):
            key = (host, rtype)
            entry = self._cache.get(key)
            if entry and entry[0] > now:
                self.hits += 1
                results.extend(entry[1])
                continue
            if self._neg_cache.get(key, 0.0) > now:
                continue  # 刚失败过，别每建一次连接就重试
            pending.append((rtype, loop.run_in_executor(None, self._resolve_blocking, host, rtype)))

        if pending:
            gathered = await asyncio.gather(*(f for _, f in pending), return_exceptions=True)
            for (rtype, _), addrs in zip(pending, gathered):
                if isinstance(addrs, BaseException) or not addrs:
                    self._neg_cache[(host, rtype)] = now + 30
                    continue
                self.misses += 1
                self._cache[(host, rtype)] = (now + self.cache_ttl, list(addrs))
                results.extend(addrs)

        if not results:
            raise ResolveError(f"无法解析 {host}")
        # 去重保序
        seen: set[str] = set()
        return [a for a in results if not (a in seen or seen.add(a))]

    # ---------------------------------------------------------------- 内部
    def _resolve_blocking(self, host: str, rtype: int) -> list[str]:
        if self.mode == "doh" and time.monotonic() >= self._doh_block_until:
            try:
                addrs = self._doh(host, rtype)
                self._doh_fails = 0
                self._doh_warned = False
                return addrs
            except Exception as exc:  # noqa: BLE001
                self._doh_fails += 1
                # 超时基本等于“这个 DoH 地址被墙”，一次就熔断；其他错误给两次机会
                timeoutish = "timed out" in str(exc).lower()
                if self._doh_fails >= (1 if timeoutish else 2):
                    self._doh_block_until = time.monotonic() + 120
                    if not self._doh_warned:
                        self._doh_warned = True
                        log.warning(
                            "DoH 不可用（%s），120s 内改用系统 DNS；"
                            "网络屏蔽了 %s 就把 dns.doh_url 换成可达的 DoH 地址",
                            exc, self.doh_url,
                        )
                else:
                    log.debug("DoH 失败，本次回退系统解析：%s", exc)
        return self._system(host, rtype)

    def _system(self, host: str, rtype: int) -> list[str]:
        family = socket.AF_INET if rtype == 1 else socket.AF_INET6
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        out: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in out:
                out.append(addr)
        return out

    def _doh(self, host: str, rtype: int) -> list[str]:
        query = urllib.parse.urlencode({"name": host, "type": "A" if rtype == 1 else "AAAA"})
        url = f"{self.doh_url}?{query}"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": "localproxy/1.0"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if payload.get("Status") not in (0, None):
            return []
        out: list[str] = []
        for answer in payload.get("Answer", []):
            if int(answer.get("type", 0)) != rtype:
                continue
            data = str(answer.get("data", "")).strip()
            if data and data not in out:
                out.append(data)
        return out


async def open_any(hosts, port: int, timeout: float, local_addr: str | None = None):
    """依次对候选地址发起连接，返回第一个成功的 (reader, writer)。"""
    last_exc: Exception | None = None
    for host in hosts:
        try:
            kwargs = {"limit": 2**20}
            if local_addr:
                kwargs["local_addr"] = (local_addr, 0)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, **kwargs), timeout
            )
            return reader, writer
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue
    raise ConnectionError(f"所有候选地址均连接失败：{hosts}（最后错误：{last_exc}）")
