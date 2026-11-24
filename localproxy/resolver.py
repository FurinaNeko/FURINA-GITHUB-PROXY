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
        self.doh_url = str(cfg.get("doh_url") or "https://dns.alidns.com/dns-query")
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
        """DoH 双格式：先试 JSON API，服务端只支持 wire 格式时自动切过去。

        各家实现并不统一：Cloudflare/Google 认 ?name=&type= 的 JSON，
        阿里/腾讯的 /dns-query 只吃 RFC8484 的 application/dns-message。
        """
        try:
            return self._doh_json(host, rtype)
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 404, 405, 415, 501):
                return self._doh_wire(host, rtype)
            raise

    def _doh_json(self, host: str, rtype: int) -> list[str]:
        query = urllib.parse.urlencode({"name": host, "type": "A" if rtype == 1 else "AAAA"})
        url = f"{self.doh_url}?{query}"
        req = urllib.request.Request(
            url, headers={"Accept": "application/dns-json", "User-Agent": "localproxy/1.0"})
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

    def _doh_wire(self, host: str, rtype: int) -> list[str]:
        import base64

        query = _build_dns_query(host, rtype)
        token = base64.urlsafe_b64encode(query).decode().rstrip("=")
        url = f"{self.doh_url}?dns={token}"
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-message", "User-Agent": "localproxy/1.0"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read()
        return _parse_dns_answers(body, rtype)


# --------------------------------------------------------------------------
# 极简 DNS wire 编解码（DoH 的 RFC8484 路径用）
# --------------------------------------------------------------------------

def _build_dns_query(host: str, rtype: int) -> bytes:
    import struct

    qid = 0
    flags = 0x0100  # RD
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in host.rstrip(".").split(".") if label
    ) + b"\x00"
    return header + qname + struct.pack(">HH", rtype, 1)


def _parse_dns_answers(data: bytes, rtype: int) -> list[str]:
    import ipaddress
    import struct

    try:
        if len(data) < 12:
            return []
        _qid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        pos = 12
        for _ in range(qd):  # 跳过问题区
            while pos < len(data) and data[pos]:
                pos += 1 + data[pos]
            pos += 5
        out: list[str] = []
        for _ in range(an):
            if pos >= len(data):
                break
            if data[pos] & 0xC0 == 0xC0:      # 压缩指针
                pos += 2
            else:
                while pos < len(data) and data[pos]:
                    pos += 1 + data[pos]
                pos += 1
            if pos + 10 > len(data):
                break
            atype, _aclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if atype == 1 and rdlen == 4:
                out.append(str(ipaddress.IPv4Address(rdata)))
            elif atype == 28 and rdlen == 16:
                out.append(str(ipaddress.IPv6Address(rdata)))
        return out
    except Exception:  # noqa: BLE001
        return []


async def open_any(hosts, port: int, timeout: float, local_addr: str | None = None,
                    stagger: float = 0.25):
    """错峰并发拨号：第 2 个地址晚 250 ms 起跑，谁先连上就用谁。

    逐个串行等待会把“第一个 IP 不通”的代价直接加到每次连接上；
    错峰并发既保留 IPv4 优先，又不会被单个坏地址拖住。
    """
    hosts = list(hosts)
    if not hosts:
        raise ConnectionError("没有可用地址")
    loop = asyncio.get_running_loop()

    async def attempt(host: str, delay: float):
        if delay:
            await asyncio.sleep(delay)
        kwargs = {"limit": 2**20}
        if local_addr:
            kwargs["local_addr"] = (local_addr, 0)
        return await asyncio.wait_for(asyncio.open_connection(host, port, **kwargs), timeout)

    tasks = [loop.create_task(attempt(h, i * stagger)) for i, h in enumerate(hosts)]
    pending = set(tasks)
    errors = []
    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task.cancelled():
                    continue
                exc = task.exception()
                if exc is None:
                    for other in pending:
                        other.cancel()
                    return task.result()
                errors.append(str(exc) or type(exc).__name__)
        raise ConnectionError(f"所有候选地址均连接失败：{hosts}（{'; '.join(errors[:3])}）")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
