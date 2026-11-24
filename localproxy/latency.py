"""网站延迟检测：直连 / 经本地代理 两条路径分别测。

指标取“TCP 连上”和“TLS 握手完成”两段，多次采样取最小值
（最小值最能反映线路质量，平均值会被偶发重传拉高）。

探测走 Resolver（默认 DoH），所以即使本地 DNS 被污染，测的也是真实可达性。
"""

from __future__ import annotations

import asyncio
import ssl
import time

from .netutil import encode_addr
from .resolver import Resolver

DEFAULT_SITES = [
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "cas-bridge.xethub.hf.co",
    "files.pythonhosted.org",
    "registry.npmjs.org",
]


async def _tcp_connect(host: str, ip: str, port: int, timeout: float):
    started = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, limit=2**16), timeout)
    return reader, writer, (time.monotonic() - started) * 1000


async def _socks5_connect(proxy_port: int, host: str, port: int, timeout: float):
    started = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", proxy_port, limit=2**16), timeout)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    _, method = await asyncio.wait_for(reader.readexactly(2), timeout)
    if method != 0:
        writer.close()
        raise ConnectionError(f"SOCKS5 协商失败（method={method}）")
    writer.write(b"\x05\x01\x00" + encode_addr(host, port))
    await writer.drain()
    _, rep, _, atyp = await asyncio.wait_for(reader.readexactly(4), timeout)
    if rep != 0:
        writer.close()
        raise ConnectionError(f"SOCKS5 CONNECT 被拒（rep={rep}）")
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x04:
        await reader.readexactly(18)
    else:
        ln = (await reader.readexactly(1))[0]
        await reader.readexactly(ln + 2)
    return reader, writer, (time.monotonic() - started) * 1000


async def measure(host: str, port: int = 443, count: int = 3, via: str = "direct",
                  proxy_port: int = 0, resolver: Resolver | None = None,
                  timeout: float = 8.0, sni: str | None = None) -> dict:
    """测一个站点，返回 TCP / TLS 两段的多次采样结果。"""
    host = host.strip().lower()
    resolv = resolver or Resolver({"mode": "doh"})
    result = {"host": host, "via": via, "tcp_ms": None, "tls_ms": None,
              "ok": False, "error": "", "samples": []}

    ips: list[str] = []
    if via == "direct":
        try:
            ips = await resolv.resolve(host)
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"解析失败：{exc}"
            return result

    tcp_times: list[float] = []
    tls_times: list[float] = []
    last_error = ""

    for _ in range(max(1, count)):
        writer = None
        try:
            if via == "direct":
                opened = None
                for ip in ips:
                    try:
                        opened = await _tcp_connect(host, ip, port, timeout)
                        break
                    except Exception as exc:  # noqa: BLE001
                        last_error = str(exc)
                if opened is None:
                    raise ConnectionError(last_error or "所有地址都连不上")
                reader, writer, tcp_ms = opened
            else:
                reader, writer, tcp_ms = await _socks5_connect(proxy_port, host, port, timeout)
            tcp_times.append(tcp_ms)

            ctx = ssl.create_default_context()
            tls_start = time.monotonic()
            await asyncio.wait_for(writer.start_tls(ctx, server_hostname=sni or host), timeout)
            tls_times.append((time.monotonic() - tls_start) * 1000)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass

    if tcp_times:
        result["tcp_ms"] = min(tcp_times)
        result["samples"] = [round(x, 1) for x in tcp_times]
        result["ok"] = True
    if tls_times:
        result["tls_ms"] = min(tls_times)
    if not result["ok"]:
        result["error"] = last_error or "超时"
    return result


async def matrix(sites: list[str], *, proxy_port: int = 0, count: int = 3,
                 paths: tuple[str, ...] = ("direct", "proxy"),
                 concurrency: int = 4, resolver: Resolver | None = None,
                 timeout: float = 8.0) -> list[dict]:
    """并发测多个站点 × 多条路径，返回按站点聚合的表格数据。"""
    resolv = resolver or Resolver({"mode": "doh"})
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(host: str, path: str):
        async with sem:
            return await measure(
                host, count=count, via=path, proxy_port=proxy_port,
                resolver=resolv, timeout=timeout)

    tasks = [(host, path) for host in sites for path in paths]
    results = await asyncio.gather(*(one(h, p) for h, p in tasks))

    table: dict[str, dict] = {}
    for item in results:
        row = table.setdefault(item["host"], {"host": item["host"]})
        key = "direct" if item["via"] == "direct" else "proxy"
        row[key] = item.get("tls_ms") or item.get("tcp_ms")
        row[f"{key}_ok"] = item["ok"]
        row[f"{key}_error"] = item["error"]
        row[f"{key}_tcp"] = item.get("tcp_ms")
    return [table[host] for host in sites if host in table]


def format_table(rows: list[dict], paths: tuple[str, ...] = ("direct", "proxy")) -> str:
    head = f"{'站点':<34}"
    if "direct" in paths:
        head += f"{'直连 ms':>10}"
    if "proxy" in paths:
        head += f"{'代理 ms':>10}"
    head += "   状态"
    lines = [head, "-" * (len(head) + 4)]
    for row in rows:
        line = f"{row['host']:<34}"
        notes = []
        if "direct" in paths:
            value = row.get("direct")
            line += f"{value:>10.0f}" if value else f"{'—':>10}"
            if not row.get("direct_ok"):
                notes.append("直连失败")
        if "proxy" in paths:
            value = row.get("proxy")
            line += f"{value:>10.0f}" if value else f"{'—':>10}"
            if not row.get("proxy_ok"):
                notes.append("代理失败")
        fastest = [v for v in (row.get("direct"), row.get("proxy")) if v]
        tail = "OK" if fastest else "FAIL"
        if notes:
            tail += "（" + "/".join(notes) + "）"
        lines.append(line + f"   {tail}")
    return "\n".join(lines)
