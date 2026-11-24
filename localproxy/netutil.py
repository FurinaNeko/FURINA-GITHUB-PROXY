"""网络底层工具：报文头读取、SOCKS5 地址编解码、双向管道。"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from contextlib import suppress

log = logging.getLogger("localproxy.net")

MAX_HEAD = 64 * 1024
CHUNK = 65536


class ProtocolError(Exception):
    """对端报文不合法。"""


# --------------------------------------------------------------------------
# 报文头
# --------------------------------------------------------------------------

async def read_head(reader: asyncio.StreamReader, limit: int = MAX_HEAD) -> tuple[bytes, bytes]:
    """读到 b"\\r\\n\\r\\n" 为止，返回 (报文头, 头后面的剩余字节)。

    剩余字节必须交给调用方处理，否则 CONNECT 隧道 / 请求体会丢数据。
    """
    buf = bytearray()
    while True:
        idx = buf.find(b"\r\n\r\n")
        if idx >= 0:
            end = idx + 4
            return bytes(buf[:end]), bytes(buf[end:])
        if len(buf) > limit:
            raise ProtocolError(f"报文头超过 {limit} 字节限制")
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("对端在报文头完整之前关闭连接")
        buf += chunk


def push_back(reader: asyncio.StreamReader, data: bytes) -> None:
    """把已读进内存的剩余字节塞回读取缓冲，避免隧道/请求体丢数据。"""
    if not data:
        return
    feed = getattr(reader, "feed_data", None)
    if feed is not None:
        feed(data)
    else:  # 兜底：理论上 StreamReader 都有 feed_data
        log.warning("StreamReader 不支持 feed_data，丢弃 %d 字节", len(data))


def parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    """把 HTTP 报文头拆成 (起始行, [(名字, 值)])。"""
    text = head.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = text.split("\r\n")
    start = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start, headers


def header_get(headers: list[tuple[str, str]], name: str) -> str | None:
    low = name.lower()
    for k, v in headers:
        if k.lower() == low:
            return v
    return None


# --------------------------------------------------------------------------
# IP / 主机
# --------------------------------------------------------------------------

def normalize_host(host: str) -> str:
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host.endswith("."):
        host = host[:-1]
    return host.lower()


def as_ip(host: str):
    """能解析成 IP 就返回 ipaddress 对象，否则 None。"""
    try:
        return ipaddress.ip_address(normalize_host(host))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# SOCKS5 地址编码（客户端请求 / 服务端应答 / Trojan 头部通用）
# --------------------------------------------------------------------------

def encode_addr(host: str, port: int) -> bytes:
    ip = as_ip(host)
    if ip is not None:
        if ip.version == 4:
            return b"\x01" + ip.packed + port.to_bytes(2, "big")
        return b"\x04" + ip.packed + port.to_bytes(2, "big")
    raw = encode_domain(host)
    if len(raw) > 255:
        raise ProtocolError("域名超过 255 字节")
    return b"\x03" + bytes([len(raw)]) + raw + port.to_bytes(2, "big")


def encode_domain(host: str) -> bytes:
    """域名 -> 线上字节。ASCII 原样，非 ASCII 走 IDNA；IDNA 不认的名字兜底 UTF-8。"""
    if host.isascii():
        return host.encode("ascii")
    try:
        return host.encode("idna")
    except UnicodeError:
        return host.encode("utf-8")


def decode_domain(raw: bytes) -> str:
    """线上字节 -> 域名。

    注意：idna 编解码器只接受 errors="strict"，写成 decode("idna", "replace")
    会直接抛 UnicodeError（这个坑会让所有域名请求 100% 失败）。
    """
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")
    try:
        return text.encode("ascii").decode("idna")
    except UnicodeError:
        return text


async def read_addr(reader: asyncio.StreamReader) -> tuple[str, int]:
    """从流里读 SOCKS5 形式的目标地址。"""
    atyp = (await reader.readexactly(1))[0]
    if atyp == 0x01:
        host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif atyp == 0x04:
        host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        host = decode_domain(await reader.readexactly(length))
    else:
        raise ProtocolError(f"未知 ATYP 0x{atyp:02x}")
    port = int.from_bytes(await reader.readexactly(2), "big")
    return host, port


def encode_reply(code: int, host: str = "0.0.0.0", port: int = 0) -> bytes:
    return b"\x05" + bytes([code]) + b"\x00" + encode_addr(host, port)


# --------------------------------------------------------------------------
# 双向管道
# --------------------------------------------------------------------------

async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    idle: float | None,
) -> int:
    total = 0
    try:
        while True:
            if idle:
                chunk = await asyncio.wait_for(reader.read(CHUNK), idle)
            else:
                chunk = await reader.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        with suppress(Exception):
            if writer.can_write_eof() and not writer.is_closing():
                writer.write_eof()
    return total


async def relay(
    c_reader: asyncio.StreamReader,
    c_writer: asyncio.StreamWriter,
    u_reader: asyncio.StreamReader,
    u_writer: asyncio.StreamWriter,
    idle: float | None = 300.0,
) -> tuple[int, int]:
    """客户端 <-> 上游双向转发，返回 (上行字节, 下行字节)。"""
    up, down = await asyncio.gather(
        _pipe(c_reader, u_writer, idle),
        _pipe(u_reader, c_writer, idle),
    )
    for w in (c_writer, u_writer):
        with suppress(Exception):
            w.close()
    return up, down


def human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.2f}{unit}"
        n /= 1024.0
    return f"{n:.2f}GiB"
