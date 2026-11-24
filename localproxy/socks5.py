"""本地 SOCKS5 服务端（CONNECT 模式）。

完整实现 RFC1928 握手 + RFC1929 用户名密码认证，仅支持 CONNECT；
UDP ASSOCIATE 明确回 0x07（浏览器遇到会退回 TCP，不影响网页与 git）。
"""

from __future__ import annotations

import asyncio
import hmac
import logging

from .netutil import encode_addr, encode_reply, push_back, read_addr, relay

log = logging.getLogger("localproxy.socks5")

NO_AUTH = 0x00
USERPASS = 0x02
CMD_CONNECT = 0x01


class Socks5Error(Exception):
    pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, srv) -> None:
    peer = _peer(writer)
    listener = srv.cfg.socks5
    srv.stats["socks5_total"] += 1
    try:
        greeting = await asyncio.wait_for(reader.readexactly(2), 15)
        if greeting[0] != 0x05:
            raise Socks5Error(f"不是 SOCKS5 握手（ver={greeting[0]}）")
        nmethods = greeting[1]
        if nmethods == 0:
            raise Socks5Error("客户端未提供认证方式")
        methods = await asyncio.wait_for(reader.readexactly(nmethods), 15)

        if listener.needs_auth:
            if USERPASS not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                raise Socks5Error("客户端不支持用户名密码认证")
            writer.write(bytes([0x05, USERPASS]))
            await writer.drain()
            await _userpass(reader, writer, listener)
        else:
            if NO_AUTH not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                raise Socks5Error("客户端未提供免认证方式")
            writer.write(bytes([0x05, NO_AUTH]))
            await writer.drain()

        ver, cmd, rsv = await asyncio.wait_for(reader.readexactly(3), 15)
        if ver != 0x05:
            raise Socks5Error("请求 VER 不是 5")
        if cmd != CMD_CONNECT:
            writer.write(encode_reply(0x07))
            await writer.drain()
            raise Socks5Error(f"不支持的命令 {cmd}（仅 CONNECT）")

        host, port = await asyncio.wait_for(read_addr(reader), 15)
        log.debug("SOCKS5 %s -> %s:%s", peer, host, port)

        try:
            u_reader, u_writer, policy, up = await srv.router.dial(host, port)
        except Exception as exc:  # noqa: BLE001
            from .router import RejectedByRule

            code = 0x02 if isinstance(exc, RejectedByRule) else 0x04
            writer.write(encode_reply(code))
            await writer.drain()
            srv.stats["socks5_failed"] += 1
            srv.log_route(peer, host, port, "-", "-", False, str(exc))
            raise Socks5Error(str(exc)) from exc

        local = u_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
        bound_host = str(local[0])
        bound_port = int(local[1])
        writer.write(encode_reply(0, bound_host, bound_port))
        await writer.drain()

        srv.stats["socks5_ok"] += 1
        srv.log_route(peer, host, port, policy, up.name, True, "")
        up_bytes, down_bytes = await relay(reader, writer, u_reader, u_writer,
                                          srv.cfg.timeout("idle", 300))
        srv.add_traffic(up_bytes, down_bytes)
    except (Socks5Error, asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError) as exc:
        log.debug("SOCKS5 会话结束 %s：%s", peer, exc)
    finally:
        _close(writer)


async def _userpass(reader, writer, listener) -> None:
    sub_ver, ulen = await asyncio.wait_for(reader.readexactly(2), 15)
    if sub_ver != 0x01:
        raise Socks5Error("认证子协商 VER 不是 1")
    user = (await asyncio.wait_for(reader.readexactly(ulen), 15)).decode("utf-8", "replace")
    plen = (await asyncio.wait_for(reader.readexactly(1), 15))[0]
    pwd = (await asyncio.wait_for(reader.readexactly(plen), 15)).decode("utf-8", "replace")
    ok = hmac.compare_digest(user, listener.username) and hmac.compare_digest(
        pwd, listener.password
    )
    writer.write(b"\x01" + (b"\x00" if ok else b"\x01"))
    await writer.drain()
    if not ok:
        raise Socks5Error("SOCKS5 认证失败")


def _peer(writer) -> str:
    info = writer.get_extra_info("peername")
    return f"{info[0]}:{info[1]}" if info else "?"


def _close(writer) -> None:
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
