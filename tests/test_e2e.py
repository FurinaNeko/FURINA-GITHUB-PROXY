"""端到端测试：真起本地代理，用真握手跑通每条链路。

覆盖：SOCKS5(CONNECT/认证/拒绝)、HTTP(CONNECT/绝对URI/407)、
上游 http / socks5 / trojan(TLS) 三种链路、故障切换、指标接口。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import unittest
import warnings
from contextlib import suppress
from pathlib import Path

from localproxy.config import Config
from localproxy.netutil import encode_addr, read_head, relay
from localproxy.server import ProxyServer

# 测试客户端故意不留 wait_closed()，屏蔽噪音
warnings.filterwarnings("ignore", category=ResourceWarning)

CERTS = Path(__file__).parent / "certs"


# --------------------------------------------------------------------------
# 测试用的服务端
# --------------------------------------------------------------------------

async def start_echo(prefix: bytes = b"ECHO:"):
    async def handler(reader, writer):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(prefix + data)
                await writer.drain()
        except (ConnectionResetError, OSError):
            pass
        finally:
            with suppress(Exception):
                writer.close()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def start_origin():
    async def handler(reader, writer):
        try:
            await read_head(reader)
            body = b"origin-ok"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        finally:
            with suppress(Exception):
                writer.close()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def start_http_proxy(record: list):
    async def handler(reader, writer):
        try:
            head, rest = await read_head(reader)
            method, target, _ = head.split(b"\r\n")[0].decode().split(" ", 2)
            record.append((method, target))
            host, port = target.rsplit(":", 1)
            tr, tw = await asyncio.open_connection(host, int(port))
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            if rest:
                tw.write(rest)
                await tw.drain()
            await relay(reader, writer, tr, tw, 10)
        except Exception:  # noqa: BLE001
            pass

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def start_socks5_proxy(record: list, user: str = "", pwd: str = ""):
    async def handler(reader, writer):
        try:
            _, n = await reader.readexactly(2)
            await reader.readexactly(n)
            if user:
                writer.write(b"\x05\x02")
                await writer.drain()
                _, ulen = await reader.readexactly(2)
                got_user = (await reader.readexactly(ulen)).decode()
                plen = (await reader.readexactly(1))[0]
                got_pwd = (await reader.readexactly(plen)).decode()
                ok = got_user == user and got_pwd == pwd
                writer.write(b"\x01" + (b"\x00" if ok else b"\x01"))
                await writer.drain()
                if not ok:
                    writer.close()
                    return
            else:
                writer.write(b"\x05\x00")
                await writer.drain()

            _, _, _, atyp = await reader.readexactly(4)
            if atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 0x04:
                host = "::1"
                await reader.readexactly(16)
            else:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            port = int.from_bytes(await reader.readexactly(2), "big")
            record.append((host, port))
            tr, tw = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            await writer.drain()
            await relay(reader, writer, tr, tw, 10)
        except Exception:  # noqa: BLE001
            pass

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def start_trojan(echo_port: int, password: str, record: list):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / "cert.pem"), str(CERTS / "key.pem"))

    async def handler(reader, writer):
        try:
            digest = (await reader.readexactly(56)).decode()
            if await reader.readexactly(2) != b"\r\n":
                record.append(("bad-crlf",))
                return
            cmd = (await reader.readexactly(1))[0]
            # 服务端按 SOCKS5 地址格式解析目标
            atyp = (await reader.readexactly(1))[0]
            if atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            else:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            port = int.from_bytes(await reader.readexactly(2), "big")
            tail = await reader.readexactly(2)
            record.append((digest, cmd, host, port, tail))
            if digest != hashlib.sha224(password.encode()).hexdigest() or tail != b"\r\n":
                return
            tr, tw = await asyncio.open_connection(host, port or echo_port)
            await relay(reader, writer, tr, tw, 10)
        except Exception:  # noqa: BLE001
            pass

    srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1]


# --------------------------------------------------------------------------
# 客户端辅助
# --------------------------------------------------------------------------

async def socks5_open(proxy_port: int, host: str, port: int,
                      user: str | None = None, pwd: str = ""):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(b"\x05\x02\x00\x02" if user is not None else b"\x05\x01\x00")
    await writer.drain()
    _, method = await reader.readexactly(2)
    if method == 0xFF:
        writer.close()
        raise ConnectionError("服务端不接受任何认证方式")
    if method == 0x02:
        u, p = (user or "").encode(), pwd.encode()
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        _, status = await reader.readexactly(2)
        if status != 0:
            writer.close()
            raise ConnectionError("认证失败")
    writer.write(b"\x05\x01\x00" + encode_addr(host, port))
    await writer.drain()
    _, rep, _, atyp = await reader.readexactly(4)
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x04:
        await reader.readexactly(18)
    elif atyp == 0x03:
        ln = (await reader.readexactly(1))[0]
        await reader.readexactly(ln + 2)
    return reader, writer, rep


def make_cfg(**over) -> Config:
    doc = {
        "log_level": "critical",
        "listeners": {
            "socks5": {"enabled": True, "host": "127.0.0.1", "port": 0},
            "http": {"enabled": True, "host": "127.0.0.1", "port": 0},
            "api": {"enabled": False, "host": "127.0.0.1", "port": 0},
        },
        "dns": {"mode": "system"},
        "health": {"interval": 0},
        "upstreams": [{"name": "direct", "type": "direct"}],
        "groups": {},
        "rules": ["FINAL,DIRECT"],
        "final": "DIRECT",
    }
    doc.update(over)
    return Config.from_dict(doc)


def cfg_via(upstream: dict, kind: str = "latency") -> Config:
    ups = [upstream]
    if upstream["type"] != "direct":
        ups.append({"name": "direct", "type": "direct"})
    return make_cfg(
        upstreams=ups,
        groups={"PROXY": {"type": kind, "members": [upstream["name"]]}},
        rules=["FINAL,PROXY"],
        final="PROXY",
    )


# --------------------------------------------------------------------------
# 测试
# --------------------------------------------------------------------------

class ProxyE2E(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._cleanup = []

    async def asyncTearDown(self):
        for item in reversed(self._cleanup):
            with suppress(Exception):
                await item()

    def keep(self, srv):
        async def closer():
            srv.close()
            await srv.wait_closed()
        self._cleanup.append(closer)
        return srv

    async def launch(self, cfg: Config) -> dict:
        server = ProxyServer(cfg)

        async def closer():
            await server.close()

        self._cleanup.append(closer)
        return await server.start()

    # ---------------------------------------------------------------- SOCKS5
    async def test_socks5_direct_echo(self):
        echo, echo_port = await start_echo()
        self.keep(echo)
        ports = await self.launch(make_cfg())

        reader, writer, rep = await socks5_open(ports["socks5"], "127.0.0.1", echo_port)
        self.assertEqual(rep, 0)
        writer.write(b"ping")
        await writer.drain()
        self.assertEqual(await reader.readexactly(9), b"ECHO:ping")
        writer.close()

    async def test_socks5_auth(self):
        echo, echo_port = await start_echo()
        self.keep(echo)
        cfg = make_cfg()
        cfg.socks5.username = "alice"
        cfg.socks5.password = "s3cret"
        ports = await self.launch(cfg)

        with self.assertRaises(ConnectionError):
            await socks5_open(ports["socks5"], "127.0.0.1", echo_port,
                              user="alice", pwd="wrong")

        reader, writer, rep = await socks5_open(
            ports["socks5"], "127.0.0.1", echo_port, user="alice", pwd="s3cret"
        )
        self.assertEqual(rep, 0)
        writer.write(b"hi")
        await writer.drain()
        self.assertEqual(await reader.readexactly(7), b"ECHO:hi")
        writer.close()

    async def test_socks5_reject_rule(self):
        ports = await self.launch(make_cfg(
            rules=["DOMAIN-SUFFIX,blocked.test,REJECT", "FINAL,DIRECT"]
        ))
        _, writer, rep = await socks5_open(ports["socks5"], "blocked.test", 80)
        self.assertEqual(rep, 2, "REJECT 应回 0x02 规则不允许")
        writer.close()

    async def test_socks5_domain_target(self):
        """ATYP=3 域名路径必须能走通（idna 解码 bug 回归测试）。"""
        echo, echo_port = await start_echo()
        self.keep(echo)
        ports = await self.launch(make_cfg())

        reader, writer, rep = await socks5_open(ports["socks5"], "localhost", echo_port)
        self.assertEqual(rep, 0, "域名目标应正常建连")
        writer.write(b"dn")
        await writer.drain()
        self.assertEqual(await reader.readexactly(7), b"ECHO:dn")
        writer.close()

    async def test_socks5_unsupported_command(self):
        ports = await self.launch(make_cfg())
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["socks5"])
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        await reader.readexactly(2)
        writer.write(b"\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x50")  # UDP ASSOCIATE
        await writer.drain()
        _, rep, _, _ = await reader.readexactly(4)
        self.assertEqual(rep, 7)
        writer.close()

    # ---------------------------------------------------------------- HTTP
    async def test_http_connect_echo(self):
        echo, echo_port = await start_echo(b"HTTP:")
        self.keep(echo)
        ports = await self.launch(make_cfg())

        reader, writer = await asyncio.open_connection("127.0.0.1", ports["http"])
        authority = f"127.0.0.1:{echo_port}"
        writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        await writer.drain()
        head, _ = await read_head(reader)
        self.assertIn(b" 200 ", head)
        writer.write(b"yo")
        await writer.drain()
        self.assertEqual(await reader.readexactly(7), b"HTTP:yo")
        writer.close()

    async def test_http_absolute_uri(self):
        origin, origin_port = await start_origin()
        self.keep(origin)
        ports = await self.launch(make_cfg())

        reader, writer = await asyncio.open_connection("127.0.0.1", ports["http"])
        writer.write(
            f"GET http://127.0.0.1:{origin_port}/hello HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n\r\n".encode()
        )
        await writer.drain()
        head, rest = await read_head(reader)
        self.assertIn(b" 200 ", head)
        body = rest or await reader.read(1024)
        self.assertIn(b"origin-ok", body)
        writer.close()

    async def test_http_proxy_auth_407(self):
        origin, origin_port = await start_origin()
        self.keep(origin)
        cfg = make_cfg()
        cfg.http.username = "bob"
        cfg.http.password = "pw"
        ports = await self.launch(cfg)

        reader, writer = await asyncio.open_connection("127.0.0.1", ports["http"])
        writer.write(
            f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n\r\n".encode()
        )
        await writer.drain()
        head, _ = await read_head(reader)
        self.assertIn(b" 407 ", head)
        self.assertIn(b"Proxy-Authenticate", head)
        writer.close()

        import base64

        token = base64.b64encode(b"bob:pw").decode()
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["http"])
        writer.write(
            f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            f"Proxy-Authorization: Basic {token}\r\n\r\n".encode()
        )
        await writer.drain()
        head, rest = await read_head(reader)
        self.assertIn(b" 200 ", head)
        writer.close()

    # ---------------------------------------------------------------- 上游链路
    async def test_upstream_http_proxy(self):
        echo, echo_port = await start_echo()
        self.keep(echo)
        record: list = []
        px, px_port = await start_http_proxy(record)
        self.keep(px)

        cfg = cfg_via({"name": "px", "type": "http",
                       "server": "127.0.0.1", "port": px_port})
        ports = await self.launch(cfg)
        reader, writer, rep = await socks5_open(ports["socks5"], "127.0.0.1", echo_port)
        self.assertEqual(rep, 0)
        writer.write(b"up")
        await writer.drain()
        self.assertEqual(await reader.readexactly(7), b"ECHO:up")
        writer.close()
        self.assertEqual(record[0][0], "CONNECT")
        self.assertEqual(record[0][1], f"127.0.0.1:{echo_port}")

    async def test_upstream_socks5_proxy_with_auth(self):
        echo, echo_port = await start_echo()
        self.keep(echo)
        record: list = []
        px, px_port = await start_socks5_proxy(record, user="u1", pwd="p1")
        self.keep(px)

        cfg = cfg_via({"name": "sx", "type": "socks5", "server": "127.0.0.1",
                       "port": px_port, "username": "u1", "password": "p1"})
        ports = await self.launch(cfg)
        reader, writer, rep = await socks5_open(ports["socks5"], "127.0.0.1", echo_port)
        self.assertEqual(rep, 0)
        writer.write(b"a")
        await writer.drain()
        self.assertEqual(await reader.readexactly(6), b"ECHO:a")
        writer.close()
        self.assertEqual(record[0], ("127.0.0.1", echo_port))

    async def test_upstream_trojan_tls(self):
        echo, echo_port = await start_echo()
        self.keep(echo)
        record: list = []
        password = "t0p-secret"
        tj, tj_port = await start_trojan(echo_port, password, record)
        self.keep(tj)

        cfg = cfg_via({
            "name": "tj", "type": "trojan", "server": "127.0.0.1", "port": tj_port,
            "password": password,
            "tls": {"sni": "127.0.0.1", "insecure": True, "alpn": ["http/1.1"]},
        })
        ports = await self.launch(cfg)
        reader, writer, rep = await socks5_open(ports["socks5"], "127.0.0.1", echo_port)
        self.assertEqual(rep, 0)
        writer.write(b"trojan")
        await writer.drain()
        self.assertEqual(await reader.readexactly(11), b"ECHO:trojan")
        writer.close()

        digest, cmd, host, port, tail = record[0]
        self.assertEqual(digest, hashlib.sha224(password.encode()).hexdigest())
        self.assertEqual(cmd, 1)
        self.assertEqual((host, port), ("127.0.0.1", echo_port))
        self.assertEqual(tail, b"\r\n")

    async def test_failover_skips_dead_upstream(self):
        echo, echo_port = await start_echo()
        self.keep(echo)
        record: list = []
        px, px_port = await start_http_proxy(record)
        self.keep(px)

        cfg = make_cfg(
            upstreams=[
                {"name": "dead", "type": "http", "server": "127.0.0.1", "port": 1},
                {"name": "px", "type": "http", "server": "127.0.0.1", "port": px_port},
            ],
            groups={"PROXY": {"type": "fallback", "members": ["dead", "px"]}},
            rules=["FINAL,PROXY"],
            final="PROXY",
        )
        ports = await self.launch(cfg)
        reader, writer, rep = await socks5_open(ports["socks5"], "127.0.0.1", echo_port)
        self.assertEqual(rep, 0, "第一个上游挂了应自动切到第二个")
        writer.write(b"z")
        await writer.drain()
        self.assertEqual(await reader.readexactly(6), b"ECHO:z")
        writer.close()
        self.assertEqual(len(record), 1)

    # ---------------------------------------------------------------- 指标
    async def test_metrics_endpoint(self):
        cfg = make_cfg()
        cfg.api.enabled = True
        ports = await self.launch(cfg)
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["api"])
        writer.write(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        head, rest = await read_head(reader)
        self.assertIn(b" 200 ", head)
        body = rest
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            body += chunk
        payload = json.loads(body.decode())
        self.assertIn("upstreams", payload)
        self.assertEqual(payload["upstreams"][0]["name"], "direct")
        writer.close()


if __name__ == "__main__":
    unittest.main()
