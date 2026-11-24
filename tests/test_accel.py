"""本地 CA 与 hosts 加速器的端到端测试。

重点验证加速链路的三个关键点：
  1. CA 签出来的证书能被 OpenSSL 校验通过（git/curl 认）；
  2. 证书模式下客户端只信任本 CA 就能和 github.com 握手，且请求能打到上游；
  3. 透传模式下客户端看到的是服务器真证书（证明没有中间人）。
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import ssl
import subprocess
import tempfile
import unittest
import warnings
from pathlib import Path

from localproxy.accelerator import parse_client_hello, read_client_hello, split_host
from localproxy.ca import CAStore
from localproxy.config import Config
from localproxy.netutil import read_head
from localproxy.server import ProxyServer

warnings.filterwarnings("ignore", category=ResourceWarning)

OPENSSL_CANDIDATES = [
    shutil.which("openssl"),
    r"C:\msys64\ucrt64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
]


def find_openssl() -> str | None:
    for item in OPENSSL_CANDIDATES:
        if item and Path(item).exists():
            return item
    return None


async def start_tls_origin(ctx: ssl.SSLContext, tag: str = "origin-ok"):
    """一个最小的 HTTPS 源站：回显自己收到的 Host。"""

    async def handler(reader, writer):
        try:
            head, _ = await read_head(reader, 32768)
            start, headers = head.split(b"\r\n", 1)[0], head
            host = "?"
            for line in headers.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode()
            body = f"{tag}:{host}".encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1]


def cfg_accel(mode: str, ca_dir: str, **accel) -> Config:
    doc = {
        "log_level": "critical",
        "listeners": {
            "socks5": {"enabled": True, "host": "127.0.0.1", "port": 0},
            "http": {"enabled": False, "port": 0},
            "api": {"enabled": False, "port": 0},
        },
        "health": {"interval": 0},
        "upstreams": [{"name": "direct", "type": "direct"}],
        "rules": ["FINAL,DIRECT"],
        "final": "DIRECT",
        "accelerator": {
            "enabled": True,
            "mode": mode,
            "host": "127.0.0.1",
            "port": 0,
            "ca_dir": ca_dir,
            **accel,
        },
    }
    return Config.from_dict(doc)


async def http_get_over_tls(port: int, ctx: ssl.SSLContext, host: str):
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=host
    )
    writer.write(
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: accel-test/1.0\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    head, rest = await read_head(reader, 32768)
    body = rest
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        body += chunk
    cert = writer.get_extra_info("peercert")
    writer.close()
    return head, body, cert


class CATests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CAStore(self.tmp.name)
        self.store.ensure()

    def tearDown(self):
        self.tmp.cleanup()

    def test_ca_and_leaf_shape(self):
        cert, key = self.store.issue("github.com")
        self.assertTrue(cert.exists() and key.exists())
        from cryptography import x509

        leaf = x509.load_pem_x509_certificate(cert.read_bytes())
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertIn("github.com", [n.value for n in san.value])
        self.assertIn("localproxy", leaf.issuer.rfc4514_string())
        self.assertEqual(len(self.store.fingerprint()), 40)

    def test_openssl_verify_chain(self):
        openssl = find_openssl()
        if not openssl:
            self.skipTest("没有 openssl 可执行文件")
        cert, _ = self.store.issue("raw.githubusercontent.com")
        proc = subprocess.run(
            [openssl, "verify", "-CAfile", str(self.store.ca_cert_path), str(cert)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("OK", proc.stdout + proc.stderr)

    def test_issue_is_cached(self):
        cert1, _ = self.store.issue("huggingface.co")
        mtime = cert1.stat().st_mtime_ns
        cert2, _ = self.store.issue("huggingface.co")
        self.assertEqual(cert1, cert2)
        self.assertEqual(mtime, cert2.stat().st_mtime_ns)

    def test_wildcard_and_ip(self):
        wild, _ = self.store.issue("*.githubusercontent.com")
        self.assertTrue(wild.exists())
        ip_cert, _ = self.store.issue("127.0.0.1")
        self.assertTrue(ip_cert.exists())

    async def test_client_handshake_with_ca_trust(self):
        ctx = self.store.base_context()
        srv, port = await start_tls_origin(ctx)
        try:
            cctx = ssl.create_default_context(cafile=str(self.store.ca_cert_path))
            head, body, cert = await http_get_over_tls(port, cctx, "github.com")
            self.assertIn(b" 200 ", head)
            self.assertTrue(body.startswith(b"origin-ok:"))
            cn = dict(x[0] for x in cert["subject"])["commonName"]
            self.assertEqual(cn, "github.com")
        finally:
            srv.close()
            await srv.wait_closed()

    async def test_sni_recorded_from_callback(self):
        store = self.store
        ctx = store.base_context()
        seen = {}

        async def handler(reader, writer):
            sslobj = writer.get_extra_info("ssl_object")
            seen["sni"] = store.pop_sni(sslobj)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

        srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
        port = srv.sockets[0].getsockname()[1]
        cctx = ssl.create_default_context(cafile=str(store.ca_cert_path))
        _, w = await asyncio.open_connection(
            "127.0.0.1", port, ssl=cctx, server_hostname="api.github.com"
        )
        peer = w.get_extra_info("peercert")
        await asyncio.sleep(0.05)
        w.close()
        srv.close()
        await srv.wait_closed()

        self.assertEqual(seen.get("sni"), "api.github.com")
        self.assertEqual(dict(x[0] for x in peer["subject"])["commonName"], "api.github.com")


class HelloParseTests(unittest.IsolatedAsyncioTestCase):
    async def capture_client_hello(self, host: str) -> bytes:
        captured = bytearray()
        done = asyncio.Event()

        async def sink(reader, writer):
            try:
                data = await reader.read(4096)
                captured.extend(data)
            finally:
                done.set()
                writer.close()

        srv = await asyncio.start_server(sink, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname=host),
                5,
            )
        except Exception:  # noqa: BLE001
            pass
        await asyncio.wait_for(done.wait(), 5)
        srv.close()
        await srv.wait_closed()
        return bytes(captured)

    async def test_parse_real_client_hello(self):
        hello = await self.capture_client_hello("raw.githubusercontent.com")
        self.assertTrue(hello)
        self.assertEqual(parse_client_hello(hello), "raw.githubusercontent.com")

    async def test_read_client_hello_matches(self):
        hello = await self.capture_client_hello("huggingface.co")
        reader = asyncio.StreamReader()
        reader.feed_data(hello)
        reader.feed_eof()
        got = await read_client_hello(reader)
        self.assertEqual(parse_client_hello(got), "huggingface.co")

    def test_parse_garbage(self):
        self.assertIsNone(parse_client_hello(b""))
        self.assertIsNone(parse_client_hello(b"\x16\x03\x01\x00\x05abc"))
        self.assertIsNone(parse_client_hello(b"GET / HTTP/1.1\r\n\r\n"))

    def test_split_host(self):
        self.assertEqual(split_host("github.com:8443", 443), ("github.com", 8443))
        self.assertEqual(split_host("github.com", 443), ("github.com", 443))
        self.assertEqual(split_host("[2606:50c0::153]:443", 443), ("2606:50c0::153", 443))
        self.assertEqual(split_host("", 443), ("", 443))


class AcceleratorE2E(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CAStore(self.tmp.name)
        self.store.ensure()
        self._cleanup = []

    async def asyncTearDown(self):
        for fn in reversed(self._cleanup):
            try:
                await fn()
            except Exception:  # noqa: BLE001
                pass
        self.tmp.cleanup()

    async def launch(self, cfg):
        server = ProxyServer(cfg)

        async def closer():
            await server.close()

        self._cleanup.append(closer)
        return server, await server.start()

    async def test_mitm_mode_forwards_and_signs(self):
        origin_ctx = self.store.context_for("github.com")
        origin, origin_port = await start_tls_origin(origin_ctx, "mitm-ok")

        async def close_origin():
            origin.close()
            await origin.wait_closed()

        self._cleanup.append(close_origin)

        cfg = cfg_accel(
            "mitm", self.tmp.name,
            upstream_port=origin_port,
            upstream_ca=str(self.store.ca_cert_path),
            ip_overrides={"github.com": ["127.0.0.1"]},
        )

        server, ports = await self.launch(cfg)
        self.assertIn("accel", ports)

        cctx = ssl.create_default_context(cafile=str(self.store.ca_cert_path))
        head, body, cert = await http_get_over_tls(ports["accel"], cctx, "github.com")
        self.assertIn(b" 200 ", head)
        self.assertEqual(body, b"mitm-ok:github.com", "Host 必须原样传给上游")
        self.assertEqual(dict(x[0] for x in cert["subject"])["commonName"], "github.com")
        self.assertGreaterEqual(server.accel.stats["ok"], 1)

    async def test_sni_mode_is_not_mitm(self):
        other = CAStore(str(Path(self.tmp.name) / "origin-ca"))
        other.ensure()
        origin_ctx = other.context_for("github.com")

        origin, origin_port = await start_tls_origin(origin_ctx, "sni-ok")

        async def close_origin():
            origin.close()
            await origin.wait_closed()

        self._cleanup.append(close_origin)

        cfg = cfg_accel(
            "sni", str(Path(self.tmp.name) / "accel-ca"),
            upstream_port=origin_port,
            ip_overrides={"github.com": ["127.0.0.1"]},
        )
        _, ports = await self.launch(cfg)

        cctx = ssl.create_default_context(cafile=str(other.ca_cert_path))
        head, body, cert = await http_get_over_tls(ports["accel"], cctx, "github.com")
        self.assertIn(b" 200 ", head)
        self.assertEqual(body, b"sni-ok:github.com")
        # 关键：透传模式下客户端看到的就是源站证书（由另一套 CA 签发），不是本地 CA 签的
        self.assertEqual(dict(x[0] for x in cert["subject"])["commonName"], "github.com")
        self.assertIn("origin-ca", other.ca_cert_path.parts[-2] + "/")


if __name__ == "__main__":
    unittest.main()
