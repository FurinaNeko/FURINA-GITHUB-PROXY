"""地址编解码测试。

这里曾经踩过坑：`bytes.decode("idna", "replace")` 会抛
`UnicodeError: Unsupported error handling: replace`，
导致 SOCKS5 请求里只要是域名就 100% 失败（IP 目标不受影响，所以粗糙测试发现不了）。
"""

from __future__ import annotations

import asyncio
import unittest

from localproxy.netutil import (
    decode_domain,
    encode_addr,
    encode_domain,
    encode_reply,
    read_addr,
)


async def _decode(blob: bytes):
    reader = asyncio.StreamReader()
    reader.feed_data(blob)
    reader.feed_eof()
    return await read_addr(reader)


class AddrCodec(unittest.IsolatedAsyncioTestCase):
    async def test_ipv4_roundtrip(self):
        host, port = await _decode(encode_addr("127.0.0.1", 8080))
        self.assertEqual((host, port), ("127.0.0.1", 8080))

    async def test_ipv6_roundtrip(self):
        host, port = await _decode(encode_addr("2606:50c0::153", 443))
        self.assertEqual((host, port), ("2606:50c0::153", 443))

    async def test_ascii_domain_roundtrip(self):
        blob = encode_addr("raw.githubusercontent.com", 443)
        self.assertEqual(blob[0], 0x03)
        self.assertEqual(await _decode(blob), ("raw.githubusercontent.com", 443))

    async def test_unicode_domain_roundtrip(self):
        host, port = await _decode(encode_addr("例子.中国", 80))
        self.assertEqual((host, port), ("例子.中国", 80))

    async def test_punycode_passthrough(self):
        self.assertEqual(decode_domain(b"xn--fsqu00a.xn--fiqs8s"), "例子.中国")

    async def test_invalid_bytes_do_not_raise(self):
        self.assertEqual(decode_domain(b"\xff\xfe"), "\ufffd\ufffd")

    def test_encode_domain_ascii_fast_path(self):
        self.assertEqual(encode_domain("huggingface.co"), b"huggingface.co")

    def test_reply_shape(self):
        reply = encode_reply(0)
        self.assertEqual(reply[:4], b"\x05\x00\x00\x01")
        self.assertEqual(len(reply), 10)


if __name__ == "__main__":
    unittest.main()
