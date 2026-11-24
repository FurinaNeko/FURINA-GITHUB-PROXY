"""探针：验证 sni_callback 里改 sslobj.context 是否真的能换证书。"""

import asyncio
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from localproxy.ca import CAStore


async def main():
    store = CAStore("certs-probe")
    store.ensure()
    ctx = store.base_context()
    print("default cert:", store.issue("localhost")[0].name)
    print("github leaf  :", store.issue("github.com")[0].name)

    seen = {}

    async def handler(reader, writer):
        sslobj = writer.get_extra_info("ssl_object")
        seen["sni"] = store.pop_sni(sslobj)
        seen["peer"] = writer.get_extra_info("peercert", {})
        writer.write(b"ok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    print("listen:", port)

    cctx = ssl.create_default_context(cafile=str(store.ca_cert_path))
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port, ssl=cctx,
                                            server_hostname="github.com")
        cert = w.get_extra_info("peercert")
        print("client handshake OK")
        print("  subject :", dict(x[0] for x in cert["subject"]))
        print("  SAN     :", cert.get("subjectAltName"))
        print("  alpn    :", w.get_extra_info("ssl_object").selected_alpn_protocol())
        print("  server saw sni:", seen.get("sni"))
        w.close()
    except Exception as exc:
        print("handshake FAILED:", type(exc).__name__, exc)

    server.close()
    await server.wait_closed()


asyncio.run(main())
