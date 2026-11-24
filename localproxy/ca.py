"""本地 CA：生成根证书 + 按 SNI 即时签发域名证书。

工作方式：把 github.com 这类域名在 hosts 里指到 127.0.0.1，
本进程用自己签的证书完成 TLS 握手，再把请求转发到真正的服务器。
客户端只要信任本 CA，就不会有任何证书告警。

产物（默认 certs/ 目录）：
    ca.key        CA 私钥（务必别外传）
    ca.crt        CA 证书 PEM
    MyCA.cer      CA 证书 DER（双击即可导入）
    leaves/*.crt  各域名叶子证书
    leaves/*.key  各域名叶子私钥
"""

from __future__ import annotations

import datetime
import ipaddress
import shutil
import ssl
import subprocess
import sys
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_KEY_NAME = "ca.key"
CA_CERT_NAME = "ca.crt"
CA_DER_NAME = "MyCA.cer"
LEAF_DIR = "leaves"
CA_DAYS = 3650
LEAF_DAYS = 397


class CAError(Exception):
    """CA 操作失败。"""


def _sanitize(host: str) -> str:
    out = host.strip().lower().rstrip(".")
    for ch in (":", "*", "/", "\\", "<", ">", "|", "?"):
        out = out.replace(ch, "_")
    return out or "default"


class CAStore:
    """证书仓库。线程安全，叶子证书与上下文都有缓存。"""

    def __init__(self, directory: str | Path = "certs",
                 common_name: str = "localproxy Local CA",
                 organization: str = "localproxy"):
        self.dir = Path(directory)
        self.common_name = common_name
        self.organization = organization
        self._lock = threading.RLock()
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._sni_by_obj: dict[int, str] = {}

    # ------------------------------------------------------------------ 路径
    @property
    def ca_key_path(self) -> Path:
        return self.dir / CA_KEY_NAME

    @property
    def ca_cert_path(self) -> Path:
        return self.dir / CA_CERT_NAME

    @property
    def ca_der_path(self) -> Path:
        return self.dir / CA_DER_NAME

    @property
    def leaf_dir(self) -> Path:
        return self.dir / LEAF_DIR

    def exists(self) -> bool:
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    # ------------------------------------------------------------------ 生成
    def ensure(self, force: bool = False, key_size: int = 2048) -> Path:
        """确保 CA 存在；force=True 会重新生成（已装的旧证书会失效）。"""
        with self._lock:
            if self.exists() and not force:
                return self.ca_cert_path
            self.dir.mkdir(parents=True, exist_ok=True)
            self.leaf_dir.mkdir(parents=True, exist_ok=True)

            key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                        encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(ski, critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()), critical=False)
                .sign(key, hashes.SHA256())
            )

            self.ca_key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            self.ca_der_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
            self._ctx_cache.clear()
            return self.ca_cert_path

    # ------------------------------------------------------------------ 读取
    def ca_cert(self) -> x509.Certificate:
        if not self.ca_cert_path.exists():
            raise CAError(f"CA 证书不存在：{self.ca_cert_path}（先执行 localproxy cert init）")
        return x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())

    def ca_key(self):
        if not self.ca_key_path.exists():
            raise CAError(f"CA 私钥不存在：{self.ca_key_path}")
        return serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)

    def fingerprint(self) -> str:
        """SHA1 指纹（大写无空格），系统证书管理器里显示的就是它。"""
        digest = hashes.Hash(hashes.SHA1())
        digest.update(self.ca_cert().public_bytes(serialization.Encoding.DER))
        return digest.finalize().hex().upper()

    def describe(self) -> dict:
        if not self.exists():
            return {"exists": False, "dir": str(self.dir)}
        cert = self.ca_cert()
        return {
            "exists": True,
            "dir": str(self.dir),
            "subject": cert.subject.rfc4514_string(),
            "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
            "fingerprint_sha1": self.fingerprint(),
            "trusted": self.is_trusted(),
            "pem": str(self.ca_cert_path),
            "cer": str(self.ca_der_path),
            "leaves": len(self.list_leaves()),
        }

    # ------------------------------------------------------------------ 签发
    def issue(self, host: str, days: int = LEAF_DAYS, force: bool = False) -> tuple[Path, Path]:
        """给单个域名（或 IP）签发叶子证书，返回 (证书, 私钥) 路径。"""
        host = host.strip().lower().rstrip(".")
        if not host:
            raise CAError("主机名为空")
        caf = self.ensure()
        leaf = self.leaf_dir / f"{_sanitize(host)}.crt"
        leaf_key = self.leaf_dir / f"{_sanitize(host)}.key"
        with self._lock:
            if leaf.exists() and leaf_key.exists() and not force:
                try:
                    existing = x509.load_pem_x509_certificate(leaf.read_bytes())
                    if existing.not_valid_after_utc > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3):
                        return leaf, leaf_key
                except Exception:  # noqa: BLE001
                    pass  # 旧文件坏了就重签

            ca_cert = self.ca_cert()
            ca_key = self.ca_key()
            key = ec.generate_private_key(ec.SECP256R1())

            try:
                ip = ipaddress.ip_address(host)
                san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
                cn = host
            except ValueError:
                san = x509.SubjectAlternativeName([x509.DNSName(host)])
                cn = host

            now = datetime.datetime.now(datetime.timezone.utc)
            builder = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
                ]))
                .issuer_name(ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=days))
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, content_commitment=False,
                        key_encipherment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=False, crl_sign=False,
                        encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                )
            )
            cert = builder.sign(ca_key, hashes.SHA256())

            self.leaf_dir.mkdir(parents=True, exist_ok=True)
            leaf_key.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            leaf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            self._ctx_cache.pop(host, None)
            return leaf, leaf_key

    def list_leaves(self) -> list[dict]:
        out: list[dict] = []
        if not self.leaf_dir.exists():
            return out
        for item in sorted(self.leaf_dir.glob("*.crt")):
            try:
                cert = x509.load_pem_x509_certificate(item.read_bytes())
                out.append({
                    "file": item.name,
                    "subject": cert.subject.rfc4514_string(),
                    "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
                })
            except Exception:  # noqa: BLE001
                continue
        return out

    # ------------------------------------------------------------------ TLS 上下文
    def context_for(self, host: str) -> ssl.SSLContext:
        """给某个域名准备服务端上下文（带缓存）。只谈 HTTP/1.1，避免协商到 h2。"""
        host = host.strip().lower().rstrip(".")
        cached = self._ctx_cache.get(host)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._ctx_cache.get(host)
            if cached is not None:
                return cached
            cert, key = self.issue(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_alpn_protocols(["http/1.1"])
            ctx.load_cert_chain(str(cert), str(key))
            self._ctx_cache[host] = ctx
            return ctx

    def base_context(self, default_host: str = "localhost") -> ssl.SSLContext:
        """监听用的服务端上下文：按 SNI 现切证书。"""
        ctx = self.context_for(default_host)  # 借它的证书做兜底
        holder = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        holder.minimum_version = ssl.TLSVersion.TLSv1_2
        holder.set_alpn_protocols(["http/1.1"])
        cert, key = self.issue(default_host)
        holder.load_cert_chain(str(cert), str(key))

        def _sni(sslobj, server_name, _ctx):
            if not server_name:
                return None
            try:
                sslobj.context = self.context_for(server_name)
            except Exception:  # noqa: BLE001
                return None
            # 两种方式都记一份：属性最可靠；id 映射兜住“包装对象被重建”的情况
            try:
                setattr(sslobj, "_localproxy_sni", server_name)
            except Exception:  # noqa: BLE001
                pass
            self._sni_by_obj[id(sslobj)] = server_name
            return None

        holder.sni_callback = _sni
        return holder

    def pop_sni(self, ssl_object) -> str | None:
        """取回握手时记录的 SNI（sni_callback 里存下的）。"""
        if ssl_object is None:
            return None
        name = getattr(ssl_object, "_localproxy_sni", None)
        if name:
            self._sni_by_obj.pop(id(ssl_object), None)
            return name
        return self._sni_by_obj.pop(id(ssl_object), None)

    # ------------------------------------------------------------------ 系统信任
    def trust(self) -> tuple[bool, str]:
        """把 CA 装进“当前用户 / 受信任的根证书颁发机构”。"""
        if not self.exists():
            return False, "CA 还没生成，先执行 localproxy cert init"
        if not sys.platform.startswith("win"):
            return False, (
                f"非 Windows：请手动把 {self.ca_cert_path} 复制到系统证书目录，"
                "例如 NODE_EXTRA_CA_CERTS 指向它，或 update-ca-certificates"
            )
        thumb = self.fingerprint()
        code, out = _run(["certutil", "-user", "-addstore", "-f", "Root", str(self.ca_der_path)])
        if code == 0:
            return True, f"已导入当前用户根证书库（指纹 {thumb}）"
        # certutil 不在 PATH 时退回 PowerShell
        ps = (
            f"Import-Certificate -FilePath '{self.ca_der_path}' "
            "-CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null"
        )
        code2, out2 = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
        if code2 == 0:
            return True, f"已导入当前用户根证书库（指纹 {thumb}）"
        return False, (out or out2).strip() or "导入失败"

    def untrust(self) -> tuple[bool, str]:
        if not self.exists():
            return False, "CA 还没生成"
        if not sys.platform.startswith("win"):
            return False, "非 Windows：请从系统证书库手动删除"
        thumb = self.fingerprint()
        code, out = _run(["certutil", "-user", "-delstore", "Root", thumb])
        return code == 0, (out.strip() or f"已从当前用户根证书库移除 {thumb}")

    def is_trusted(self) -> bool:
        if not sys.platform.startswith("win") or not self.exists():
            return False
        code, out = _run(["certutil", "-user", "-store", "Root", self.fingerprint()])
        return code == 0 and "找不到" not in out and "Cannot find" not in out

    # ------------------------------------------------------------------ 导出
    def export_der(self) -> bytes:
        return self.ca_cert().public_bytes(serialization.Encoding.DER)

    def export_to(self, target: str | Path) -> Path:
        """导出 .cer 到任意位置（给浏览器 / 另一台机器导入）。"""
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.export_der())
        return target

    def export_bundle(self) -> bytes:
        """PEM 连接包：ca.crt + 现有叶子证书，方便当单一的信任锚给工具用。"""
        data = self.ca_cert_path.read_bytes()
        for item in sorted(self.leaf_dir.glob("*.crt")) if self.leaf_dir.exists() else []:
            data += item.read_bytes()
        return data


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 127, f"找不到命令：{cmd[0]}"
    except subprocess.SubprocessError as exc:
        return 1, str(exc)


def ensure_hosts_snippet(hosts: list[str], target: str = "127.0.0.1",
                         path: str | Path = "certs/hosts-snippet.txt") -> Path:
    """生成 hosts 片段（由用户或脚本合并进系统 hosts）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# localproxy 加速用（把下列域名指到本机，由本地证书代理接管）"]
    lines += [f"{target}\t{host}" for host in hosts]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
