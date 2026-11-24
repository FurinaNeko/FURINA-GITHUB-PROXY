"""配置加载与校验（纯 JSON，不依赖 pyyaml）。"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .rules import DIRECT, RuleEngine, RuleError, parse_rules

UPSTREAM_TYPES = {"direct", "http", "socks5", "trojan"}
RESERVED_POLICIES = {DIRECT, "REJECT"}


class ConfigError(Exception):
    """配置不合法。"""


DEFAULTS: dict[str, Any] = {
    "log_level": "info",
    "listeners": {
        "socks5": {"enabled": True, "host": "127.0.0.1", "port": 7890,
                   "username": "", "password": ""},
        "http": {"enabled": True, "host": "127.0.0.1", "port": 7891,
                 "username": "", "password": ""},
        "api": {"enabled": True, "host": "127.0.0.1", "port": 7892},
    },
    "dns": {"mode": "system", "doh_url": "https://1.1.1.1/dns-query",
            "cache_ttl": 300, "timeout": 5},
    "timeouts": {"connect": 8, "handshake": 10, "idle": 300},
    "health": {"interval": 30, "timeout": 4, "fail_threshold": 2, "cooldown": 20},
    "ui": {"language": "en"},
    "accelerator": {
        "enabled": False,
        "mode": "mitm",
        "host": "127.0.0.1",
        "port": 443,
        "ca_dir": "certs",
        "ca_common_name": "localproxy Local CA",
        "ca_organization": "localproxy",
        "upstream_verify": True,
        "upstream_ca": "",
        "upstream_port": 443,
        "ip_overrides": {},
        "strip_csp": True,
    },
    "upstreams": [],
    "groups": {},
    "rules": [],
    "final": DIRECT,
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass
class Listener:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 0
    username: str = ""
    password: str = ""
    family_label: str = ""

    @property
    def needs_auth(self) -> bool:
        return bool(self.username or self.password)


@dataclass
class UpstreamSpec:
    name: str
    type: str
    server: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    tls: dict = field(default_factory=dict)
    priority: int = 0
    resolve_locally: bool | None = None
    connect_timeout: float | None = None

    def masked(self) -> str:
        if self.type == "direct":
            return "direct://"
        auth = f"{self.username}:***@" if self.username else ""
        return f"{self.type}://{auth}{self.server}:{self.port}"


@dataclass
class GroupSpec:
    name: str
    kind: str = "latency"   # latency | fallback
    members: list[str] = field(default_factory=list)


@dataclass
class AccelSpec:
    """hosts 加速器（证书模式 / SNI 透传模式）。"""
    enabled: bool = False
    mode: str = "mitm"          # mitm | sni
    host: str = "127.0.0.1"
    port: int = 443
    ca_dir: str = "certs"
    ca_common_name: str = "localproxy Local CA"
    ca_organization: str = "localproxy"
    upstream_verify: bool = True
    upstream_ca: str = ""
    upstream_port: int = 443
    ip_overrides: dict = field(default_factory=dict)
    strip_csp: bool = True


@dataclass
class Config:
    raw: dict
    log_level: str
    socks5: Listener
    http: Listener
    api: Listener
    dns: dict
    timeouts: dict
    health: dict
    upstreams: dict[str, UpstreamSpec]
    groups: dict[str, GroupSpec]
    engine: RuleEngine
    final: str
    accel: AccelSpec = field(default_factory=AccelSpec)
    ui: dict = field(default_factory=dict)
    source: str = "<memory>"

    # ------------------------------------------------------------------ 构造
    @classmethod
    def from_dict(cls, data: dict, source: str = "<memory>") -> "Config":
        if not isinstance(data, dict):
            raise ConfigError("配置根节点必须是 JSON 对象")
        merged = _merge(DEFAULTS, data)
        listeners = merged["listeners"]

        socks5 = _listener("socks5", listeners.get("socks5") or {}, "SOCKS5")
        http = _listener("http", listeners.get("http") or {}, "HTTP")
        api = _listener("api", listeners.get("api") or {}, "API")
        if not socks5.enabled and not http.enabled:
            raise ConfigError("socks5 与 http 监听至少启用一个")

        ports = [p.port for p in (socks5, http, api) if p.enabled and p.port]
        if len(ports) != len(set(ports)):
            raise ConfigError("监听端口冲突，请为 socks5 / http / api 分配不同端口")

        upstreams: dict[str, UpstreamSpec] = {}
        for item in merged.get("upstreams") or []:
            spec = _upstream(item)
            if spec.name in upstreams:
                raise ConfigError(f"上游重名：{spec.name}")
            upstreams[spec.name] = spec
        if not any(s.type == "direct" for s in upstreams.values()):
            upstreams.setdefault("direct", UpstreamSpec(name="direct", type="direct"))

        groups: dict[str, GroupSpec] = {}
        for name, item in (merged.get("groups") or {}).items():
            if not isinstance(item, dict):
                raise ConfigError(f"组 {name} 必须是对象")
            members = list(item.get("members") or [])
            if not members:
                raise ConfigError(f"组 {name} 没有成员")
            for member in members:
                if member not in upstreams:
                    raise ConfigError(f"组 {name} 引用了不存在的上游 {member}")
            kind = str(item.get("type", "latency")).lower()
            if kind not in ("latency", "fallback"):
                raise ConfigError(f"组 {name} 的 type 只能是 latency 或 fallback")
            if name in upstreams:
                raise ConfigError(f"组名与上游名冲突：{name}")
            groups[name] = GroupSpec(name=name, kind=kind, members=members)

        try:
            rules = parse_rules(merged.get("rules") or [])
        except RuleError as exc:
            raise ConfigError(str(exc)) from exc

        final = str(merged.get("final") or DIRECT)
        known = set(upstreams) | set(groups) | RESERVED_POLICIES
        for rule in rules:
            if rule.policy not in known:
                raise ConfigError(f"规则策略 {rule.policy!r} 未定义（{rule.raw}）")
        if final not in known:
            raise ConfigError(f"final 策略 {final!r} 未定义")

        return cls(
            raw=merged,
            log_level=str(merged.get("log_level", "info")).lower(),
            socks5=socks5,
            http=http,
            api=api,
            dns=dict(merged.get("dns") or {}),
            timeouts=dict(merged.get("timeouts") or {}),
            health=dict(merged.get("health") or {}),
            upstreams=upstreams,
            groups=groups,
            engine=RuleEngine(rules, final),
            final=final,
            accel=_accel(merged.get("accelerator") or {}),
            ui=dict(merged.get("ui") or {}),
            source=source,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        p = Path(path)
        if not p.exists():
            raise ConfigError(f"配置文件不存在：{p}")
        text = p.read_text(encoding="utf-8-sig")
        text = _strip_json_comments(text)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{p} 不是合法 JSON：{exc}") from exc
        return cls.from_dict(data, source=str(p))

    # ------------------------------------------------------------------ 查询
    def cost(self, name: str) -> int:
        return self.health.get("interval", 30)

    def timeout(self, key: str, default: float) -> float:
        try:
            return float(self.timeouts.get(key, default))
        except (TypeError, ValueError):
            return float(default)


def _strip_json_comments(text: str) -> str:
    """允许在 JSON 里写 // 与 /* */ 注释，方便写说明。"""
    out: list[str] = []
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _listener(kind: str, item: dict, label: str) -> Listener:
    if not isinstance(item, dict):
        raise ConfigError(f"listeners.{kind} 必须是对象")
    port = item.get("port", 0)
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"listeners.{kind}.port 不是整数") from exc
    if item.get("enabled", True) and not (0 <= port < 65536):
        raise ConfigError(f"listeners.{kind}.port 端口不合法：{port}")
    host = str(item.get("host", "127.0.0.1"))
    return Listener(
        enabled=bool(item.get("enabled", True)),
        host=host,
        port=port,
        username=str(item.get("username", "") or ""),
        password=str(item.get("password", "") or ""),
        family_label=label,
    )


def _accel(item: dict) -> AccelSpec:
    if not isinstance(item, dict):
        raise ConfigError("accelerator 必须是对象")
    mode = str(item.get("mode", "mitm")).strip().lower()
    if mode not in ("mitm", "sni"):
        raise ConfigError("accelerator.mode 只能是 mitm 或 sni")
    try:
        port = int(item.get("port", 443))
        upstream_port = int(item.get("upstream_port", 443))
    except (TypeError, ValueError) as exc:
        raise ConfigError("accelerator 端口必须是整数") from exc
    for label, value in (("port", port), ("upstream_port", upstream_port)):
        if not 0 <= value < 65536:
            raise ConfigError(f"accelerator.{label} 端口不合法：{value}")

    overrides = item.get("ip_overrides") or {}
    if not isinstance(overrides, dict):
        raise ConfigError("accelerator.ip_overrides 必须是 {域名: IP 或 [IP]} 形式")
    clean: dict[str, list[str]] = {}
    for host, value in overrides.items():
        if isinstance(value, str):
            clean[str(host).lower()] = [value]
        elif isinstance(value, (list, tuple)):
            clean[str(host).lower()] = [str(v) for v in value]
        else:
            raise ConfigError(f"accelerator.ip_overrides[{host}] 格式不对")

    ca_dir = str(item.get("ca_dir", "certs") or "certs")
    if ca_dir in (".", ""):
        raise ConfigError("accelerator.ca_dir 不能为空")
    return AccelSpec(
        enabled=bool(item.get("enabled", False)),
        mode=mode,
        host=str(item.get("host", "127.0.0.1")),
        port=port,
        ca_dir=ca_dir,
        ca_common_name=str(item.get("ca_common_name") or "localproxy Local CA"),
        ca_organization=str(item.get("ca_organization") or "localproxy"),
        upstream_verify=bool(item.get("upstream_verify", True)),
        upstream_ca=str(item.get("upstream_ca", "") or ""),
        upstream_port=upstream_port,
        ip_overrides=clean,
        strip_csp=bool(item.get("strip_csp", True)),
    )


def _upstream(item: dict) -> UpstreamSpec:
    if not isinstance(item, dict):
        raise ConfigError("upstreams 的每一项必须是对象")
    name = str(item.get("name", "")).strip()
    if not name:
        raise ConfigError("上游缺少 name")
    kind = str(item.get("type", "")).strip().lower()
    if kind not in UPSTREAM_TYPES:
        raise ConfigError(f"上游 {name} 的 type 必须是 {sorted(UPSTREAM_TYPES)}")
    if kind == "direct":
        return UpstreamSpec(name=name, type=kind)
    server = str(item.get("server", "")).strip()
    if not server:
        raise ConfigError(f"上游 {name} 缺少 server")
    try:
        port = int(item.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"上游 {name} 的 port 不是整数") from exc
    if not 0 < port < 65536:
        raise ConfigError(f"上游 {name} 的 port 不合法：{port}")

    tls = item.get("tls") or {}
    if not isinstance(tls, dict):
        raise ConfigError(f"上游 {name} 的 tls 必须是对象")
    password = str(item.get("password", "") or "")
    if kind == "trojan" and not password:
        raise ConfigError(f"Trojan 上游 {name} 必须提供 password")

    return UpstreamSpec(
        name=name,
        type=kind,
        server=server,
        port=port,
        username=str(item.get("username", "") or ""),
        password=password,
        tls=dict(tls),
        priority=int(item.get("priority", 0) or 0),
        resolve_locally=item.get("resolve_locally"),
        connect_timeout=item.get("connect_timeout"),
    )


EXAMPLE_CONFIG: dict[str, Any] = {
    "log_level": "info",
    "listeners": {
        "socks5": {"enabled": True, "host": "127.0.0.1", "port": 7890,
                   "username": "", "password": ""},
        "http": {"enabled": True, "host": "127.0.0.1", "port": 7891,
                 "username": "", "password": ""},
        "api": {"enabled": True, "host": "127.0.0.1", "port": 7892},
    },
    "dns": {"mode": "doh", "doh_url": "https://1.1.1.1/dns-query",
            "cache_ttl": 300, "timeout": 5},
    "timeouts": {"connect": 8, "handshake": 10, "idle": 300},
    "health": {"interval": 30, "timeout": 4, "fail_threshold": 2, "cooldown": 20},
    "upstreams": [
        {"name": "direct", "type": "direct"},
        {"name": "http-node", "type": "http", "server": "127.0.0.1", "port": 10809,
         "username": "", "password": ""},
        {"name": "socks-node", "type": "socks5", "server": "127.0.0.1", "port": 1080,
         "username": "user", "password": "pass"},
        {"name": "trojan-node", "type": "trojan", "server": "NODE_HOST", "port": 443,
         "password": "NODE_PASSWORD",
         "tls": {"sni": "NODE_SNI", "insecure": False, "alpn": ["http/1.1"]}},
    ],
    "groups": {
        "PROXY": {"type": "latency", "members": ["trojan-node", "socks-node", "http-node"]},
        "STABLE": {"type": "fallback", "members": ["trojan-node", "socks-node"]},
    },
    "rules": [
        "DOMAIN-SUFFIX,github.com,PROXY",
        "DOMAIN-SUFFIX,githubusercontent.com,PROXY",
        "DOMAIN-SUFFIX,githubassets.com,PROXY",
        "DOMAIN-SUFFIX,github.io,PROXY",
        "DOMAIN-SUFFIX,ghcr.io,PROXY",
        "DOMAIN-SUFFIX,npmjs.org,PROXY",
        "DOMAIN-SUFFIX,gstatic.com,PROXY",
        "IP-CIDR,140.82.112.0/20,PROXY,no-resolve",
        "IP-CIDR,185.199.108.0/22,PROXY,no-resolve",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "FINAL,DIRECT",
    ],
    "final": "DIRECT",
}
