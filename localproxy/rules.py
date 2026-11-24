"""规则引擎：按域名 / IP / 端口决定走哪条链路。

支持写法（与 Clash 习惯一致，便于直接抄现成规则集）：
    DOMAIN,github.com,PROXY
    DOMAIN-SUFFIX,githubusercontent.com,PROXY
    DOMAIN-KEYWORD,github,PROXY
    DOMAIN-REGEX,^api\\..*\\.com$,PROXY
    IP-CIDR,140.82.112.0/20,PROXY,no-resolve
    IP-CIDR6,2606:50c0::/32,PROXY
    DST-PORT,22,REJECT
    FINAL,DIRECT
策略取值：DIRECT / REJECT / 组名 / 上游名。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .netutil import as_ip, normalize_host

DIRECT = "DIRECT"
REJECT = "REJECT"

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}
OTHER_TYPES = {"DST-PORT", "MATCH", "FINAL"}
ALL_TYPES = DOMAIN_TYPES | IP_TYPES | OTHER_TYPES


class RuleError(Exception):
    """规则写错。"""


@dataclass
class Rule:
    kind: str
    value: str
    policy: str
    no_resolve: bool = False
    regex: re.Pattern | None = None
    network: object | None = None
    port: int | None = None
    raw: str = ""

    def match_domain(self, host: str, port: int) -> bool:
        if self.kind == "DOMAIN":
            return host == self.value
        if self.kind == "DOMAIN-SUFFIX":
            return host == self.value or host.endswith("." + self.value)
        if self.kind == "DOMAIN-KEYWORD":
            return self.value in host
        if self.kind == "DOMAIN-REGEX":
            assert self.regex is not None
            return bool(self.regex.search(host))
        if self.kind == "DST-PORT":
            return port == self.port
        if self.kind in ("MATCH", "FINAL"):
            return True
        return False


def parse_rule(line: str) -> Rule:
    raw = line.strip()
    if not raw or raw.startswith("#") or raw.startswith("//"):
        raise RuleError("空规则")
    parts = [p.strip() for p in raw.split(",")]
    kind = parts[0].upper()
    if kind not in ALL_TYPES:
        raise RuleError(f"未知规则类型 {kind!r}（支持：{', '.join(sorted(ALL_TYPES))}）")

    if kind in ("MATCH", "FINAL"):
        if len(parts) < 2:
            raise RuleError(f"规则 {raw!r} 缺少策略")
        return Rule(kind=kind, value="", policy=parts[1], raw=raw)

    if len(parts) < 3:
        raise RuleError(f"规则 {raw!r} 需要 类型,值,策略 三段")

    value, policy = parts[1], parts[2]
    extra = [p.lower() for p in parts[3:]]
    rule = Rule(kind=kind, value=value, policy=policy, raw=raw)

    if kind in DOMAIN_TYPES:
        if kind != "DOMAIN-REGEX":
            rule.value = normalize_host(value)
        try:
            rule.regex = re.compile(value, re.IGNORECASE) if kind == "DOMAIN-REGEX" else None
        except re.error as exc:
            raise RuleError(f"正则 {value!r} 不合法：{exc}") from exc
    elif kind in IP_TYPES:
        import ipaddress

        try:
            rule.network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuleError(f"网段 {value!r} 不合法：{exc}") from exc
        rule.no_resolve = "no-resolve" in extra
    elif kind == "DST-PORT":
        try:
            rule.port = int(value)
        except ValueError as exc:
            raise RuleError(f"端口 {value!r} 不是整数") from exc
    return rule


def parse_rules(lines) -> list[Rule]:
    rules: list[Rule] = []
    for idx, line in enumerate(lines, 1):
        try:
            rules.append(parse_rule(line))
        except RuleError:
            text = str(line).strip()
            if not text or text.startswith("#") or text.startswith("//"):
                continue
            raise RuleError(f"第 {idx} 条规则无法解析：{text}") from None
    return rules


class RuleEngine:
    """首条命中即生效。命中 FINAL 之前若需要 IP 判断，会按需解析域名。"""

    def __init__(self, rules: list[Rule], final: str = DIRECT):
        self.rules = rules
        self.final = final
        self._terminal = any(r.kind in ("MATCH", "FINAL") for r in rules)

    async def match(self, host: str, port: int, resolver=None) -> str:
        host = normalize_host(host)
        ip_obj = as_ip(host)
        resolved_ips = None

        for rule in self.rules:
            if rule.kind in IP_TYPES:
                if ip_obj is None:
                    if rule.no_resolve:
                        continue
                    if resolver is None:
                        continue
                    if resolved_ips is None:
                        try:
                            resolved_ips = await resolver.resolve(host)
                        except Exception:
                            resolved_ips = []
                    for text in resolved_ips:
                        candidate = as_ip(text)
                        if candidate is not None and candidate in rule.network:
                            return rule.policy
                    continue
                if ip_obj in rule.network:
                    return rule.policy
                continue

            if rule.match_domain(host, port):
                return rule.policy

        return self.final
