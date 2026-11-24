"""规则与配置的单元测试。"""

from __future__ import annotations

import unittest

from localproxy.config import Config, ConfigError
from localproxy.rules import RuleError, parse_rules


class FakeResolver:
    def __init__(self, table):
        self.table = table
        self.calls = 0

    async def resolve(self, host):
        self.calls += 1
        if host not in self.table:
            raise RuntimeError(f"no record {host}")
        return self.table[host]


def engine(*rules, final="DIRECT"):
    from localproxy.rules import RuleEngine

    return RuleEngine(parse_rules(rules), final)


class RuleTests(unittest.IsolatedAsyncioTestCase):
    async def test_domain_suffix_does_not_match_partial_label(self):
        eng = engine("DOMAIN-SUFFIX,github.com,PROXY")
        self.assertEqual(await eng.match("github.com", 443), "PROXY")
        self.assertEqual(await eng.match("api.github.com", 443), "PROXY")
        self.assertEqual(await eng.match("notgithub.com", 443), "DIRECT")
        self.assertEqual(await eng.match("github.com.evil.io", 443), "DIRECT")

    async def test_keyword_and_regex(self):
        eng = engine("DOMAIN-KEYWORD,hugging,PROXY", "DOMAIN-REGEX,^hf\\..*$,PROXY")
        self.assertEqual(await eng.match("cdn.huggingface.co", 443), "PROXY")
        self.assertEqual(await eng.match("hf.space", 443), "PROXY")
        self.assertEqual(await eng.match("hfspace.io", 443), "DIRECT")

    async def test_case_and_trailing_dot_normalized(self):
        eng = engine("DOMAIN,Example.COM,PROXY")
        self.assertEqual(await eng.match("EXAMPLE.com.", 443), "PROXY")

    async def test_first_match_wins(self):
        eng = engine("DOMAIN,keep.test,DIRECT", "DOMAIN-SUFFIX,test,PROXY")
        self.assertEqual(await eng.match("keep.test", 443), "DIRECT")
        self.assertEqual(await eng.match("other.test", 443), "PROXY")

    async def test_ip_cidr_literal(self):
        eng = engine("IP-CIDR,185.199.108.0/22,PROXY,no-resolve")
        self.assertEqual(await eng.match("185.199.109.153", 443), "PROXY")
        self.assertEqual(await eng.match("8.8.8.8", 443), "DIRECT")

    async def test_no_resolve_skips_dns(self):
        res = FakeResolver({"cdn-lfs.huggingface.co": ["18.64.1.1"]})
        eng = engine("IP-CIDR,18.64.0.0/12,PROXY,no-resolve")
        self.assertEqual(await eng.match("cdn-lfs.huggingface.co", 443, res), "DIRECT")
        self.assertEqual(res.calls, 0)

    async def test_resolves_when_needed(self):
        res = FakeResolver({"inner.test": ["18.64.1.1"]})
        eng = engine("IP-CIDR,18.64.0.0/12,PROXY")
        self.assertEqual(await eng.match("inner.test", 443, res), "PROXY")
        self.assertEqual(res.calls, 1)

    async def test_dst_port_and_final(self):
        eng = engine("DST-PORT,22,REJECT", final="PROXY")
        self.assertEqual(await eng.match("any.host", 22), "REJECT")
        self.assertEqual(await eng.match("any.host", 443), "PROXY")

    async def test_ipv6_rule(self):
        eng = engine("IP-CIDR6,2606:50c0::/32,PROXY,no-resolve")
        self.assertEqual(await eng.match("2606:50c0::153", 443), "PROXY")

    async def test_bad_rule_message(self):
        with self.assertRaises(RuleError):
            parse_rules(["WRONG-TYPE,a,b"])


class ConfigTests(unittest.TestCase):
    def base(self, **over):
        doc = {
            "listeners": {
                "socks5": {"enabled": True, "port": 7890},
                "http": {"enabled": True, "port": 7891},
                "api": {"enabled": True, "port": 7892},
            },
            "upstreams": [{"name": "direct", "type": "direct"}],
            "rules": ["FINAL,DIRECT"],
            "final": "DIRECT",
        }
        doc.update(over)
        return doc

    def test_defaults_and_auto_direct(self):
        cfg = Config.from_dict(self.base(upstreams=[]))
        self.assertIn("direct", cfg.upstreams)
        self.assertEqual(cfg.final, "DIRECT")

    def test_unknown_policy_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(self.base(rules=["DOMAIN-SUFFIX,github.com,NOPE"]))

    def test_group_member_must_exist(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(self.base(groups={"PROXY": {"members": ["ghost"]}}))

    def test_port_conflict(self):
        doc = self.base()
        doc["listeners"]["http"] = {"enabled": True, "port": 7890}
        with self.assertRaises(ConfigError):
            Config.from_dict(doc)

    def test_trojan_requires_password(self):
        with self.assertRaises(ConfigError):
            Config.from_dict(
                self.base(upstreams=[
                    {"name": "direct", "type": "direct"},
                    {"name": "t", "type": "trojan", "server": "a.b", "port": 443},
                ])
            )

    def test_json_comments_allowed(self):
        from localproxy.config import _strip_json_comments

        text = '{"a": 1, // 行注释\n "b": "http://x//y", /* 块 */ "c": 2}'
        import json

        self.assertEqual(json.loads(_strip_json_comments(text)),
                         {"a": 1, "b": "http://x//y", "c": 2})


if __name__ == "__main__":
    unittest.main()
