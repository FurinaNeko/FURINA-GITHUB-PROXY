"""选路：规则 -> 策略 -> 候选上游 -> 实际拨号（带故障切换）。"""

from __future__ import annotations

import logging
import time

from .config import Config
from .rules import DIRECT, REJECT
from .resolver import Resolver
from .upstream import Upstream, UpstreamError

log = logging.getLogger("localproxy.router")


class RejectedByRule(Exception):
    """规则要求拒绝。"""


class NoRoute(Exception):
    """所有候选上游都连不上。"""


class Router:
    def __init__(self, cfg: Config, resolver: Resolver):
        self.cfg = cfg
        self.resolver = resolver
        self.upstreams = {
            name: Upstream(spec, resolver, cfg) for name, spec in cfg.upstreams.items()
        }
        self._direct_name = next(
            (n for n, s in cfg.upstreams.items() if s.type == "direct"), None
        )

    # ------------------------------------------------------------------ 选路
    def candidates(self, policy: str) -> list[Upstream]:
        policy = (policy or "").strip()
        if policy.upper() == REJECT:
            raise RejectedByRule("规则命中 REJECT")
        if policy.upper() == DIRECT:
            if self._direct_name is None:
                raise NoRoute("配置里没有 direct 上游")
            return [self.upstreams[self._direct_name]]

        group = self.cfg.groups.get(policy)
        if group is not None:
            members = [self.upstreams[n] for n in group.members]
            return _order(members, group.kind)

        single = self.upstreams.get(policy)
        if single is not None:
            return [single]
        raise NoRoute(f"策略 {policy!r} 没有对应上游或组")

    async def decide(self, host: str, port: int) -> str:
        return await self.cfg.engine.match(host, port, self.resolver)

    async def dial(self, host: str, port: int, policy: str | None = None):
        """返回 (reader, writer, policy, upstream)。失败逐个换上游。"""
        if policy is None:
            policy = await self.decide(host, port)
        cands = self.candidates(policy)
        # 刚失败过、还在冷却期的上游先跳过：否则占位节点会把每次连接都拖到超时
        now = time.monotonic()
        warm = [u for u in cands if u.blocked_until <= now]
        if warm:
            cands = warm
        errors: list[str] = []
        for up in cands:
            try:
                reader, writer = await up.connect(host, port)
                up.connects += 1
                up.mark_success()
                return reader, writer, policy, up
            except UpstreamError as exc:
                up.mark_failure(str(exc))
                errors.append(str(exc))
                log.debug("上游 %s 失败，尝试下一个：%s", up.name, exc)
        raise NoRoute(
            f"{host}:{port} 在策略 {policy} 下全部失败：" + " | ".join(errors[:4])
        )

    # ------------------------------------------------------------------ 健康
    async def start_health_loop(self, stop: "asyncio.Event") -> None:
        import asyncio

        interval = float(self.cfg.health.get("interval", 30.0))
        if interval <= 0:
            return
        await asyncio.gather(
            *(self._health_worker(up, interval, stop) for up in self.upstreams.values())
        )

    async def _health_worker(self, up: Upstream, interval: float, stop) -> None:
        import asyncio

        # 错开启动，避免同时打满
        await asyncio.sleep(0.2 + 0.1 * list(self.upstreams).index(up.name))
        while not stop.is_set():
            await up.probe()
            try:
                await asyncio.wait_for(stop.wait(), interval)
            except asyncio.TimeoutError:
                continue

    def snapshot(self) -> list[dict]:
        return [up.describe() for up in self.upstreams.values()]


def _order(members: list[Upstream], kind: str) -> list[Upstream]:
    now = time.monotonic()

    def healthy(up: Upstream) -> bool:
        return up.healthy and up.blocked_until <= now

    if kind == "fallback":
        return sorted(members, key=lambda u: (0 if healthy(u) else 1, members.index(u)))
    return sorted(
        members,
        key=lambda u: (
            0 if healthy(u) else 1,
            u.latency if u.latency is not None else 999.0,
            members.index(u),
        ),
    )
