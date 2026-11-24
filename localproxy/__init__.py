"""localproxy —— 纯标准库实现的本地代理（SOCKS5 + HTTP），支持多上游链路与规则分流。

设计目标：作为本机唯一代理入口，把 github.com / raw.githubusercontent.com 等流量
按规则送到可用的上游链路（HTTP 代理、SOCKS5、Trojan over TLS），其余流量直连。
"""

__version__ = "1.1.0"

NAME = "localproxy"
