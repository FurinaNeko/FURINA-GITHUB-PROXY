"""预置规则集：GitHub / HuggingFace / 包管理器 / 常见开发站点。

这些域名在国内直连经常超时或被重置，统一交给 PROXY 组；
真实 IP 段用 no-resolve 直连判断，避免每个域名都去查一次 DNS。
"""

from __future__ import annotations

# ------------------------------------------------------------------ GitHub
GITHUB = [
    "DOMAIN-SUFFIX,github.com,PROXY",
    "DOMAIN-SUFFIX,githubusercontent.com,PROXY",
    "DOMAIN-SUFFIX,githubassets.com,PROXY",
    "DOMAIN-SUFFIX,github.io,PROXY",
    "DOMAIN-SUFFIX,github.dev,PROXY",
    "DOMAIN-SUFFIX,ghcr.io,PROXY",
    "DOMAIN-SUFFIX,gist.githubusercontent.com,PROXY",
    "DOMAIN,codeload.github.com,PROXY",
    "DOMAIN,objects.githubusercontent.com,PROXY",
    "DOMAIN,raw.githubusercontent.com,PROXY",
    "DOMAIN,avatars.githubusercontent.com,PROXY",
    "DOMAIN,uploads.github.com,PROXY",
    "DOMAIN,api.github.com,PROXY",
    "DOMAIN-SUFFIX,git-lfs.github.com,PROXY",
    "IP-CIDR,140.82.112.0/20,PROXY,no-resolve",
    "IP-CIDR,143.55.64.0/20,PROXY,no-resolve",
    "IP-CIDR,185.199.108.0/22,PROXY,no-resolve",
    "IP-CIDR,192.30.252.0/22,PROXY,no-resolve",
    "IP-CIDR,20.205.243.160/28,PROXY,no-resolve",
    "IP-CIDR6,2606:50c0::/32,PROXY,no-resolve",
]

# ------------------------------------------------------------------ HuggingFace
# 注意：真正耗流量的是 LFS / CDN / Xet 这几个域名，缺一个就会出现
# “模型页面能开、下载到 99% 卡住”或 “下载直接 403”。
HUGGINGFACE = [
    "DOMAIN-SUFFIX,huggingface.co,PROXY",
    "DOMAIN-SUFFIX,hf.co,PROXY",
    "DOMAIN-SUFFIX,hf.space,PROXY",
    "DOMAIN-SUFFIX,huggingface.space,PROXY",
    "DOMAIN,huggingface.co,PROXY",
    "DOMAIN,cdn-lfs.huggingface.co,PROXY",
    "DOMAIN,cdn-lfs-us-1.huggingface.co,PROXY",
    "DOMAIN,cdn-lfs-eu-1.huggingface.co,PROXY",
    "DOMAIN,cas-server.huggingface.co,PROXY",
    "DOMAIN,datasets-server.huggingface.co,PROXY",
    "DOMAIN,transfer.xethub.hf.co,PROXY",
    "DOMAIN,cas-bridge.xethub.hf.co,PROXY",
    "DOMAIN,xethub.hf.co,PROXY",
    "IP-CIDR,13.107.42.0/24,PROXY,no-resolve",
]

# ------------------------------------------------------------------ 其他常用开发资源
DEV_EXTRA = [
    "DOMAIN-SUFFIX,npmjs.org,PROXY",
    "DOMAIN-SUFFIX,npmjs.com,PROXY",
    "DOMAIN-SUFFIX,nodejs.org,PROXY",
    "DOMAIN-SUFFIX,yarnpkg.com,PROXY",
    "DOMAIN-SUFFIX,pypi.org,PROXY",
    "DOMAIN-SUFFIX,pythonhosted.org,PROXY",
    "DOMAIN-SUFFIX,files.pythonhosted.org,PROXY",
    "DOMAIN-SUFFIX,rust-lang.org,PROXY",
    "DOMAIN-SUFFIX,crates.io,PROXY",
    "DOMAIN-SUFFIX,static.crates.io,PROXY",
    "DOMAIN-SUFFIX,docker.com,PROXY",
    "DOMAIN-SUFFIX,docker.io,PROXY",
    "DOMAIN-SUFFIX,dockerusercontent.com,PROXY",
    "DOMAIN,registry-1.docker.io,PROXY",
    "DOMAIN,auth.docker.io,PROXY",
    "DOMAIN,production.cloudflare.docker.com,PROXY",
    "DOMAIN-SUFFIX,gcr.io,PROXY",
    "DOMAIN-SUFFIX,quay.io,PROXY",
    "DOMAIN-SUFFIX,maven.org,PROXY",
    "DOMAIN-SUFFIX,repo1.maven.org,PROXY",
    "DOMAIN-SUFFIX,gradle.org,PROXY",
    "DOMAIN-SUFFIX,googleapis.com,PROXY",
    "DOMAIN-SUFFIX,gstatic.com,PROXY",
    "DOMAIN-SUFFIX,openai.com,PROXY",
    "DOMAIN-SUFFIX,anthropic.com,PROXY",
    "DOMAIN-SUFFIX,claude.ai,PROXY",
    "DOMAIN-SUFFIX,sourceforge.net,PROXY",
    "DOMAIN-SUFFIX,arxiv.org,PROXY",
]

# ------------------------------------------------------------------ 直连兜底
DIRECT_TAIL = [
    "DOMAIN-SUFFIX,cn,DIRECT",
    "DOMAIN-SUFFIX,aliyun.com,DIRECT",
    "DOMAIN-SUFFIX,aliyuncs.com,DIRECT",
    "DOMAIN-SUFFIX,tencent.com,DIRECT",
    "DOMAIN-SUFFIX,myqcloud.com,DIRECT",
    "DOMAIN-SUFFIX,bilibili.com,DIRECT",
    "DOMAIN-SUFFIX,taobao.com,DIRECT",
    "DOMAIN-SUFFIX,jd.com,DIRECT",
    "DOMAIN-SUFFIX,baidu.com,DIRECT",
    "DOMAIN-SUFFIX,qq.com,DIRECT",
    "DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
    "DOMAIN-SUFFIX,mirrors.ustc.edu.cn,DIRECT",
    "DOMAIN-SUFFIX,tuna.tsinghua.edu.cn,DIRECT",
    "DOMAIN-SUFFIX,hf-mirror.com,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "DST-PORT,22,DIRECT",
]

PRESETS: dict[str, list[str]] = {
    "github": GITHUB + DIRECT_TAIL + ["FINAL,DIRECT"],
    "huggingface": HUGGINGFACE + DIRECT_TAIL + ["FINAL,DIRECT"],
    # 推荐默认：GitHub + HuggingFace + 包管理器
    "dev": GITHUB + HUGGINGFACE + DEV_EXTRA + DIRECT_TAIL + ["FINAL,DIRECT"],
    # 全量走代理（除了内网与 .cn）
    "global": [
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "FINAL,PROXY",
    ],
}


def get(name: str) -> list[str]:
    key = (name or "dev").strip().lower()
    if key not in PRESETS:
        raise KeyError(f"未知预置规则集 {name!r}，可选：{', '.join(sorted(PRESETS))}")
    return list(PRESETS[key])


# ------------------------------------------------------------------ hosts 加速名单
# 这些域名建议写进 hosts 指到 127.0.0.1，由本机加速器接管。
# 只写真正需要绕的，别把 hf-mirror 之类的国内镜像也拖进来。
ACCEL_HOSTS = [
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "avatars.githubusercontent.com",
    "uploads.github.com",
    "github.githubassets.com",
    "collector.github.com",
    "alive.github.com",
    "pkg-containers.githubusercontent.com",
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "cdn-lfs-us-1.huggingface.co",
    "cdn-lfs-eu-1.huggingface.co",
    "cas-server.huggingface.co",
    "datasets-server.huggingface.co",
    "transfer.xethub.hf.co",
    "cas-bridge.xethub.hf.co",
    "hf.co",
    "files.pythonhosted.org",
    "registry.npmjs.org",
]
