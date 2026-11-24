"""项目元信息（应用名 / 作者 / GitHub 链接），供 UI、安装器、CLI 共用。

所有对外展示的名字、QQ、仓库地址都从 assets/about.json 读，
改一处全局生效；缺失时用下面的默认值兜住。
"""

from __future__ import annotations

import json
from pathlib import Path

from .icon import resource_path

DEFAULTS = {
    "name": "FURINA-GITHUB-PROXY",
    "display_name": "FURINA-GITHUB-PROXY",
    "version": "1.0.0",
    "tagline": "本地 SOCKS5 / HTTP 代理 · GitHub 与 HuggingFace 加速",
    "author": "FurinaNeko",
    "author_qq": "2252296536",
    "github_user": "FurinaNeko",
    "github_url": "https://github.com/FurinaNeko",
    "project_url": "https://github.com/FurinaNeko/FURINA-GITHUB-PROXY",
    "issues_url": "https://github.com/FurinaNeko/FURINA-GITHUB-PROXY/issues",
}


def load_about() -> dict:
    data = dict(DEFAULTS)
    path = resource_path("assets/about.json")
    try:
        if path.exists():
            data.update(json.loads(Path(path).read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001
        pass
    return data


ABOUT = load_about()
APP_NAME = ABOUT["name"]
APP_TITLE = ABOUT["display_name"]
AUTHOR_QQ = str(ABOUT["author_qq"])
GITHUB_URL = ABOUT["project_url"]
GITHUB_USER_URL = ABOUT["github_url"]
ISSUES_URL = ABOUT["issues_url"]
TAGLINE = ABOUT["tagline"]
