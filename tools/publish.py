"""把本项目（且只有本项目）发布到 GitHub：源码树 + Release 安装包。

为什么要单独写：工作区里还有大量无关工程，直接 git push 会把 2 万个文件推上去；
而且远端仓库为空时 Git Data API 会返回 409，必须先用 Contents API 建首个提交。

用法：
    $env:GH_TOKEN = "ghp_xxx"
    python tools/publish.py --owner FurinaNeko --repo FURINA-GITHUB-PROXY \
        --release dist/FURINA-GITHUB-PROXY-Setup.exe
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

API = "https://api.github.com"
ROOT = Path(__file__).resolve().parent.parent
EXPORT = ROOT / "dist" / "repo-src"

# 只发布这些（相对仓库根目录的 glob）
INCLUDE = [
    "README.md", "LICENSE", ".gitignore",
    "localproxy.spec", "installer.spec", "run_localproxy.py",
    "localproxy/*.py",
    "installer/*.py",
    "tests/*.py", "tests/certs/*.pem",
    "scripts/*.ps1",
    "tools/make_icon.py", "tools/make_sponsor.py", "tools/probe_tls.py",
    "tools/shot_setup.py", "tools/publish.py",
    "assets/app.ico", "assets/app-256.png", "assets/app-32.png",
    "assets/app-sheet.png", "assets/about.json", "assets/i18n.json",
    "assets/sponsor-qr.png",
    "docs/*.png",
]

TEXT_SUFFIX = {".py", ".md", ".json", ".ps1", ".spec", ".txt", ".yml", ".yaml",
               ".gitignore", ".pem", ""}


def export() -> list[Path]:
    if EXPORT.exists():
        shutil.rmtree(EXPORT)
    EXPORT.mkdir(parents=True)
    copied: list[Path] = []
    for pattern in INCLUDE:
        for src in ROOT.glob(pattern):
            if not src.is_file():
                continue
            rel = src.relative_to(ROOT)
            dst = EXPORT / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(dst)
    return sorted(set(copied))


def api(method: str, url: str, token: str, payload=None, raw: bytes | None = None,
        ctype: str = "application/json", timeout: int = 120):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("User-Agent", "FurinaNeko-publish")
    req.add_header("Accept", "application/vnd.github+json")
    if data is not None:
        req.add_header("Content-Type", ctype)
    import time

    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return resp.status, (json.loads(body) if body else {})
        except urllib.error.HTTPError as exc:
            code = exc.code
            detail = exc.read().decode("utf-8", "replace")[:400]
            if code in (429, 500, 502, 503, 504) and attempt < 4:
                time.sleep(1.5 * (attempt + 1))   # 次级限流靠退避解决
                continue
            return code, {"error": detail}
        except Exception as exc:  # noqa: BLE001
            if attempt < 4:
                time.sleep(1.5 * (attempt + 1))
                continue
            return 0, {"error": str(exc)}
    return 0, {"error": "retry exhausted"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", default="FurinaNeko")
    parser.add_argument("--repo", default="FURINA-GITHUB-PROXY")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--release", default="dist/FURINA-GITHUB-PROXY-Setup.exe")
    parser.add_argument("--tag", default="v1.0.0")
    parser.add_argument("--skip-release", action="store_true")
    args = parser.parse_args(argv)

    token = os.environ.get("GH_TOKEN")
    if not token:
        print("缺少 GH_TOKEN", file=sys.stderr)
        return 2

    repo_api = f"{API}/repos/{args.owner}/{args.repo}"
    status, info = api("GET", repo_api, token)
    if status != 200:
        print(f"仓库不可用（{status}）：{info.get('error')}", file=sys.stderr)
        return 1
    print(f"repo: {info['html_url']}  size={info.get('size')}KB")

    files = export()
    print(f"导出 {len(files)} 个文件 -> {EXPORT}")

    # 1) 空仓库先用 Contents API 建首个提交
    status, head = api("GET", f"{repo_api}/git/ref/heads/{args.branch}", token)
    if status != 200:
        seed = EXPORT / "README.md"
        payload = {
            "message": "chore: bootstrap repository",
            "content": base64.b64encode(seed.read_bytes()).decode(),
            "branch": args.branch,
        }
        code, out = api("PUT", f"{repo_api}/contents/README.md", token, payload)
        if code not in (200, 201):
            print(f"首个提交失败：{code} {out}", file=sys.stderr)
            return 1
        print("已用 Contents API 建立 initial commit")

    # 2) 上传 blobs
    def blob(path: Path):
        rel = path.relative_to(EXPORT)
        payload = {"content": base64.b64encode(path.read_bytes()).decode(),
                   "encoding": "base64"}
        code, data = api("POST", f"{repo_api}/git/blobs", token, payload)
        if code not in (200, 201):
            raise RuntimeError(f"blob 失败 {rel}: {code} {data}")
        return rel, data["sha"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        blobs = dict(pool.map(blob, files))
    print(f"blobs: {len(blobs)}")

    # 3) 树 + 提交 + 更新分支
    tree = [{"path": rel.as_posix(), "mode": "100644", "type": "blob", "sha": sha}
            for rel, sha in blobs.items()]
    code, out = api("POST", f"{repo_api}/git/trees", token, {"tree": tree})
    if code not in (200, 201):
        print(f"tree 失败：{code} {out}", file=sys.stderr)
        return 1
    code, ref = api("GET", f"{repo_api}/git/ref/heads/{args.branch}", token)
    parents = [ref["object"]["sha"]] if code == 200 else []
    code, commit = api("POST", f"{repo_api}/git/commits", token, {
        "message": "feat: FURINA-GITHUB-PROXY 1.0.0\n\n"
                   "SOCKS5/HTTP local proxy, rule routing, DoH resolver, "
                   "trojan/http/socks5 upstreams, local-CA accelerator, "
                   "Tkinter UI (en/zh-CN/ja/ru), per-user installer.",
        "tree": out["sha"],
        "parents": parents,
    })
    if code not in (200, 201):
        print(f"commit 失败：{code} {commit}", file=sys.stderr)
        return 1
    if parents:
        code, upd = api("PATCH", f"{repo_api}/git/refs/heads/{args.branch}", token,
                        {"sha": commit["sha"], "force": True})
    else:
        code, upd = api("POST", f"{repo_api}/git/refs", token,
                        {"ref": f"refs/heads/{args.branch}", "sha": commit["sha"]})
    print(f"branch {args.branch}: {commit['sha'][:12]} (parents={len(parents)}) -> {code}")
    if code not in (200, 201):
        print(upd, file=sys.stderr)
        return 1

    # 4) Release + 安装包
    if args.skip_release:
        return 0
    asset = ROOT / args.release
    if not asset.exists():
        print(f"找不到安装包：{asset}", file=sys.stderr)
        return 1
    code, rel = api("GET", f"{repo_api}/releases/tags/{args.tag}", token)
    if code != 200:
        code, rel = api("POST", f"{repo_api}/releases", token, {
            "tag_name": args.tag,
            "name": f"FURINA-GITHUB-PROXY {args.tag}",
            "target_commitish": args.branch,
            "body": ("Windows installer — no Python required, per-user install.\n\n"
                     "- SOCKS5 + HTTP local proxy with rule routing\n"
                     "- GitHub / HuggingFace acceleration (local CA)\n"
                     "- UI: English by default · zh-CN / ja / ru\n"
                     "- Sponsor page (WeChat QR) · Author QQ 2252296536"),
        })
        if code not in (200, 201):
            print(f"release 失败：{code} {rel}", file=sys.stderr)
            return 1
    print(f"release: {rel['html_url']}")
    for old in rel.get("assets", []):
        if old["name"] == asset.name:
            api("DELETE", f"{repo_api}/releases/assets/{old['id']}", token)
    upload = (f"https://uploads.github.com/repos/{args.owner}/{args.repo}"
              f"/releases/{rel['id']}/assets?name={asset.name}")
    code, up = api("POST", upload, token, raw=asset.read_bytes(),
                   ctype="application/octet-stream", timeout=600)
    if code not in (200, 201):
        print(f"上传失败：{code} {up}", file=sys.stderr)
        return 1
    print(f"asset: {up['name']} {up['size']} bytes")
    print(f"download: {up['browser_download_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
