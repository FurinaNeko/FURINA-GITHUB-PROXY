"""把源图做成 Windows 多尺寸图标（assets/app.ico）。

用法：
    python tools/make_icon.py [源图] [输出目录]

要点：
  * 大尺寸用“头肩”构图，小尺寸（<=32px）改用脸部特写，否则缩到 16px 只剩一团粉。
  * 自己封装 ICO（PNG 载荷），这样每个尺寸可以用不同的裁剪与锐化参数；
    Pillow 自带的 ICO 保存只能从同一张图机械缩放。
  * 4 倍超采样画圆角遮罩，圆角边缘不发毛。

产物：
    assets/app.ico       16/20/24/32/40/48/64/96/128/256
    assets/app-256.png   预览大图
    assets/app-sheet.png 全尺寸放大对照表（人工验收用）
"""

from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "assets" / "icon-source.jpg"

SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
SMALL_MAX = 32

# 源图 286x300
HEAD_BOX = (33, 0, 269, 236)        # 头肩：含发夹、铃铛、手
FACE_BOX = (78, 26, 240, 188)       # 脸部特写：眼睛 + 嘴 + 少量粉色头发
RADIUS_RATIO = {"large": 0.20, "small": 0.16}


def rounded_alpha(size: int, ratio: float) -> Image.Image:
    ss = 4
    mask = Image.new("L", (size * ss, size * ss), 0)
    draw = ImageDraw.Draw(mask)
    radius = int(size * ss * ratio)
    draw.rounded_rectangle((0, 0, size * ss - 1, size * ss - 1), radius=radius, fill=255)
    return mask.resize((size, size), Image.LANCZOS)


def render(src: Image.Image, size: int) -> Image.Image:
    """按目标尺寸选裁剪框，输出带圆角透明通道的 RGBA 图。"""
    small = size <= SMALL_MAX
    box = FACE_BOX if small else HEAD_BOX
    crop = src.crop(box)
    # 小图先放大 8 倍再缩回去，等于做一次高质量重采样
    work = crop.resize((size * 8, size * 8), Image.LANCZOS)
    work = work.filter(
        ImageFilter.UnsharpMask(radius=2.2 if small else 1.6,
                                percent=140 if small else 100, threshold=1)
    )
    if small:
        work = ImageEnhance.Contrast(work).enhance(1.10)
        work = ImageEnhance.Color(work).enhance(1.08)
    out = work.resize((size, size), Image.LANCZOS).convert("RGBA")
    out.putalpha(rounded_alpha(size, RADIUS_RATIO["small" if small else "large"]))
    return out


def write_ico(frames: dict[int, Image.Image], path: Path) -> None:
    """写 PNG 载荷的 ICO（Vista 以后全支持，Explorer/任务栏渲染正常）。"""
    blobs: list[tuple[int, bytes]] = []
    for size in sorted(frames):
        buf = io.BytesIO()
        frames[size].save(buf, format="PNG", optimize=True)
        blobs.append((size, buf.getvalue()))

    header = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    entries = bytearray()
    for size, data in blobs:
        dim = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)
    path.write_bytes(header + bytes(entries) + b"".join(d for _, d in blobs))


def contact_sheet(frames: dict[int, Image.Image], path: Path, zoom: int = 4) -> None:
    """把各尺寸放大后排一行，方便肉眼检查小图是否还认得出。"""
    tiles = [frames[s] for s in SIZES if s <= 64] + [frames[256]]
    pad = 8
    width = sum(t.width * (zoom if t.width < 256 else 1) + pad for t in tiles) + pad
    height = max(t.height * (zoom if t.height < 256 else 1) for t in tiles) + pad * 2
    sheet = Image.new("RGB", (width, height), (250, 250, 252))
    x = pad
    for tile in tiles:
        scale = zoom if tile.width < 256 else 1
        big = tile.resize((tile.width * scale, tile.height * scale), Image.NEAREST)
        sheet.paste(big, (x, pad), big)
        x += big.width + pad
    sheet.save(path)


def build(src: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    img = Image.open(src).convert("RGB")
    if img.width < HEAD_BOX[2] or img.height < HEAD_BOX[3]:
        raise SystemExit(f"源图太小：{img.size}，至少需要 {HEAD_BOX[2]}x{HEAD_BOX[3]}")

    frames = {size: render(img, size) for size in SIZES}
    ico = out_dir / "app.ico"
    write_ico(frames, ico)
    frames[256].save(out_dir / "app-256.png")
    frames[32].resize((128, 128), Image.NEAREST).save(out_dir / "app-32.png")
    contact_sheet(frames, out_dir / "app-sheet.png")
    return {"ico": ico, "frames": frames}


def verify(ico: Path) -> list[int]:
    """独立读回 ICO 目录，确认尺寸齐全。"""
    data = ico.read_bytes()
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind) == (0, 1), "ICO 头不对"
    out = []
    for i in range(count):
        dim = data[6 + i * 16]
        out.append(256 if dim == 0 else dim)
    return out


def main(argv: list[str]) -> int:
    src = Path(argv[1]) if len(argv) > 1 else DEFAULT_SRC
    out_dir = Path(argv[2]) if len(argv) > 2 else ROOT / "assets"
    result = build(src, out_dir)
    sizes = verify(result["ico"])
    print(f"source   : {src}")
    print(f"ico      : {result['ico']}  {result['ico'].stat().st_size} bytes")
    print(f"sizes    : {sizes}")
    print(f"preview  : {out_dir / 'app-256.png'} , {out_dir / 'app-sheet.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
