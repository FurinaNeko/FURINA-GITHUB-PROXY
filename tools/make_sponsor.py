from PIL import Image
from pathlib import Path

src = Image.open("assets/sponsor-source.png").convert("RGB")
print("source:", src.size)
# 裁掉外圈多余的绿边，保留“推荐使用微信支付 + 二维码 + 微信支付”三块
w, h = src.size
box = (int(w * 0.03), int(h * 0.02), int(w * 0.97), int(h * 0.98))
img = src.crop(box)
target_w = 640
img = img.resize((target_w, int(img.height * target_w / img.width)), Image.LANCZOS)
img.save("assets/sponsor-qr.png", optimize=True)
print("saved:", img.size, Path("assets/sponsor-qr.png").stat().st_size)
