#!/usr/bin/env python3
"""Render the CCC app icon -> crates/connector/assets/icon.png + icon.ico.
Usage: make-icon.py <font.ttf> <out_dir>"""
import sys
from PIL import Image, ImageDraw, ImageFont

font_path, out = sys.argv[1], sys.argv[2]
S = 1024  # draw large, downsample for smooth edges
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
# rounded square with a vertical gradient
top, bot = (52, 120, 246), (28, 64, 175)
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([24, 24, S - 24, S - 24], radius=210, fill=255)
grad = Image.new("RGBA", (S, S))
gd = ImageDraw.Draw(grad)
for y in range(S):
    t = y / (S - 1)
    gd.line([(0, y), (S, y)], fill=tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)) + (255,))
img.paste(grad, (0, 0), mask)
# "CCC" in white, fitted to ~78% width
text = "CCC"
size = 600
while True:
    f = ImageFont.truetype(font_path, size)
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    if r - l <= S * 0.78:
        break
    size -= 10
x = (S - (r - l)) / 2 - l
y = (S - (b - t)) / 2 - t
d.text((x, y), text, font=f, fill=(255, 255, 255, 255))
icon = img.resize((256, 256), Image.LANCZOS)
icon.save(f"{out}/icon.png")
icon.save(f"{out}/icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("ok", size)
