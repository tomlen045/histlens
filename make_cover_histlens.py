#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""900x383 公众号封面：对话钩子形态，白句+金句反驳，不晒星数。"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.expanduser("~/Desktop/histlens_cover.png")
W, H = 900, 383
CJK = "/System/Library/Fonts/STHeiti Medium.ttc"

img = Image.new("RGB", (W, H))
px = img.load()
c0 = (11, 14, 26)
c1 = (26, 15, 46)
for y in range(H):
    for x in range(W):
        t = x / W * 0.5 + y / H * 0.5
        px[x, y] = tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(3))
d = ImageDraw.Draw(img)

_fc = {}


def F(sz):
    if sz not in _fc:
        _fc[sz] = ImageFont.truetype(CJK, sz)
    return _fc[sz]


GOLD = (240, 180, 41)
WHITE = (235, 240, 245)
GREY = (139, 148, 158)
RED = (248, 81, 73)
DIM = (92, 99, 112)

# 栏目标签
d.text((48, 30), "小薅薅 · 自研安全工具", font=F(24), fill=GOLD)
d.text((48, 68), "Sentinel Suite · 07", font=F(16), fill=DIM)

# 左金竖条
d.rectangle([34, 100, 39, 218], fill=GOLD)

# 主钩子（对话形态：AI 说 vs 事实）
d.text((52, 96), "「应该修好了。」", font=F(42), fill=WHITE)
d.text((52, 158), "证据在 shell 历史里躺了 800 天。", font=F(40), fill=GOLD)

# 底部数据条（黑衬底）
d.rectangle([40, 252, 860, 292], fill=(0, 0, 0))
d.text((52, 258), "1 条命令扫全史 · 4 类判决 · 零依赖只读 · 退出码接 cron", font=F(24), fill=RED)

# 底部信息行
d.text((48, 312), "histlens · shell 历史取证透镜 · 哨兵套件第七件", font=F(20), fill=GREY)
d.text((48, 344), "gitee.com/tomlen/histlens", font=F(17), fill=DIM)

img.save(OUT)
print("OK", OUT, os.path.getsize(OUT))
