#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""histlens 证据图：内容 100% 来自 /tmp/histlens-cap/*.txt 真实采集输出。1200x675。
含中文段路由黑体(STHeiti)、纯 ASCII 用 Menlo；色块行用 d.rectangle 自绘，不依赖 emoji。"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE, CYAN = ("#98c379", "#e6edf3", "#7f8794",
                                             "#e06c75", "#e5c07b", "#61afef", "#56b6c2")

_fc = {}


def F(size, mono):
    k = (size, mono)
    if k not in _fc:
        _fc[k] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[k]


def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·％【】▲…' for ch in t)


def shot(name, lines, title="histlens — zsh", footer=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57")
    d.ellipse([44, 15, 56, 27], fill="#febc2e")
    d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 70
    for item in lines:
        text, color, size, mono = item
        if text is None:            # 色块条（自绘，不用 emoji）
            d.rectangle([52, y, W - 52, y + size], fill=color)
            y += size + 14
            continue
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((52, y), text, font=font, fill=color)
        y += int(size * 1.62)
    if footer:
        d.rectangle([0, H - 52, W, H], fill=BAR)
        d.text((52, H - 40), footer, font=F(18, False), fill=GREY)
    img.save(os.path.join(OUT, name + ".png"))
    print(name, "OK")


# ── shot1 敏感残留（真实采集 demo_scan.txt，第 800 天那条）──
shot("shot1_secrets", [
    ("$ python3 histlens.py old-laptop_hist", GREY, 20, True),
    ("== histlens v1.0.0 — shell 历史取证透镜 ==", WHITE, 22, True),
    ("文件 1 份 | 命令 353 条(唯一 50) | 跨度 799 天 | 坏行 0 | 非UTF8字符 0", GREY, 20, True),
    ("", WHITE, 8, True),
    ("[HL-01] 敏感残留 (6)", RED, 24, True),
    ("  - P0 [old-laptop_hist:1] GitHub token  首现 2024-09-17", WHITE, 21, True),
    ("      > export API_TOKEN=ghp_a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8", WHITE, 21, True),
    ("  - P0 [old-laptop_hist:2] Bearer 长令牌 + sk- 密钥  首现 2024-09-17", WHITE, 21, True),
    ("  - P0 [:5] 连接串内嵌 user:pass@   [:6] AWS Access Key ID", WHITE, 21, True),
    ("  - P1 [:4] mysql 命令行明文密码  首现 2024-12-26", GOLD, 21, True),
    ("", WHITE, 10, True),
    ("结论: P0=8 P1=5 P2=0 | 风险分 100/100 等级[危]   退出码: 2", GREEN, 24, True),
], title="敏感残留取证 — histlens", footer="▲ 那句带着 token 的命令，在历史里躺了 800 天，一天都没少")

# ── shot2 --redact 半掩码（demo_redact.txt）──
shot("shot2_redact", [
    ("$ python3 histlens.py old-laptop_hist --redact", GREY, 20, True),
    ("[HL-01] 敏感残留 (6)", RED, 24, True),
    ("  - P0 export API_TOKEN=ghp_…b8", WHITE, 22, True),
    ("  - P0 curl -s -H 'Authorization: ***' https://api.demo.internal/v1/me", WHITE, 22, True),
    ("  - P0 git clone ssh://build:a1b2…b8@git.demo.internal/team/repo.git", WHITE, 22, True),
    ("  - P0 --aws-access-key-id AKIA…LE", WHITE, 22, True),
    ("  - P1 mysql -u report -pa1b2…b8 -h db.internal", GOLD, 22, True),
    ("", WHITE, 10, True),
    ("凭据前 4 后 2 保留，中段全掩：", GOLD, 21, False),
    ("证据链还在（能对上是哪条命令），密文不再二次泄露", GOLD, 21, False),
    ("", WHITE, 10, True),
    ("把报告贴进工单/群里之前，先加 --redact", WHITE, 21, False),
], title="--redact 半掩码模式 — histlens", footer="▲ 审计报告要给人看，也要防止报告本身变成泄漏源")

# ── shot3 破坏性命令（demo_scan.txt HL-02 段）──
shot("shot3_destructive", [
    ("$ python3 histlens.py old-laptop_hist", GREY, 20, True),
    ("[HL-02] 破坏性命令 (6)", RED, 24, True),
    ("  - P0 rm --no-preserve-root（解除删根保险）  首现 2026-01-29", WHITE, 21, True),
    ("      > rm -rf /tmp/oldbuild cache/* --no-preserve-root", WHITE, 21, True),
    ("  - P0 dd 直写块设备 of=/dev/disk5      首现 2026-01-30", WHITE, 21, True),
    ("  - P0 mkfs 格式化 /dev/sdb9            首现 2026-03-20", WHITE, 21, True),
    ("  - P1 chmod -R 全开 /srv/demo-share    首现 2026-02-01", GOLD, 21, True),
    ("  - P1 shutdown -h now   +P1 抹除历史记录痕迹", GOLD, 21, True),
    ("", WHITE, 10, True),
    ("每一条都带行号和首次出现时间——", GOLD, 21, False),
    ("事后取证时，「什么时候干的」和「干了什么」一样重要", GOLD, 21, False),
    ("", WHITE, 8, True),
    ("结论: P0=8 P1=5 P2=0 | 退出码: 2", GREEN, 24, True),
], title="破坏性命令点名 — histlens", footer="▲ rm -rf 手滑过的人不少，敢承认时间戳还在的不多")

# ── shot4 习惯画像（demo_profile.txt 画像段）──
shot("shot4_profile", [
    ("$ python3 histlens.py old-laptop_hist --top 4", GREY, 20, True),
    ("[HL-03] 习惯画像：夜行者指数偏高 (1)", GOLD, 24, True),
    ("  - P2 深夜(0-6点)命令占比 32%", WHITE, 22, True),
    ("", WHITE, 8, True),
    ("画像: top: docker(45) git(41) python3(29) ssh(25)", CYAN, 22, True),
    ("            make(22) grep(21) npm(20) tail(19)", CYAN, 22, True),
    ("     sudo 36 次(10.2%) | 夜行者指数 32% | 最长重试链 5 连发", CYAN, 22, True),
    ("", WHITE, 10, True),
    ("[HL-03] 习惯画像：失败重试链 (1)", GOLD, 22, True),
    ("  - P2 同一命令最多 5 连发: helm upgrade api ./chart", WHITE, 21, True),
    ("", WHITE, 10, True),
    ("凌晨 2-5 点的 32% 命令里，有一部分不需要发生", GOLD, 21, False),
    ("重试链是故障现场快照：连发 5 次的那条，就是当晚的火源", GOLD, 21, False),
], title="习惯画像 — histlens", footer="▲ 你的 shell 历史是一份行为档案：什么人、什么点、在修什么")

# ── shot5 跨机对比（demo_compare.txt HL-04 段）──
shot("shot5_compare", [
    ("$ python3 histlens.py old-laptop_hist work-server_hist", GREY, 20, True),
    ("文件 2 份 | 命令 373 条(唯一 59) | 跨度 799 天 | 坏行 1", GREY, 20, True),
    ("", WHITE, 8, True),
    ("[HL-04] 跨机对比 (1)", BLUE, 24, True),
    ("  - P2 共同核心 7 条 | old-laptop_hist 独有 39 | work-server_hist 独有 9", WHITE, 21, True),
    ("跨机: old-laptop_hist 353 条(独有 39) | work-server_hist 20 条(独有 9)", CYAN, 21, True),
    ("     | 共同核心 7 条", CYAN, 21, True),
    ("", WHITE, 10, True),
    ("[HL-01] 敏感残留 (8)：两台机器各有各的把柄", RED, 22, True),
    ("  - work-server: sshpass 明文密码 + mysql -p + Basic 头（P0/P1）", GOLD, 21, True),
    ("", WHITE, 10, True),
    ("交接审计：共同核心是标准动作，独有命令才要逐条过", GOLD, 21, False),
    ("结论: P0=9 P1=5 P2=0 | 退出码: 2", GREEN, 23, True),
], title="跨机对比 — histlens", footer="▲ 离职交接 / 捡到二手机 / 接手祖传服务器：两份历史一比，问题自己浮出来")

# ── shot6 真机聚合 + cron 接入（realmachine_aggregate.txt，只有统计数）──
shot("shot6_real_aggregate", [
    ("$ python3 histlens.py --aggregate        # 只读本机真实 ~/.zsh_history", GREY, 20, True),
    ("文件 1 份 | 命令 348 条(唯一 170) | 跨度 无时间戳 | 坏行 2 | 非UTF8字符 201", WHITE, 21, True),
    ("", WHITE, 8, True),
    ("[HL-01] 敏感残留 (2)", RED, 24, True),
    ("  - P0 sk- 开头长密钥 ×2 （聚合模式只报行号，不展示命令）", WHITE, 21, True),
    ("[HL-02] 破坏性命令 (2)", RED, 24, True),
    ("  - P0 rm 递归强删(根/家目录) ×1   P1 rm(系统目录) ×1", WHITE, 21, True),
    ("[HL-03] 时间戳缺失：348/348 条没有时间戳", GOLD, 22, True),
    ("画像: top: ping(78) claude(28) cd(23) hermes(17) bash(17) brew(10)", CYAN, 21, True),
    ("     sudo 11 次(3.2%) | 夜行者指数 无时间戳", CYAN, 21, True),
    ("结论: P0=3 P1=1 P2=0 | 风险分 61/100 等级[高]   退出码: 2", GREEN, 23, True),
    ("", WHITE, 8, True),
    ("cron 例：0 9 * * * python3 histlens.py --aggregate || 告警", GREY, 20, True),
], title="真机实扫（聚合安全模式） — histlens", footer="▲ 我自己的机器：2 行带 sk- 密钥的命令、1 次 rm 手滑、0 条时间戳")

print("DONE:", len([f for f in os.listdir(OUT) if f.endswith(".png")]), "shots ->", OUT)
