#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""采集 histlens 真实输出：沙箱演示历史库 6 组 + 真机聚合 1 组，存 /tmp/histlens-cap/*.txt。
演示库全部是合成内容（凭据用显眼合成串），真机只用 --aggregate 出统计数，不展示原始行。"""
import os
import random
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "histlens.py")
OUT = "/tmp/histlens-cap"
DEMO = os.path.join(OUT, "demo")
NOW = int(time.time())
DAY = 86400
os.makedirs(DEMO, exist_ok=True)

FAKE_GHP = "ghp_" + "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
FAKE_SK = "sk-" + "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
FAKE_DB = "a1b2c3d4e5f6a7b8"
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def run(tag, args, files):
    p = subprocess.run([sys.executable, TOOL] + files + args,
                       capture_output=True, timeout=120)
    txt = p.stdout.decode("utf-8", "replace")
    with open(os.path.join(OUT, tag + ".txt"), "w") as f:
        f.write(txt)
    print("== %s rc=%d ==" % (tag, p.returncode))
    print(txt)
    return txt


# ============================================================ 演示历史库
# 机器A「old-laptop」：zsh EXTENDED_HISTORY，800 天跨度，埋合成凭据+破坏性命令
rng = random.Random(20261125)
DAILY = ["git pull --rebase", "git status", "ls -la", "docker compose up -d",
         "docker ps", "npm run build", "python3 manage.py migrate", "cd ~/proj/api",
         "grep -rn TODO src/", "ssh deploy@staging-01", "tail -f app.log",
         "curl -s https://ci.internal/ping", "brew upgrade", "df -h", "htop",
         "make build && make test", "scp build.tar.gz deploy@staging-01:/tmp/"]
lines_a = []


def add_a(days_ago, hour, cmd, dur=0):
    ts = NOW - days_ago * DAY
    ts = ts - (ts % 3600) + hour * 3600 + rng.randint(0, 3300)
    lines_a.append(":%d:%d:%s" % (ts, dur, cmd))


# 800 天前：那条带着 token 的命令
add_a(800, 14, "export API_TOKEN=%s" % FAKE_GHP)
add_a(800, 14, "curl -s -H 'Authorization: Bearer %s' https://api.demo.internal/v1/me" % FAKE_SK)
add_a(799, 10, "git push origin main")
# 700 天前后：数据库密码进命令行、连接串带凭据
add_a(700, 15, "mysql -u report -p%s -h db.internal analytics < monthly.sql" % FAKE_DB)
add_a(690, 11, "git clone ssh://build:%s@git.demo.internal/team/repo.git" % FAKE_DB)
add_a(688, 16, "aws s3 sync ./dist s3://prod-assets/ --aws-access-key-id %s" % FAKE_AWS)
# 日常填充（约 300 条，其中 ~9% 落在 0-6 点）
for k in range(300):
    days = rng.randint(1, 680)
    hour = rng.choice([2, 3, 4]) if rng.random() < 0.09 else rng.randint(8, 23)
    add_a(days, hour, rng.choice(DAILY))
# sudo 习惯
for k in range(36):
    add_a(rng.randint(1, 660), rng.randint(9, 21), "sudo " + rng.choice(DAILY))
# 一条 5 连发的重试链（部署失败反复试，命令完全相同才构成链）
t0 = NOW - 40 * DAY
base_ts = t0 - (t0 % 3600) + 23 * 3600
for k in range(5):
    lines_a.append(":%d:%d:helm upgrade api ./chart" % (base_ts + k * 90, 0))
# 破坏性命令（演示目标都写成显眼的演示路径/合成值）
add_a(300, 2, "rm -rf /tmp/oldbuild cache/* --no-preserve-root")
add_a(299, 3, "dd if=backup.img of=/dev/disk5")
add_a(298, 15, "chmod -R 777 /srv/demo-share")
add_a(297, 15, "shutdown -h now")
add_a(250, 10, "mkfs.ext4 /dev/sdb9")
add_a(249, 10, "history -c && unset HISTFILE")

fa = os.path.join(DEMO, "old-laptop_hist")
with open(fa, "w", encoding="utf-8") as f:
    f.write("\n".join(lines_a) + "\n")

# 机器B「work-server」：bash 无时间戳（HISTTIMEFORMAT 缺失的真实常态）
lines_b = [
    "# work-server, HISTTIMEFORMAT not set",
    "ls -la", "git status", "docker ps", "cd /srv/api",
    "sudo systemctl restart api", "tail -n 200 app.log",
    "mysql -u backup -p%s dbcore < restore.sql" % FAKE_DB,
    "sshpass -p %s rsync -av logs/ ops@10.20.0.8:/logs/" % FAKE_DB,
    "curl -H \"Authorization: Basic %s\" https://gw.demo.internal/health" % ("dXNlcjpwYXNzd29yZA==" + "a1b2c3"),
    "docker compose down && docker compose up -d",
    "git pull", "git status", "htop", "df -h", "free -m",
    "curl -s https://ci.internal/ping", "ssh deploy@staging-01",
    "git pull", "docker ps", "df -h",
]
fb = os.path.join(DEMO, "work-server_hist")
with open(fb, "w", encoding="utf-8") as f:
    f.write("\n".join(lines_b) + "\n")

# ============================================================ 7 组采集
run("demo_scan", ["--top", "10"], [fa])                       # 1 全量判决
run("demo_redact", ["--top", "10", "--redact"], [fa])         # 2 半掩码
run("demo_profile", ["--top", "4"], [fa])                     # 3 画像（跟1同文件，截图取画像段）
run("demo_compare", ["--top", "4"], [fa, fb])                 # 4 跨机对比
base = os.path.join(DEMO, "allow.txt")
with open(base, "w") as f:
    f.write("# 已核可的命中（子串匹配）\nAPI_TOKEN=%s\nmysql -u report\n" % FAKE_GHP)
run("demo_baseline", ["--top", "10", "--baseline", base], [fa])   # 5 基线豁免
run("demo_aggregate", ["--aggregate"], [fa, fb])              # 6 聚合安全模式

# 7 真机：只读聚合统计，绝不展示原始命令行
real = os.path.expanduser("~/.zsh_history")
run("realmachine_aggregate", ["--aggregate", "--top", "4"], [real])

print("\nCAPTURED:", sorted(x for x in os.listdir(OUT) if x.endswith(".txt")))
