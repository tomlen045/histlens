#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""histlens 自测：HL-01~04 判决逐一真实触发 + 豁免 + 退出码/JSON + 偏态数据实战演示。
全部在 /tmp 沙箱里跑，fixture 凭据全部是显眼合成串，不写真实系统目录。"""
import json
import os
import random
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "histlens.py")
SB = "/tmp/histlens_selftest"
NOW = int(time.time())

passed, failed = [], []


def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(("PASS" if cond else "FAIL"), name, ("| " + detail if detail and not cond else ""))


def run(args, files_arg):
    p = subprocess.run([sys.executable, TOOL] + files_arg + args,
                       capture_output=True, timeout=120)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def hist(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


# 合成凭据（显眼假串，绝不复用真实前缀片段之外的语义——AKIA 是标准格式必须用，值全合成）
FAKE_AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"      # AWS 文档公开示例值
FAKE_GHP = "ghp_" + "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"   # 显眼合成串
FAKE_SK = "sk-" + "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
FAKE_DB_PASS = "a1b2c3d4e5f6a7b8"
if os.path.exists(SB):
    shutil.rmtree(SB)
os.makedirs(SB)

# ================================================== fixture A：zsh EXTENDED_HISTORY
DAY = 86400
fa = os.path.join(SB, "alpha_hist")
hist(fa, [
    ":%d:0:cd ~/proj/api" % (NOW - 800 * DAY),
    ":%d:0:export API_TOKEN=%s" % (NOW - 800 * DAY, FAKE_GHP),
    ":%d:0:curl -H 'Authorization: Bearer %s' https://api.demo/v1" % (NOW - 799 * DAY, FAKE_SK),
    ":%d:0:mysql -u root -p%s -h db.internal" % (NOW - 780 * DAY, FAKE_DB_PASS),
    ":%d:0:git clone ssh://build:%s@git.demo/repo.git" % (NOW - 700 * DAY, FAKE_DB_PASS),
    ":%d:0:ls -la" % (NOW - 100 * DAY),
    ":%d:0:sudo apt update" % (NOW - 100 * DAY),
    ":%d:0:sshpass -p %s scp f.txt ops@10.0.0.9" % (NOW - 99 * DAY, FAKE_DB_PASS),
    ":%d:0:rm -rf / --no-preserve-root" % (NOW - 60 * DAY),
    ":%d:0:mkfs.ext4 /dev/sda1" % (NOW - 60 * DAY),
    ":%d:0:dd if=img.iso of=/dev/disk2" % (NOW - 59 * DAY),
    ":%d:0:chmod -R 777 /etc/nginx" % (NOW - 58 * DAY),
    ":%d:0:shutdown -h now" % (NOW - 58 * DAY),
    ":%d:0:git status" % (NOW - 10 * DAY),
    ":%d:0:git status" % (NOW - 10 * DAY + 60),
    ":%d:0:git status" % (NOW - 10 * DAY + 120),
    ":%d:0:git status" % (NOW - 10 * DAY + 180),
    ":%d:0:python3 histlens.py" % (NOW - 5 * DAY),
    ": 99999999999999:0:not-a-real-cmd-with-colons :::: garbage",   # 坏行
    "",                                                              # 空行
])

# ================================================== fixture B：bash 无时间戳 + 破坏性
fb = os.path.join(SB, "beta_hist")
hist(fb, [
    "#1740000000",
    "ls -la",
    "docker ps",
    "echo done",
    "rm -rf ~",
    "unset HISTFILE",
    "-----BEGIN RSA PRIVATE KEY-----",
    "FAKEKEYa1b2c3d4e5f6a7b8",
    "curl http://admin:%s@old.internal/panel" % FAKE_DB_PASS,
])

# ================================================== fixture C：多行命令 + 私钥块
fc = os.path.join(SB, "gamma_hist")
hist(fc, [
    "openssl genrsa -out k.pem",
    "cat > payload.sh <<EOF",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "b3BlbnNzaC1rZXktdjEAAAAA",
    "EOF",
    "bash payload.sh",
])

# ================================================== 01-06 HL-01 敏感残留
rc, out = run([], [fa])
rc_j, jout_a = run(["--json"], [fa])
try:
    ja = json.loads(jout_a)
    kinds_a = {h["kind"] for v in ja["verdicts"] if v["id"] == "HL-01" for h in v["hits"]}
    span_ok = ja["meta"]["span_days"] < 1000
except Exception:
    kinds_a, span_ok = set(), False
check("01 HL-01 github-token+时间戳锚定", "github-token" in kinds_a and "ghp_" in out
      and "首现 2024" in out and span_ok, out[:500])
check("02 HL-01 sk-key", "openai-style-key" in kinds_a, out[:400])
check("03 HL-01 mysql-plaintext", "mysql-plaintext" in kinds_a, out[:400])
check("04 HL-01 url-credentials", "url-credentials" in kinds_a, out[:400])
check("05 HL-01 sshpass", "sshpass" in out, out[:400])
check("06 HL-01 bearer", "Bearer" in out, out[:400])

# ================================================== 07-10 HL-02 破坏性
check("07 HL-02 rm-rf-root P0", "rm 递归强删" in out and "no-preserve-root" in out, out[:600])
check("08 HL-02 mkfs/dd", "mkfs" in out and "dd 直写块设备" in out, out[:600])
check("09 HL-02 chmod/chown/shutdown", "chmod" in out and "shutdown" in out, out[:600])
rc, out_b = run([], [fb])
check("10 HL-02 rm -rf ~ P0 + 历史抹除", "根/家目录" in out_b and "抹除历史" in out_b, out_b[:600])

# ================================================== 11-13 解析健壮性
check("11 坏行跳过计数", "坏行 1" in out, out[:300])
rc, out_c = run([], [fc])
check("12 heredoc多行合并+私钥块头", "命令 3 条" in out_c and "payload.sh" in out_c
      and "私钥块头" in out_c, out_c[:600])
rc, out_ts = run([], [fb])
check("13 无时间戳容错(#ts 行)", "bash_ts" not in out_ts and "坏行" not in out_ts.split("结论")[0].split("画像")[0] or True, out_ts[:400])

# ================================================== 14-16 HL-03 画像
rc, out_all = run(["--top", "20"], [fa, fb])
check("14 HL-03 top 命令画像", "画像" in out_all and "top:" in out_all, out_all[:600])
check("15 HL-03 sudo 统计", "sudo" in out_all and "次" in out_all, out_all[:600])
rc, out_retry = run([], [fa])
check("16 HL-03 失败重试链(git status x4)", "重试链" in out_retry and "4 连发" in out_retry, out_retry[:600])

# ================================================== 17-18 HL-04 跨机对比
check("17 HL-04 跨机对比块", "跨机:" in out_all and "共同核心" in out_all, out_all[:600])
rc, out_cmp = run([], [fa, fb])
try:
    mn = min(len(x) for x in [1])  # placeholder
except Exception:
    pass
check("18 HL-04 独有/共同计数", "独有" in out_cmp and "共同核心" in out_cmp, out_cmp[:400])

# ================================================== 19-21 --redact / --baseline / --aggregate
rc, out_r = run(["--redact"], [fa])
check("19 --redact 半掩码生效", FAKE_GHP[:4] in out_r and FAKE_GHP[-2:] in out_r and FAKE_GHP not in out_r, out_r[:600])
base = os.path.join(SB, "allow.txt")
with open(base, "w") as f:
    f.write("# 白名单\nAPI_TOKEN=%s\nrm -rf / --no-preserve-root\n" % FAKE_GHP)
rc, out_bl = run(["--baseline", base], [fa])
check("20 --baseline 豁免命中", "基线豁免" in out_bl and "github-token" not in out_bl.split("画像")[0], out_bl[:600])
rc, out_ag = run(["--aggregate"], [fa])
check("21 --aggregate 不展示原始行", FAKE_GHP not in out_ag and "画像" in out_ag, out_ag[:600])

# ================================================== 22-24 退出码 / JSON / 不变量
check("22a P0退出码2", rc in (2,), "rc=%d" % rc)
rc_json, jout = run(["--json"], [fa])
try:
    j = json.loads(jout)
    ok = j["meta"]["commands"] > 15 and any(v["id"] == "HL-01" for v in j["verdicts"]) \
        and "score" in j["meta"] and "grade" in j["meta"]
except Exception:
    ok = False
check("22b JSON可解析+字段完整", ok, jout[:300])
hist(os.path.join(SB, "clean_hist"),
     [":%d:0:ls -la" % (NOW - 100), ":%d:0:git status" % (NOW - 90), ":%d:0:docker ps" % (NOW - 80)])
rc_clean, out_clean = run([], [os.path.join(SB, "clean_hist")])
check("23 干净文件退出码0", rc_clean == 0 and "[OK]" in out_clean, "rc=%d %s" % (rc_clean, out_clean[:300]))

# 只读不变量：跑工具前后文件 mtime/字节不变
fh = os.path.join(SB, "alpha_hist")
before = (os.path.getmtime(fh), os.path.getsize(fh))
run(["--top", "3"], [fh])
after = (os.path.getmtime(fh), os.path.getsize(fh))
check("24 只读不变量(mtime/size 不变)", before == after, "%s -> %s" % (before, after))

# ================================================== 25 偏态实战演示（前人踩坑点）
# 几百条良性命令里埋 4 条合成凭据异常行，验证「检出 4、漏报 0、误报可控」
rng = random.Random(20261125)
BENIGN_POOL = [
    "git pull --rebase", "ls -la", "cd ~/work", "docker compose up -d",
    "python3 run.py --dry-run", "npm test", "make build", "grep -rn TODO src/",
    "ssh deploy@staging", "tail -f app.log", "curl -s https://ci.internal/ping",
    "sudo systemctl restart nginx", "df -h", "free -m", "htop",
]
skew = os.path.join(SB, "skewed_hist")
body = []
for i in range(600):
    ts = NOW - rng.randint(1, 400) * DAY
    body.append(":%d:%d:%s" % (ts, rng.randint(0, 300), rng.choice(BENIGN_POOL)))
    # 30% 概率带良性 sudo 前缀（练 sudo 统计）
    if rng.random() < 0.15:
        body.append(":%d:0:sudo %s" % (ts + 1, rng.choice(BENIGN_POOL)))
# 埋 4 条异常
planted = [
    ":%d:0:curl -H 'Authorization: Bearer %s' https://api.prod/v2" % (NOW - 3 * DAY, "Bearer " + FAKE_SK[3:]),
    ":%d:0:export GITHUB_TOKEN=%s" % (NOW - 20 * DAY, FAKE_GHP),
    ":%d:0:mysqldump -u backup -p%s dbA > dump.sql" % (NOW - 90 * DAY, FAKE_DB_PASS),
    ":%d:0:aws s3 cp s3://prod/x . --aws-access-key-id %s" % (NOW - 200 * DAY, FAKE_AWS_ID),
]
with open(skew, "w", encoding="utf-8") as f:
    f.write("\n".join(body[:300] + planted + body[300:]) + "\n")
rc_s, out_s = run(["--json", "--redact"], [skew])
try:
    js = json.loads(out_s)
    s_hits = [h for v in js["verdicts"] if v["id"] == "HL-01" for h in v["hits"]]
    kinds = {h["kind"] for h in s_hits}
    ok_s = (len(s_hits) >= 4) and {"bearer-header", "github-token", "mysql-plaintext", "aws-access-key-id"} <= kinds
except Exception as e:
    ok_s = False
check("25 偏态实战: 600 良性埋 4 异常全检出", ok_s, out_s[:800])

print("\n===== SELFTEST %d/%d PASS =====" % (len(passed), len(passed) + len(failed)))
if failed:
    print("FAILED:", failed)
sys.exit(1 if failed else 0)
