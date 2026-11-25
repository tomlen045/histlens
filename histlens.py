#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
histlens — shell 历史取证透镜 (v1.0.0)

哨兵套件第七面：porteye 管「谁在听」、authguard 管「谁想进来」、sudolens 管
「谁能提权」、pathlens 管「谁在替你执行」、cfgdrift 管「配置被谁改了」——
histlens 管「这台机器实际跑过什么」：shell 历史是唯一自带完整执行记录的文件，
但几乎没人回头审计它。这里躺着没删的 token、rm -rf 的手滑、深夜的操作习惯。

零依赖单文件，Python 3.8+，macOS / Linux / Windows 通用，拷走就能跑。

用法:
    python3 histlens.py                          # 自动找 ~/.zsh_history / ~/.bash_history
    python3 histlens.py hist_a hist_b            # 多份历史文件做跨机合并对比
    python3 histlens.py --redact                 # 命中串半掩码（前4后2）
    python3 histlens.py --baseline allow.txt     # 白名单（手动兜底基线）
    python3 histlens.py --aggregate              # 只出统计数，不展示任何原始命令行
    python3 histlens.py --json                   # 机器可读输出

退出码: 0 = 干净(无P0/P1)  1 = 存在P1  2 = 存在P0  3 = 内部错误

不变量: 只读绝不变更历史文件；坏行跳过并计数；非 UTF-8 容错；无第三方依赖。
"""
import argparse
import json
import os
import re
import sys
import time
import unicodedata

VERSION = "1.0.0"
NIGHT_START, NIGHT_END = 0, 6          # 夜行者时段 [0,6)
RETRY_GAP_MAX = 600                    # 重试链相邻两条最大间隔秒（有时间戳时）
RETRY_MIN = 3                          # 连续 N 次算一条重试链

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2}
SCORE_WEIGHT = {"P0": 18, "P1": 7, "P2": 2}

# ---------------------------------------------------------------- HL-01 敏感残留
# (kind, sev, compiled_regex, value_group_idx or None, 说明)
# value_group_idx 指向「凭据本体」捕获组，--redact 时按前4后2掩码
SENSITIVE_PATTERNS = [
    ("aws-access-key-id", "P0",
     re.compile(r"AKIA[0-9A-Z]{16}"), 0, "AWS Access Key ID"),
    ("aws-secret-key", "P0",
     re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[\"']?([^\s\"';&]{8,})", re.I), 1,
     "AWS Secret Access Key"),
    ("github-token", "P0",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0, "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)"),
    ("openai-style-key", "P0",
     re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 0, "sk- 开头长密钥（OpenAI/通用）"),
    ("private-key-block", "P0",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0, "私钥块头落进历史"),
    ("bearer-header", "P0",
     re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"), 0, "Bearer 长令牌"),
    ("url-credentials", "P0",
     re.compile(r"[a-z][a-z0-9+.-]{1,15}://[^\s/:@]{1,64}:([^\s/@]{4,64})@"), 1,
     "连接串内嵌 user:pass@"),
    ("sshpass-plaintext", "P0",
     re.compile(r"(?i)\bsshpass\s+-p\s*[\"']?([^\s\"']{4,})", re.I), 1, "sshpass 明文密码"),
    ("password-kw", "P1",
     re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[=:]\s*[\"']?([^\s\"';&$<{]{4,})", re.I), 2,
     "password 关键字赋值"),
    ("token-kw", "P1",
     re.compile(r"(?i)\b(token|secret|api[_-]?key|apikey|access[_-]?key|auth)\w*\s*[=:]\s*[\"']?([^\s\"';&$<{]{8,})", re.I), 2,
     "token/secret/api_key 关键字赋值"),
    ("mysql-plaintext", "P1",
     re.compile(r"(?i)\b(mysql|mysqldump)\b[^\n;]*\s(-p|--password[= ])\s*[\"']?([^\s\"';]{4,})"), 3,
     "mysql 命令行明文密码"),
    ("authorization-header", "P1",
     re.compile(r"(?i)[\"']?authorization[\"']?\s*[=:]\s*[\"']?([^\s\"';]{12,})"), 1,
     "Authorization 头"),
]

# 占位符值不算命中（环境变量引用/模板/重定向到 stdin 等良好习惯）
BENIGN_VALUE_RE = re.compile(
    r"^($|\$|\$\{|<|\{\{|\?|stdin|env|prompt|askpass|-)$", re.I)

# ---------------------------------------------------------------- HL-02 破坏性命令
DESTRUCTIVE_PATTERNS = [
    ("no-preserve-root", "P0",
     re.compile(r"(?i)--no-preserve-root"), None, "rm --no-preserve-root（解除删根保险）"),
    ("rm-rf-root", "P0",
     re.compile(r"(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\b(.*)"),
     None, "rm 递归强删"),
    ("mkfs", "P0",
     re.compile(r"(?i)\bmkfs(\.[a-z0-9]+)?\b"), None, "mkfs 格式化"),
    ("dd-to-device", "P0",
     re.compile(r"(?i)\bdd\b[^;|&]*\bof=/dev/"), None, "dd 直写块设备"),
    ("redirect-device", "P0",
     re.compile(r">\s*/dev/(sd[a-z]|disk\d|hd[a-z])\b"), None, "重定向直写块设备"),
    ("fork-bomb", "P0",
     re.compile(r":\s*\(\s*\)\s*\{[^}]*\|\s*:[^}]*&[^}]*\}"), None, "fork 炸弹"),
    ("chmod-r-777", "P0",
     re.compile(r"(?i)\bchmod\s+-R\s+(777|[aug]*rwx[aug]*x*|o\+w|rwxrwxrwx)\b(.*)"),
     None, "chmod -R 全开"),
    ("chown-r-root", "P0",
     re.compile(r"(?i)\bchown\s+-R\b(.*)"), None, "chown -R 递归改属主"),
    ("power-event", "P1",
     re.compile(r"(?i)\b(shutdown|reboot|halt|poweroff)\b"), None, "关机/重启命令"),
    ("history-wipe", "P1",
     re.compile(r"(?i)\b(history\s+-c\b|unset\s+HISTFILE\b|export\s+HISTFILE\s*=/dev/null\b|"
                r"HISTSIZE\s*=\s*0\b|rm\s+[^;|&]*\.zsh_history|rm\s+[^;|&]*\.bash_history)"),
     None, "抹除历史记录痕迹"),
    ("rm-cwd-wild", "P1",
     re.compile(r"(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+[\"']?\*"),
     None, "rm 递归强删当前目录通配"),
]

RM_DANGEROUS_TARGETS = {"/", "/*", "~", "~/", "$HOME", "${HOME}", "/Users", "/Users/*",
                        "/root", "/root/*", ".", "..", "*", '"*"', "'*'", "~/.*"}
RM_P1_PREFIXES = ("/etc", "/usr", "/var", "/opt", "/boot", "/Library")
CHOWN_DANGEROUS = {"/", "~", "$HOME", "${HOME}", "/Users", "/root"}


# ================================================================ 解析
def decode_file(path):
    """读文件 → (文本, replacement_chars)。非 UTF-8 容错。"""
    with open(path, "rb") as f:
        raw = f.read()
    txt = raw.decode("utf-8", "replace")
    bad = txt.count("\ufffd")
    return txt.replace("\r\n", "\n").replace("\r", "\n"), bad


# 兼容两种扩展格式：zsh 真实格式 ": <ts>:<dur>;<cmd>" 与规格格式 ":<ts>:<dur>:0:<cmd>"
# 中段可选字段只允许纯数字（时长/序号），防止把命令里的冒号吃进前缀
ZSH_EXT_RE = re.compile(r"^:\s*(\d+):(\d+)[:;](?:\d{1,12}[:;])?")
BASH_TS_RE = re.compile(r"^#(\d{9,11})$")
TS_MIN = 631152000                      # 1990-01-01：早于此视为坏时间戳
TS_MAX_SLACK = 365 * 86400              # 允许未来 1 年内的时钟偏差


HEREDOC_RE = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")


def parse_history(path):
    """解析一份历史文件。返回 dict：
    file/commands/[{cmd,ts,lineno}]/skipped/nonutf8/zsh_ext/bash_ts/plain。
    坏行跳过并计数；heredoc 块合并为一条命令；时间戳做合理性校验。"""
    txt, bad = decode_file(path)
    lines = txt.split("\n")
    cmds = []
    skipped = 0
    zsh_ext = bash_ts = 0
    pending_ts = None
    buf = None          # 多行命令缓冲 [cmd, ts, start_lineno]
    i = 0               # 0-based 游标
    n = len(lines)
    while i < n:
        line = lines[i]
        ln = i + 1      # 1-based 行号
        if buf is not None:
            piece = line
            m = ZSH_EXT_RE.match(piece)
            if m:
                piece = piece[m.end():]
            cont = piece.endswith("\\")
            if cont:
                piece = piece[:-1]
            buf[0] += piece
            if not cont:
                cmds.append({"cmd": buf[0], "ts": buf[1], "lineno": buf[2]})
                buf = None
            i += 1
            continue
        if line.strip() == "":
            i += 1
            continue
        m = ZSH_EXT_RE.match(line)
        if m:
            ts = int(m.group(1))
            if ts < TS_MIN or ts > time.time() + TS_MAX_SLACK:
                skipped += 1        # 时间戳荒诞（坏行）
                i += 1
                continue
            zsh_ext += 1
            body = line[m.end():]
            if body.endswith("\\"):
                buf = [body[:-1], ts, ln]
            elif body.strip():
                cmds.append({"cmd": body, "ts": ts, "lineno": ln})
            else:
                skipped += 1
            i += 1
            continue
        if line.startswith(":"):
            skipped += 1        # 扩展格式但时间戳非数字 → 坏行
            i += 1
            continue
        m = BASH_TS_RE.match(line)
        if m:
            bash_ts += 1
            pending_ts = int(m.group(1))
            i += 1
            continue
        if line.startswith("#"):
            skipped += 1        # 非时间戳注释行 → 跳过不当作命令
            i += 1
            continue
        # 普通命令行
        cont = line.endswith("\\")
        body = line[:-1] if cont else line
        ts = pending_ts
        pending_ts = None
        # heredoc 块合并：<<终结符 出现时，把后续行（含私钥块等）并入同一条命令
        hm = HEREDOC_RE.search(body)
        if hm:
            term = hm.group(1)
            j = i + 1
            while j < n and lines[j].strip() != term:
                j += 1
            end = j if j < n else n     # 找不到终结符：吞到文件尾
            merged = [body] + lines[i + 1:end + (1 if j < n else 0)]
            cmds.append({"cmd": "\n".join(merged), "ts": ts, "lineno": ln})
            skipped += end - i          # 被并入的行不计为命令
            i = end + 1
            continue
        if cont:
            buf = [body, ts, ln]
        elif body.strip():
            cmds.append({"cmd": body, "ts": ts, "lineno": ln})
        else:
            skipped += 1
        i += 1
    if buf is not None:
        cmds.append({"cmd": buf[0], "ts": buf[1], "lineno": buf[2]})
    return {
        "file": path,
        "commands": cmds,
        "skipped": skipped,
        "nonutf8": bad,
        "total_lines": n,
        "zsh_ext": zsh_ext,
        "bash_ts": bash_ts,
        "plain": len(cmds) - zsh_ext,
    }


def default_history_files():
    out = []
    for name in (".zsh_history", ".bash_history"):
        p = os.path.join(os.path.expanduser("~"), name)
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            out.append(p)
    return out


# ================================================================ 掩码
def mask_value(v):
    if len(v) <= 8:
        return "*" * max(len(v), 4)
    return v[:4] + "…" + v[-2:]


def redact_line(line):
    """对整行里所有敏感 value 组做前4后2掩码。"""
    spans = []
    for _kind, _sev, rx, gidx, _label in SENSITIVE_PATTERNS:
        if gidx is None:
            continue
        for m in rx.finditer(line):
            try:
                s, e = m.span(gidx)
            except Exception:
                continue
            if e > s:
                spans.append((s, e))
    if not spans:
        return line
    spans.sort()
    out, pos = [], 0
    for s, e in spans:
        if s < pos:
            continue
        out.append(line[pos:s])
        out.append(mask_value(line[s:e]))
        pos = e
    out.append(line[pos:])
    return "".join(out)


def value_ok(v):
    """占位符/环境变量引用不算真凭据。"""
    return not BENIGN_VALUE_RE.match(v or "")


# ================================================================ 检测
def scan_sensitive(cmd_rec, fname):
    """HL-01：返回 hits [{sev,kind,label,value}]。"""
    hits = []
    seen_spans = set()
    for kind, sev, rx, gidx, label in SENSITIVE_PATTERNS:
        for m in rx.finditer(cmd_rec["cmd"]):
            if gidx is not None:
                try:
                    val = m.group(gidx)
                except Exception:
                    val = None
                if not value_ok(val):
                    continue
                span = m.span(gidx)
                if span in seen_spans:
                    continue
                seen_spans.add(span)
            hits.append({"sev": sev, "kind": kind, "label": label,
                         "value": m.group(0) if gidx is None else val})
    return hits


def rm_target_severity(rest):
    """rm -rf 目标分析：根/家 → P0；系统目录 → P1；其余不在此报。"""
    toks = rest.split()
    for t in toks:
        tt = t.strip("'\"")
        if tt in RM_DANGEROUS_TARGETS or tt.startswith(("~/", "$HOME", "${HOME}", "/Users/", "/root/")) \
                or tt in ("/",):
            return "P0"
    for t in toks:
        tt = t.strip("'\"")
        if any(tt.startswith(p) for p in RM_P1_PREFIXES):
            return "P1"
    return None


def scan_destructive(cmd_rec):
    """HL-02：返回 hits [{sev,kind,label}]。"""
    cmd = cmd_rec["cmd"]
    hits = []
    for kind, sev, rx, _g, label in DESTRUCTIVE_PATTERNS:
        m = rx.search(cmd)
        if not m:
            continue
        if kind == "rm-rf-root":
            sev2 = rm_target_severity(m.group(2))
            if sev2 is None:
                continue
            hits.append({"sev": sev2, "kind": kind, "label": "rm 递归强删（目标=%s）" %
                         ("根/家目录" if sev2 == "P0" else "系统目录")})
            continue
        if kind == "chmod-r-777":
            rest = m.group(2)
            toks = rest.split()
            tgt = next((t for t in toks if not t.startswith("-")), "")
            tgt = tgt.strip("'\"")
            if tgt in CHOWN_DANGEROUS or tgt.startswith(("~", "$HOME", "${HOME}", "/Users", "/root")):
                hits.append({"sev": "P0", "kind": kind, "label": "chmod -R 全开（目标=根/家目录）"})
            else:
                hits.append({"sev": "P1", "kind": "chmod-r-wide", "label": "chmod -R 全开（目标=%s）" % (tgt or "当前目录")})
            continue
        if kind == "chown-r-root":
            rest = m.group(1)
            toks = rest.split()
            tgt = toks[-1].strip("'\"") if toks else ""
            if tgt in CHOWN_DANGEROUS or tgt.startswith(("~", "$HOME", "${HOME}", "/Users", "/root")):
                hits.append({"sev": "P0", "kind": kind, "label": "chown -R（目标=根/家目录）"})
            continue
        hits.append({"sev": sev, "kind": kind, "label": label})
    return hits


def first_word(cmd):
    w = cmd.strip().split()
    if not w:
        return ""
    if w[0] in ("sudo", "doas") and len(w) > 1:
        return w[1]
    return w[0]


def norm_cmd(cmd):
    return " ".join(cmd.strip().split())


# ================================================================ 主扫描
def scan(files, opts):
    parsed = [parse_history(p) for p in files]
    verdicts = []

    def add(v_id, sev, title, hit):
        for v in verdicts:
            if v["id"] == v_id:
                v["hits"].append(hit)
                return
        verdicts.append({"id": v_id, "sev": sev, "title": title, "hits": [hit]})

    baseline = []
    if opts.baseline:
        try:
            with open(opts.baseline, encoding="utf-8", errors="replace") as f:
                baseline = [ln.strip() for ln in f
                            if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            print("警告: 基线读取失败 %s" % e, file=sys.stderr)

    all_cmd_count = 0
    unique_set = set()
    p0 = p1 = p2 = 0
    exempt_count = 0
    tmin = tmax = None
    no_ts_count = 0

    profile = {
        "top_cmds": [], "sudo_count": 0, "sudo_share": 0.0,
        "night_count": 0, "night_share": None, "retry_chains": [],
        "active_days": None,
    }
    compare = None

    for res in parsed:
        fname = os.path.basename(res["file"])
        prev_cmd, prev_ts, chain_len, chain_start = None, None, 0, None
        for rec in res["commands"]:
            all_cmd_count += 1
            unique_set.add(norm_cmd(rec["cmd"]))
            ts = rec.get("ts")
            if ts is None:
                no_ts_count += 1
            else:
                tmin = ts if tmin is None else min(tmin, ts)
                tmax = ts if tmax is None else max(tmax, ts)

            # ---- HL-01 / HL-02 检测
            hits1 = scan_sensitive(rec, fname)
            hits2 = scan_destructive(rec)
            for h in hits1 + hits2:
                if baseline and any(b in rec["cmd"] for b in baseline):
                    exempt_count += 1
                    continue
                if h["sev"] == "P0":
                    p0 += 1
                elif h["sev"] == "P1":
                    p1 += 1
                vid = "HL-01" if h in hits1 else "HL-02"
                add(vid, "P0", "敏感残留" if vid == "HL-01" else "破坏性命令",
                    {"sev": h["sev"], "file": fname, "lineno": rec["lineno"],
                     "ts": ts, "kind": h["kind"], "label": h["label"],
                     "cmd": rec["cmd"]})

            # ---- HL-03 画像
            fw = first_word(rec["cmd"])
            if fw:
                profile["top_cmds"].append(fw)
            if re.match(r"^(sudo|doas)\b", rec["cmd"].strip()):
                profile["sudo_count"] += 1
            if ts is not None:
                hour = time.localtime(ts).tm_hour
                if NIGHT_START <= hour < NIGHT_END:
                    profile["night_count"] += 1
            nc = norm_cmd(rec["cmd"])
            gap_ok = (prev_ts is not None and ts is not None
                      and 0 <= ts - prev_ts <= RETRY_GAP_MAX) or (ts is None and prev_ts is not None and ts is None)
            if nc == prev_cmd and gap_ok:
                chain_len += 1
            else:
                if chain_len >= RETRY_MIN and prev_cmd:
                    label = "同一命令最多 %d 连发" % chain_len
                    if not opts.aggregate:
                        label += ": %s" % prev_cmd[:60]
                    profile["retry_chains"].append(
                        {"cmd": prev_cmd if not opts.aggregate else "(聚合模式隐藏)",
                         "count": chain_len, "file": fname, "start_ts": chain_start})
                chain_len = 1
                chain_start = ts
            prev_cmd, prev_ts = nc, ts
        if chain_len >= RETRY_MIN and prev_cmd:
            profile["retry_chains"].append(
                {"cmd": prev_cmd, "count": chain_len, "file": fname, "start_ts": chain_start})

    # ---- HL-03 汇总
    if all_cmd_count:
        cnt = {}
        for w in profile["top_cmds"]:
            cnt[w] = cnt.get(w, 0) + 1
        profile["top_cmds"] = sorted(cnt.items(), key=lambda kv: -kv[1])
        profile["sudo_share"] = profile["sudo_count"] * 100.0 / all_cmd_count
        ts_total = all_cmd_count - no_ts_count
        profile["night_share"] = (profile["night_count"] * 100.0 / ts_total) if ts_total else None
        if tmin and tmax:
            profile["active_days"] = int((tmax - tmin) / 86400) + 1
        if profile["retry_chains"]:
            profile["retry_chains"].sort(key=lambda c: -c["count"])
            add("HL-03", "P2", "习惯画像：失败重试链",
                {"sev": "P2", "label": "同一命令最多 %d 连发" %
                 profile["retry_chains"][0]["count"] +
                 ("" if opts.aggregate else ": %s" % profile["retry_chains"][0]["cmd"][:60]),
                 "count": len(profile["retry_chains"])})
        if profile["night_share"] is not None and profile["night_share"] >= 30:
            add("HL-03", "P2", "习惯画像：夜行者指数偏高",
                {"sev": "P2", "label": "深夜(0-6点)命令占比 %.0f%%" % profile["night_share"],
                 "count": profile["night_count"]})
        if no_ts_count * 2 > all_cmd_count and all_cmd_count:
            add("HL-03", "P2", "习惯画像：时间戳缺失（取证能力受损）",
                {"sev": "P2", "label": "%d/%d 条命令没有时间戳，出事时无法定位时间" %
                 (no_ts_count, all_cmd_count), "count": no_ts_count})

    # ---- HL-04 跨机对比
    if len(parsed) >= 2:
        sets = []
        for res in parsed:
            s = {norm_cmd(c["cmd"]) for c in res["commands"]}
            sets.append(s)
        common = set.intersection(*sets)
        compare = {"files": [os.path.basename(r["file"]) for r in parsed],
                   "totals": [len(r["commands"]) for r in parsed],
                   "uniques": [len(s - common) for s in sets],
                   "common": len(common),
                   "common_top": []}
        if common:
            freq = {}
            for res in parsed:
                seen = set()
                for c in res["commands"]:
                    nc = norm_cmd(c["cmd"])
                    if nc in common and nc not in seen:
                        seen.add(nc)
            compare["common_top"] = sorted(common)[:0]  # 占位，展示在 render 阶段抽样
        add("HL-04", "P2", "跨机对比",
            {"sev": "P2", "label": "共同核心 %d 条 | " % compare["common"] +
             " | ".join("%s 独有 %d" % (f, u) for f, u in zip(compare["files"], compare["uniques"])),
             "count": compare["common"]})

    verdicts.sort(key=lambda v: (min(SEV_ORDER[h["sev"]] for h in v["hits"]), v["id"]))
    score = min(100, p0 * SCORE_WEIGHT["P0"] + p1 * SCORE_WEIGHT["P1"] + p2 * SCORE_WEIGHT["P2"])
    grade = ("低" if score <= 14 else "中" if score <= 39 else "高" if score <= 69 else "危")
    meta = {
        "version": VERSION, "files": [os.path.basename(f) for f in files],
        "commands": all_cmd_count, "unique": len(unique_set),
        "no_ts": no_ts_count, "skipped": sum(r["skipped"] for r in parsed),
        "nonutf8": sum(r["nonutf8"] for r in parsed),
        "span_days": profile["active_days"],
        "first_ts": tmin, "last_ts": tmax,
        "p0": p0, "p1": p1, "p2": p2, "exempt": exempt_count,
        "score": score, "grade": grade,
        "scan_ts": time.time(),
    }
    return {"meta": meta, "verdicts": verdicts, "profile": profile,
            "compare": compare, "parsed": parsed}


# ================================================================ 输出
def fmt_ts(ts):
    if ts is None:
        return "无时间戳"
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def render(res, opts):
    m = res["meta"]
    lines = []
    lines.append("== histlens v%s — shell 历史取证透镜 ==" % VERSION)
    span = ("%d 天" % m["span_days"]) if m["span_days"] is not None else "无时间戳"
    lines.append("文件 %d 份 | 命令 %d 条(唯一 %d) | 跨度 %s | 坏行 %d | 非UTF8字符 %d" %
                 (len(m["files"]), m["commands"], m["unique"], span,
                  m["skipped"], m["nonutf8"]))
    lines.append("")
    if not res["verdicts"]:
        lines.append("[OK] 未发现敏感残留或破坏性命令。")
    for v in res["verdicts"]:
        hs = sorted(v["hits"], key=lambda h: SEV_ORDER[h["sev"]])
        lines.append("[%s] %s (%d)" % (v["id"], v["title"], len(hs)))
        show = hs if len(hs) <= opts.top else hs[:opts.top]
        for h in show:
            if v["id"] == "HL-01":
                if opts.aggregate:
                    lines.append("  - %s [%s:%d] %s  首现 %s" %
                                 (h["sev"], h["file"], h["lineno"], h["label"], fmt_ts(h.get("ts"))))
                else:
                    cmd = redact_line(h["cmd"]) if opts.redact else h["cmd"]
                    lines.append("  - %s [%s:%d] %s %s  首现 %s" %
                                 (h["sev"], h["file"], h["lineno"], h["label"],
                                  cmd[:88], fmt_ts(h.get("ts"))))
            elif v["id"] == "HL-02":
                if not opts.aggregate:
                    cmd = redact_line(h["cmd"]) if opts.redact else h["cmd"]
                    lines.append("      > " + cmd[:96])
                lines.append("  - %s [%s:%d] %s  首现 %s" %
                             (h["sev"], h["file"], h["lineno"], h["label"], fmt_ts(h.get("ts"))))
            else:
                lines.append("  - %s %s" % (h["sev"], h["label"]))
        if len(hs) > opts.top:
            lines.append("  … 另有 %d 条未展示（--top 调整）" % (len(hs) - opts.top))
        lines.append("")
    p = res["profile"]
    if m["commands"]:
        top = " ".join("%s(%d)" % (w, c) for w, c in p["top_cmds"][:8])
        night = ("%.0f%%" % p["night_share"]) if p["night_share"] is not None else "无时间戳"
        chain = ("%d 连发" % p["retry_chains"][0]["count"]) if p["retry_chains"] else "无"
        lines.append("画像: top: %s" % (top or "无"))
        lines.append("     sudo %d 次(%.1f%%) | 夜行者指数 %s | 最长重试链 %s" %
                     (p["sudo_count"], p["sudo_share"], night, chain))
    if res["compare"]:
        c = res["compare"]
        lines.append("跨机: " + " | ".join(
            "%s %d 条(独有 %d)" % (f, t, u)
            for f, t, u in zip(c["files"], c["totals"], c["uniques"])) +
            " | 共同核心 %d 条" % c["common"])
    if m["exempt"]:
        lines.append("基线豁免: %d 条命中被 --baseline 覆盖" % m["exempt"])
    lines.append("结论: P0=%d P1=%d P2=%d | 风险分 %d/100 等级[%s]" %
                 (m["p0"], m["p1"], m["p2"], m["score"], m["grade"]))
    lines.append("退出码: %d" % exit_code(res))
    return "\n".join(lines)


def exit_code(res):
    m = res["meta"]
    if m["p0"]:
        return 2
    if m["p1"]:
        return 1
    return 0


def to_json(res):
    out = {"meta": res["meta"], "verdicts": [], "profile": {}}
    for v in res["verdicts"]:
        out["verdicts"].append({
            "id": v["id"], "title": v["title"],
            "hits": [{k: h.get(k) for k in ("sev", "file", "lineno", "ts", "kind", "label", "cmd", "count")}
                     for h in v["hits"]]})
    p = res["profile"]
    out["profile"] = {
        "top_cmds": p["top_cmds"][:15], "sudo_count": p["sudo_count"],
        "sudo_share": round(p["sudo_share"], 2),
        "night_share": None if p["night_share"] is None else round(p["night_share"], 2),
        "retry_chains": p["retry_chains"][:5],
    }
    if res["compare"]:
        out["compare"] = res["compare"]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="histlens",
        description="shell 历史取证透镜：敏感残留/破坏性命令/习惯画像/跨机对比")
    ap.add_argument("files", nargs="*", help="历史文件（可多份做跨机对比；默认自动找 ~/.zsh_history ~/.bash_history）")
    ap.add_argument("--redact", action="store_true", help="命中串半掩码（前4后2）")
    ap.add_argument("--baseline", default=None, help="白名单文件：每行一个子串，命中含该子串即豁免")
    ap.add_argument("--top", type=int, default=12, help="每个判决最多展示条数（默认12）")
    ap.add_argument("--aggregate", action="store_true", help="聚合模式：只出统计，不展示任何原始命令行")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--quiet", action="store_true", help="只给退出码")
    opts = ap.parse_args(argv)

    files = opts.files or default_history_files()
    if not files:
        print("未找到历史文件（试 histlens.py ~/.zsh_history）", file=sys.stderr)
        return 3
    for f in files:
        if not os.path.isfile(f):
            print("历史文件不存在: %s" % f, file=sys.stderr)
            return 3
    try:
        res = scan(files, opts)
        if opts.json:
            print(json.dumps(to_json(res), ensure_ascii=False, indent=1))
        elif not opts.quiet:
            print(render(res, opts))
        return exit_code(res)
    except Exception as e:  # 内部错误兜底
        if opts.json:
            print(json.dumps({"error": str(e)}, ensure_ascii=False))
        else:
            print("histlens 内部错误: %r" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
