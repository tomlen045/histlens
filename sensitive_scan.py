#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫仓：真实敏感信息必须零命中；合成 fixture 凭据单独列出供人工核对。"""
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/Users/len/CodeBuddy/dx/histlens"
REAL_PATTERNS = [
    ("corp-net-172.16", re.compile(r"172\.16\.\d+\.\d+")),
    ("corp-net-172.18", re.compile(r"172\.18\.\d+\.\d+")),
    ("corp-net-10.92", re.compile(r"10\.92\.\d+\.\d+")),
    ("gitee-token-32hex", re.compile(r"https://\w+:[a-f0-9]{32}@gitee\.com")),
    ("gitee-token-32hex-bare", re.compile(r"(?<![a-zA-Z0-9])[a-f0-9]{32}(?![a-zA-Z0-9])")),
    ("github-token-ghp", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("github-token-gho", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    ("github-token-github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("aws-akia", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("sk-long-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("private-key-body", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?!.*fixture)")),
    ("password-assignment", re.compile(r"(?i)\b(password|passwd)\b\s*[=:]\s*[\"'][^\"']{6,}[\"']")),
    ("bearer-real", re.compile(r"(?i)bearer\s+[A-Za-z0-9._~-]{24,}")),
    ("corp-hostname", re.compile(r"(?i)\b(maas|idc-|core-sw|gateway-\d)\b.*\.internal\b")),
]
# 已知合成串（显眼假值，允许出现在 fixture/演示库/selftest/capture 里）
SYNTHETIC_OK = {
    "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
    "a1b2c3d4e5f6a7b8",
    "AKIAIOSFODNN7EXAMPLE",
}
# 规则级豁免：(文件名, 规则名, 原因)
EXEMPT_RULES = {
    ("sensitive_scan.py", "corp-hostname"): "扫描器自身源码里的正则文本",
    ("selftest.py", "private-key-body"): "自测 fixture 的 PEM 块头（HL-01 检测目标，合成内容）",
    ("capture_outputs.py", "private-key-body"): "演示库生成器里的 PEM 块头（合成内容）",
}
SKIP_DIRS = {".git", "__pycache__", "node_modules"}
SKIP_EXT = {".png", ".jpg", ".gif", ".pyc", ".ttc", ".ico"}

real_hits = []
synth_hits = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if os.path.splitext(fn)[1].lower() in SKIP_EXT:
            continue
        p = os.path.join(dirpath, fn)
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for ln_no, ln in enumerate(txt.splitlines(), 1):
            for name, rx in REAL_PATTERNS:
                if (fn, name) in EXEMPT_RULES:
                    continue
                for m in rx.finditer(ln):
                    val = m.group(0)
                    if any(s in val for s in SYNTHETIC_OK) or any(s in ln for s in ("SYNTHETIC", "FAKE", "合成")):
                        synth_hits.append((p, ln_no, name, val[:44]))
                    else:
                        real_hits.append((p, ln_no, name, val[:44]))

print("== REAL sensitive hits (must be 0) ==")
for h in real_hits:
    print("  REAL", h)
print("REAL_HITS=%d" % len(real_hits))
print("== synthetic-marker hits (expected in fixtures/demos) ==")
for h in synth_hits[:12]:
    print("  synth", h)
print("SYNTH_HITS=%d" % len(synth_hits))
sys.exit(1 if real_hits else 0)
