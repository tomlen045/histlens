#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实测文章内的安装命令：gitee raw curl -L 拉回真 Python 文件，比对字节数与语法。"""
import os
import py_compile
import subprocess
import sys

LOCAL = "/Users/len/CodeBuddy/dx/histlens/histlens.py"
TMP = "/tmp/hl_install_test.py"
url = "https://gitee.com/tomlen/histlens/raw/main/histlens.py"
code = subprocess.run(["curl", "-sL", "-o", TMP, "-w", "%{http_code}", "-m", "30", url],
                      capture_output=True, timeout=60).stdout.decode()
local_size = os.path.getsize(LOCAL)
dl_size = os.path.getsize(TMP)
head = open(TMP, encoding="utf-8", errors="replace").read(60)
is_py = head.startswith("#!")
try:
    py_compile.compile(TMP, doraise=True)
    syntax_ok = True
    msg = "syntax OK"
except py_compile.PyCompileError as e:
    syntax_ok = False
    msg = str(e)[:120]
print("http=%s local_bytes=%d downloaded_bytes=%d head=%r is_script=%s %s" %
      (code, local_size, dl_size, head[:24], is_py, msg))
print("INSTALL_CMD_OK=%s" % (code == "200" and dl_size == local_size and is_py and syntax_ok))
sys.exit(0 if (code == "200" and dl_size == local_size and is_py and syntax_ok) else 1)
