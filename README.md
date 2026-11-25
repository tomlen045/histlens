# histlens · shell 历史取证透镜

**你的 shell 历史文件里，躺着多少年没删的 token、没意识到 problem 的 rm -rf？**

porteye 管「谁在听」、authguard 管「谁想进来」、sudolens 管「谁能提权」、
pathlens 管「谁在替你执行」、cfgdrift 管「配置被谁改了」——
唯独没人管「这台机器实际跑过什么」。shell 历史是唯一自带完整执行记录的文件，
但几乎没人回头审计它。histlens 只读打开它，回答一个问题：

**这台机器实际跑过什么、留下了什么把柄。**

```
$ python3 histlens.py old-laptop_hist --redact
== histlens v1.0.0 — shell 历史取证透镜 ==
文件 1 份 | 命令 353 条(唯一 50) | 跨度 799 天 | 坏行 0 | 非UTF8字符 0

[HL-01] 敏感残留 (6)
  - P0 [old-laptop_hist:1] GitHub token (ghp_/gho_/ghu_/ghs_/ghr_) export API_TOKEN=ghp_…b8  首现 2024-09-17
  - P0 [old-laptop_hist:2] Bearer 长令牌 curl -s -H 'Authorization: ***' …  首现 2024-09-17
  …

[HL-02] 破坏性命令 (6)
  - P0 rm --no-preserve-root（解除删根保险）  首现 2026-01-29
  - P0 dd 直写块设备 of=/dev/disk5           首现 2026-01-30

画像: top: docker(45) git(41) python3(29)
     sudo 36 次(10.2%) | 夜行者指数 32% | 最长重试链 5 连发
结论: P0=8 P1=5 P2=0 | 风险分 100/100 等级[危]
退出码: 2
```

## 为什么盯 shell 历史

- 它是**唯一自带时间戳的完整执行记录**：端口快照只有当下，日志会被轮转，历史文件从装机攒到现在
- 攻击者和手滑的你自己，都会在里面对账：`export API_TOKEN=…` 躺 800 天没人发现
- 应急取证要回答「什么时候干的」——前提是历史里有时间戳（`EXTENDED_HISTORY`/`HISTTIMEFORMAT`）
- 离职交接、捡到二手机、接手祖传服务器：第一件事就该扫一遍历史

## 4 类判决（HL-01 ~ HL-04）

| 编号 | 判决 | 内容 |
|---|---|---|
| HL-01 | 敏感残留 | password/token/secret/api_key/AKIA/sk-/ghp_/Bearer 头/私钥块头/连接串带凭据/sshpass/mysql -p，命中报行号+首次出现时间 |
| HL-02 | 破坏性命令 | rm -rf 根/家、mkfs、dd of=/dev/、chmod -R 777、fork bomb、shutdown/reboot、抹除历史痕迹 |
| HL-03 | 习惯画像 | top 命令、sudo 频率、夜行者指数（0-6 点占比）、失败重试链（同命令连发≥3） |
| HL-04 | 跨机对比 | 两份以上历史文件的独有命令/共同核心——交接审计用 |

风险分 0-100 + 等级（低/中/高/危），退出码 0/1/2/3 直接接 cron。

## 解析能力

- `~/.zsh_history`：EXTENDED_HISTORY 时间戳格式（`: <ts>:<dur>;<cmd>`）与 `:<ts>:<dur>:0:<cmd>` 变体都认
- `~/.bash_history`：`#<unix_ts>` 行（HISTTIMEFORMAT 开启时）
- 完全无时间戳的文件：照常解析，画像里明确标注「取证能力受损」
- 多行命令（行尾 `\` 续行、heredoc 块）合并为一条
- 坏行跳过并计数、非 UTF-8 字符计数容错、跨机合并传多个文件即可

## 豁免与安全模式

```bash
# 白名单：每行一个子串，命中含该子串即豁免（手动兜底基线）
python3 histlens.py --baseline allow.txt

# 半掩码：凭据前 4 后 2 保留，中段全掩——报告要给人看，也别变成二次泄漏
python3 histlens.py --redact

# 聚合模式：只出统计数，不展示任何原始命令行——扫别人的机器/发群里的唯一正确姿势
python3 histlens.py --aggregate
```

**不变量**：只读绝不变更历史文件；坏行跳过并计数；非 UTF-8 容错；零第三方依赖。

## 接进 cron（退出码分级）

| 退出码 | 含义 |
|---|---|
| 0 | 干净：无 P0/P1 |
| 1 | 存在 P1 |
| 2 | 存在 P0（敏感凭据/破坏性命令） |
| 3 | 内部错误 |

```cron
# 每天 09:00 聚合巡检（不展示任何命令行），P0 即邮件
0 9 * * *  /usr/bin/python3 /opt/histlens/histlens.py --aggregate || echo "histlens: 需要人工过目" | mail -s "[histlens] $(hostname)" you@example.com
```

## 30 秒上手

```bash
git clone https://gitee.com/tomlen/histlens.git && cd histlens
python3 histlens.py                    # 自动找 ~/.zsh_history / ~/.bash_history
python3 histlens.py hist_a hist_b      # 两台机器的合并对比
python3 histlens.py --json             # 机器可读
```

零依赖，Python 3.8+，macOS / Linux / Windows 通用，单文件拷走就能跑。

## 自测

```bash
python3 selftest.py    # 26 项断言：HL-01~04 逐一真实触发 + 豁免/退出码/JSON/只读不变量
# ===== SELFTEST 26/26 PASS =====
# 第 25 项是偏态实战：600 条良性命令里埋 4 条合成凭据异常行，验证「检出 4、漏报 0」
```

## 一句大实话

histlens 管「已经跑过的命令留下了什么」这一个问题。它不删历史、不替你 Rotate 泄漏的 key——
看见之后，改密码、换 token、补 `EXTENDED_HISTORY`，扳手还得你自己抡。

## 哨兵套件 · 七面合璧

| 工具 | 管 | 回答的问题 |
|---|---|---|
| [porteye](https://gitee.com/tomlen/porteye) | 端口 | 谁在听？ |
| [authguard](https://gitee.com/tomlen/authguard) | 登录 | 谁想进来？ |
| [sudolens](https://gitee.com/tomlen/sudolens) | sudoers | 谁能提权？ |
| [pathlens](https://gitee.com/tomlen/pathlens) | PATH | 谁在替你执行？ |
| [cfgdrift](https://gitee.com/tomlen/cfgdrift) | 配置 | 配置被谁改了？ |
| [freshlens](https://gitee.com/tomlen/freshlens) | 文件 | 什么文件被动了？ |
| **histlens** | **shell 历史** | **这台机器实际跑过什么？** |

## License

MIT
