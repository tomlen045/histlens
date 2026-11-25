# histlens 更新日志

## v1.0.0 (2026-11-25)

首个公开版本。

- HL-01 敏感残留扫描：12 类模式（AWS/AWS Secret/GitHub token/sk- 密钥/私钥块头/
  Bearer 头/连接串凭据/sshpass/password=/token=/mysql -p/Authorization 头），
  命中报行号 + 首次出现时间；`--redact` 前 4 后 2 半掩码
- HL-02 破坏性命令：rm -rf 根/家/系统目录分级、mkfs、dd 直写块设备、
  chmod -R 777、fork bomb、shutdown/reboot、抹除历史痕迹
- HL-03 习惯画像：top 命令、sudo 频率、夜行者指数、失败重试链、
  时间戳缺失告警（取证能力受损）
- HL-04 跨机对比：多文件独有命令/共同核心统计
- 综合风险分 0-100 + 等级，退出码 0/1/2/3
- `--baseline` 白名单（子串匹配）、`--aggregate` 聚合安全模式、`--json` 机器可读
- 解析：zsh EXTENDED_HISTORY 双格式、bash #ts、无时间戳容错、
  多行命令（续行/heredoc）合并、坏行计数、非 UTF-8 容错
- 不变量：只读、零第三方依赖、Python 3.8+、macOS/Linux/Windows
- 自测 26 项全绿（含偏态实战：600 良性埋 4 异常全检出）
