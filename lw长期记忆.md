# lw长期记忆

## 任务理解规则

1. **不要瞎猜**：需向用户提问确认需求后再执行
2. **不要擅自**：复杂任务需整理计划，确认后执行
3. **代码注释**：详细注释，查看项目文档可用信息

## 代码风格/约定

- 数据库写入时如需替换字段值，在 `insert_xxx` 调用前做覆盖处理
- TLS1.1 特殊处理：`protocol_version` → `SSL3.0`，`cipher_suite` → `SSL_RSA_WITH_RC4_128_MD5`

## 踩坑记录

- SSL3 支持问题：设置 `DEFAULT_MIN_VERSION = Version.SSL3` 时，`max_version` 不能为 `UNBOUNDED(0)`，需设为具体版本

## 命令记忆

- 项目文档位置：`/home/unumtu/Desktop/TLS_middle/middle-man/`
- 主要修改文件：`midman/reporter.py`