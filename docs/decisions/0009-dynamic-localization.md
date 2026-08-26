# ADR-0009：动态语言与租户文案继承

状态：Accepted（2026-08-26）

## 决策

语言编码只接受规范 BCP 47，例如 `zh-CN`、`en-US`、`ja-JP`。迁移 V6 一次性修正数据库中的 `zh_CN/en_US`，运行时不提供旧格式转换。

`app_configs.languages` 的 `tenant_id=0` 保存全局语言目录；租户记录只保存与全局不同的字段和租户已发布资源。读取时同时查询全局与租户记录，并按语言、按字段合并，不能使用 `ORDER BY tenant_id DESC LIMIT 1` 整条覆盖。

`language_document` 使用 `(lang,key,type,tenant_id)` 唯一约束。租户文案优先于全局文案；生成目标语言完整 JSON 时，依次使用租户目标语言、全局目标语言、租户回退语言、全局回退语言和消息 Key。发布文件上传到已有租户对象存储，校验大小和 SHA-256 后才更新 `app_configs.languages.resources`。

## 后果

全局新增语言会自动出现在未显式覆盖的租户中；租户编辑继承文案不会修改全局数据。语言资源发布失败不会覆盖上一成功资源，RN-App 继续使用旧缓存或内置包。
