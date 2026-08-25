# ADR-0007：多租户 APK Artifact 与 S3 兼容对象存储

- 状态：Accepted
- 日期：2026-08-25

## 背景

Android Direct 发布必须支持不经过应用商店的 APK 分发。原实现只把前端构造的
下载地址、大小和哈希写入 `app_releases.artifact` JSON，没有真实文件上传、签名
校验、不可变对象或租户边界，不能作为生产发布系统。

## 决策

RN-Server 增加 Tenant、Application、StorageConfig 和 Artifact 四个资源，并将
Release、AppConfig 与 Audit 迁移到 tenant scope。当前管理员仍是平台管理员，
可以显式切换租户；服务端从受保护路由的 path 解析目标租户并校验存在性，不接受
任意 `tenantId` header 作为授权事实。所有 repository SQL、唯一约束、审计事件和
对象 key 都包含 `tenant_id`。

对象存储使用 AWS SDK for Go v2 的 S3 协议，支持 AWS S3、Cloudflare R2、MinIO
及兼容服务。浏览器先向服务端申请短时 presigned PUT，再直接上传对象；服务端在
finalize 阶段重新读取对象，计算 SHA-256/大小，解析 AndroidManifest，并用
APK Signature Scheme v1/v2/v3/v4 兼容校验器验证签名。只有 `verified` Artifact
可以绑定 Direct Release，已绑定或已激活对象不能覆盖。

每租户的 endpoint、region、bucket、prefix、path-style 与 CDN base URL 保存在
MySQL。access key、secret key 和 session token 使用 AES-256-GCM 加密后保存；
主密钥只来自 `STORAGE_MASTER_KEY` 环境秘密，不能写入 MySQL、镜像、日志或管理端。
读取配置时只返回掩码和“已配置”标志。私有对象下载由 API 生成短时 presigned GET；
配置 CDN base URL 时返回不可变对象的公开 CDN 地址。

schema 通过有序、只向前、可重复恢复的迁移执行。历史数据迁入服务端创建的
`default` 租户；生产部署先运行迁移，再滚动启动兼容新旧字段的服务。

## 替代方案

- 由 Go API 代理整个 APK 上传/下载：部署简单，但大文件会占用 API 带宽和连接，
  不适合发布流量。
- 把 S3 密钥放环境变量：单租户简单，但不能满足租户独立维护和复用要求。
- 在浏览器保存 S3 secret：会直接泄露长期凭证，拒绝采用。
- 只校验扩展名或客户端哈希：无法证明包身份和签名，拒绝采用。

## 影响与退出策略

新增 AWS S3 SDK、APK manifest/signature 校验依赖和 `STORAGE_MASTER_KEY` 运维秘密。
浏览器直传要求 bucket CORS 允许管理端 origin、PUT/HEAD 与必要 header。finalize
会临时占用最多一个 APK 大小的本地磁盘空间，大小和超时由配置限制。

对象存储通过内部 adapter 隔离；更换供应商只需实现相同 port。密钥轮换采用新主
密钥解密/重加密批任务，不能直接替换环境值。关闭本功能时先停止新上传，保留
Artifact/Release 只读和下载窗口，再迁移对象；数据库只做向前修复，不回滚已执行 DDL。
