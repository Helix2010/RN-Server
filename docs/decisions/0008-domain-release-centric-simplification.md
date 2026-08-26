# ADR-0008：域名租户上下文与 Release-Centric 安装包发布

状态：Accepted（2026-08-25）

## 背景

早期发布链路将租户、应用身份、对象存储配置和安装包拆成多个控制面资源。对当前 DEX/Web3 基座而言，这增加了管理页面操作步骤和跨表一致性风险；租户已经由平台的 `tenants` 与 `tenant_domain` 维护，服务端只需要安全地解析请求域名并隔离业务数据。

## 决策

1. 所有 App/Admin/Public 请求优先通过 `Host → tenant_domain → tenants.id` 解析租户。解析结果使用短 TTL、有界正负缓存，并写入请求上下文；客户端传入的 tenant id 不能覆盖它。
2. `app_configs` 使用 `(tenant_id, config_key)` 主键。`tenant_id=0` 是全局默认，查询始终按“租户覆盖优先、全局回退”读取；保存全局回退配置时创建租户覆盖记录，并使用版本 compare-and-swap。
3. 新发布流程只以 `app_releases` 为事实源：平台、语义化版本、递增 build number、多语言 release notes、对象 key、文件大小、SHA-256、解析 metadata、校验和发布状态全部在一行内维护。
4. 上传使用短时 presigned PUT；finalize 由服务端读取对象、计算 hash 并按平台校验。Android 校验 APK 的 versionName/versionCode 与提交值一致；发布状态 `active` 表示全量官网分发，当前不实现灰度。
5. 对象存储使用 `app_configs` 的 `release.storage` 配置键，租户配置优先、`tenant_id=0` 全局配置回退；Access Key、Secret 与 Session Token 使用 `STORAGE_MASTER_KEY` 加密后存入 JSON，接口永不回显明文。
6. 开发阶段直接删除 `tenant_applications`、`tenant_storage_configs`、`artifacts` 和旧 tenant-path endpoint，不保留双写或兼容读取。

## 取舍

- 优点：管理流程短、租户隔离事实单一、发布查询和官网下载简单、可复用到 Android/iOS/HarmonyOS。
- 代价：当前不提供灰度/双人审批/RBAC；平台级签名策略和 iOS/鸿蒙专属元数据在后续适配器中补齐。
- 迁移：V5 为开发阶段破坏性迁移，保留 `tenants` 与 `tenant_domain`，删除并重建发布、配置、审计与会话表。

## 回滚

当前为开发阶段，不承诺旧数据或旧接口回滚。需要回退时重新执行目标版本的开发库初始化迁移。
