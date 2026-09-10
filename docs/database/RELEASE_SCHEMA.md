# 发布与 OTA 相关列的 JSON 键（app_releases / ota_releases）

表结构本身以 `internal/store/migrations.go` 为准；本文只记录两个 JSON 列里由代码读写、影响下发决策的键，避免"列有 COMMENT 但键无处可查"。

## app_releases.file_metadata（JSON）

| 键 | 来源 | 含义 / 取值 | 缺失或非法的处理 |
| --- | --- | --- | --- |
| `fileName`、`size`、`sha256` | 入库校验（`createReleaseFromArtifact`） | 文件名、字节数、内容 SHA-256（小写 hex） | 入库必写 |
| `objectEtag` | 入库时 `objectstore.Stat` | 对象存储 ETag，去引号；分段上传形如 `<md5>-<n>` | **键不存在**：2026-09-10 前的旧记录，下载只比大小并 warning 一次；**键存在但为空/非字串**：500 `RELEASE_METADATA_INVALID`。入库时 ETag 为空直接拒绝（`RELEASE_OBJECT_ETAG_MISSING`） |
| `packageName`、`versionName`、`versionCode`、`minSdk`、`signerSha256`、`signingScheme`、`runtimeVersion` | `apkinspect`（仅 Android） | 包身份；`signerSha256` 小写 hex | 入库必写（Android） |
| `applicationId` | `apkinspect` 读内嵌 `extra.applicationId`（仅 Android） | App 身份（`X-Application-ID`），OTA 的 `extra.applicationId` 必须与之相等 | 旧记录缺失时由 OTA 创建路径回填（先核对对象 sha256/大小，见 OPERATIONS §5） |

## ota_releases.object_metadata（JSON，迁移 37）

`{ "<相对路径>": { "size": <字节数>, "etag": "<对象 ETag>" } }`，每个资源对象一条，不含 `manifest.json`（manifest 由 `manifest_sha256` 全文校验）。

| 状态 | 判定 | 下发行为 |
| --- | --- | --- |
| 列为 NULL | 迁移 37 之前的记录 | 放行并 warning 一次 |
| 有该路径且 `size` 为非负数、`etag` 为非空字串 | 正常记录 | `Stat` 比对大小与 ETag，不符 502 `OTA_OBJECT_CHANGED` |
| 列有内容但不是合法 JSON，或条目缺 `size` / `etag` | 数据事故 | 500 `OTA_OBJECT_METADATA_INVALID` |
| 列合法但没有该路径 | 包里没有这个文件 | 404 |
