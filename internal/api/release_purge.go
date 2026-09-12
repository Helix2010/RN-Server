package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/objectstore"
)

// 历史版本清理。发布记录本身没有"删除"状态机——状态只在 verified / active / canary /
// paused / completed / rejected 之间走，谁都不会把一行变成不存在。那是对的：升级决策要
// 看得见历史。但产物不一样，一个安卓包 37MB，几十个版本累计就是几个 G 的对象存储，
// 而真正会被下发的只有 active 那一个。
//
// 所以清理是一个**显式的、要写理由的破坏性动作**，不是状态迁移，且带两条硬约束：
//
//  1. 正在下发的东西删不掉。全量包看 status（active / canary）；OTA 看它是不是当前
//     出货版本那条运行时线上还在服务的那一条。
//  2. 先 OTA 后全量包。OTA 记录靠 base_release_id 认包身份（applicationId、签名证书
//     指纹都是从基线 APK 读出来的），基线先没了，剩下的 OTA 行就永远校验不过去。
//
// 对象先列后删：2026-09-10 之前入库的 OTA 没有 object_metadata，只按数据库枚举会把同
// 目录下的 bundle 和图片留在桶里。删除顺序是"先删库、后删对象"——反过来一旦库里那步
// 失败，留下的是一行指向空对象的记录，下发时才炸；这个方向最坏只是桶里多几个孤儿对象，
// 审计里记了前缀，可以再扫。

type purgeRequest struct {
	Reason  string `json:"reason"`
	Confirm bool   `json:"confirm"`
}

// purgeIntent 校验"确认 + 理由"。和 releaseAction / otaAction 保持同一套口径。
func purgeIntent(c *gin.Context) (string, bool) {
	var body purgeRequest
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "CONFIRMATION_REQUIRED", "reason and confirm=true are required")
		return "", false
	}
	return strings.TrimSpace(body.Reason), true
}

// activeReleaseRuntime 返回某平台 active 全量包的运行时版本。没有 active 时返回空串，
// 此时任何 OTA 都不再是"当前出货版本在用的那条"。
func (s *server) activeReleaseRuntime(ctx context.Context, tenant, platform string) string {
	var runtime sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT runtime_version FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`, tenant, platform).Scan(&runtime)
	if err != nil {
		return ""
	}
	return runtime.String
}

func (s *server) purgeOTARelease(c *gin.Context) {
	reason, ok := purgeIntent(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")
	deleteStoredObjects := func() {}
	var status, platform, runtime string
	var manifestKey sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT status,platform,runtime_version,manifest_key FROM ota_releases WHERE tenant_id=? AND id=?`, tenantID(c), id).Scan(&status, &platform, &runtime, &manifestKey)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "OTA_RELEASE_NOT_FOUND", "OTA release not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_PURGE_FAILED", "Unable to read the OTA release")
		return
	}
	// 还在给当前出货版本下发的那一条不能删：设备下次检查更新就会拿到 404，而它本来
	// 应该拿到这个包。已经被取代（superseded）或更老运行时线上的 active 不在此列——
	// 那些设备收到的是全量升级，不是 OTA。
	if (status == "active" || status == "canary") && runtime == s.activeReleaseRuntime(ctx, tenantID(c), platform) {
		problem(c, http.StatusConflict, "OTA_RELEASE_IN_USE", "This OTA release is still served to the current shipping build; publish a replacement or roll back first")
		return
	}

	prefix, keys := "", []string(nil)
	if manifestKey.Valid && strings.TrimSpace(manifestKey.String) != "" {
		client, _, clientErr := s.storageClientForTenant(ctx, tenantID(c))
		if clientErr != nil {
			problem(c, http.StatusBadGateway, "STORAGE_UNAVAILABLE", "Unable to reach release storage")
			return
		}
		prefix = path.Dir(manifestKey.String) + "/"
		if keys, err = client.List(ctx, prefix); err != nil {
			// 列不出来就不动数据库：删了行就再也不知道该删哪些对象了
			problem(c, http.StatusBadGateway, "STORAGE_LIST_FAILED", "Unable to list the stored OTA objects")
			return
		}
		deleteStoredObjects = func() { deleteObjects(ctx, client, prefix, keys) }
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_PURGE_FAILED", "Unable to delete the OTA release")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM ota_releases WHERE tenant_id=? AND id=?`, tenantID(c), id); err != nil {
		problem(c, http.StatusInternalServerError, "OTA_PURGE_FAILED", "Unable to delete the OTA release")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ota_release_purge", "ota-release", id, reason, requestID(c),
		map[string]any{"status": status, "platform": platform, "runtimeVersion": runtime, "objectPrefix": prefix, "objects": len(keys)})
	if err = insertAudit(ctx, tx, event); err != nil {
		problem(c, http.StatusInternalServerError, "OTA_PURGE_FAILED", "Unable to record the deletion")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "OTA_PURGE_FAILED", "Unable to delete the OTA release")
		return
	}
	deleteStoredObjects()
	c.JSON(http.StatusOK, gin.H{"deleted": true, "id": id, "objects": len(keys)})
}

func (s *server) purgeRelease(c *gin.Context) {
	reason, ok := purgeIntent(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")
	deleteStoredObjects := func() {}
	var status, platform, version string
	var buildNumber int
	var objectKey sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT status,platform,version,build_number,object_key FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), id).Scan(&status, &platform, &version, &buildNumber, &objectKey)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "RELEASE_NOT_FOUND", "Release not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to read the release")
		return
	}
	if status == "active" || status == "canary" {
		problem(c, http.StatusConflict, "RELEASE_IN_USE", "This release is still being delivered; pause it or publish a replacement first")
		return
	}
	// OTA 记录的包身份（applicationId、签名指纹）是从基线 APK 读出来的，基线先没了，
	// 那些 OTA 行就永远校验不过去。所以顺序固定：先清 OTA，再清它的基线包。
	var attached int
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ota_releases WHERE tenant_id=? AND base_release_id=?`, tenantID(c), id).Scan(&attached); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to check attached OTA releases")
		return
	}
	if attached > 0 {
		problem(c, http.StatusConflict, "RELEASE_HAS_OTA", "Delete the OTA releases built on this base release first")
		return
	}

	key := strings.TrimSpace(objectKey.String)
	if key != "" {
		client, _, clientErr := s.storageClientForTenant(ctx, tenantID(c))
		if clientErr != nil {
			problem(c, http.StatusBadGateway, "STORAGE_UNAVAILABLE", "Unable to reach release storage")
			return
		}
		deleteStoredObjects = func() { deleteObjects(ctx, client, key, []string{key}) }
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to delete the release")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), id); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to delete the release")
		return
	}
	// 构建任务指回发布记录。任务本身是历史，不跟着删；把指针清掉，免得管理端点进去 404
	if _, err = tx.ExecContext(ctx, `UPDATE build_jobs SET release_id=NULL WHERE tenant_id=? AND release_id=?`, tenantID(c), id); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to detach the build job")
		return
	}
	event := newAudit(tenantID(c), actor(c), "release_purge", "release", id, reason, requestID(c),
		map[string]any{"status": status, "platform": platform, "version": version, "buildNumber": buildNumber, "objectKey": key})
	if err = insertAudit(ctx, tx, event); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to record the deletion")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_PURGE_FAILED", "Unable to delete the release")
		return
	}
	deleteStoredObjects()
	c.JSON(http.StatusOK, gin.H{"deleted": true, "id": id})
}

// deleteObjects 只在数据库那步提交之后调用——反过来一旦入库失败，删掉的对象就再也
// 回不来，而记录还在，下发时才炸。删不掉只记日志：此时记录已经没了，把请求判失败会让
// 运营以为没删成而重试，重试同样删不掉。日志带前缀，之后可以按前缀扫孤儿对象。
func deleteObjects(ctx context.Context, client objectstore.Client, prefix string, keys []string) {
	for _, key := range keys {
		if err := client.Delete(ctx, key); err != nil {
			slog.Error("stored object was not deleted", "prefix", prefix, "key", key, "error", err)
		}
	}
}
