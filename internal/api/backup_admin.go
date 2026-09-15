package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/gin-gonic/gin"
)

// 控制台侧的备份接口（设计 platform-backup-recovery-2026-09-15 §8.2）。

// requireBackupSameOrigin 挡住「一个租户域名上的页面替平台管理员把备份拉走」。
//
// 背景：authenticate() 的 Origin 闸只对非安全方法生效（safeMethod 含 GET），而
// originAllowed 末尾会回落去查 tenant_domain 表，cors() 又对任何通过 originAllowed
// 的来源发 Access-Control-Allow-Credentials: true。不补的话，「谁能读平台备份」
// 实际由那张表的内容决定。
//
// 设计原话是「平台组关掉 tenant_domain 回退，只认 CORS_ORIGINS 里显式列出的来源」。
// **照做会把控制台打死**：生产上 CORS_ORIGINS 默认是空的（租户域名由表推导），
// 控制台自己的来源也不在里面。所以这里改成等价但不误伤的判据——
//
//	Origin 缺失，或 Origin 的 host 等于请求的 Host（同源），或显式列在 CORS_ORIGINS 里 → 放行
//	其余一律 403
//
// 同源的控制台照常用，而任何**跨源**页面都拿不到备份，包括租户域名上的页面。
func (s *server) requireBackupSameOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 备份内容永远不该进任何缓存
		c.Header("Cache-Control", "no-store")
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" {
			c.Next()
			return
		}
		for _, allowed := range s.cfg.CORSOrigins {
			if allowed == origin {
				c.Next()
				return
			}
		}
		parsed, err := url.Parse(origin)
		if err == nil && parsed.Host != "" && strings.EqualFold(parsed.Host, c.Request.Host) {
			c.Next()
			return
		}
		slog.Warn("a cross-origin request to the platform backup routes was refused",
			"origin", origin, "host", c.Request.Host, "path", c.Request.URL.Path)
		problem(c, http.StatusForbidden, "BACKUP_CROSS_ORIGIN_REFUSED",
			"platform backups are not readable cross-origin")
		c.Abort()
	}
}

// getBackupStatus 是控制台那一页的数据源。
func (s *server) getBackupStatus(c *gin.Context) {
	ctx := c.Request.Context()
	runs, err := s.listBackupRuns(ctx, 30)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_LIST_FAILED", "Unable to list backups")
		return
	}
	failures, err := s.consecutiveBackupFailures(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_LIST_FAILED", "Unable to count failures")
		return
	}
	holders := s.backupHolders(ctx)

	slots := make([]gin.H, 0, backupcontainer.SlotCount)
	for i, slot := range backupcontainer.SlotNames {
		recipient := s.cfg.Backup.Recipients[i]
		slots = append(slots, gin.H{
			"slot":        slot,
			"fingerprint": nullableString(recipient.Fingerprint),
			"configured":  recipient.Fingerprint != "",
			"holder":      nullableString(strings.TrimSpace(holders[slot])),
		})
	}

	signing := gin.H{"registered": false, "fingerprint": nil}
	if record, err := s.backupSigningKeyRecord(ctx); err == nil && record != nil {
		signing = gin.H{"registered": true, "fingerprint": record.Current.Fingerprint}
	}

	items := make([]gin.H, 0, len(runs))
	for _, run := range runs {
		items = append(items, backupRunView(run))
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled": s.cfg.Backup.Enabled(),
		// 三把齐了才是就绪。少一把服务端根本起不来（§8.3），所以正常情况下
		// 这里恒为 true；它存在是为了让人一眼确认「三个指纹都是我认识的那三个」
		"ready":            s.backupRecoveryReady(),
		"threshold":        "2-of-3",
		"instanceId":       nullableString(s.cfg.Backup.InstanceID),
		"intervalHours":    s.cfg.Backup.IntervalHours,
		"bucket":           nullableString(s.cfg.Backup.Bucket.Bucket),
		"recoverySlots":    slots,
		"signingKey":       signing,
		"consecutiveFails": failures,
		"runs":             items,
	})
}

func (s *server) backupRecoveryReady() bool {
	for _, recipient := range s.cfg.Backup.Recipients {
		if recipient.Fingerprint == "" {
			return false
		}
	}
	return true
}

func backupRunView(run backupRun) gin.H {
	// 每条记录按它**自己那一次**产出了哪几组来渲染，不按当前配置。
	// 换过公钥之后，老记录要的钥匙和现在配的不是同一批
	objects := make([]gin.H, 0, len(run.Objects))
	for _, object := range run.Objects {
		objects = append(objects, gin.H{
			"pair": object.Pair, "sha256": object.SHA256, "sizeBytes": object.SizeBytes,
		})
	}
	view := gin.H{
		"seq": run.Seq, "status": run.Status, "triggerBy": run.TriggerBy,
		"requestedBy": run.RequestedBy, "reason": run.Reason,
		"createdAt": iso(run.CreatedAt), "updatedAt": iso(run.UpdatedAt),
		"objects": objects, "failureReason": nullableString(run.FailureReason),
		"claimedBy": nullableString(run.ClaimedBy),
	}
	if run.TenantCount != nil {
		view["tenantCount"] = *run.TenantCount
	} else {
		view["tenantCount"] = nil
	}
	return view
}

// runBackupNow 建一条待办。**毫秒级返回**——真正耗时的活在打包机上。
func (s *server) runBackupNow(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_RUN", "reason and confirm=true are required")
		return
	}
	if !s.cfg.Backup.Enabled() {
		problem(c, http.StatusPreconditionFailed, "BACKUP_NOT_CONFIGURED",
			"backups are not configured on this deployment")
		return
	}
	run, err := s.createBackupRun(c.Request.Context(), "manual", actor(c), strings.TrimSpace(body.Reason))
	if errors.Is(err, errBackupInFlight) {
		// 409 要告诉运维是**哪一条**占着闸——他没有别的出口去看
		live, liveErr := s.liveBackupRun(c.Request.Context())
		detail := gin.H{"error": "BACKUP_IN_FLIGHT",
			"detail": "a backup is already in flight; wait for it to finish or force-fail it"}
		if liveErr == nil {
			detail["seq"] = live.Seq
			detail["status"] = live.Status
			detail["claimedBy"] = nullableString(live.ClaimedBy)
		}
		c.JSON(http.StatusConflict, detail)
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_RUN_FAILED", "Unable to queue a backup")
		return
	}
	s.auditNow(newAudit(platformTenantID, actor(c), "backup_requested", "platform-backup", run.ID,
		strings.TrimSpace(body.Reason), requestID(c), map[string]any{"seq": run.Seq}))
	// 异步：不要让控制台转圈等结果
	c.JSON(http.StatusAccepted, gin.H{"seq": run.Seq, "status": run.Status,
		"detail": "queued; the build agent will pick this up on its next poll"})
}

// forceFailBackup 是逃生口。
//
// 没有它的话：运维按 rn-build-agent.service 注释教的 `systemctl kill -s SIGKILL`
// 换二进制之后，记录停在 running、live_slot 被占，控制台显示「备份进行中」但什么
// 都没在跑，点「立即备份」一直 409——**30 分钟内一次备份都做不了，而运维手上
// 没有任何动作能改变它**。
func (s *server) forceFailBackup(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_FORCE_FAIL", "reason and confirm=true are required")
		return
	}
	seq, ok := parseSeq(c.Param("seq"))
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SEQ", "seq must be a positive integer")
		return
	}
	run, err := s.backupRunBySeq(c.Request.Context(), seq)
	if err != nil {
		problem(c, http.StatusNotFound, "BACKUP_NOT_FOUND", "No such backup")
		return
	}
	changed, err := s.failBackupRun(c.Request.Context(), run.ID, "forced: "+strings.TrimSpace(body.Reason))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_FORCE_FAIL_FAILED", "Unable to fail the backup")
		return
	}
	if !changed {
		problem(c, http.StatusConflict, "BACKUP_ALREADY_FINISHED", "That backup already finished")
		return
	}
	cleanBackupStaging(run.ID)
	s.auditNow(newAudit(platformTenantID, actor(c), "backup_force_failed", "platform-backup", run.ID,
		strings.TrimSpace(body.Reason), requestID(c), map[string]any{"seq": run.Seq, "was": run.Status}))
	c.JSON(http.StatusOK, gin.H{"seq": run.Seq, "status": backupStatusFailed})
}

// downloadBackup 下载某一组的包。
//
// 路径以 /download 结尾是有意的：既有的数据库超时中间件正好豁免这个后缀。
//
// 对象键**从行上读**，不重新拼。重新拼要依赖 instanceId，而主机改名、或者恰好
// 在新机器上恢复之后前缀就变了，历史备份会全部 404。:pair 只当查表的键用，
// 匹配不到就 404，绝不参与拼字符串。
func (s *server) downloadBackup(c *gin.Context) {
	seq, ok := parseSeq(c.Param("seq"))
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SEQ", "seq must be a positive integer")
		return
	}
	run, err := s.backupRunBySeq(c.Request.Context(), seq)
	if err != nil {
		problem(c, http.StatusNotFound, "BACKUP_NOT_FOUND", "No such backup")
		return
	}
	pair := strings.TrimSpace(c.Param("pair"))
	var found *backupObject
	for i := range run.Objects {
		if run.Objects[i].Pair == pair {
			found = &run.Objects[i]
			break
		}
	}
	if found == nil {
		problem(c, http.StatusNotFound, "BACKUP_PAIR_NOT_FOUND",
			"this backup has no package for that pair of key holders")
		return
	}

	client, err := s.backupBucketClient()
	if err != nil {
		problem(c, http.StatusPreconditionFailed, "BACKUP_BUCKET_UNAVAILABLE", err.Error())
		return
	}
	body, err := client.Get(c.Request.Context(), found.ObjectKey)
	if err != nil {
		// 行比对象活得久：生命周期删掉对象之后这一行还在。给一句看得懂的话，
		// 而不是把 S3 的 NoSuchKey 原样吐出去
		problem(c, http.StatusGone, "BACKUP_OBJECT_GONE",
			"the object is no longer in the bucket; it is probably past the retention period")
		return
	}
	defer body.Close()

	s.auditNow(newAudit(platformTenantID, actor(c), "backup_downloaded", "platform-backup", run.ID,
		"a platform administrator downloaded a backup package", requestID(c),
		map[string]any{"seq": run.Seq, "pair": pair}))

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename=\"backup-"+c.Param("seq")+"-"+pair+".rnbk\"")
	c.Header("X-Backup-Sha256", found.SHA256)
	if _, err := io.Copy(c.Writer, body); err != nil {
		slog.Error("streaming a backup download failed", "seq", run.Seq, "pair", pair, "error", err)
	}
}

// updateBackupHolders 维护「哪个槽位由谁保管」。
//
// 这一行印进 README-FIRST.txt——拿到包的人得知道该去找谁。它不是机密，但它是
// 恢复流程里唯一能把「槽位 A」翻译成一个具体的人的东西。
func (s *server) updateBackupHolders(c *gin.Context) {
	var body struct {
		Holders map[string]string `json:"holders"`
		Reason  string            `json:"reason"`
	}
	if decode(c, &body) != nil || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_HOLDERS", "holders and reason are required")
		return
	}
	cleaned := map[string]string{}
	for slot, name := range body.Holders {
		if !backupbundle.IsSlotName(slot) {
			problem(c, http.StatusBadRequest, "INVALID_BACKUP_HOLDERS", "unknown slot "+slot)
			return
		}
		trimmed := clipRunes(strings.TrimSpace(name), 120)
		// 这个值会被渲染进 README-FIRST.txt。那份文件不是脚本，但它会被人照着读，
		// 一段带控制字符的内容只会让人困惑
		if strings.ContainsAny(trimmed, "\n\r\t") {
			problem(c, http.StatusBadRequest, "INVALID_BACKUP_HOLDERS", "a holder name cannot contain newlines")
			return
		}
		cleaned[slot] = trimmed
	}
	encoded, err := marshalIndentJSON(cleaned)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_HOLDERS_SAVE_FAILED", "Unable to save")
		return
	}
	if _, err := s.db.ExecContext(c.Request.Context(),
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=app_configs.version+1,
		   updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		platformTenantID, backupRecoveryHoldersKey, encoded, actor(c), time.Now().UTC()); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_HOLDERS_SAVE_FAILED", "Unable to save")
		return
	}
	s.auditNow(newAudit(platformTenantID, actor(c), "backup_holders_updated", "app-config",
		backupRecoveryHoldersKey, strings.TrimSpace(body.Reason), requestID(c), nil))
	c.JSON(http.StatusOK, gin.H{"holders": cleaned})
}

// testBackupBucket 只 Put 一个随机探针键。
//
// 不能用现成的 objectstore.Test()：它 Put 固定键再 HeadObject，既要 Get 权限，
// 固定键在开了 versioning 的桶上还会永久留存一堆版本。
func (s *server) testBackupBucket(c *gin.Context) {
	client, err := s.backupBucketClient()
	if err != nil {
		problem(c, http.StatusPreconditionFailed, "BACKUP_BUCKET_UNAVAILABLE", err.Error())
		return
	}
	key := backupObjectKey(s.cfg.Backup.Bucket.Prefix, s.cfg.Backup.InstanceID, 0,
		"probe-"+randomID(8), ".txt")
	probe := "rn-foundation backup bucket probe " + iso(time.Now().UTC()) + "\n"
	// 另起 ctx：桶不可达时，10 秒的数据库超时会把这条测试砍掉，
	// 而运维看到的是一句和桶无关的 deadline exceeded
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Put(ctx, key, strings.NewReader(probe), int64(len(probe)), "text/plain"); err != nil {
		problem(c, http.StatusFailedDependency, "BACKUP_BUCKET_TEST_FAILED",
			"cannot write to the backup bucket: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "bucket": s.cfg.Backup.Bucket.Bucket, "probeKey": key,
		"checkedAt": iso(time.Now().UTC())})
}
