package api

import (
	"context"
	"errors"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

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

		// Origin 判据和其它所有管理端路由**保持一致**（originAllowed）。
		//
		// 设计 §6 要的是「对平台组关掉 tenant_domain 回退」，理由是那张表是租户
		// 数据、不该由它决定谁能读平台备份。这条实现不了，而且照做会把控制台
		// 自己关在门外：备份页是挂在同一个控制台里的（它就是那个租户控制台，
		// 平台管理员多看见几个菜单），而生产的 CORS_ORIGINS 按设计就是空的
		// ——「租户控制台的来源已由 tenant_domain 表推导，不必再列一遍」
		// （deploy/amos/rn-foundation.env.example:94）。
		//
		// 我先前按「同源或显式列出」实现，结果是任何生产部署上这一页必然 403：
		// 控制台域名和 API 主机本来就不是同一个。
		//
		// 真正的授权边界不在这里，而是 requirePlatformAdmin：要有已登录会话，
		// 且操作者在平台管理员白名单里。Origin 这一层挡的是「别的站点用你的
		// cookie 跨源把响应读走」，而那件事由浏览器同源策略加 CORS 响应头兜底
		// ——服务端不给不可信来源发 Access-Control-Allow-Origin，对方就读不到。
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" || sameOrigin(origin, c.Request.Host) || s.originAllowed(origin) {
			c.Next()
			return
		}
		slog.Warn("a cross-origin request to the platform backup routes was refused",
			"origin", origin, "host", c.Request.Host, "path", c.Request.URL.Path)
		problem(c, http.StatusForbidden, "BACKUP_CROSS_ORIGIN_REFUSED",
			"platform backups are not readable from "+origin)
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
	// 打包机公钥指纹。它和上面三把恢复公钥的指纹算法不同（16 字符 vs 64 字符），
	// 设计 §2.2 特意要求分开显示——混在一起显示会让核对仪式失效。
	//
	// pending 一定要回：换过机器之后打包机会报上来一把新的，而 current 不动。
	// 控制台上不显示 pending 的话，人看到的是一切正常的旧指纹，而每一次备份都在
	// 失败——「register it first」里的 register，在控制台上根本没有入口
	agentKeyView := gin.H{"registered": false, "fingerprint": nil, "pending": nil,
		"algorithm": "X25519 公钥 sha256 前 16 字符"}
	if record, err := s.buildAgentKey(ctx); err == nil && record != nil {
		if record.Current.Fingerprint() != "" {
			agentKeyView["registered"] = true
			agentKeyView["fingerprint"] = record.Current.Fingerprint()
		}
		if record.Pending != nil {
			agentKeyView["pending"] = gin.H{"fingerprint": record.Pending.Fingerprint(),
				"agent": nullableString(record.PendingAgent), "reportedAt": nullableString(record.PendingAt)}
		}
	}

	// 桶在控制台上配的时候 env 里那份可能是空的，显示的必须是生效的那个
	effectiveBucket, _, _ := s.resolveBackupBucket(ctx)

	signing := gin.H{"registered": false, "fingerprint": nil, "pending": nil}
	if record, err := s.backupSigningKeyRecord(ctx); err == nil && record != nil {
		signing["registered"] = true
		signing["fingerprint"] = record.Current.Fingerprint
		if record.Pending != nil {
			signing["pending"] = gin.H{"fingerprint": record.Pending.Fingerprint,
				"agent": nullableString(record.Pending.Agent), "reportedAt": nullableString(record.Pending.At)}
		}
	}

	items := make([]gin.H, 0, len(runs))
	for _, run := range runs {
		items = append(items, backupRunView(run))
	}
	c.JSON(http.StatusOK, gin.H{
		// 同一个判据：生效的桶（控制台优先）或者开了定时。只看 env 的话，桶在控制台上
		// 配好之后这里永远是 false
		"enabled": strings.TrimSpace(effectiveBucket.Bucket) != "" || s.cfg.Backup.IntervalHours > 0,
		// 三把齐了才是就绪。少一把就产不出备份（§2.1 没有降级模式），控制台
		// 靠它把「立刻备份」置灰并说明差哪几把
		"ready":            s.backupRecoveryReady(),
		"threshold":        "2-of-3",
		"instanceId":       nullableString(s.cfg.Backup.InstanceID),
		"intervalHours":    s.cfg.Backup.IntervalHours,
		"bucket":           nullableString(effectiveBucket.Bucket),
		"bucketVersioning": s.backupBucketVersioning(),
		// 保留期只是抄桶上生命周期规则的一份给人看。0 = 没配，控制台显示
		// 「未设置」——比按一个猜出来的天数把按钮置灰诚实
		"retentionDays": s.cfg.Backup.RetentionDays,
		// 第四个指纹：打包机公钥。它是 16 字符的（buildkeystore 那套），
		// 和上面三把 64 字符的**不是一回事**，所以单独一项、单独标注算法。
		// 恢复时 build-agent show-key 要比对的正是它
		"agentKey": agentKeyView,
		// 三个恢复槽位不在这里回：它们有自己的接口（GET /backup/recipients），
		// 两处各回一份迟早会漂，而漂开的表现是同一个指纹在同一页上显示成两个值
		// ——那正好毁掉设计 §2.2 那个唯一的人工核对
		"signingKey":       signing,
		"consecutiveFails": failures,
		"runs":             items,
	})
}

// backupRecoveryReady 说明三把公钥配齐了没有。没配齐就产不出备份（§2.1 没有降级模式）
func (s *server) backupRecoveryReady() bool {
	for _, recipient := range s.backupRecipients() {
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
		// 重新输一次管理员口令。理由见 backup_reauth.go 开头：会话 TTL 8 小时，
		// 一个被偷走的 cookie 否则能直接触发并拉走全平台每个租户的签名密钥
		Password string `json:"password"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_RUN", "reason and confirm=true are required")
		return
	}
	if !s.requireBackupPassword(c, body.Password) {
		return
	}
	run, err := s.createBackupRun(c.Request.Context(), "manual", actor(c), strings.TrimSpace(body.Reason))
	// 三道前置各回各的码，detail 原样说差什么。只回一句「没配置」的话，
	// 人对着一页全绿的卡片不知道该去改哪
	for _, gate := range []struct {
		err  error
		code string
	}{
		{errBackupBucketMissing, "BACKUP_NOT_CONFIGURED"},
		{errBackupRecipientsIncomplete, "BACKUP_RECIPIENTS_INCOMPLETE"},
		{errBackupInstanceIDInvalid, "BACKUP_INSTANCE_ID_INVALID"},
	} {
		if errors.Is(err, gate.err) {
			problem(c, http.StatusPreconditionFailed, gate.code, err.Error())
			return
		}
	}
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
	run, found, ok := s.backupObjectFor(c)
	if !ok {
		return
	}
	// 票据换文件。口令在换票那一步验过，这里只认票——链接带不了请求体，
	// 而下载必须走普通链接：包有几十 MB，让浏览器流式落盘比在内存里攒 blob 靠谱
	if !s.backupReauth.redeem(strings.TrimSpace(c.Query("ticket")), run.Seq, found.Pair, actor(c)) {
		problem(c, http.StatusForbidden, "BACKUP_TICKET_INVALID",
			"this download link needs a fresh ticket; enter the administrator password again")
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
		// 而不是把 S3 的 NoSuchKey 原样吐出去。
		//
		// 但只有「确实没有这个对象」才说得上保留期。桶不可达、凭据过期、网络断
		// 都会走到这里，此前一律显示「多半是过了保留期」——真出事那天这是一句会
		// 把人带偏的文案：他会去查生命周期规则，而问题在凭据上。
		if errors.Is(err, objectstore.ErrObjectNotFound) {
			problem(c, http.StatusGone, "BACKUP_OBJECT_GONE",
				"the object is no longer in the bucket; it is probably past the retention period")
			return
		}
		problem(c, http.StatusFailedDependency, "BACKUP_BUCKET_UNREACHABLE",
			"the bucket could not be read (this is not a retention problem): "+err.Error())
		return
	}
	defer body.Close()

	s.auditNow(newAudit(platformTenantID, actor(c), "backup_downloaded", "platform-backup", run.ID,
		"a platform administrator downloaded a backup package", requestID(c),
		map[string]any{"seq": run.Seq, "pair": found.Pair}))

	c.Header("Content-Type", "application/octet-stream")
	// 下载下来的文件名和桶里的对象名一致：README-FIRST 上印的是桶里的名字，
	// 灾难当天人要拿它去对
	c.Header("Content-Disposition", "attachment; filename=\""+path.Base(found.ObjectKey)+"\"")
	c.Header("X-Backup-Sha256", found.SHA256)
	if _, err := io.Copy(c.Writer, body); err != nil {
		slog.Error("streaming a backup download failed", "seq", run.Seq, "pair", found.Pair, "error", err)
	}
}

// testBackupBucket 是控制台上那个「测试连接」。
//
// 检查本身在 runBackupBucketChecks 里，和 `rn-server backup-bucket-test` 共用一份。
// 结果永远是 200 + 三项明细，不是第一项失败就 424：人要一次看到全部缺口。
func (s *server) testBackupBucket(c *gin.Context) {
	// 另起 ctx：桶不可达时，10 秒的数据库超时会把这条测试砍掉，
	// 而运维看到的是一句和桶无关的 deadline exceeded
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bucket, _, err := s.resolveBackupBucket(ctx)
	if err != nil {
		problem(c, http.StatusPreconditionFailed, "BACKUP_BUCKET_UNAVAILABLE", err.Error())
		return
	}
	client, err := s.backupBucketClient()
	if err != nil {
		problem(c, http.StatusPreconditionFailed, "BACKUP_BUCKET_UNAVAILABLE", err.Error())
		return
	}
	result := runBackupBucketChecks(ctx, client, bucket, s.cfg.Backup.InstanceID)
	s.cacheBackupBucketVersioning(result.Versioning)
	c.JSON(http.StatusOK, result)
}

// resetKeystoreChecks 把每个租户的签名密钥校验结果作废，让打包机重新验一遍。
//
// **恢复之后必须做这件事。** 待验清单会跳过「这一版已经验过」的租户
// （build_keystore_check.go），而恢复场景里数据库一个字都没动——于是控制台显示
// 「正常」，看的却是灾难前那台机器写下的记录。真相要等到第一次构建才暴露，
// 而那时明文 keystore 多半已经不在手边了。
//
// 做成接口而不是让人连库跑 DELETE（设计 §11）：灾难当天每少一步手工 SQL，
// 就少一次敲错表名的机会，而且这一步会进审计。
func (s *server) resetKeystoreChecks(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_CHECK_RESET",
			"reason and confirm=true are required")
		return
	}
	result, err := s.db.ExecContext(c.Request.Context(),
		`DELETE FROM app_configs WHERE config_key=?`, buildKeystoreCheckConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "KEYSTORE_CHECK_RESET_FAILED",
			"Unable to reset the keystore verification state")
		return
	}
	cleared, _ := result.RowsAffected()
	s.auditNow(newAudit(platformTenantID, actor(c), "keystore_checks_reset", "app-config",
		buildKeystoreCheckConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"cleared": cleared}))
	c.JSON(http.StatusOK, gin.H{"cleared": cleared,
		"detail": "the build agent will re-verify every tenant on its next idle poll"})
}

// 桶的 versioning 状态是「测试连接」那一刻的缓存值（设计 §8.2）。
//
// 不在每次看状态时都去问桶：那是一次跨网调用，而这个页面会被反复刷新。
// 从没测过时是 nil，控制台显示「未检查」——比显示一个乐观的 false 诚实。
func (s *server) cacheBackupBucketVersioning(enabled bool) {
	s.backupBucketVersioningMu.Lock()
	defer s.backupBucketVersioningMu.Unlock()
	s.backupBucketVersioningOK = &enabled
}

// forgetBackupBucketVersioning 在桶换掉之后把缓存结论作废。
//
// 不清的话，控制台会拿着「上一个桶开着 versioning」的结论去描述新桶——
// 而新桶多半还没开，那正是最需要提醒的时刻。
func (s *server) forgetBackupBucketVersioning() {
	s.backupBucketVersioningMu.Lock()
	defer s.backupBucketVersioningMu.Unlock()
	s.backupBucketVersioningOK = nil
}

func (s *server) backupBucketVersioning() any {
	s.backupBucketVersioningMu.RLock()
	defer s.backupBucketVersioningMu.RUnlock()
	if s.backupBucketVersioningOK == nil {
		return nil
	}
	return *s.backupBucketVersioningOK
}

// backupObjectFor 解析 :seq/:pair 并查到那一个包。发票据和下载都要做这件事。
//
// :pair 只当查表的键用，匹配不到就 404，**绝不参与拼字符串**——它来自 URL。
func (s *server) backupObjectFor(c *gin.Context) (backupRun, *backupObject, bool) {
	seq, ok := parseSeq(c.Param("seq"))
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SEQ", "seq must be a positive integer")
		return backupRun{}, nil, false
	}
	run, err := s.backupRunBySeq(c.Request.Context(), seq)
	if err != nil {
		problem(c, http.StatusNotFound, "BACKUP_NOT_FOUND", "No such backup")
		return backupRun{}, nil, false
	}
	pair := strings.TrimSpace(c.Param("pair"))
	for i := range run.Objects {
		if run.Objects[i].Pair == pair {
			return run, &run.Objects[i], true
		}
	}
	problem(c, http.StatusNotFound, "BACKUP_PAIR_NOT_FOUND",
		"this backup has no package for that pair of key holders")
	return backupRun{}, nil, false
}

// sameOrigin 判断 Origin 头指的就是这台机器自己。
//
// 同源永远放行：它在任何配置下都是安全的，而且不依赖 CORS_ORIGINS 配没配。
func sameOrigin(origin, host string) bool {
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host != "" && strings.EqualFold(parsed.Host, host)
}
