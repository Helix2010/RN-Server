package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/gin-gonic/gin"
)

// 打包机侧的备份接口（设计 platform-backup-recovery-2026-09-15 §8.1）。
//
// 打包机只出不进、从不监听端口（那台机器握着签名密钥），所以「立即备份」只能是
// 异步的：控制台建一条待办，打包机下一轮轮询自己来领。

const (
	// backupPayloadMaxBytes 是单份内层密文的上限
	backupPayloadMaxBytes = 512 * 1024 * 1024
	// backupStagingDirName 是两份内层密文在服务端落脚的地方。
	// 它们是**封给持有人的密文**，服务端读不懂——落盘是为了校验大小和流式封外层，
	// 不是设计缺口。真正的边界问题是它存在过（见 §2.1 的范围说明）
	backupStagingDirName = "rn-backup-staging"
)

func backupStagingRoot() string { return filepath.Join(os.TempDir(), backupStagingDirName) }

func backupStagingDir(runID string) string {
	// runID 是我们自己生成的 pbk_<hex>，但它从 URL 来，所以仍然做一次白名单过滤：
	// 一个带 ../ 的 id 会让下面的写入跑到暂存目录外面
	return filepath.Join(backupStagingRoot(), sanitizeBackupID(runID))
}

func sanitizeBackupID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cleanBackupStaging 清掉一次备份的暂存。收尾、判死、以及进程启动时都要调。
func cleanBackupStaging(runID string) {
	if id := sanitizeBackupID(runID); id != "" {
		_ = os.RemoveAll(filepath.Join(backupStagingRoot(), id))
	}
}

// ResetBackupStaging 在服务端启动时清掉上一次进程留下的残留。
//
// 不清的话，SIGKILL 或崩溃之后那些密文会一直留在磁盘上。它们打不开，但没有理由
// 留着——而且残留会让「两份都到齐了吗」这个判断读到上一次的文件。
func ResetBackupStaging() {
	_ = os.RemoveAll(backupStagingRoot())
}

// claimBackupRequest 原子认领一条待办（POST，不是 GET）。
//
// 用 POST 是因为它会改状态，而 safeMethod 把 GET 当安全方法——Origin 闸对 GET
// 完全不生效，而且任何 HTTP 客户端和代理都会对 GET 自动重试。
func (s *server) claimBackupRequest(c *gin.Context) {
	var body struct {
		Agent string `json:"agent"`
	}
	// 请求体可有可无：认领不需要参数，agent 只用于排查
	_ = decode(c, &body)

	run, ok, err := s.claimBackupRun(c.Request.Context(), strings.TrimSpace(body.Agent))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_CLAIM_FAILED", "Unable to claim a backup request")
		return
	}
	if !ok {
		c.Status(http.StatusNoContent)
		return
	}
	// 下发三个指纹供打包机**核对**——它封给自己 env 里那三把，任何一个对不上
	// 就拒绝执行并上报。比对的是指纹不是公钥本体，所以下发的内容没有被信任过
	recipients := make([]gin.H, 0, backupcontainer.SlotCount)
	for i, slot := range backupcontainer.SlotNames {
		recipients = append(recipients, gin.H{"slot": slot, "fingerprint": s.cfg.Backup.Recipients[i].Fingerprint})
	}
	cleanBackupStaging(run.ID)
	c.JSON(http.StatusOK, gin.H{"id": run.ID, "seq": run.Seq, "recipients": recipients})
}

// backupKeystores 返回**全部**租户的密封盒子。
//
// 门禁判据是「这个令牌名下有一条 running 的待办，而且 id 匹配」。v5 写的是「有
// pending 待办时才返回」——那和状态机自相矛盾：认领那一刻状态就变 running 了，
// 库里没有 pending，于是**每一次备份都拿不到盒子**。
//
// 不能复用 /keystore-checks：它 LIMIT 20 且跳过「这一版已验过」的租户，
// 拿它做备份会静默漏租户，而漏掉的那个租户的密钥就永远没有离线副本了。
func (s *server) backupKeystores(c *gin.Context) {
	runID := strings.TrimSpace(c.Query("request"))
	if runID == "" {
		problem(c, http.StatusBadRequest, "BACKUP_REQUEST_REQUIRED", "request is required")
		return
	}
	run, err := s.backupRunByID(c.Request.Context(), runID)
	if err != nil || run.Status != backupStatusRunning {
		// 403 而不是 404：这个接口一次给出全平台的密封盒子，比现有任何代理接口
		// 的价值都高，不该让人用它探测 id 是否存在
		problem(c, http.StatusForbidden, "BACKUP_REQUEST_NOT_RUNNING",
			"There is no backup request being produced under that id")
		return
	}

	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT tenant_id, version FROM app_configs WHERE config_key=? ORDER BY tenant_id`,
		buildKeystoreConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_KEYSTORE_QUERY_FAILED", "Unable to list keystores")
		return
	}
	defer rows.Close()

	type pending struct {
		tenant  string
		version int
	}
	all := []pending{}
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.tenant, &item.version); err != nil {
			problem(c, http.StatusInternalServerError, "BACKUP_KEYSTORE_QUERY_FAILED", "Unable to list keystores")
			return
		}
		all = append(all, item)
	}
	if err := rows.Err(); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_KEYSTORE_QUERY_FAILED", "Unable to list keystores")
		return
	}

	items := []gin.H{}
	for _, item := range all {
		sealed, alias, err := s.sealedBuildKeystoreFor(c.Request.Context(), item.tenant)
		if err != nil || len(sealed) == 0 {
			// 漏掉一个租户是**严重**的：它的签名密钥就此没有离线副本。
			// 所以记一条 error，而不是安静地跳过
			slog.Error("a tenant keystore could not be prepared for backup",
				"tenant", item.tenant, "backupId", run.ID, "error", err)
			continue
		}
		items = append(items, gin.H{
			"tenant": item.tenant, "version": item.version,
			"sealedKeystore": sealed, "keyAlias": alias,
		})
	}
	// 这个接口的价值比现有任何代理接口都高，单独记一条审计
	s.auditNow(newAudit(platformTenantID, "build-agent", "backup_keystores_read", "platform-backup", run.ID,
		"the build agent read every sealed keystore for a backup", requestID(c),
		map[string]any{"seq": run.Seq, "tenants": len(items)}))
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// receiveBackupPayload 收一份内层密文（multipart：meta / payload / sig，见 §4.7）。
//
// 一次备份要传两次（槽位 A 一份、B 一份）。两份都到齐时，服务端在**这一次请求里**
// 合并自己那部分、封三个外层、上传、落库。
func (s *server) receiveBackupPayload(c *gin.Context) {
	run, err := s.backupRunByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		problem(c, http.StatusNotFound, "BACKUP_REQUEST_NOT_FOUND", "No such backup request")
		return
	}
	if run.Status != backupStatusRunning {
		// 迟到的上报不是重复上报：记录可能已经被超时扫描判死了。
		// 明确告诉打包机不用重试，并且把本地明文暂存删掉
		c.JSON(http.StatusConflict, gin.H{
			"error":  "BACKUP_REQUEST_NOT_RUNNING",
			"status": run.Status,
			"detail": "This backup is no longer being produced; do not retry, and delete your local staging copy",
		})
		return
	}

	mediaType, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") || params["boundary"] == "" {
		problem(c, http.StatusBadRequest, "BACKUP_PAYLOAD_NOT_MULTIPART",
			"the body must be multipart/form-data with parts meta, payload and sig")
		return
	}

	reader := multipart.NewReader(c.Request.Body, params["boundary"])
	var (
		meta      backupbundle.PayloadMeta
		haveMeta  bool
		signature []byte
		staged    string
	)
	seenParts := map[string]bool{}
	// 这个请求出错时要把它自己写下的东西撤掉。留下一个半截的 <槽位>.enc 的话，
	// 此后**合法的**同槽位上报永远被当成「已经传过」拒掉，而这条记录只能等
	// 30 分钟产出超时——一次畸形请求就能让一次备份报废
	dir := backupStagingDir(run.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_STAGING_FAILED", "Unable to stage the payload")
		return
	}

	committed := false
	defer func() {
		if committed || staged == "" {
			return
		}
		for _, suffix := range []string{".enc", ".sig", ".meta.json"} {
			_ = os.Remove(filepath.Join(dir, meta.RecipientSlot+suffix))
		}
	}()

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			problem(c, http.StatusBadRequest, "BACKUP_PAYLOAD_MALFORMED", "the multipart body could not be read")
			return
		}
		// 每个部件只许出现一次。两个 meta 的后果很具体：第一个决定 payload 落到
		// 哪个文件，最后一个决定 sidecar 写成哪个槽位——暂存目录里会出现
		// A.enc + B.sig + B.meta.json 这种自相矛盾的组合，而此后**合法的 A 上报
		// 永远 400**（A.enc 已被占住），这条记录只能等 30 分钟产出超时
		if seenParts[part.FormName()] {
			problem(c, http.StatusBadRequest, "BACKUP_PAYLOAD_DUPLICATE_PART",
				"the "+part.FormName()+" part appears more than once")
			return
		}
		seenParts[part.FormName()] = true

		switch part.FormName() {
		case "meta":
			raw, err := io.ReadAll(io.LimitReader(part, backupbundle.PayloadMetaMaxBytes+1))
			if err != nil {
				problem(c, http.StatusBadRequest, "BACKUP_PAYLOAD_MALFORMED", "the meta part could not be read")
				return
			}
			parsed, err := backupbundle.ParsePayloadMeta(raw)
			if err != nil {
				problem(c, http.StatusBadRequest, "BACKUP_META_INVALID", err.Error())
				return
			}
			// 槽位名合法不等于**该收**：合法集合是 A/B/C，而内层收件人只有 A/B
			// （AB 与 AC 共用封给 A 的那份）。不在这里拒掉的话，一份封给 C 的内层
			// 会被静默收下、占掉磁盘，然后这次备份干等到产出超时——运维看到的是
			// 「打包机半路没了」，而不是「它传错了槽位」
			if !backupcontainer.IsInnerSlot(parsed.RecipientSlot) {
				problem(c, http.StatusBadRequest, "BACKUP_SLOT_NOT_AN_INNER_RECIPIENT",
					"slot "+parsed.RecipientSlot+" is not an inner recipient for this threshold; expected one of "+
						strings.Join(backupcontainer.InnerSlots(), ", "))
				return
			}
			meta, haveMeta = parsed, true
		case "sig":
			signature, err = io.ReadAll(io.LimitReader(part, 1024))
			if err != nil {
				problem(c, http.StatusBadRequest, "BACKUP_PAYLOAD_MALFORMED", "the sig part could not be read")
				return
			}
		case "payload":
			// meta 必须排在 payload 之前。这样服务端可以先解析元数据、校验通过
			// 再决定要不要收那 512 MiB——否则「先校验再收」这句话不成立
			if !haveMeta {
				problem(c, http.StatusBadRequest, "BACKUP_META_MISSING",
					"the meta part must come before the payload part")
				return
			}
			var duplicate bool
			staged, duplicate, err = stageBackupPayload(dir, meta.RecipientSlot, part)
			if duplicate {
				// 409 而不是 400：同一槽位重复传是**正常的重试**撞上了已经收到的
				// 那一份，不是请求有错。打包机据此知道不用再传这一份
				c.JSON(http.StatusConflict, gin.H{"error": "BACKUP_SLOT_ALREADY_UPLOADED",
					"slot": meta.RecipientSlot, "detail": err.Error()})
				return
			}
			if err != nil {
				problem(c, http.StatusRequestEntityTooLarge, "BACKUP_PAYLOAD_REJECTED", err.Error())
				return
			}
		}
		_ = part.Close()
	}
	if !haveMeta || staged == "" || len(signature) == 0 {
		problem(c, http.StatusBadRequest, "BACKUP_PAYLOAD_INCOMPLETE",
			"all three parts (meta, payload, sig) are required")
		return
	}

	// 打包机换了签名密钥而没走登记流程，是个必须让人看见的信号
	if err := s.checkBackupSigningFingerprint(c, run, meta); err != nil {
		return
	}
	if err := writeStagedSidecars(dir, meta, signature); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_STAGING_FAILED", "Unable to stage the payload")
		return
	}

	missing := missingInnerSlots(dir)
	if len(missing) > 0 {
		committed = true
		c.JSON(http.StatusAccepted, gin.H{"received": meta.RecipientSlot, "stillExpecting": missing})
		return
	}
	// **在这里记，不等组装。** payload_received_at 的语义是「两份都到齐了」，
	// 而这一刻就是。记在组装里面的话，服务端自己那部分读不到时它会停在 NULL，
	// 于是运维照 §8.4 的列注释排查，得出的是「打包机没传上来」——一个完全错误的
	// 结论，而真相是打包机做完了、服务端配置有问题。
	if _, err := s.markBackupPayloadComplete(c.Request.Context(), run.ID); err != nil {
		slog.Error("cannot record that both backup payloads arrived", "backupId", run.ID, "error", err)
	}
	committed = true
	s.completeBackup(c, run)
}

func (s *server) checkBackupSigningFingerprint(c *gin.Context, run backupRun, meta backupbundle.PayloadMeta) error {
	record, err := s.backupSigningKeyRecord(c.Request.Context())
	if err != nil || record == nil || record.Current.Fingerprint != meta.BackupSigningFingerprint {
		reason := "the build agent reported a backup signing key that is not the registered one"
		if _, failErr := s.failBackupRun(c.Request.Context(), run.ID, reason); failErr != nil {
			slog.Error("unable to fail a backup after a signing key mismatch", "backupId", run.ID, "error", failErr)
		}
		cleanBackupStaging(run.ID)
		problem(c, http.StatusConflict, "BACKUP_SIGNING_KEY_MISMATCH",
			"the reported backup signing fingerprint is not the registered one; register it first")
		return errors.New("signing key mismatch")
	}
	return nil
}

// stageBackupPayload 把密文落到 0700 的暂存目录里，同一槽位重复传直接拒绝。
// stageBackupPayload 把密文落到 0700 的暂存目录里。
//
// 第二个返回值说明失败是不是「这个槽位已经传过了」——那是正常重试撞上已收到的
// 那一份，调用方翻 409；其余是请求本身有问题，翻 413。
func stageBackupPayload(dir, slot string, body io.Reader) (string, bool, error) {
	path := filepath.Join(dir, slot+".enc")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", true, fmt.Errorf("slot %s has already been uploaded for this backup", slot)
	}
	defer file.Close()
	written, err := io.Copy(file, io.LimitReader(body, backupPayloadMaxBytes+1))
	if err != nil {
		_ = os.Remove(path)
		return "", false, fmt.Errorf("the payload could not be received")
	}
	if written > backupPayloadMaxBytes {
		_ = os.Remove(path)
		return "", false, fmt.Errorf("the payload exceeds %d bytes", int64(backupPayloadMaxBytes))
	}
	return path, false, nil
}

func writeStagedSidecars(dir string, meta backupbundle.PayloadMeta, signature []byte) error {
	if err := os.WriteFile(filepath.Join(dir, meta.RecipientSlot+".sig"), signature, 0o600); err != nil {
		return err
	}
	encoded, err := marshalIndentJSON(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, meta.RecipientSlot+".meta.json"), encoded, 0o600)
}

// missingInnerSlots 说明还差哪几份。判据是文件系统而不是内存：服务端重启之后
// 暂存还在就还能继续，暂存没了就走产出超时，两种情况都不会卡死
func missingInnerSlots(dir string) []string {
	missing := []string{}
	for _, slot := range backupcontainer.InnerSlots() {
		for _, suffix := range []string{".enc", ".sig", ".meta.json"} {
			if _, err := os.Stat(filepath.Join(dir, slot+suffix)); err != nil {
				missing = append(missing, slot)
				break
			}
		}
	}
	return missing
}

// failBackupRequest 让打包机主动上报失败，不要让服务端干等到超时。
func (s *server) failBackupRequest(c *gin.Context) {
	var body struct {
		Reason string `json:"reason"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.Reason) == "" {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_FAIL", "reason is required")
		return
	}
	run, err := s.backupRunByID(c.Request.Context(), c.Param("id"))
	if err != nil {
		problem(c, http.StatusNotFound, "BACKUP_REQUEST_NOT_FOUND", "No such backup request")
		return
	}
	changed, err := s.failBackupRun(c.Request.Context(), run.ID, body.Reason)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_FAIL_FAILED", "Unable to record the failure")
		return
	}
	cleanBackupStaging(run.ID)
	if !changed {
		// 迟到的 /fail：记录可能已经 succeeded 了。**不做任何写**，
		// 并且让打包机知道不用重试
		current, _ := s.backupRunByID(c.Request.Context(), run.ID)
		c.JSON(http.StatusConflict, gin.H{
			"error":  "BACKUP_ALREADY_FINISHED",
			"status": current.Status,
			"detail": "This backup already finished; do not retry, and delete your local staging copy",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": backupStatusFailed})
}

// backupBucketClient 按 env 里那组独立凭据建一个客户端。
//
// **独立的桶和独立凭据**，不复用产物桶：产物桶凭据泄露不该等于全平台签名密钥泄露。
func (s *server) backupBucketClient() (objectstore.Client, error) {
	bucket := s.cfg.Backup.Bucket
	if strings.TrimSpace(bucket.Bucket) == "" {
		return nil, errors.New("the backup bucket is not configured")
	}
	if s.cfg.Environment == "production" && bucket.Endpoint != "" &&
		!strings.HasPrefix(bucket.Endpoint, "https://") {
		return nil, errors.New("the backup bucket endpoint must be https in production")
	}
	return s.objects.New(objectstore.Config{
		Endpoint: bucket.Endpoint, Region: bucket.Region, Bucket: bucket.Bucket,
		AccessKeyID: bucket.AccessKeyID, SecretAccessKey: bucket.SecretAccessKey,
		ForcePathStyle: bucket.Endpoint != "",
	})
}

// backupObjectKey 拼对象键。它只在**上传**时用一次，结果存进 objects 那一列；
// 下载时从行上读，不重新拼——主机改名或在新机器上恢复之后前缀就变了
func backupObjectKey(prefix, instance string, seq uint64, pair, suffix string) string {
	parts := []string{}
	if p := strings.Trim(strings.TrimSpace(prefix), "/"); p != "" {
		parts = append(parts, p)
	}
	parts = append(parts, instance, fmt.Sprintf("backup-%08d-%s%s", seq, pair, suffix))
	return strings.Join(parts, "/")
}

func sha256File(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func parseSeq(raw string) (uint64, bool) {
	seq, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil || seq == 0 {
		return 0, false
	}
	return seq, true
}

var _ = time.Now

// sweepBackupStaging 清掉不再属于任何在途备份的暂存目录。
//
// 判死（超时扫描、force-fail、打包机上报失败）只写库，暂存还留在盘上——一条被
// 判死的备份会留下最多两份 512 MiB 的密文。它们是封给持有人的密文、服务端读不懂，
// 但这台机器同时在构建 APK，磁盘被占满倒下的不止备份功能。
//
// 扫一遍而不是让每个判死点各自清：那样漏一个点就漏一份，而崩溃留下的残留谁也
// 收不掉。这里以「库里这条还 running 吗」为唯一判据，和超时扫描一样不依赖内存状态。
func (s *server) sweepBackupStaging(ctx context.Context) {
	entries, err := os.ReadDir(backupStagingRoot())
	if err != nil {
		return // 目录还没建起来就是没有残留
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		run, err := s.backupRunByID(ctx, entry.Name())
		if err == nil && run.Status == backupStatusRunning {
			continue // 还在产出，留着
		}
		slog.Info("removing staging for a backup that is no longer in flight", "backupId", entry.Name())
		cleanBackupStaging(entry.Name())
	}
}
