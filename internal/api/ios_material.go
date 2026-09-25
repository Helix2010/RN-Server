package api

// iOS 签名材料的密文分发（设计 docs/design/ios-signing-material-distribution-2026-09-19.md）。
//
// 材料在管理员的浏览器或离线机器上加密给平台公钥，服务端**只存、只转发密文**：它没有任何
// 一把私钥，读不懂自己存的每一份。这是整套打包机设计的前提——服务端被攻破也变不出能用的
// 签名材料。明文存服务端、机器来取的做法在设计第 2 节被明确排除。
//
// 这里做的检查**全部是帮运维当场发现拿错了文件**，不是安全控制：形状对不对、用途与种类
// 配不配、加密给的是不是一把登记过的公钥。传错了当场报错，好过等一台 Mac 取回去解不开。
// 真正的判据在 Mac 上：私钥只在那里，解不开就是解不开。

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
	"github.com/gin-gonic/gin"
)

// buildIOSMaterialConfigKey 存两把平台公钥。公钥不是机密，明文存。
const buildIOSMaterialConfigKey = "build.ios.material"

const (
	iosMaterialAuditTarget = "ios-signing-material"
	// iosMaterialMaxBody 是一份密文的大小上限，比 iosmaterial 自己的上限略宽，
	// 好让"超了"这件事由那一侧报出具体原因
	iosMaterialMaxBody = int64(iosmaterial.MaxBoxSize + 4096)
	// iosMaterialMaxRows 是一次列出的上限。真实数量是租户数的个位数倍
	iosMaterialMaxRows = 512
)

// iosMaterialRecipient 是一把平台公钥。
type iosMaterialRecipient struct {
	PublicKey    string `json:"publicKey"`
	SHA256       string `json:"sha256"`
	RegisteredBy string `json:"registeredBy"`
	RegisteredAt string `json:"registeredAt"`
}

// iosMaterialDoc 是 build.ios.material 的内容：按角色两把。
//
// **两把而不是一把**：合成一把的话，拿到构建账户那把私钥就同时获得了上传能力——而那正是
// Mac 上三个账户分开要挡的事（设计 §4.1）。
type iosMaterialDoc struct {
	Builder  *iosMaterialRecipient `json:"builder,omitempty"`
	Uploader *iosMaterialRecipient `json:"uploader,omitempty"`
}

type iosMaterialSnapshot struct {
	Doc     iosMaterialDoc
	Version int
}

// forPurpose 回这个用途该用哪一把公钥。
func (d iosMaterialDoc) forPurpose(purpose string) (iosMaterialRecipient, bool) {
	switch purpose {
	case iosmaterial.PurposeBuilder:
		if d.Builder != nil {
			return *d.Builder, true
		}
	case iosmaterial.PurposeUploader:
		if d.Uploader != nil {
			return *d.Uploader, true
		}
	}
	return iosMaterialRecipient{}, false
}

func (d iosMaterialDoc) validate() error {
	for role, recipient := range map[string]*iosMaterialRecipient{"builder": d.Builder, "uploader": d.Uploader} {
		if recipient == nil {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(recipient.PublicKey)
		switch {
		case err != nil || len(raw) != 32:
			return fmt.Errorf("%s public key is not a 32 byte base64 X25519 key", role)
		case recipient.SHA256 != fingerprint.SHA256Hex(raw):
			return fmt.Errorf("%s sha256 does not match its public key", role)
		}
	}
	if d.Builder != nil && d.Uploader != nil && d.Builder.SHA256 == d.Uploader.SHA256 {
		return errors.New("the builder and uploader keys are the same; then the build account can also decrypt upload keys")
	}
	return nil
}

func readIOSMaterialRecipients(ctx context.Context, q rowQuerier, forUpdate bool) (iosMaterialSnapshot, error) {
	var snapshot iosMaterialSnapshot
	var raw []byte
	query := `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=?`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query, platformTenantID, buildIOSMaterialConfigKey).Scan(&raw, &snapshot.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(raw, &snapshot.Doc); err != nil {
		return snapshot, fmt.Errorf("%s is not valid JSON: %w", buildIOSMaterialConfigKey, err)
	}
	if err := snapshot.Doc.validate(); err != nil {
		return snapshot, fmt.Errorf("%s is invalid: %w", buildIOSMaterialConfigKey, err)
	}
	return snapshot, nil
}

// rowsQuerier 是要跑多行查询的那一部分（rowQuerier 只有单行）。
type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// storedIOSMaterial 是表里的一行，不含密文。
type storedIOSMaterial struct {
	Kind            string `json:"kind"`
	TeamID          string `json:"teamId"`
	Scope           string `json:"scope"`
	Purpose         string `json:"purpose"`
	RecipientSHA256 string `json:"recipientSha256"`
	Version         int64  `json:"version"`
	UploadedBy      string `json:"uploadedBy"`
	UploadedAt      string `json:"uploadedAt"`
}

// scopeFor 回这一份材料在 (kind, team) 下的那一维：描述文件按 bundle id 分，证书与上传 Key
// 都是**这个 Team 一份、所有 Mac 共用**，所以是空串。
//
// 上传 Key 起初按机器分（每台一把，想让丢一台只吊销一把）。那条策略挡不住它真正要挡的事：
// 证书本来就全机共用，丢一台 Mac 就要在 Apple 后台吊销证书、重签、给所有机器重发——那一刻
// 所有 Mac 本来就停了，上传 Key 分不分机器省不下这次停机。代价却是天天在付：ASC Key 只能
// 在租户自己的 Apple 账号里建，按机器分就等于把"平台有几台打包机"漏给租户，租户页上还得
// 摆一份机器列表（设计 ios-signing-material-distribution-2026-09-19 §5）。
func scopeFor(box iosmaterial.Box) string {
	if box.Kind == iosmaterial.KindProfile {
		return box.BundleID
	}
	return ""
}

func listIOSMaterial(ctx context.Context, q rowsQuerier, where string, args ...any) ([]storedIOSMaterial, error) {
	query := `SELECT kind,team_id,scope,purpose,recipient_sha256,version,uploaded_by,uploaded_at
		FROM ios_signing_material`
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" ORDER BY team_id,kind,scope LIMIT %d", iosMaterialMaxRows)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storedIOSMaterial{}
	for rows.Next() {
		var item storedIOSMaterial
		var uploadedAt time.Time
		if err := rows.Scan(&item.Kind, &item.TeamID, &item.Scope, &item.Purpose,
			&item.RecipientSHA256, &item.Version, &item.UploadedBy, &uploadedAt); err != nil {
			return nil, err
		}
		item.UploadedAt = uploadedAt.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	return out, rows.Err()
}

// ---- 管理端 ----

// iosMaterialOverview GET /v1/admin/platform/ios-material：两把公钥与已经存着的材料。
// **不下发密文**：控制台不需要它，而少一个出口就少一处要想清楚的地方。
func (s *server) iosMaterialOverview(c *gin.Context) {
	ctx := c.Request.Context()
	snapshot, err := readIOSMaterialRecipients(ctx, s.db, false)
	if err != nil {
		slog.Error("cannot read the iOS material recipients", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_RECIPIENTS_INVALID",
			"Stored "+buildIOSMaterialConfigKey+" configuration cannot be read")
		return
	}
	items, err := listIOSMaterial(ctx, s.db, "")
	if err != nil {
		slog.Error("cannot list the iOS signing material", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"version":    snapshot.Version,
		"recipients": gin.H{"builder": snapshot.Doc.Builder, "uploader": snapshot.Doc.Uploader},
		"items":      items,
	})
}

// registerIOSMaterialRecipients PUT /v1/admin/platform/ios-material/recipients：登记两把平台公钥。
func (s *server) registerIOSMaterialRecipients(c *gin.Context) {
	var body struct {
		Builder  string `json:"builderPublicKey"`
		Uploader string `json:"uploaderPublicKey"`
		machineWriteCommon
	}
	if decode(c, &body) != nil || !body.valid() {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL",
			"builderPublicKey, uploaderPublicKey, expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	doc := iosMaterialDoc{}
	for role, value := range map[string]string{"builder": body.Builder, "uploader": body.Uploader} {
		raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
		if err != nil || len(raw) != 32 {
			problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL",
				role+"PublicKey must be a 32 byte X25519 public key in standard base64 (ios-material keygen writes it next to the private key)")
			return
		}
		recipient := &iosMaterialRecipient{
			PublicKey: strings.TrimSpace(value), SHA256: fingerprint.SHA256Hex(raw),
			RegisteredBy: actor(c), RegisteredAt: now.Format(time.RFC3339),
		}
		if role == "builder" {
			doc.Builder = recipient
		} else {
			doc.Uploader = recipient
		}
	}
	if err := doc.validate(); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", err.Error())
		return
	}

	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to save the iOS material recipients")
		return
	}
	defer tx.Rollback()
	snapshot, err := readIOSMaterialRecipients(ctx, tx, true)
	if err != nil {
		slog.Error("cannot read the iOS material recipients", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_RECIPIENTS_INVALID",
			"Stored "+buildIOSMaterialConfigKey+" configuration cannot be read")
		return
	}
	if snapshot.Version != *body.ExpectedVersion {
		problem(c, http.StatusConflict, "IOS_MATERIAL_VERSION_CONFLICT", "The iOS material configuration changed; refresh and retry")
		return
	}
	// 换公钥 = 已经存着的密文全部作废：它们是加密给旧公钥的，新私钥解不开。与其留着让机器
	// 一份份地取回去解不开，不如当场说清楚有多少份会失效，由人决定
	stale, err := listIOSMaterial(ctx, tx, "")
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	orphaned := 0
	for _, item := range stale {
		if recipient, ok := doc.forPurpose(item.Purpose); !ok || recipient.SHA256 != item.RecipientSHA256 {
			orphaned++
		}
	}
	value, _ := json.Marshal(doc)
	var result sql.Result
	if snapshot.Version == 0 {
		result, err = tx.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			platformTenantID, buildIOSMaterialConfigKey, value, actor(c), now, platformTenantID, buildIOSMaterialConfigKey)
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, platformTenantID, buildIOSMaterialConfigKey, snapshot.Version)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to save the iOS material recipients")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "IOS_MATERIAL_VERSION_CONFLICT", "The iOS material configuration changed; refresh and retry")
		return
	}
	event := newAudit(platformTenantID, actor(c), "ios_material_recipients", iosMaterialAuditTarget, "recipients",
		strings.TrimSpace(body.Reason), requestID(c), map[string]any{
			"builderSha256": doc.Builder.SHA256, "uploaderSha256": doc.Uploader.SHA256, "orphanedMaterial": orphaned,
		})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to save the iOS material recipients")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"version":    snapshot.Version + 1,
		"recipients": gin.H{"builder": doc.Builder, "uploader": doc.Uploader},
		// 有多少份密文因为换钥匙而作废。控制台要把这个数字摆在人眼前
		"orphanedMaterial": orphaned,
	})
}

// uploadIOSMaterial POST /v1/admin/platform/ios-material：收一份密文。
func (s *server) uploadIOSMaterial(c *gin.Context) {
	ctx := c.Request.Context()
	recipients, err := readIOSMaterialRecipients(ctx, s.db, false)
	if err != nil {
		slog.Error("cannot read the iOS material recipients", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_RECIPIENTS_INVALID",
			"Stored "+buildIOSMaterialConfigKey+" configuration cannot be read")
		return
	}
	raw, err := readLimitedBody(c, iosMaterialMaxBody)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", "The ciphertext could not be read: "+err.Error())
		return
	}
	box, err := iosmaterial.ParseBox(raw)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", err.Error())
		return
	}
	recipient, ok := recipients.Doc.forPurpose(box.Purpose)
	switch {
	case !ok:
		problem(c, http.StatusConflict, "IOS_MATERIAL_RECIPIENT_NOT_REGISTERED",
			"No platform key is registered for "+box.Purpose+"; register the two public keys from `ios-material keygen` first")
		return
	case recipient.SHA256 != box.RecipientSHA256:
		problem(c, http.StatusConflict, "IOS_MATERIAL_RECIPIENT_UNKNOWN",
			"This material is encrypted to "+box.RecipientSHA256+", but the registered "+box.Purpose+" key is "+recipient.SHA256+
				". No machine holds the private key for that fingerprint, so nothing could ever decrypt it.")
		return
	}
	scope := scopeFor(box)

	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to store the material")
		return
	}
	defer tx.Rollback()
	// 读旧版本要在事务里加锁：两个人同时传同一格时，不加锁会算出同一个版本号，后传的那份
	// 在装过前一份的机器上被当成"已经装了"
	var previous int64
	err = tx.QueryRowContext(ctx,
		`SELECT version FROM ios_signing_material WHERE kind=? AND team_id=? AND scope=? FOR UPDATE`,
		box.Kind, box.TeamID, scope).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	version := nextIOSMaterialVersion(previous, now)
	// 一格只留当前这一版：旧密文直接被替换，换过什么在审计里查
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ios_signing_material(kind,team_id,scope,purpose,recipient_sha256,version,ciphertext,uploaded_by,uploaded_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE purpose=VALUES(purpose),recipient_sha256=VALUES(recipient_sha256),
		   version=VALUES(version),ciphertext=VALUES(ciphertext),uploaded_by=VALUES(uploaded_by),uploaded_at=VALUES(uploaded_at)`,
		box.Kind, box.TeamID, scope, box.Purpose, box.RecipientSHA256, version, raw, actor(c), now); err != nil {
		slog.Error("cannot store the iOS signing material", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to store the material")
		return
	}
	event := newAudit(platformTenantID, actor(c), "ios_material_upload", iosMaterialAuditTarget,
		box.Kind+":"+box.TeamID+":"+scope, "", requestID(c), map[string]any{
			"kind": box.Kind, "teamId": box.TeamID, "scope": scope,
			"recipientSha256": box.RecipientSHA256, "version": version,
		})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to store the material")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"kind": box.Kind, "teamId": box.TeamID, "scope": scope,
		"version": version, "recipientSha256": box.RecipientSHA256,
		"uploadedAt": now.Format(time.RFC3339),
	})
}

// nextIOSMaterialVersion 给一格材料的新版本号：当前的毫秒时间戳，但至少比旧版本大 1。
//
// 版本号不能随删除重来。打包机按「本机装到的版本 >= 清单上的版本」跳过已装的材料，而删除是
// 直接删行：删掉再传的那份如果从 1 开始，一台装过第 3 版的机器会一直把它当成旧的，新证书
// 永远装不上。用时间戳就不必另外记住「这一格曾经到过第几版」；以前的小版本号（1、2、3……）
// 自然小于任何时间戳，已经装在机器上的那些照样会被新传的替换。
func nextIOSMaterialVersion(previous int64, now time.Time) int64 {
	if version := now.UnixMilli(); version > previous {
		return version
	}
	return previous + 1
}

// removeIOSMaterial POST /v1/admin/platform/ios-material/remove：删一格。
func (s *server) removeIOSMaterial(c *gin.Context) {
	var body struct {
		Kind   string `json:"kind"`
		TeamID string `json:"teamId"`
		Scope  string `json:"scope"`
		// ExpectedVersion 可选：大于 0 时只删这一版。确认框开着的那几十秒里有人传了新版，
		// 删掉的就不该是那份新的
		ExpectedVersion int64  `json:"expectedVersion"`
		Reason          string `json:"reason"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || body.ExpectedVersion < 0 || len([]rune(strings.TrimSpace(body.Reason))) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", "kind, teamId, reason (at least 3 characters) and confirm=true are required")
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT version FROM ios_signing_material WHERE kind=? AND team_id=? AND scope=? FOR UPDATE`,
		body.Kind, body.TeamID, body.Scope).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "IOS_MATERIAL_NOT_FOUND", "No material is stored for that kind, team and scope")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return
	}
	if body.ExpectedVersion > 0 && current != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_IOS_MATERIAL", "This material was replaced by a newer version; refresh and decide again")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ios_signing_material WHERE kind=? AND team_id=? AND scope=?`,
		body.Kind, body.TeamID, body.Scope); err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return
	}
	event := newAudit(platformTenantID, actor(c), "ios_material_remove", iosMaterialAuditTarget,
		body.Kind+":"+body.TeamID+":"+body.Scope, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"kind": body.Kind, "teamId": body.TeamID, "scope": body.Scope, "version": current})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return
	}
	// 删掉之后机器下次盘点就不再看见它。上传 Key 会被打包机当作墓碑处理：下一轮同步发现清单里
	// 这个 Team 没有上传 Key 了，就请上传账户删掉本机那一份（cmd/build-agent/ios_material.go，
	// 只删从清单装上的）。证书与描述文件**已经装到机器上的那一份不会消失**——那要人去那台
	// 机器上清（运维手册 §5 退役清单），或者吊销机器
	c.JSON(http.StatusOK, gin.H{"removed": true})
}

// ---- 构建机 ----

// listIOSMaterialForMachine GET /v1/build-agent/ios-material：这台机器该装哪些材料。
// 只回清单，不回密文——密文一份一份取，每份都是几 KB 到几十 KB。
func (s *server) listIOSMaterialForMachine(c *gin.Context) {
	// 三样材料都是这个 Team 一份、所有 Mac 共用：不再按机器筛（scopeFor 那段注释说了为什么）
	items, err := listIOSMaterial(c.Request.Context(), s.db, "")
	if err != nil {
		slog.Error("cannot list the iOS signing material", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	// complete：清单没被 LIMIT 截断。打包机只在清单完整时才把"清单里没有"当成"已撤下"去删本机
	// 的上传 Key（墓碑，cmd/build-agent/ios_material.go）——截断时删，就会把排在后面的 Team 的 Key
	// 从每台 Mac 上删掉
	c.JSON(http.StatusOK, gin.H{"items": items, "complete": len(items) < iosMaterialMaxRows})
}

// getIOSMaterialBox GET /v1/build-agent/ios-material/box：取一份密文，原样下发。
func (s *server) getIOSMaterialBox(c *gin.Context) {
	kind := strings.TrimSpace(c.Query("kind"))
	team := strings.TrimSpace(c.Query("teamId"))
	scope := strings.TrimSpace(c.Query("scope"))
	var ciphertext []byte
	err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT ciphertext FROM ios_signing_material WHERE kind=? AND team_id=? AND scope=?`,
		kind, team, scope).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "IOS_MATERIAL_NOT_FOUND", "No material is stored for that kind, team and scope")
		return
	}
	if err != nil {
		slog.Error("cannot read the iOS signing material", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/json; charset=utf-8", ciphertext)
}
