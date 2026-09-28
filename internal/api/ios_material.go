package api

// iOS 签名材料的密文分发（设计 docs/design/ios-signing-material-distribution-2026-09-19.md）。
//
// 材料在租户成员的浏览器里加密给平台公钥，服务端**只存、只转发密文**：它没有任何
// 一把私钥，读不懂自己存的每一份。这是整套打包机设计的前提——服务端被攻破也变不出能用的
// 签名材料。明文存服务端、机器来取的做法在设计第 2 节被明确排除。
//
// 材料按租户存（设计 ios-tenant-owned-signing-material-2026-09-25 §3.1）：同一个 Team 的租户各交各的，
// 一个租户换、删自己的材料碰不到别人。租户怎么交在 ios_material_tenant.go；这里是存储、平台公钥、
// 平台的紧急删除与打包机取材料。
//
// 这里做的检查**全部是帮人当场发现拿错了文件**，不是安全控制：形状对不对、用途与种类
// 配不配、加密给的是不是一把登记过的公钥。传错了当场报错，好过等一台 Mac 取回去解不开。
// 真正的判据在 Mac 上：私钥只在那里，解不开就是解不开；解开之后还要核对内容（§4.2）。

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
	// iosMaterialEmergencyRemoveAction 是平台紧急删除的审计动作：租户页按它列出「平台管理员删了什么」
	iosMaterialEmergencyRemoveAction = "ios_material_emergency_remove"
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
	// TenantID 是这份材料属于的租户；"0" 是按 Team 存的旧行（只下发给还没升级的打包机）
	TenantID        string `json:"tenantId"`
	Kind            string `json:"kind"`
	TeamID          string `json:"teamId"`
	Scope           string `json:"scope"`
	Purpose         string `json:"purpose"`
	RecipientSHA256 string `json:"recipientSha256"`
	Version         int64  `json:"version"`
	UploadedBy      string `json:"uploadedBy"`
	UploadedAt      string `json:"uploadedAt"`
	// Legacy：从旧行复制来的 v1 密文，里面没有租户。打包机只对这种项接受 v1
	Legacy bool `json:"legacy"`
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
	query := `SELECT tenant_id,kind,team_id,scope,purpose,recipient_sha256,version,uploaded_by,uploaded_at,legacy
		FROM ios_signing_material`
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" ORDER BY tenant_id,team_id,kind,scope LIMIT %d", iosMaterialMaxRows)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storedIOSMaterial{}
	for rows.Next() {
		var item storedIOSMaterial
		var uploadedAt time.Time
		if err := rows.Scan(&item.TenantID, &item.Kind, &item.TeamID, &item.Scope, &item.Purpose,
			&item.RecipientSHA256, &item.Version, &item.UploadedBy, &uploadedAt, &item.Legacy); err != nil {
			return nil, err
		}
		item.UploadedAt = uploadedAt.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	return out, rows.Err()
}

// ---- 管理端 ----

// iosMaterialOverview GET /v1/admin/platform/ios-material：两把公钥与已经存着的材料（每项带租户 slug）。
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
	slugs, err := s.tenantSlugsByID(ctx)
	if err != nil {
		slog.Error("cannot read the tenant slugs", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	views := make([]gin.H, 0, len(items))
	for _, item := range items {
		views = append(views, gin.H{
			"tenantId": item.TenantID, "tenantSlug": slugs[item.TenantID], "kind": item.Kind, "teamId": item.TeamID,
			"scope": item.Scope, "purpose": item.Purpose, "recipientSha256": item.RecipientSHA256, "version": item.Version,
			"uploadedBy": item.UploadedBy, "uploadedAt": item.UploadedAt, "legacy": item.Legacy,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"version":    snapshot.Version,
		"recipients": gin.H{"builder": snapshot.Doc.Builder, "uploader": snapshot.Doc.Uploader},
		"items":      views,
	})
}

// tenantSlugsByID 是租户 id → slug，删掉的租户也在里面（材料行可能还留着）。
func (s *server) tenantSlugsByID(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,slug FROM tenants`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, slug string
		if err := rows.Scan(&id, &slug); err != nil {
			return nil, err
		}
		out[id] = slug
	}
	return out, rows.Err()
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

// storeIOSMaterial 把一份核对过的密文存进这个租户的那一格，返回新版本号。调用方负责提交事务。
//
// 读旧版本要在事务里加锁：同一格被同时传两次时，不加锁会算出同一个版本号，后传的那份在装过前一份的
// 机器上被当成"已经装了"。一格只留当前这一版：旧密文直接被替换，换过什么在审计里查；租户重传之后
// 是 v2，legacy 回到 0。
func storeIOSMaterial(ctx context.Context, tx *sql.Tx, tenant string, box iosmaterial.Box, raw []byte, by string, now time.Time) (int64, error) {
	scope := scopeFor(box)
	var previous int64
	err := tx.QueryRowContext(ctx,
		`SELECT version FROM ios_signing_material WHERE tenant_id=? AND kind=? AND team_id=? AND scope=? FOR UPDATE`,
		tenant, box.Kind, box.TeamID, scope).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	version := nextIOSMaterialVersion(previous, now)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ios_signing_material(tenant_id,kind,team_id,scope,purpose,recipient_sha256,version,ciphertext,uploaded_by,uploaded_at,legacy)
		 VALUES(?,?,?,?,?,?,?,?,?,?,0)
		 ON DUPLICATE KEY UPDATE purpose=VALUES(purpose),recipient_sha256=VALUES(recipient_sha256),
		   version=VALUES(version),ciphertext=VALUES(ciphertext),uploaded_by=VALUES(uploaded_by),uploaded_at=VALUES(uploaded_at),legacy=0`,
		tenant, box.Kind, box.TeamID, scope, box.Purpose, box.RecipientSHA256, version, raw, by, now); err != nil {
		return 0, err
	}
	return version, nil
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

// removeIOSMaterial POST /v1/admin/platform/ios-material/remove：平台管理员的**紧急删除**（设计
// ios-tenant-owned-signing-material-2026-09-25 §3.4），用于证书泄露、账号被盗。平台不代交材料，只能删。
//
// 审计记在那个租户名下：租户页上要显示「平台管理员于某时删除了某材料：原因」。删掉之后 Mac 下一轮同步
// 发现清单里没有这一格，就把本机那一份撤掉（墓碑，cmd/build-agent/ios_material.go）——不撤等于没删。
// tenantId="0" 是按 Team 存的旧行，只有还没升级的打包机取它。
func (s *server) removeIOSMaterial(c *gin.Context) {
	var body struct {
		TenantID string `json:"tenantId"`
		Kind     string `json:"kind"`
		TeamID   string `json:"teamId"`
		Scope    string `json:"scope"`
		// ExpectedVersion 可选：大于 0 时只删这一版。确认框开着的那几十秒里租户传了新版，
		// 删掉的就不该是那份新的
		ExpectedVersion int64  `json:"expectedVersion"`
		Reason          string `json:"reason"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || body.ExpectedVersion < 0 || len([]rune(strings.TrimSpace(body.Reason))) < 3 ||
		(body.TenantID != platformTenantID && !iosmaterial.ValidTenantID(body.TenantID)) {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", "tenantId, kind, teamId, reason (at least 3 characters) and confirm=true are required")
		return
	}
	reason := clipRunes(strings.TrimSpace(body.Reason), 500)
	if !s.deleteIOSMaterial(c, body.TenantID, body.Kind, body.TeamID, body.Scope, body.ExpectedVersion,
		iosMaterialEmergencyRemoveAction, reason) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"removed": true})
}

// deleteIOSMaterial 删一个租户的一格并记审计（记在这个租户名下）。出错时已经写好了响应，返回 false。
func (s *server) deleteIOSMaterial(c *gin.Context, tenant, kind, team, scope string, expected int64, action, reason string) bool {
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return false
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT version FROM ios_signing_material WHERE tenant_id=? AND kind=? AND team_id=? AND scope=? FOR UPDATE`,
		tenant, kind, team, scope).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "IOS_MATERIAL_NOT_FOUND", "No material is stored for that kind, team and scope")
		return false
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return false
	}
	if expected > 0 && current != expected {
		problem(c, http.StatusConflict, "STALE_IOS_MATERIAL", "This material was replaced by a newer version; refresh and decide again")
		return false
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ios_signing_material WHERE tenant_id=? AND kind=? AND team_id=? AND scope=?`,
		tenant, kind, team, scope); err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return false
	}
	event := newAudit(tenant, actor(c), action, iosMaterialAuditTarget, kind+":"+team+":"+scope, reason, requestID(c),
		map[string]any{"kind": kind, "teamId": team, "scope": scope, "version": current})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to remove the material")
		return false
	}
	return true
}

// ---- 构建机 ----

// machineCapabilityTenantMaterial：打包机认得按租户的清单（设计 ios-tenant-owned-signing-material-2026-09-25 §4.5、
// §12.2）。它在**取清单的请求里**带上，因为材料同步发生在认领之前。
const machineCapabilityTenantMaterial = "tenant-signing-material"

// listIOSMaterialForMachine GET /v1/build-agent/ios-material：这台机器该装哪些材料。
// 只回清单，不回密文——密文一份一份取，每份都是几 KB 到几十 KB。
//
// 带了 tenant-signing-material 能力的请求拿按租户的清单；不带的（还没升级的打包机）拿按 Team 的旧行。
// 旧版打包机永远不能拿到按租户的清单：它会把两个租户落进同一格互相覆盖，取密文时也不带租户。
func (s *server) listIOSMaterialForMachine(c *gin.Context) {
	tenantLayout := c.Query("capability") == machineCapabilityTenantMaterial
	where := "tenant_id=0"
	if tenantLayout {
		where = "tenant_id<>0"
	}
	items, err := listIOSMaterial(c.Request.Context(), s.db, where)
	if err != nil {
		slog.Error("cannot list the iOS signing material", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Stored iOS signing material cannot be read")
		return
	}
	// complete：清单没被 LIMIT 截断。打包机只在清单完整时才把"清单里没有"当成"已撤下"去删本机
	// 的那一份（墓碑，cmd/build-agent/ios_material.go）——截断时删，就会把排在后面的材料从每台 Mac 上删掉
	complete := len(items) < iosMaterialMaxRows
	if !tenantLayout {
		// 旧打包机按 Team 记本机装到第几版，旧清单里不带租户与 legacy
		legacy := make([]gin.H, 0, len(items))
		for _, item := range items {
			legacy = append(legacy, gin.H{
				"kind": item.Kind, "teamId": item.TeamID, "scope": item.Scope, "purpose": item.Purpose,
				"recipientSha256": item.RecipientSHA256, "version": item.Version,
			})
		}
		c.JSON(http.StatusOK, gin.H{"items": legacy, "complete": complete})
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, item := range items {
		out = append(out, gin.H{
			"tenantId": item.TenantID, "kind": item.Kind, "teamId": item.TeamID, "scope": item.Scope, "purpose": item.Purpose,
			"recipientSha256": item.RecipientSHA256, "version": item.Version, "legacy": item.Legacy,
		})
	}
	c.JSON(http.StatusOK, gin.H{"layout": "tenant", "items": out, "complete": complete})
}

// getIOSMaterialBox GET /v1/build-agent/ios-material/box：取一份密文，原样下发。不带 tenantId 取按 Team 的旧行。
func (s *server) getIOSMaterialBox(c *gin.Context) {
	tenant := strings.TrimSpace(c.Query("tenantId"))
	if tenant == "" {
		tenant = platformTenantID
	} else if !iosmaterial.ValidTenantID(tenant) {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", "tenantId must be a tenant id")
		return
	}
	kind := strings.TrimSpace(c.Query("kind"))
	team := strings.TrimSpace(c.Query("teamId"))
	scope := strings.TrimSpace(c.Query("scope"))
	var ciphertext []byte
	err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT ciphertext FROM ios_signing_material WHERE tenant_id=? AND kind=? AND team_id=? AND scope=?`,
		tenant, kind, team, scope).Scan(&ciphertext)
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
