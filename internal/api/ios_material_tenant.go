package api

// 租户自己交 iOS 签名材料（设计 ios-tenant-owned-signing-material-2026-09-25 §3.2、§3.3、§12.4）。
//
// 平台管理员不代交（用户明确要求）：Distribution 证书、App Store 描述文件、上传 Key 都由租户在自己的
// 「iOS 打包与分发」页上传。材料在浏览器里加密（v2，材料里带租户 id），服务端只核对密文外层的明文
// 提示——那是帮人当场发现传错了，不是安全边界。真正的关在 Mac 上：解开之后核对「清单说属于谁」与
// 「材料自己说属于谁」一致、证书属于这个 Team、描述文件的 bundle id 与类型对得上才装（§4.2）。
//
// 一个租户换、删自己的材料碰不到别的租户：表按租户存，Mac 按租户 id 落盘，构建时只给本租户的描述文件，
// 签名身份按证书指纹钉死。

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
	"github.com/gin-gonic/gin"
)

const (
	// iosMaterialWritesPerHour：一个租户一小时内最多传、删几次。三类材料各传一次、传错重来几次绰绰有余；
	// 挡的是脚本反复覆盖，每次覆盖都会让每台 Mac 重新取、重新核对一遍
	iosMaterialWritesPerHour = 30
	// iosMaterialRemovalsShown：租户页上列最近几条平台紧急删除
	iosMaterialRemovalsShown = 5
	// iosMaterialProblemsShown：每一类材料最多列几条 Mac 报的原因
	iosMaterialProblemsShown = 5
)

// 一类材料对这个租户的要求。
const (
	iosMaterialNeedRequired = "required"
	// iosMaterialNeedRejected：自助上传时的上传 Key——平台不持有能替租户上传的 Key（§3.3）
	iosMaterialNeedRejected = "rejected"
)

// 一类材料现在的状态，控制台按它出文案。
const (
	iosMaterialStatusOK         = "ok"         // 至少一台 Mac 核对通过、装好了
	iosMaterialStatusPending    = "pending"    // 已交，还没有 Mac 装好（同步间隔约 2 分钟）
	iosMaterialStatusFailed     = "failed"     // 没有 Mac 装好，而且有 Mac 报了这一类的问题
	iosMaterialStatusMissing    = "missing"    // 要交，还没交
	iosMaterialStatusStale      = "stale"      // 加密给的公钥已经不是现在登记的那一把，Mac 解不开
	iosMaterialStatusUnexpected = "unexpected" // 不该有却有（自助上传却存着上传 Key，多半是迁移复制来的）
	iosMaterialStatusNotNeeded  = "not-needed"
)

// getTenantIOSMaterial GET /v1/admin/ios/material：本租户的材料、按交付方式的要求清单与 Mac 核对结果。
//
// 两把平台公钥一起给：浏览器要用它们加密，而公钥本来就不是机密。机器只给台数，不给 id 与名字——
// 打包机是平台的基础设施（设计 tenant-console-accounts-and-sso §3.4）。
func (s *server) getTenantIOSMaterial(c *gin.Context) {
	ctx := c.Request.Context()
	tenant := tenantID(c)
	fail := func(what string, err error) {
		slog.Error("cannot read the tenant's iOS signing material", "tenant", tenant, "step", what, "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_UNAVAILABLE", "Unable to read "+what)
	}
	recipients, err := readIOSMaterialRecipients(ctx, s.db, false)
	if err != nil {
		fail("the platform encryption keys", err)
		return
	}
	identity, err := s.iosReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		fail("the iOS release identity", err)
		return
	}
	mode, err := s.iosDeliveryModeFor(ctx, tenant)
	if err != nil {
		fail("the delivery mode", err)
		return
	}
	items, err := listIOSMaterial(ctx, s.db, "tenant_id=?", tenant)
	if err != nil {
		fail("the stored material", err)
		return
	}
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		fail("the build machines", err)
		return
	}
	liveness, err := s.machineLivenessByID(ctx)
	if err != nil {
		fail("the build machine liveness", err)
		return
	}
	removals, err := s.iosMaterialRemovals(c, tenant)
	if err != nil {
		fail("the platform removals", err)
		return
	}
	index := iosMaterialIndex{items: items, doc: recipients.Doc}
	itemViews := make([]gin.H, 0, len(items))
	for _, item := range items {
		itemViews = append(itemViews, tenantIOSMaterialItem(index, item))
	}

	builders := []machineLiveness{}
	for _, m := range registry.Machines {
		if !iosBuilder(m) {
			continue
		}
		if live, ok := liveness[m.ID]; ok {
			builders = append(builders, live)
		} else {
			builders = append(builders, machineLiveness{MachineID: m.ID})
		}
	}
	var identityView any
	requirements := []gin.H{}
	ready := 0
	if identity != nil && identity.Value.AppleTeamID != "" && identity.Value.BundleID != "" {
		team, bundle := strings.ToUpper(identity.Value.AppleTeamID), identity.Value.BundleID
		identityView = gin.H{"teamId": team, "bundleId": bundle}
		for _, live := range builders {
			if live.signs(tenant, team, bundle) {
				ready++
			}
		}
		for _, kind := range []string{iosmaterial.KindCertificate, iosmaterial.KindProfile, iosmaterial.KindUploadKey} {
			requirements = append(requirements, tenantIOSMaterialRequirement(index, builders, tenant, team, bundle, mode, kind))
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"tenantId":     tenant,
		"identity":     identityView,
		"delivery":     mode,
		"recipients":   gin.H{"builder": tenantIOSRecipient(recipients.Doc.Builder), "uploader": tenantIOSRecipient(recipients.Doc.Uploader)},
		"items":        itemViews,
		"requirements": requirements,
		"machines":     gin.H{"total": len(builders), "ready": ready},
		"removals":     removals,
	})
}

// tenantIOSRecipient 只给公钥与指纹：谁在什么时候登记的是平台的事。
func tenantIOSRecipient(recipient *iosMaterialRecipient) any {
	if recipient == nil {
		return nil
	}
	return gin.H{"publicKey": recipient.PublicKey, "sha256": recipient.SHA256}
}

func tenantIOSMaterialItem(index iosMaterialIndex, item storedIOSMaterial) gin.H {
	slot := index.slot(item)
	return gin.H{
		"kind": item.Kind, "teamId": item.TeamID, "scope": item.Scope, "version": item.Version,
		"uploadedBy": item.UploadedBy, "uploadedAt": item.UploadedAt, "legacy": item.Legacy, "stale": slot.Stale,
	}
}

// tenantIOSMaterialRequirement 算一类材料对这个租户的要求与现状（§3.3 的表）。
//
// 「装好了」只看按租户自报的 Mac：旧机器报的是按 Team 共用的那一份，说明不了这个租户自己交的材料装没装上。
func tenantIOSMaterialRequirement(index iosMaterialIndex, builders []machineLiveness, tenant, team, bundle, mode, kind string) gin.H {
	need := iosMaterialNeedRequired
	if kind == iosmaterial.KindUploadKey && mode == iosDeliveryIPA {
		need = iosMaterialNeedRejected
	}
	scope := ""
	if kind == iosmaterial.KindProfile {
		scope = bundle
	}
	var item any
	var stored *storedIOSMaterial
	for i := range index.items {
		candidate := index.items[i]
		if candidate.Kind == kind && strings.EqualFold(candidate.TeamID, team) && strings.EqualFold(candidate.Scope, scope) {
			stored = &candidate
			item = tenantIOSMaterialItem(index, candidate)
			break
		}
	}
	problems := []string{}
	installed := false
	prefix := kind + ": "
	for _, live := range builders {
		report := live.tenantReport(tenant, team)
		if report == nil {
			continue
		}
		switch kind {
		case iosmaterial.KindCertificate:
			installed = installed || report.CertificateReady
		case iosmaterial.KindProfile:
			installed = installed || containsString(report.BundleIDs, bundle)
		case iosmaterial.KindUploadKey:
			installed = installed || report.UploadProbe == uploadProbeOK
			if report.UploadProbe == uploadProbeForbidden || report.UploadProbe == uploadProbeError {
				problems = appendProblem(problems, "upload probe: "+report.UploadProbe)
			}
		}
		for _, text := range report.Problems {
			if reason, ok := strings.CutPrefix(text, prefix); ok {
				problems = appendProblem(problems, reason)
			}
		}
	}
	status := iosMaterialStatusPending
	switch {
	case need == iosMaterialNeedRejected && stored != nil:
		status = iosMaterialStatusUnexpected
	case need == iosMaterialNeedRejected:
		status = iosMaterialStatusNotNeeded
	case stored == nil:
		status = iosMaterialStatusMissing
	case index.slot(*stored).Stale:
		status = iosMaterialStatusStale
	case installed:
		status = iosMaterialStatusOK
	case len(problems) > 0:
		status = iosMaterialStatusFailed
	}
	return gin.H{"kind": kind, "need": need, "status": status, "item": item, "problems": problems}
}

// appendProblem 去重并限条数：几台 Mac 报同一句话，控制台上只列一次。
func appendProblem(problems []string, text string) []string {
	text = strings.TrimSpace(text)
	if text == "" || containsString(problems, text) || len(problems) >= iosMaterialProblemsShown {
		return problems
	}
	return append(problems, text)
}

// iosMaterialRemovals 是最近几条平台紧急删除。不带操作人：租户要知道的是「平台删了什么、为什么」。
func (s *server) iosMaterialRemovals(c *gin.Context, tenant string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT reason,summary,created_at FROM audit_events WHERE tenant_id=? AND action=? ORDER BY created_at DESC LIMIT ?`,
		tenant, iosMaterialEmergencyRemoveAction, iosMaterialRemovalsShown)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var reason sql.NullString
		var summary []byte
		var at time.Time
		if err := rows.Scan(&reason, &summary, &at); err != nil {
			return nil, err
		}
		var slot struct {
			Kind   string `json:"kind"`
			TeamID string `json:"teamId"`
			Scope  string `json:"scope"`
		}
		_ = json.Unmarshal(summary, &slot)
		out = append(out, gin.H{"kind": slot.Kind, "teamId": slot.TeamID, "scope": slot.Scope,
			"reason": reason.String, "at": at.UTC().Format(time.RFC3339)})
	}
	return out, rows.Err()
}

// uploadTenantIOSMaterial POST /v1/admin/ios/material：收本租户的一份密文（请求体就是 v2 的 Box）。
func (s *server) uploadTenantIOSMaterial(c *gin.Context) {
	ctx := c.Request.Context()
	tenant := tenantID(c)
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
	// 只收 v2：v1 里没有租户，Mac 没法核对它属于谁。旧行迁移时复制的 v1 只由服务端自己写（legacy）
	if box.Version != iosmaterial.VersionTenant {
		problem(c, http.StatusBadRequest, "IOS_MATERIAL_VERSION_UNSUPPORTED",
			"Only version 2 material (sealed with this tenant's id) is accepted; refresh the console and upload again")
		return
	}
	if box.TenantID != tenant {
		problem(c, http.StatusForbidden, "IOS_MATERIAL_TENANT_MISMATCH", "This material is sealed for another tenant")
		return
	}
	identity, err := s.iosReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if identity == nil || identity.Value.AppleTeamID == "" || identity.Value.BundleID == "" {
		problem(c, http.StatusConflict, "IOS_IDENTITY_REQUIRED", "Save the iOS release identity (Apple Team ID and bundle id) first")
		return
	}
	switch {
	case !strings.EqualFold(box.TeamID, identity.Value.AppleTeamID):
		problem(c, http.StatusConflict, "IOS_MATERIAL_TEAM_MISMATCH",
			"This material belongs to Apple Team "+box.TeamID+", but this app is registered under "+strings.ToUpper(identity.Value.AppleTeamID))
		return
	// 原样比：Mac 按描述文件里的 application-identifier 认，认领时也按 release.ios 原样比，大小写不同就签不出来
	case box.Kind == iosmaterial.KindProfile && box.BundleID != identity.Value.BundleID:
		problem(c, http.StatusConflict, "IOS_MATERIAL_BUNDLE_MISMATCH",
			"This provisioning profile is for "+box.BundleID+", but this app's bundle id is "+identity.Value.BundleID)
		return
	}
	if box.Kind == iosmaterial.KindUploadKey {
		mode, err := s.iosDeliveryModeFor(ctx, tenant)
		if err != nil {
			problem(c, http.StatusInternalServerError, "IOS_DELIVERY_CONFIG_INVALID", "Stored "+iosDeliveryConfigKey+" configuration is invalid")
			return
		}
		if mode == iosDeliveryIPA {
			problem(c, http.StatusConflict, "IOS_DELIVERY_SELF_UPLOAD",
				"This app uploads to App Store Connect itself; the platform does not keep an upload key for it")
			return
		}
	}
	recipients, err := readIOSMaterialRecipients(ctx, s.db, false)
	if err != nil {
		slog.Error("cannot read the iOS material recipients", "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_RECIPIENTS_INVALID",
			"Stored "+buildIOSMaterialConfigKey+" configuration cannot be read")
		return
	}
	recipient, ok := recipients.Doc.forPurpose(box.Purpose)
	switch {
	case !ok:
		problem(c, http.StatusConflict, "IOS_MATERIAL_RECIPIENT_NOT_REGISTERED",
			"The platform has not registered its "+box.Purpose+" key yet; ask the platform to do that first")
		return
	case recipient.SHA256 != box.RecipientSHA256:
		problem(c, http.StatusConflict, "IOS_MATERIAL_RECIPIENT_UNKNOWN",
			"This material is encrypted to a key the platform no longer uses; refresh the console and upload again")
		return
	}
	if !s.iosMaterialWrites.allow(tenant, iosMaterialWritesPerHour, time.Hour, s.now()) {
		problem(c, http.StatusTooManyRequests, "IOS_MATERIAL_RATE_LIMITED", "Too many signing material changes in the last hour; try again later")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to store the material")
		return
	}
	defer tx.Rollback()
	version, err := storeIOSMaterial(ctx, tx, tenant, box, raw, actor(c), now)
	if err != nil {
		slog.Error("cannot store the iOS signing material", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_SAVE_FAILED", "Unable to store the material")
		return
	}
	scope := scopeFor(box)
	event := newAudit(tenant, actor(c), "ios_material_upload", iosMaterialAuditTarget,
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
		"version": version, "uploadedAt": now.Format(time.RFC3339),
	})
}

// removeTenantIOSMaterial POST /v1/admin/ios/material/remove：删本租户的一格。Mac 下一轮同步把本机那一份撤掉。
//
// Team 与 scope 由请求给：租户改过 Team 或 bundle id 之后，旧的那几格还在，也要删得掉。
func (s *server) removeTenantIOSMaterial(c *gin.Context) {
	var body struct {
		Kind   string `json:"kind"`
		TeamID string `json:"teamId"`
		Scope  string `json:"scope"`
		// ExpectedVersion 可选：大于 0 时只删这一版
		ExpectedVersion int64  `json:"expectedVersion"`
		Reason          string `json:"reason"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || body.ExpectedVersion < 0 || len([]rune(strings.TrimSpace(body.Reason))) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL", "kind, teamId, reason (at least 3 characters) and confirm=true are required")
		return
	}
	tenant := tenantID(c)
	if !s.iosMaterialWrites.allow(tenant, iosMaterialWritesPerHour, time.Hour, s.now()) {
		problem(c, http.StatusTooManyRequests, "IOS_MATERIAL_RATE_LIMITED", "Too many signing material changes in the last hour; try again later")
		return
	}
	if !s.deleteIOSMaterial(c, tenant, body.Kind, body.TeamID, body.Scope, body.ExpectedVersion,
		"ios_material_remove", clipRunes(strings.TrimSpace(body.Reason), 500)) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"removed": true})
}
