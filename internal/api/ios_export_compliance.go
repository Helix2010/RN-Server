package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// iOS 出口合规（Export Compliance）由租户自己声明（设计 ios-platform-testflight-upload-2026-09-23 §9，
// ios-testflight-distribution-2026-09-17 §8.2）。
//
// 每个传进 App Store Connect 的 build 都要回答"用没用非豁免的加密"，不答 TestFlight 显示
// Missing Compliance、谁都装不了。这是租户（它的法务）的判断，平台不替它答：
//
//   - 没声明（默认）：打包时不写 ITSAppUsesNonExemptEncryption，每个 build 在 ASC 上人工回答——
//     和这个配置出现之前一样；
//   - 声明了：tenant.json 带 iosUsesNonExemptEncryption，RN-App 打包时写进 Info.plist，ASC 不再问。
//
// 单独一个键，不塞进 release.ios：那一份会被身份表单整份保存、被 TestFlight 同步整份重写，
// 夹带的字段会丢（ios_delivery.go 同样的理由）。
const iosExportComplianceConfigKey = "release.ios.export-compliance"

type iosExportCompliance struct {
	UsesNonExemptEncryption bool `json:"usesNonExemptEncryption"`
}

type iosExportComplianceRecord struct {
	Value     iosExportCompliance
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

// iosExportComplianceRecordFor 读租户的声明。没声明是 nil。
func (s *server) iosExportComplianceRecordFor(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tenant string) (*iosExportComplianceRecord, error) {
	var raw []byte
	var record iosExportComplianceRecord
	err := q.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		tenant, iosExportComplianceConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record.Value); err != nil {
		return nil, errors.New(iosExportComplianceConfigKey + " is not a valid declaration")
	}
	return &record, nil
}

func iosExportComplianceView(record *iosExportComplianceRecord) gin.H {
	if record == nil {
		return gin.H{"declared": false, "usesNonExemptEncryption": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{"declared": true, "usesNonExemptEncryption": record.Value.UsesNonExemptEncryption,
		"version": record.Version, "updatedBy": record.UpdatedBy, "updatedAt": iso(record.UpdatedAt)}
}

func (s *server) getIOSExportCompliance(c *gin.Context) {
	record, err := s.iosExportComplianceRecordFor(c.Request.Context(), s.db, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_EXPORT_COMPLIANCE_CONFIG_INVALID", "Stored "+iosExportComplianceConfigKey+" configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, iosExportComplianceView(record))
}

type iosExportComplianceWrite struct {
	// UsesNonExemptEncryption：true / false 是声明；null 是撤回声明，回到每个 build 在 ASC 上人工回答
	UsesNonExemptEncryption *bool  `json:"usesNonExemptEncryption"`
	ExpectedVersion         int    `json:"expectedVersion"`
	Reason                  string `json:"reason"`
	Confirm                 bool   `json:"confirm"`
}

// updateIOSExportCompliance 保存或撤回声明。只影响之后**被认领**的构建：tenant.json 在打包机领任务时合成，
// 已经在打的包不变。
func (s *server) updateIOSExportCompliance(c *gin.Context) {
	var body iosExportComplianceWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_IOS_EXPORT_COMPLIANCE", "usesNonExemptEncryption (true, false, or null to withdraw), expectedVersion, reason and confirm=true are required")
		return
	}
	ctx := c.Request.Context()
	reason := clipRunes(strings.TrimSpace(body.Reason), 500)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_EXPORT_COMPLIANCE_SAVE_FAILED", "Unable to save the export compliance declaration")
		return
	}
	defer tx.Rollback()
	current, err := s.iosExportComplianceRecordFor(ctx, tx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_EXPORT_COMPLIANCE_CONFIG_INVALID", "Stored "+iosExportComplianceConfigKey+" configuration is invalid")
		return
	}
	currentVersion := 0
	var previous any
	if current != nil {
		currentVersion, previous = current.Version, current.Value.UsesNonExemptEncryption
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_IOS_EXPORT_COMPLIANCE", "The export compliance declaration changed; refresh and retry")
		return
	}
	if (current == nil && body.UsesNonExemptEncryption == nil) ||
		(current != nil && body.UsesNonExemptEncryption != nil && current.Value.UsesNonExemptEncryption == *body.UsesNonExemptEncryption) {
		problem(c, http.StatusConflict, "IOS_EXPORT_COMPLIANCE_UNCHANGED", "This is already the declaration")
		return
	}
	now := time.Now().UTC()
	var result sql.Result
	var next *iosExportComplianceRecord
	switch {
	case body.UsesNonExemptEncryption == nil:
		result, err = tx.ExecContext(ctx, `DELETE FROM app_configs WHERE tenant_id=? AND config_key=? AND version=?`,
			tenantID(c), iosExportComplianceConfigKey, currentVersion)
	case current != nil:
		raw, _ := json.Marshal(iosExportCompliance{UsesNonExemptEncryption: *body.UsesNonExemptEncryption})
		result, err = tx.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			raw, actor(c), now, tenantID(c), iosExportComplianceConfigKey, currentVersion)
		next = &iosExportComplianceRecord{Value: iosExportCompliance{UsesNonExemptEncryption: *body.UsesNonExemptEncryption}, Version: currentVersion + 1, UpdatedBy: actor(c), UpdatedAt: now}
	default:
		raw, _ := json.Marshal(iosExportCompliance{UsesNonExemptEncryption: *body.UsesNonExemptEncryption})
		result, err = tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), iosExportComplianceConfigKey, raw, actor(c), now, tenantID(c), iosExportComplianceConfigKey)
		next = &iosExportComplianceRecord{Value: iosExportCompliance{UsesNonExemptEncryption: *body.UsesNonExemptEncryption}, Version: 1, UpdatedBy: actor(c), UpdatedAt: now}
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_EXPORT_COMPLIANCE_SAVE_FAILED", "Unable to save the export compliance declaration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_IOS_EXPORT_COMPLIANCE", "The export compliance declaration changed; refresh and retry")
		return
	}
	var to any
	if body.UsesNonExemptEncryption != nil {
		to = *body.UsesNonExemptEncryption
	}
	event := newAudit(tenantID(c), actor(c), "ios_export_compliance_update", "app-config", iosExportComplianceConfigKey, reason, requestID(c),
		map[string]any{"from": previous, "to": to})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_EXPORT_COMPLIANCE_SAVE_FAILED", "Unable to save the export compliance declaration")
		return
	}
	c.JSON(http.StatusOK, iosExportComplianceView(next))
}
