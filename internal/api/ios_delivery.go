package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
	"github.com/gin-gonic/gin"
)

// iOS 交付方式：全托管 / 自助上传（设计 docs/design/ios-tenant-delivery-tiers-2026-09-24.md）。
//
//   - testflight（全托管）：Mac 上的上传账户把 .ipa 传进租户的 App Store Connect。租户交了上传 Key。
//   - ipa（自助上传）：Mac 把 .ipa 交回服务端，租户下载后自己用 Transporter 上传。平台手里没有
//     任何能操作租户 App 的 Key。
//
// 交付方式是租户自己的配置，单独一个键，**不放进 release.ios**：手工保存与 TestFlight 同步都按
// 固定字段整份重写 release.ios，放进去会在每次保存公开链接时被冲回默认值。
//
// 也**不从"Mac 上有没有这个 Team 的上传 Key"推出来**：那样全托管租户的 Key 丢了或被吊销时会被
// 悄悄降成自助上传——包停在存储里没人去传，运营却以为已经进了 TestFlight。
//
// 交付方式在排队那一刻抄进任务行（build_jobs.delivery），之后改配置只影响新排的任务。
// 保证 build 号顺序的是认领时"同租户按排队顺序"那一条（build_agent.go），不是这里的切换检查：
// 切换检查只是让运营别在还有任务没跑完的时候换方式，两者之间就算撞上，顺序也不会乱。
const (
	iosDeliveryConfigKey  = "release.ios.delivery"
	iosDeliveryTestFlight = "testflight"
	iosDeliveryIPA        = "ipa"
	// machineCapabilityIPADelivery：这台机器的构建机程序能把 .ipa 交回服务端。旧版代理不报，
	// 自助上传的任务就既排不进去、也派不给它
	machineCapabilityIPADelivery = "ios-ipa-delivery"
	maxMachineCapabilities       = 16
)

var machineCapabilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

type iosDeliveryConfig struct {
	Mode string `json:"mode"`
}

type iosDeliveryRecord struct {
	Mode      string
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func validIOSDelivery(mode string) bool {
	return mode == iosDeliveryTestFlight || mode == iosDeliveryIPA
}

// iosDeliveryRecordFor 读租户的交付方式。没配过是 nil——等于全托管，也就是这个配置出现之前
// 所有 iOS 租户的行为。
func (s *server) iosDeliveryRecordFor(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tenant string) (*iosDeliveryRecord, error) {
	var raw []byte
	var record iosDeliveryRecord
	err := q.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		tenant, iosDeliveryConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value iosDeliveryConfig
	if err := json.Unmarshal(raw, &value); err != nil || !validIOSDelivery(value.Mode) {
		return nil, fmt.Errorf("%s is not a valid delivery mode", iosDeliveryConfigKey)
	}
	record.Mode = value.Mode
	return &record, nil
}

// iosDeliveryModeFor 是排队要抄进任务的那个值。
func (s *server) iosDeliveryModeFor(ctx context.Context, tenant string) (string, error) {
	record, err := s.iosDeliveryRecordFor(ctx, s.db, tenant)
	if err != nil {
		return "", err
	}
	if record == nil {
		return iosDeliveryTestFlight, nil
	}
	return record.Mode, nil
}

// jobDelivery 是一条任务实际的交付方式。只有 iOS 安装包任务有；迁移之前的 iOS 任务按全托管。
func jobDelivery(j buildJob) string {
	if j.Platform != buildPlatformIOS || j.Kind != jobKindAPK {
		return ""
	}
	if j.Delivery.Valid && validIOSDelivery(j.Delivery.String) {
		return j.Delivery.String
	}
	return iosDeliveryTestFlight
}

func buildJobDeliveryView(j buildJob) any {
	return nullableString(jobDelivery(j))
}

// normalizeMachineCapabilities 校验机器自报的能力。不认识的能力照收（新代理可以先于服务端
// 报新能力），只要形状对；形状不对就 400——认领是高频路径，坏数据不进库。
func normalizeMachineCapabilities(raw []string) ([]string, bool) {
	if len(raw) > maxMachineCapabilities {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, capability := range raw {
		capability = strings.TrimSpace(capability)
		if !machineCapabilityPattern.MatchString(capability) {
			return nil, false
		}
		if !containsString(out, capability) {
			out = append(out, capability)
		}
	}
	return out, true
}

// uploadablePairs 是自报盘点里"上传 Key 装着、Apple 没拒"的那些 (Team, bundle id)。
//
// error 也算：它多半是代理临时断了，让任务因此排不进去、派不出去，比让它在上传那一步失败更糟
// ——后者至少有重试。missing（没装 Key）与 forbidden（角色不够）不算，空（这台机器没开上传）
// 也不算。
func uploadablePairs(reports []appleTeamReport) []string {
	out := []string{}
	for _, report := range reports {
		if report.UploadProbe != uploadProbeOK && report.UploadProbe != uploadProbeError {
			continue
		}
		out = append(out, signingPairs([]appleTeamReport{report})...)
	}
	return out
}

// iosDeliveryUnfinishedJobs 列出这个租户还没跑完的 iOS 安装包任务。有的时候不许切换交付方式。
func (s *server) iosDeliveryUnfinishedJobs(ctx context.Context, tenant string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,status,build_number,COALESCE(delivery,'`+iosDeliveryTestFlight+`') FROM build_jobs
		  WHERE tenant_id=? AND platform='`+buildPlatformIOS+`' AND kind='`+jobKindAPK+`' AND status IN (`+sqlInFlight+`)
		  ORDER BY created_at LIMIT 20`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, status, delivery string
		var number int
		if err := rows.Scan(&id, &status, &number, &delivery); err != nil {
			return nil, err
		}
		out = append(out, gin.H{"id": id, "status": status, "buildNumber": number, "delivery": delivery})
	}
	return out, rows.Err()
}

// iosDeliveryReadiness 回答"按这种方式现在排得进去吗"，给配置页与排队共用同一套判据。
type iosDeliveryReadiness struct {
	coverage iosSigningCoverage
}

func (r iosDeliveryReadiness) problem(mode, teamID, bundleID string) (string, string) {
	switch {
	case !r.coverage.Reported:
		return "NO_BUILDER_FOR_TEAM", "没有任何一台 iOS 打包机报告过它手上有 Team " + teamID + "、bundle id " + bundleID +
			" 的签名材料，排进去的任务不会有人认领。把这个 Team 的证书与描述文件下发到至少一台 Mac，" +
			"到「平台维护 → 构建机」确认它报上来之后再排。"
	case mode == iosDeliveryTestFlight && !r.coverage.Uploadable:
		return "NO_UPLOADER_FOR_TEAM", "这个租户是「全托管」，但没有任何一台打包机报告过 Team " + teamID +
			" 的上传 Key 可用，排进去的任务不会有人认领。先把上传 Key 下发到打包机并确认探测结果，或者把交付方式改成「自助上传」。"
	case mode == iosDeliveryIPA && !r.coverage.IPACapable:
		return "NO_IPA_BUILDER_FOR_TEAM", "这个租户是「自助上传」，但手上有 Team " + teamID +
			" 签名材料的打包机都还不支持把 .ipa 交回平台（打包机程序版本太旧）。批准新版打包机、等它升级之后再排。"
	}
	return "", ""
}

func (r iosDeliveryReadiness) online(mode string) bool {
	if mode == iosDeliveryIPA {
		return r.coverage.IPACapableOnline
	}
	return r.coverage.UploadableOnline
}

func (s *server) iosDeliveryReadinessFor(ctx context.Context, teamID, bundleID string) (iosDeliveryReadiness, error) {
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		return iosDeliveryReadiness{}, err
	}
	coverage, err := s.iosSigningCoverage(ctx, registry, teamID, bundleID, s.now())
	if err != nil {
		return iosDeliveryReadiness{}, err
	}
	return iosDeliveryReadiness{coverage: coverage}, nil
}

func iosDeliveryView(record *iosDeliveryRecord) gin.H {
	if record == nil {
		return gin.H{"mode": iosDeliveryTestFlight, "configured": false, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{"mode": record.Mode, "configured": true, "version": record.Version, "updatedBy": record.UpdatedBy, "updatedAt": iso(record.UpdatedAt)}
}

// getIOSDelivery 返回交付方式，以及切换要看的几件事：两种方式现在各自排不排得进去、还有没有
// 没跑完的任务、平台这边还存着 App Manager Key 没有。
func (s *server) getIOSDelivery(c *gin.Context) {
	ctx := c.Request.Context()
	record, err := s.iosDeliveryRecordFor(ctx, s.db, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_CONFIG_INVALID", "Stored "+iosDeliveryConfigKey+" configuration is invalid")
		return
	}
	view := iosDeliveryView(record)
	unfinished, err := s.iosDeliveryUnfinishedJobs(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_QUERY_FAILED", "Unable to read unfinished iOS builds")
		return
	}
	view["unfinishedJobs"] = unfinished
	var ascStored int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_configs WHERE tenant_id=? AND config_key=?`, tenantID(c), iosASCConfigKey).Scan(&ascStored); err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_QUERY_FAILED", "Unable to read the App Store Connect key state")
		return
	}
	view["ascKeyStored"] = ascStored > 0
	readiness := gin.H{}
	identity, err := s.iosReleaseIdentityRecord(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if identity != nil {
		ready, err := s.iosDeliveryReadinessFor(ctx, identity.Value.AppleTeamID, identity.Value.BundleID)
		if err != nil {
			problem(c, http.StatusInternalServerError, "IOS_DELIVERY_QUERY_FAILED", "Unable to read build machine liveness")
			return
		}
		for _, mode := range []string{iosDeliveryTestFlight, iosDeliveryIPA} {
			code, detail := ready.problem(mode, identity.Value.AppleTeamID, identity.Value.BundleID)
			readiness[mode] = gin.H{"ready": code == "", "code": nullableString(code), "detail": nullableString(detail), "online": ready.online(mode)}
		}
		// 同一个 Team 下还有别的租户是全托管：这个 Team 的上传 Key 会继续留在打包机上
		// （Team Key 限不了 App，一个 Team 一把），切到自助上传也收不回这份授权
		shared, err := s.iosTeamSharedWithTestFlightTenants(ctx, tenantID(c), identity.Value.AppleTeamID)
		if err != nil {
			problem(c, http.StatusInternalServerError, "IOS_DELIVERY_QUERY_FAILED", "Unable to read other tenants on this Apple team")
			return
		}
		view["teamSharedWithTestFlightTenants"] = shared
	} else {
		view["teamSharedWithTestFlightTenants"] = []string{}
	}
	view["readiness"] = readiness
	c.JSON(http.StatusOK, view)
}

// iosTeamSharedWithTestFlightTenants 列出同一个 Team 下、交付方式是全托管的其它租户 slug。
func (s *server) iosTeamSharedWithTestFlightTenants(ctx context.Context, tenant, teamID string) ([]string, error) {
	targets, err := s.iosSigningTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, target := range targets {
		if target.TenantID == tenant || !strings.EqualFold(target.TeamID, teamID) {
			continue
		}
		mode, err := s.iosDeliveryModeFor(ctx, target.TenantID)
		if err != nil {
			// 读不出来按全托管算：宁可多提醒一句
			mode = iosDeliveryTestFlight
		}
		if mode == iosDeliveryTestFlight {
			out = append(out, target.Slug)
		}
	}
	return out, nil
}

type iosDeliveryWrite struct {
	Mode            string `json:"mode"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
	// AcknowledgeKeysRevoked：从全托管切到自助上传时必须带上，意思是"我已经在 App Store Connect
	// 吊销了上传 Key 与 App Manager Key"。平台删掉自己这边的副本不等于授权收回：打包机上装着的
	// 上传 Key 服务端删不掉，Key 本身在 Apple 那边也仍然有效——真正收回授权只能靠吊销
	AcknowledgeKeysRevoked bool `json:"acknowledgeKeysRevoked"`
}

func (s *server) updateIOSDelivery(c *gin.Context) {
	var body iosDeliveryWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 || !validIOSDelivery(body.Mode) {
		problem(c, http.StatusBadRequest, "INVALID_IOS_DELIVERY", "mode (testflight or ipa), expectedVersion, reason and confirm=true are required")
		return
	}
	ctx := c.Request.Context()
	reason := clipRunes(strings.TrimSpace(body.Reason), 500)
	unfinished, err := s.iosDeliveryUnfinishedJobs(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_QUERY_FAILED", "Unable to read unfinished iOS builds")
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_SAVE_FAILED", "Unable to save the delivery mode")
		return
	}
	defer tx.Rollback()
	current, err := s.iosDeliveryRecordFor(ctx, tx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_CONFIG_INVALID", "Stored "+iosDeliveryConfigKey+" configuration is invalid")
		return
	}
	currentVersion, previous := 0, iosDeliveryTestFlight
	if current != nil {
		currentVersion, previous = current.Version, current.Mode
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_IOS_DELIVERY", "The delivery mode changed; refresh and retry")
		return
	}
	if previous == body.Mode {
		problem(c, http.StatusConflict, "IOS_DELIVERY_UNCHANGED", "This is already the delivery mode")
		return
	}
	// 还有任务没跑完就不许换：排队中的任务按排队时的方式交付，换了配置它们也不会跟着变，
	// 运营看到的"现在是自助上传"和"下一个出来的包进了 TestFlight"对不上
	if len(unfinished) > 0 {
		problemWith(c, http.StatusConflict, "IOS_DELIVERY_SWITCH_BLOCKED",
			"这个租户还有没跑完的 iOS 构建，先等它们跑完或者取消（排队中、已领取、构建中都能取消）再切换交付方式",
			gin.H{"unfinishedJobs": unfinished})
		return
	}
	ascDeleted, uploadKeyWithdrawn := false, false
	sharedWith := []string{}
	if previous == iosDeliveryTestFlight && body.Mode == iosDeliveryIPA {
		if !body.AcknowledgeKeysRevoked {
			problem(c, http.StatusConflict, "IOS_DELIVERY_KEYS_NOT_REVOKED",
				"切到「自助上传」之前，请先在 App Store Connect → 用户和访问 → 集成里吊销交给平台的上传 Key 与 App Manager Key，再带 acknowledgeKeysRevoked=true 提交。"+
					"平台删掉自己存的那份不等于收回授权：打包机上已装的上传 Key 平台删不掉，Key 在 Apple 那边也仍然有效。")
			return
		}
		// 服务端存的 App Manager Key 一起删：这把 Key 本身就能上传，留着就不是自助上传
		result, err := tx.ExecContext(ctx, `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, tenantID(c), iosASCConfigKey)
		if err != nil {
			problem(c, http.StatusInternalServerError, "IOS_DELIVERY_SAVE_FAILED", "Unable to delete the stored App Store Connect key")
			return
		}
		affected, _ := result.RowsAffected()
		ascDeleted = affected > 0
		// 这个 Team 的上传 Key 材料也撤下——除非同一个 Team 下还有别的租户是全托管（Team Key 限不了
		// App，一个 Team 一把，撤了那些租户就传不了）。撤下之后，打包机下一轮同步发现清单里没有这个
		// Team 的上传 Key，就请上传账户删掉本机那份（墓碑，cmd/build-agent/ios_material.go）
		identity, err := s.iosReleaseIdentityRecord(ctx, tenantID(c))
		if err != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
			return
		}
		if identity != nil {
			if sharedWith, err = s.iosTeamSharedWithTestFlightTenants(ctx, tenantID(c), identity.Value.AppleTeamID); err != nil {
				problem(c, http.StatusInternalServerError, "IOS_DELIVERY_QUERY_FAILED", "Unable to read other tenants on this Apple team")
				return
			}
			if len(sharedWith) == 0 {
				result, err := tx.ExecContext(ctx, `DELETE FROM ios_signing_material WHERE kind=? AND team_id=?`, iosmaterial.KindUploadKey, identity.Value.AppleTeamID)
				if err != nil {
					problem(c, http.StatusInternalServerError, "IOS_DELIVERY_SAVE_FAILED", "Unable to withdraw the upload key of this team")
					return
				}
				withdrawn, _ := result.RowsAffected()
				uploadKeyWithdrawn = withdrawn > 0
			}
		}
	}
	raw, _ := json.Marshal(iosDeliveryConfig{Mode: body.Mode})
	now := time.Now().UTC()
	var result sql.Result
	if currentVersion > 0 {
		result, err = tx.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			raw, actor(c), now, tenantID(c), iosDeliveryConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), iosDeliveryConfigKey, raw, actor(c), now, tenantID(c), iosDeliveryConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_SAVE_FAILED", "Unable to save the delivery mode")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_IOS_DELIVERY", "The delivery mode changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ios_delivery_update", "app-config", iosDeliveryConfigKey, reason, requestID(c),
		map[string]any{"from": previous, "to": body.Mode, "ascKeyDeleted": ascDeleted, "uploadKeyWithdrawn": uploadKeyWithdrawn,
			"teamSharedWith": sharedWith, "acknowledgeKeysRevoked": body.AcknowledgeKeysRevoked})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_SAVE_FAILED", "Unable to save the delivery mode")
		return
	}
	view := iosDeliveryView(&iosDeliveryRecord{Mode: body.Mode, Version: currentVersion + 1, UpdatedBy: actor(c), UpdatedAt: now})
	view["ascKeyDeleted"] = ascDeleted
	view["uploadKeyWithdrawn"] = uploadKeyWithdrawn
	if body.Mode == iosDeliveryIPA {
		switch {
		case len(sharedWith) > 0:
			shown := sharedWith
			if len(shown) > 5 {
				shown = append(append([]string{}, shown[:5]...), fmt.Sprintf("等 %d 个", len(sharedWith)))
			}
			view["reminder"] = "已切到「自助上传」。同一个 Apple Team 下还有租户（" + strings.Join(shown, "、") +
				"）是「全托管」，这个 Team 的上传 Key 仍留在平台与打包机上。Key 本身在 Apple 那边是否作废，取决于 App Store Connect 里有没有吊销。"
		default:
			view["reminder"] = "已切到「自助上传」。平台存的 App Store Connect Key 已删除、这个 Team 的上传 Key 已从平台材料里撤下，打包机下一轮同步（几分钟内）会删掉本机那份。" +
				"平台删掉副本不等于 Key 作废：请确认已在 App Store Connect 吊销。"
		}
	}
	c.JSON(http.StatusOK, view)
}
