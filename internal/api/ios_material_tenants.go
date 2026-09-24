package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
	"github.com/gin-gonic/gin"
)

// 控制台「Apple 证书与密钥」页的按租户总览（设计 RN-Admin
// docs/design/ios-credentials-overview-2026-09-24.md）。
//
// 材料表按 Team 存（证书、上传 Key 每 Team 一份，描述文件每 Team + bundle id 一份），没有租户列；
// 「按租户」是从 release.ios 拼出来的视图。匹配、上传 Key 需不需要、现在能不能排都在这里算——
// 这些规则与排队、切换交付方式用的是同一套函数，控制台只负责画出来，不另写一份。
//
// 单独一个接口，不往 GET /ios-material 里加字段：租户页的上传卡也读那一个，而这里要读机器登记与
// liveness，读失败不该连累上传卡。

// iOS 上传 Key 对一个租户的用途。
const (
	iosUploadKeyRequired      = "required"            // 全托管：要有
	iosUploadKeyKeptForOthers = "kept-for-others"     // 自助上传，同 Team 的全托管租户还在用
	iosUploadKeyWithdraw      = "should-be-withdrawn" // 自助上传，同 Team 没人用，按设计切换时就该撤下
	iosUploadKeyNotNeeded     = "not-needed"          // 自助上传，平台上也没有
)

type iosMaterialSlotView struct {
	// TeamID、Scope 是表里存的原样：删除按它们精确匹配，而 bundle id 的大小写可能与租户身份不同
	TeamID     string `json:"teamId"`
	Scope      string `json:"scope"`
	Version    int64  `json:"version"`
	UploadedBy string `json:"uploadedBy"`
	UploadedAt string `json:"uploadedAt"`
	// Stale：加密给的公钥已经不是现在登记的那一把。新装的 Mac 解不开它，已经装好的照常能签
	Stale bool `json:"stale"`
}

type iosMaterialOrphanView struct {
	Kind string `json:"kind"`
	iosMaterialSlotView
}

type iosMaterialMachineView struct {
	ID          string `json:"id"`
	Installed   bool   `json:"installed"`
	UploadProbe any    `json:"uploadProbe"`
}

type iosMaterialTenantView struct {
	Slug                  string                   `json:"slug"`
	Current               bool                     `json:"current"`
	AppName               string                   `json:"appName"`
	TeamID                string                   `json:"teamId"`
	BundleID              string                   `json:"bundleId"`
	Delivery              string                   `json:"delivery"`
	TeamTenants           []string                 `json:"teamTenants"`
	TeamTestFlightTenants []string                 `json:"teamTestFlightTenants"`
	BundleTenants         []string                 `json:"bundleTenants"`
	Certificate           *iosMaterialSlotView     `json:"certificate"`
	Profile               *iosMaterialSlotView     `json:"profile"`
	UploadKey             *iosMaterialSlotView     `json:"uploadKey"`
	UploadKeyUse          string                   `json:"uploadKeyUse"`
	Machines              []iosMaterialMachineView `json:"machines"`
	EarliestExpiry        any                      `json:"earliestExpiry"`
	Readiness             gin.H                    `json:"readiness"`
}

func (s *server) iosMaterialTenants(c *gin.Context) {
	ctx := c.Request.Context()
	fail := func(what string, err error) {
		slog.Error("cannot build the iOS material overview by tenant", "step", what, "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_TENANTS_UNAVAILABLE", "Unable to read "+what)
	}
	snapshot, err := readIOSMaterialRecipients(ctx, s.db, false)
	if err != nil {
		fail("the platform encryption keys", err)
		return
	}
	items, err := listIOSMaterial(ctx, s.db, "")
	if err != nil {
		fail("the stored material", err)
		return
	}
	targets, invalid, err := s.iosSigningTargetsAndInvalid(ctx)
	if err != nil {
		fail("the tenants' iOS identities", err)
		return
	}
	modes, err := s.iosDeliveryModes(ctx)
	if err != nil {
		fail("the delivery modes", err)
		return
	}
	appNames, err := s.appNamesByTenant(ctx)
	if err != nil {
		fail("the app names", err)
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
	var tenantCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE deleted=0`).Scan(&tenantCount); err != nil {
		fail("the tenants", err)
		return
	}
	now := s.now()
	current := s.requestTenant(c)
	modeOf := func(id string) string {
		if mode, ok := modes[id]; ok {
			return mode
		}
		return iosDeliveryTestFlight
	}
	slotOf := func(item storedIOSMaterial) *iosMaterialSlotView {
		recipient, ok := snapshot.Doc.forPurpose(item.Purpose)
		return &iosMaterialSlotView{TeamID: item.TeamID, Scope: item.Scope, Version: item.Version,
			UploadedBy: item.UploadedBy, UploadedAt: item.UploadedAt, Stale: !ok || recipient.SHA256 != item.RecipientSHA256}
	}
	find := func(kind, team, scope string) *iosMaterialSlotView {
		for _, item := range items {
			// bundle id 不分大小写比：表的主键多半不区分大小写，而重传时 scope 不更新，大小写不同的一次
			// 重传会沿用旧 scope——按原样比，控制台会把传了的描述文件显示成"缺"
			if item.Kind == kind && strings.EqualFold(item.TeamID, team) && strings.EqualFold(item.Scope, scope) {
				return slotOf(item)
			}
		}
		return nil
	}

	builders := []buildMachine{}
	machines := []gin.H{}
	for _, m := range registry.Machines {
		if !iosBuilder(m) {
			continue
		}
		builders = append(builders, m)
		live, reported := liveness[m.ID]
		machines = append(machines, gin.H{
			"id": m.ID, "name": m.Name, "reported": reported,
			"online": reported && live.online(now), "paused": reported && live.PausedReason != "",
		})
	}

	views := make([]iosMaterialTenantView, 0, len(targets))
	for _, target := range targets {
		team := strings.ToUpper(target.TeamID)
		view := iosMaterialTenantView{
			Slug: target.Slug, Current: target.TenantID == current, AppName: appNames[target.TenantID],
			TeamID: team, BundleID: target.BundleID, Delivery: modeOf(target.TenantID),
			TeamTenants: []string{}, BundleTenants: []string{},
			TeamTestFlightTenants: testFlightTenantsOnTeam(targets, modeOf, target.TenantID, team),
			Certificate:           find(iosmaterial.KindCertificate, team, ""),
			Profile:               find(iosmaterial.KindProfile, team, target.BundleID),
			UploadKey:             find(iosmaterial.KindUploadKey, team, ""),
		}
		for _, other := range targets {
			if other.TenantID == target.TenantID || !strings.EqualFold(other.TeamID, team) {
				continue
			}
			view.TeamTenants = append(view.TeamTenants, other.Slug)
			if strings.EqualFold(other.BundleID, target.BundleID) {
				view.BundleTenants = append(view.BundleTenants, other.Slug)
			}
		}
		switch {
		case view.Delivery == iosDeliveryTestFlight:
			view.UploadKeyUse = iosUploadKeyRequired
		case view.UploadKey == nil:
			view.UploadKeyUse = iosUploadKeyNotNeeded
		case len(view.TeamTestFlightTenants) > 0:
			view.UploadKeyUse = iosUploadKeyKeptForOthers
		default:
			view.UploadKeyUse = iosUploadKeyWithdraw
		}
		view.Machines, view.EarliestExpiry = iosTenantMachines(builders, liveness, team, target.BundleID)
		code, detail := iosDeliveryReadiness{coverage: iosSigningCoverageFrom(registry, liveness, team, target.BundleID, now)}.
			problem(view.Delivery, team, target.BundleID)
		view.Readiness = gin.H{"ready": code == "", "code": nullableString(code), "detail": nullableString(detail)}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Slug < views[j].Slug })

	orphans := []iosMaterialOrphanView{}
	for _, item := range items {
		if iosMaterialInUse(item, targets) {
			continue
		}
		orphans = append(orphans, iosMaterialOrphanView{Kind: item.Kind, iosMaterialSlotView: *slotOf(item)})
	}
	invalidSlugs := make([]gin.H, 0, len(invalid))
	for _, target := range invalid {
		invalidSlugs = append(invalidSlugs, gin.H{"slug": target.Slug})
	}
	complete := len(items) < iosMaterialMaxRows
	c.JSON(http.StatusOK, gin.H{
		"complete":            complete,
		"invalidTenants":      invalidSlugs,
		"unconfiguredTenants": max(0, tenantCount-len(targets)-len(invalid)),
		"machines":            machines,
		"tenants":             views,
		"orphans":             orphans,
		// "没有租户在用"只在两件事都成立时才可信：清单没被截断；每个配了 iOS 的租户都读得出用哪个 Team
		"orphansDeletable": complete && len(invalid) == 0,
	})
}

// requestTenant 是发请求的那个控制台所属的租户：控制台只能跳到它自己的页面，所以要标出来。
//
// 平台级路由不经过按 Host 解析租户的中间件（它们本来就不按租户过滤），这里自己解析一次；
// 解析不出来（域名没登记、本地调试）就谁都不是当前租户，只是少一个跳转，不报错。
func (s *server) requestTenant(c *gin.Context) string {
	if value, ok := c.Get("tenantId"); ok && value != nil {
		return fmt.Sprint(value)
	}
	item, err := s.tenant.resolve(c.Request.Context(), c.Request.Host)
	if err != nil {
		return ""
	}
	return item.ID
}

// iosMaterialInUse：有没有租户在用这份材料。证书、上传 Key 按 Team，描述文件按 Team + bundle id。
func iosMaterialInUse(item storedIOSMaterial, targets []iosSigningTarget) bool {
	for _, target := range targets {
		if !strings.EqualFold(item.TeamID, target.TeamID) {
			continue
		}
		if item.Kind != iosmaterial.KindProfile || strings.EqualFold(item.Scope, target.BundleID) {
			return true
		}
	}
	return false
}

// iosTenantMachines 是一个租户在每台 iOS 构建机上的情况，以及这个 Team 最早的到期时间。
//
// 装没装按 (Team, bundle id) **原样**比，与认领时同一个判据：大小写对不上的话任务确实派不出去，
// 这里就该显示没装。到期时间是 Mac 按 Team 报的一个值——钥匙串里这个 Team 的全部证书（含过期、
// 已轮换掉的旧证书）与同 Team 所有描述文件里最早的那个，不是这个租户独有的。
func iosTenantMachines(builders []buildMachine, liveness map[string]machineLiveness, team, bundle string) ([]iosMaterialMachineView, any) {
	want := team + "." + strings.TrimSpace(bundle)
	out := make([]iosMaterialMachineView, 0, len(builders))
	var earliest *time.Time
	for _, m := range builders {
		view := iosMaterialMachineView{ID: m.ID}
		live, ok := liveness[m.ID]
		if ok {
			view.Installed = containsString(signingPairs(live.AppleTeams), want)
			for _, report := range live.AppleTeams {
				if !strings.EqualFold(report.TeamID, team) {
					continue
				}
				view.UploadProbe = nullableString(report.UploadProbe)
				if at, err := time.Parse(time.RFC3339, report.ExpiresAt); err == nil && (earliest == nil || at.Before(*earliest)) {
					earliest = &at
				}
			}
		}
		out = append(out, view)
	}
	if earliest == nil {
		return out, nil
	}
	return out, earliest.UTC().Format(time.RFC3339)
}

// appNamesByTenant 是每个租户在「应用身份」里填的应用名。租户表没有名称列，控制台拿它当显示名，
// 没填的租户不在里面（控制台退回 slug）。读不出来的一条跳过：它只是显示名。
func (s *server) appNamesByTenant(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id,config_value FROM app_configs WHERE config_key=? AND tenant_id<>0`, buildConfigKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tenant string
		var raw []byte
		if err := rows.Scan(&tenant, &raw); err != nil {
			return nil, err
		}
		var cfg struct {
			Identity struct {
				AppName string `json:"appName"`
			} `json:"identity"`
		}
		if json.Unmarshal(raw, &cfg) == nil && strings.TrimSpace(cfg.Identity.AppName) != "" {
			out[tenant] = strings.TrimSpace(cfg.Identity.AppName)
		}
	}
	return out, rows.Err()
}
