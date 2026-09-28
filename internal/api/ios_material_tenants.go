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
// 材料按租户存（设计 ios-tenant-owned-signing-material-2026-09-25 §3.1）：每个租户的证书、上传 Key 各一份，
// 描述文件每 bundle id 一份。这一页是平台的**只读**总览加紧急删除（§3.4）：缺什么、哪台 Mac 没装上、
// Mac 核对不过的原因。匹配、上传 Key 需不需要、现在能不能排都在这里算——这些规则与排队、切换交付方式
// 用的是同一套函数，控制台只负责画出来，不另写一份。

// iOS 上传 Key 对一个租户的用途。上传 Key 按租户存之后，一个租户的那一份与别人无关：自助上传却还存着，
// 就是该撤下的（切换时本来会删，留着多半是迁移复制过来的）。
const (
	iosUploadKeyRequired  = "required"            // 全托管：要有
	iosUploadKeyWithdraw  = "should-be-withdrawn" // 自助上传，却还存着这个租户的上传 Key
	iosUploadKeyNotNeeded = "not-needed"          // 自助上传，也没有存
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
	// Legacy：迁移时从按 Team 存的旧行复制来的 v1 密文，租户重传之后变成 v2
	Legacy bool `json:"legacy"`
}

// iosMaterialOrphanView 是没有租户在用的一格：tenant_id=0 的旧行，或者 Team / bundle id 已经和租户当前
// 配置对不上的行。删除按 (tenantId, kind, teamId, scope) 精确匹配。
type iosMaterialOrphanView struct {
	TenantID   string `json:"tenantId"`
	TenantSlug string `json:"tenantSlug"`
	Kind       string `json:"kind"`
	iosMaterialSlotView
}

type iosMaterialMachineView struct {
	ID          string `json:"id"`
	Installed   bool   `json:"installed"`
	UploadProbe any    `json:"uploadProbe"`
	// Problems 是这台 Mac 核对这个租户的材料时报的原因（按租户自报的机器才有），每条以 "<kind>: " 开头
	Problems []string `json:"problems"`
}

type iosMaterialTenantView struct {
	TenantID              string                   `json:"tenantId"`
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
	// Status / Problems：这一行齐不齐、差什么（第二轮设计 §10.1）。判定在这里做：列表要按状态
	// 在服务端筛，规则只能有一份
	Status   string               `json:"status"`
	Problems []iosMaterialProblem `json:"problems"`
	// Delivered：证书与描述文件都在平台上、且新装的 Mac 解得开。只有已下发还没装上才算机器的问题
	Delivered bool `json:"delivered"`
}

// 一行的状态等级。
const (
	iosMaterialReady     = "ready"
	iosMaterialMissing   = "missing"
	iosMaterialAttention = "attention"
)

// iosMaterialProblem 是一行差的一件事。控制台按 Code 出文案，Slugs / Count / Detail 是填进文案的值。
type iosMaterialProblem struct {
	Code   string   `json:"code"`
	Slugs  []string `json:"slugs,omitempty"`
	Count  int      `json:"count,omitempty"`
	Detail string   `json:"detail,omitempty"`
}

// iosMaterialIndex 是平台存的全部材料加上现在登记的两把公钥：匹配、判"加密给了旧公钥"、判"已下发"
// 都从这里来。按租户的总览与打包机列表（pendingInstall）共用，两处的"已下发"必须是同一个判据。
type iosMaterialIndex struct {
	items []storedIOSMaterial
	doc   iosMaterialDoc
}

func (s *server) readIOSMaterialIndex(ctx context.Context) (iosMaterialIndex, error) {
	snapshot, err := readIOSMaterialRecipients(ctx, s.db, false)
	if err != nil {
		return iosMaterialIndex{}, fmt.Errorf("platform encryption keys: %w", err)
	}
	items, err := listIOSMaterial(ctx, s.db, "")
	if err != nil {
		return iosMaterialIndex{}, fmt.Errorf("stored material: %w", err)
	}
	return iosMaterialIndex{items: items, doc: snapshot.Doc}, nil
}

// complete：材料清单没被行数上限截断。截断了"没人用""没传"都不可信
func (x iosMaterialIndex) complete() bool { return len(x.items) < iosMaterialMaxRows }

func (x iosMaterialIndex) slot(item storedIOSMaterial) *iosMaterialSlotView {
	recipient, ok := x.doc.forPurpose(item.Purpose)
	return &iosMaterialSlotView{TeamID: item.TeamID, Scope: item.Scope, Version: item.Version,
		UploadedBy: item.UploadedBy, UploadedAt: item.UploadedAt, Stale: !ok || recipient.SHA256 != item.RecipientSHA256,
		Legacy: item.Legacy}
}

// find 找这个租户的一格。
func (x iosMaterialIndex) find(tenant, kind, team, scope string) *iosMaterialSlotView {
	for _, item := range x.items {
		// bundle id 不分大小写比：表的主键多半不区分大小写，而重传时 scope 不更新，大小写不同的一次
		// 重传会沿用旧 scope——按原样比，控制台会把传了的描述文件显示成"缺"
		if item.TenantID == tenant && item.Kind == kind && strings.EqualFold(item.TeamID, team) && strings.EqualFold(item.Scope, scope) {
			return x.slot(item)
		}
	}
	return nil
}

// delivered：这个租户的证书与描述文件都在平台上、且加密给的是现在登记的公钥——新装的 Mac 解得开。
// 上传 Key 不在其中：Mac 报不报这个租户与上传 Key 无关（没装报 missing），全托管缺 Key 另有问题码
func (x iosMaterialIndex) delivered(target iosSigningTarget) bool {
	certificate := x.find(target.TenantID, iosmaterial.KindCertificate, target.TeamID, "")
	profile := x.find(target.TenantID, iosmaterial.KindProfile, target.TeamID, target.BundleID)
	return certificate != nil && profile != nil && !certificate.Stale && !profile.Stale
}

// deliveredTargets 是材料已下发的那些租户。打包机列表拿它数"这台还没装上几个"
func (x iosMaterialIndex) deliveredTargets(targets []iosSigningTarget) []iosSigningTarget {
	out := []iosSigningTarget{}
	for _, target := range targets {
		if x.delivered(target) {
			out = append(out, target)
		}
	}
	return out
}

// iosMaterialStatus 算一行的问题与等级（设计 §10.1）。顺序即优先级：先缺材料，再是会出错的配置，
// 再是机器没装上，最后是排队判据——排队判据只在它说的不是前面已经说过的那件事时才加。
func iosMaterialStatus(view iosMaterialTenantView, builders int, readinessCode, readinessDetail string) (string, []iosMaterialProblem) {
	problems := []iosMaterialProblem{}
	add := func(code string) { problems = append(problems, iosMaterialProblem{Code: code}) }
	if view.Certificate == nil {
		add("certificate-missing")
	}
	if view.Profile == nil {
		add("profile-missing")
	}
	if view.UploadKeyUse == iosUploadKeyRequired && view.UploadKey == nil {
		add("upload-key-missing")
	}
	missing := len(problems) > 0
	for _, slot := range []*iosMaterialSlotView{view.Certificate, view.Profile, view.UploadKey} {
		if slot != nil && slot.Stale {
			add("material-stale")
			break
		}
	}
	if len(view.BundleTenants) > 0 {
		problems = append(problems, iosMaterialProblem{Code: "bundle-duplicated", Slugs: view.BundleTenants})
	}
	if view.UploadKeyUse == iosUploadKeyWithdraw {
		add("upload-key-should-be-withdrawn")
	}
	notInstalled, rejected := 0, 0
	detail := ""
	for _, machine := range view.Machines {
		if !machine.Installed {
			notInstalled++
		}
		if len(machine.Problems) > 0 {
			rejected++
			if detail == "" {
				detail = machine.Problems[0]
			}
		}
	}
	// Mac 装前核对不过（设计 §4.2）：租户交的东西不对，原因是 Mac 报的原话
	if rejected > 0 {
		problems = append(problems, iosMaterialProblem{Code: "mac-rejected", Count: rejected, Detail: detail})
	}
	switch {
	case builders == 0:
		add("no-builders")
	case view.Delivered && notInstalled > 0:
		problems = append(problems, iosMaterialProblem{Code: "not-installed", Count: notInstalled})
	}
	if readinessCode != "" {
		explained := false
		switch readinessCode {
		// "没有打包机报过这份材料"：缺材料、旧公钥、没有打包机、已下发没装上都已经说了这件事
		case "NO_BUILDER_FOR_TEAM":
			explained = len(problems) > 0
		// "上传 Key 不可用"：没传 Key 已经说了
		case "NO_UPLOADER_FOR_TEAM":
			explained = view.UploadKeyUse == iosUploadKeyRequired && view.UploadKey == nil
		}
		if !explained {
			problems = append(problems, iosMaterialProblem{Code: "not-ready", Detail: readinessDetail})
		}
	}
	switch {
	case missing:
		return iosMaterialMissing, problems
	case len(problems) > 0:
		return iosMaterialAttention, problems
	}
	return iosMaterialReady, problems
}

func (s *server) iosMaterialTenants(c *gin.Context) {
	ctx := c.Request.Context()
	fail := func(what string, err error) {
		slog.Error("cannot build the iOS material overview by tenant", "step", what, "error", err)
		problem(c, http.StatusInternalServerError, "IOS_MATERIAL_TENANTS_UNAVAILABLE", "Unable to read "+what)
	}
	filter, bad := parseIOSMaterialTenantFilter(c)
	if bad != "" {
		problem(c, http.StatusBadRequest, "INVALID_IOS_MATERIAL_FILTER", bad)
		return
	}
	index, err := s.readIOSMaterialIndex(ctx)
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
			TenantID: target.TenantID, Slug: target.Slug, Current: target.TenantID == current, AppName: appNames[target.TenantID],
			TeamID: team, BundleID: target.BundleID, Delivery: modeOf(target.TenantID),
			TeamTenants: []string{}, BundleTenants: []string{},
			TeamTestFlightTenants: testFlightTenantsOnTeam(targets, modeOf, target.TenantID, team),
			Certificate:           index.find(target.TenantID, iosmaterial.KindCertificate, team, ""),
			Profile:               index.find(target.TenantID, iosmaterial.KindProfile, team, target.BundleID),
			UploadKey:             index.find(target.TenantID, iosmaterial.KindUploadKey, team, ""),
			Delivered:             index.delivered(target),
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
		default:
			view.UploadKeyUse = iosUploadKeyWithdraw
		}
		view.Machines, view.EarliestExpiry = iosTenantMachines(builders, liveness, target.TenantID, team, target.BundleID)
		code, detail := iosDeliveryReadiness{coverage: iosSigningCoverageFrom(registry, liveness, target.TenantID, team, target.BundleID, now)}.
			problem(view.Delivery, team, target.BundleID)
		view.Readiness = gin.H{"ready": code == "", "code": nullableString(code), "detail": nullableString(detail)}
		view.Status, view.Problems = iosMaterialStatus(view, len(builders), code, detail)
		views = append(views, view)
	}
	page, total, next, counts := filterIOSMaterialTenants(views, filter)

	slugs, err := s.tenantSlugsByID(ctx)
	if err != nil {
		fail("the tenants", err)
		return
	}
	orphans := []iosMaterialOrphanView{}
	for _, item := range index.items {
		if iosMaterialInUse(item, targets) {
			continue
		}
		orphans = append(orphans, iosMaterialOrphanView{TenantID: item.TenantID, TenantSlug: slugs[item.TenantID],
			Kind: item.Kind, iosMaterialSlotView: *index.slot(item)})
	}
	invalidSlugs := make([]gin.H, 0, len(invalid))
	for _, target := range invalid {
		invalidSlugs = append(invalidSlugs, gin.H{"slug": target.Slug})
	}
	complete := index.complete()
	c.JSON(http.StatusOK, gin.H{
		"complete":            complete,
		"invalidTenants":      invalidSlugs,
		"unconfiguredTenants": max(0, tenantCount-len(targets)-len(invalid)),
		"machines":            machines,
		// tenants 是筛选、分页之后的这一页；total 是筛选后的总数；counts 按 q 与 machine 筛过、
		// 不按 status——顶部汇总点一下就是切状态
		"tenants":    page,
		"total":      total,
		"nextCursor": next,
		"hasMore":    next != nil,
		"limit":      filter.limit,
		"counts":     counts,
		"orphans":    orphans,
		// "没有租户在用"只在两件事都成立时才可信：清单没被截断；每个配了 iOS 的租户都读得出用哪个 Team
		"orphansDeletable": complete && len(invalid) == 0,
	})
}

// iosMaterialTenantFilter 是按租户总览的查询条件（设计 §10.2）。
type iosMaterialTenantFilter struct {
	status  string
	machine string
	q       string
	limit   int
	after   string
}

func parseIOSMaterialTenantFilter(c *gin.Context) (iosMaterialTenantFilter, string) {
	filter := iosMaterialTenantFilter{
		status:  strings.TrimSpace(c.Query("status")),
		machine: strings.TrimSpace(c.Query("machine")),
		q:       strings.ToLower(strings.TrimSpace(c.Query("q"))),
	}
	switch filter.status {
	case "", iosMaterialReady, iosMaterialMissing, iosMaterialAttention:
	default:
		return filter, "status must be ready, missing or attention"
	}
	if len([]rune(filter.q)) > 100 || len(filter.machine) > 100 {
		return filter, "q and machine must be at most 100 characters"
	}
	limit, bad := parseListLimit(c)
	if bad != "" {
		return filter, bad
	}
	filter.limit = limit
	if raw := strings.TrimSpace(c.Query("cursor")); raw != "" {
		values, err := decodeListCursor(raw, []sortKey{{column: "slug", kind: cursorText}})
		if err != nil {
			return filter, "cursor is invalid"
		}
		filter.after, _ = values[0].(string)
	}
	return filter, ""
}

// filterIOSMaterialTenants 在服务端筛选、计数、分页（标准 §3.1：服务端是唯一事实源）。租户是百级以内，
// 每行先算完再筛；按 slug 升序（slug 有唯一索引），游标是上一页最后一个 slug。
func filterIOSMaterialTenants(views []iosMaterialTenantView, filter iosMaterialTenantFilter) ([]iosMaterialTenantView, int, any, gin.H) {
	counts := map[string]int{iosMaterialReady: 0, iosMaterialMissing: 0, iosMaterialAttention: 0}
	matched := make([]iosMaterialTenantView, 0, len(views))
	for _, view := range views {
		if filter.q != "" && !strings.Contains(strings.ToLower(view.Slug+"\n"+view.AppName+"\n"+view.TeamID+"\n"+view.BundleID), filter.q) {
			continue
		}
		if filter.machine != "" && !iosMaterialPendingOn(view, filter.machine) {
			continue
		}
		counts[view.Status]++
		if filter.status != "" && view.Status != filter.status {
			continue
		}
		matched = append(matched, view)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Slug < matched[j].Slug })
	start := 0
	if filter.after != "" {
		start = sort.Search(len(matched), func(i int) bool { return matched[i].Slug > filter.after })
	}
	end := min(start+filter.limit, len(matched))
	var next any
	if end < len(matched) {
		next = encodeListCursor(matched[end-1].Slug)
	}
	return matched[start:end], len(matched), next, gin.H{
		iosMaterialReady: counts[iosMaterialReady], iosMaterialMissing: counts[iosMaterialMissing], iosMaterialAttention: counts[iosMaterialAttention],
	}
}

// iosMaterialPendingOn：材料已下发、但这台机器没装上。打包机卡片上的 pendingInstall 与这里的
// machine 筛选是同一件事（那边用 machineLivenessView 数，判据同为"已下发 + 这台没报这个 pair"）
func iosMaterialPendingOn(view iosMaterialTenantView, machineID string) bool {
	if !view.Delivered {
		return false
	}
	for _, machine := range view.Machines {
		if machine.ID == machineID {
			return !machine.Installed
		}
	}
	return false
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

// iosMaterialInUse：这份材料的租户还在用它——租户当前的 Team 对得上，描述文件还要 bundle id 对得上。
// tenant_id=0 的旧行不属于任何租户，永远算孤儿：它们只给还没升级的打包机用（设计 §3.5）。
func iosMaterialInUse(item storedIOSMaterial, targets []iosSigningTarget) bool {
	for _, target := range targets {
		if item.TenantID != target.TenantID || !strings.EqualFold(item.TeamID, target.TeamID) {
			continue
		}
		if item.Kind != iosmaterial.KindProfile || strings.EqualFold(item.Scope, target.BundleID) {
			return true
		}
	}
	return false
}

// iosTenantMachines 是一个租户在每台 iOS 构建机上的情况，以及最早的到期时间。
//
// 装没装与认领时同一个判据（machineLiveness.signs）：按租户自报的机器看这个租户自己的材料，旧机器按
// (Team, bundle id) 原样比。到期时间：按租户自报的机器报的是这个租户的证书与描述文件；旧机器报的是
// 这个 Team 在钥匙串里全部证书与所有描述文件里最早的那个，不是这个租户独有的。
func iosTenantMachines(builders []buildMachine, liveness map[string]machineLiveness, tenant, team, bundle string) ([]iosMaterialMachineView, any) {
	out := make([]iosMaterialMachineView, 0, len(builders))
	var earliest *time.Time
	note := func(expiresAt string) {
		if at, err := time.Parse(time.RFC3339, expiresAt); err == nil && (earliest == nil || at.Before(*earliest)) {
			earliest = &at
		}
	}
	for _, m := range builders {
		view := iosMaterialMachineView{ID: m.ID, Problems: []string{}}
		live, ok := liveness[m.ID]
		if ok && live.TenantMaterial != nil {
			view.Installed = live.signs(tenant, team, bundle)
			if report := live.tenantReport(tenant, team); report != nil {
				view.UploadProbe = nullableString(report.UploadProbe)
				view.Problems = append(view.Problems, report.Problems...)
				note(report.ExpiresAt)
			}
		} else if ok {
			view.Installed = live.signs(tenant, team, bundle)
			for _, report := range live.AppleTeams {
				if !strings.EqualFold(report.TeamID, team) {
					continue
				}
				view.UploadProbe = nullableString(report.UploadProbe)
				note(report.ExpiresAt)
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
