package main

// 签名材料的自动装配（设计 ios-signing-material-distribution-2026-09-19.md §6.2）。
//
// 控制进程做的事只有搬运：取清单、比对本机已经装到第几版、把新的那几份**密文**交给对应
// 角色的程序。**它不解密，也解不开**——两把私钥分别在 _rnbuilder 与 _rnuploader 名下，
// 而它持有的是机器令牌与出处密钥。这条界线就是 Mac 上三个账户分开的理由（§4.1）。
//
// 密文走标准输入交过去，不落盘：控制进程的状态目录 0700、同一棵树里放着出处私钥，为了
// 递一份不是机密的密文去放宽那个目录不值得。
//
// 按租户（设计 ios-tenant-owned-signing-material-2026-09-25 §4、§12.2）：取清单时带上能力
// tenant-signing-material，服务端回 layout=tenant 的清单时，这台机器切到按租户的布局并且**不再回落**。
// 旧版服务端不认这个能力、回的清单没有 layout——那时的行为与以前一字不差（syncTeamMaterial）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// installedMaterialFile 记本机每一格材料装到了第几版。
//
// 记在控制进程这一侧而不是问两个角色账户："装到了第几版"是个调度问题，不是材料本身的
// 属性；而且问它们等于每一轮都要多起两个子进程。
const installedMaterialFile = "ios-material.json"

// iosMaterialSyncEvery 是两次取清单之间的最短间隔。认领每 10 秒一次，而材料几个月才
// 动一次——每一轮都去问一次纯属浪费，服务端那边也是。
const iosMaterialSyncEvery = 2 * time.Minute

// 清单与本机记录的两种布局。team：材料按 Apple Team 存、同 Team 的租户共用（旧）；tenant：按租户。
const (
	materialLayoutTeam   = "team"
	materialLayoutTenant = "tenant"
)

// capabilityTenantMaterial 是这一版会按租户落盘的能力名：认领时报，取清单时也带（§4.5：材料同步
// 发生在认领之前，只在认领里报的话服务端来不及知道）。
const capabilityTenantMaterial = "tenant-signing-material"

// rejectedPrefix 是两个角色程序标出「材料本身不合格」的前缀：同一版不再反复试。
const rejectedPrefix = "rejected: "

// materialEntry 是清单里的一项，与服务端 storedIOSMaterial 对齐。TenantID 与 Legacy 只在按租户的清单里有。
type materialEntry struct {
	TenantID        string `json:"tenantId"`
	Kind            string `json:"kind"`
	TeamID          string `json:"teamId"`
	Scope           string `json:"scope"`
	Purpose         string `json:"purpose"`
	RecipientSHA256 string `json:"recipientSha256"`
	Version         int64  `json:"version"`
	// Legacy：从按 Team 的旧行复制给这个租户的 v1 密文，里面没有租户。只有这种项才许装 v1
	Legacy bool `json:"legacy"`
}

// slot 是这一格在本机记录里的键：旧布局 kind/team/scope，按租户 <租户>/kind/team/scope。
func (e materialEntry) slot() string {
	if e.TenantID != "" {
		return e.TenantID + "/" + e.Kind + "/" + e.TeamID + "/" + e.Scope
	}
	return e.Kind + "/" + e.TeamID + "/" + e.Scope
}

// parseSlot 把本机记录里的一格拆回来。scope 里没有斜杠（bundle id、旧的机器 id）。
func parseSlot(slot string) (materialEntry, bool) {
	parts := strings.Split(slot, "/")
	switch {
	case len(parts) == 3:
		return materialEntry{Kind: parts[0], TeamID: parts[1], Scope: parts[2]}, true
	case len(parts) == 4 && iosmaterial.ValidTenantID(parts[0]):
		return materialEntry{TenantID: parts[0], Kind: parts[1], TeamID: parts[2], Scope: parts[3]}, true
	}
	return materialEntry{}, false
}

// kindOrder 是同一轮里装的顺序：描述文件要核对「包含本租户那张证书」，证书得先装上。
func kindOrder(kind string) int {
	switch kind {
	case iosmaterial.KindCertificate:
		return 0
	case iosmaterial.KindProfile:
		return 1
	}
	return 2
}

// materialManifest 是一次取回的清单。
type materialManifest struct {
	// Layout 为空是旧版服务端（等于 team）
	Layout string          `json:"layout"`
	Items  []materialEntry `json:"items"`
	// Complete：服务端明说清单没被截断；旧版服务端不带，按不完整处理
	Complete bool `json:"complete"`
}

// materialRecord 是本机记录：布局，与每一格装到了第几版。
type materialRecord struct {
	Layout    string           `json:"layout"`
	Installed map[string]int64 `json:"installed"`
}

// materialProblem 是按租户的一格装不上的原因。rejected=材料本身不合格，同一版不再试；否则下一轮再试。
type materialProblem struct {
	version  int64
	reason   string
	rejected bool
}

// installFailure 是一次安装失败：角色程序说的原因，以及它是不是「材料不合格」。
type installFailure struct {
	err      error
	reason   string
	rejected bool
}

func (f installFailure) Error() string { return f.err.Error() + ": " + f.reason }

// syncIOSMaterial 取一次清单，把还没装或版本更高的那几份装上。
//
// 失败不是致命错误：这一轮装不上，下一轮再来。装不上的后果是"这台机器少报一个 Team"，
// 而那件事控制台上看得见（missingTenants）——比在这里把认领循环卡住好。
func (a *agent) syncIOSMaterial(ctx context.Context) {
	if a.cfg.MachineEnv[jobspec.IOSSigningDirEnv] == "" {
		return // 不是 iOS 打包机
	}
	if !a.materialDue() {
		return
	}
	manifest, err := a.api.iosMaterial(ctx)
	if err != nil {
		a.sayOnce("iosMaterialList", "cannot read the signing material list: "+err.Error())
		return
	}
	record := readMaterialRecord(a.cfg.StateDir)
	switch {
	case manifest.Layout == materialLayoutTenant:
		a.serverLayout = materialLayoutTenant
		if record.Layout != materialLayoutTenant {
			// 先记下来再装：装到一半重启的话，下一轮仍然按租户来，不会把租户的格当成旧格处理
			record.Layout = materialLayoutTenant
			if err := writeMaterialRecord(a.cfg.StateDir, record); err != nil {
				a.log.Error("cannot record the switch to per-tenant signing material", "error", err)
				return
			}
			a.log.Info("the server hands out signing material per tenant; this machine switches to the per-tenant layout for good")
		}
		a.layout = materialLayoutTenant
		a.syncTenantMaterial(ctx, manifest, record)
	case record.Layout == materialLayoutTenant:
		// 已经按租户落盘了，服务端却回了按 Team 的清单（多半是服务端回滚）。不回落：按 Team 装回去，
		// 同 Team 的租户就又共用一份材料了。认领里也不再报任何 iOS 材料（claimRequest），宁可不派
		a.serverLayout = materialLayoutTeam
		a.sayOnce("iosMaterialLayout", "this machine installs signing material per tenant, but the server now answers "+
			"with the per-team list; ignoring it and taking no iOS jobs until the server hands out material per tenant again")
	default:
		a.serverLayout, a.layout = materialLayoutTeam, materialLayoutTeam
		a.syncTeamMaterial(ctx, manifest.Items, manifest.Complete, record.Installed)
	}
}

// syncTeamMaterial 是旧布局（材料按 Team）那一套，与按租户之前一字不差。
func (a *agent) syncTeamMaterial(ctx context.Context, entries []materialEntry, complete bool, installed map[string]int64) {
	changed := false
	for _, entry := range entries {
		if have, ok := installed[entry.slot()]; ok && have >= entry.Version {
			continue
		}
		if err := a.installMaterial(ctx, entry); err != nil {
			// 一份装不上不该挡住别的：证书没装上时描述文件照样该放好，人能从控制台上
			// 看出缺的是哪一片
			a.log.Error("cannot install signing material", "slot", entry.slot(), "error", err)
			continue
		}
		a.log.Info("signing material installed", "slot", entry.slot(), "version", entry.Version)
		installed[entry.slot()] = entry.Version
		changed = true
	}
	// 墓碑：本机从服务端装过、而清单里这个 Team 已经没有上传 Key 了（租户切到自助上传、Key 被撤下）
	// ——请上传账户把本机那一份删掉。服务端删材料只删它自己的密文，不这样做的话，切到自助上传的
	// 租户的 Key 会一直留在每台 Mac 上（设计 ios-tenant-delivery-tiers-2026-09-24 §3.9）。
	// 只动本机从清单装上的那几格：装机时手工放的 Key 不在记录里，不碰
	// 清单被截断（或者旧版服务端没说）时不做：那时"清单里没有"不等于"撤下了"
	if complete {
		if removed := a.removeWithdrawnUploadKeys(ctx, entries, installed); removed {
			changed = true
		}
	}
	if changed {
		if err := writeInstalledMaterial(a.cfg.StateDir, installed); err != nil {
			// 记不下来的后果是下一轮重装一遍——幂等，但会白跑两个子进程
			a.log.Error("cannot record which signing material is installed", "error", err)
		}
	}
}

// syncTenantMaterial 按租户装、按租户撤（§4.1、§12.2）。
func (a *agent) syncTenantMaterial(ctx context.Context, manifest materialManifest, record materialRecord) {
	installed := record.Installed
	if a.materialProblems == nil {
		a.materialProblems = map[string]materialProblem{}
	}
	entries := make([]materialEntry, 0, len(manifest.Items))
	for _, entry := range manifest.Items {
		// 租户 id 要拼进 Mac 上的路径：形状不对的一项不碰，也不能让它把整份清单当成不完整
		if !iosmaterial.ValidTenantID(entry.TenantID) {
			a.sayOnce("iosMaterialTenant", "the per-tenant signing material list has an item without a usable tenantId; skipping it")
			continue
		}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if kindOrder(entries[i].Kind) != kindOrder(entries[j].Kind) {
			return kindOrder(entries[i].Kind) < kindOrder(entries[j].Kind)
		}
		return entries[i].slot() < entries[j].slot()
	})
	changed := false
	allInstalled := len(entries) == len(manifest.Items)
	listed := map[string]bool{}
	for _, entry := range entries {
		slot := entry.slot()
		listed[slot] = true
		if have, ok := installed[slot]; ok && have >= entry.Version {
			continue
		}
		if problem, ok := a.materialProblems[slot]; ok && problem.rejected && problem.version == entry.Version {
			allInstalled = false
			continue
		}
		if err := a.installMaterial(ctx, entry); err != nil {
			allInstalled = false
			problem := materialProblem{version: entry.Version, reason: err.Error()}
			var failure installFailure
			if errors.As(err, &failure) {
				problem.reason, problem.rejected = strings.TrimPrefix(failure.reason, rejectedPrefix), failure.rejected
			}
			a.materialProblems[slot] = problem
			a.log.Error("cannot install signing material", "slot", slot, "rejected", problem.rejected, "error", err)
			continue
		}
		a.log.Info("signing material installed", "slot", slot, "version", entry.Version)
		delete(a.materialProblems, slot)
		if entry.Kind == iosmaterial.KindCertificate {
			// 描述文件是对着这个租户当时那张证书核的：证书换了，之前核不过的那几份要重新核
			a.forgetRejectedProfiles(entry.TenantID, entry.TeamID)
		}
		installed[slot] = entry.Version
		changed = true
	}
	for slot := range a.materialProblems {
		if !listed[slot] {
			delete(a.materialProblems, slot)
		}
	}
	// 墓碑与旧布局的清理都只在清单完整时做：截断的清单里"没有"不等于"撤下了"
	if manifest.Complete {
		if a.removeWithdrawnTenantMaterial(ctx, listed, installed) {
			changed = true
		}
		// 旧布局的格在新布局装齐之后才删（§4.1）
		if allInstalled && a.removeLegacyMaterial(ctx, installed) {
			changed = true
		}
	}
	if changed {
		if err := writeMaterialRecord(a.cfg.StateDir, materialRecord{Layout: materialLayoutTenant, Installed: installed}); err != nil {
			a.log.Error("cannot record which signing material is installed", "error", err)
		}
	}
}

// forgetRejectedProfiles 清掉一个 (租户, Team) 下核对不过的描述文件，让它们下一次重新核。
func (a *agent) forgetRejectedProfiles(tenant, team string) {
	for slot := range a.materialProblems {
		if entry, ok := parseSlot(slot); ok && entry.TenantID == tenant && entry.TeamID == team && entry.Kind == iosmaterial.KindProfile {
			delete(a.materialProblems, slot)
		}
	}
}

// removeWithdrawnTenantMaterial 撤掉本机从清单装过、清单里已经没有的租户格：租户删了自己的材料、
// 平台紧急删除、租户换了 Team 或 bundle id、切到自助上传撤下的上传 Key，都走这一条（§4.1）。
func (a *agent) removeWithdrawnTenantMaterial(ctx context.Context, listed map[string]bool, installed map[string]int64) bool {
	changed := false
	for _, slot := range sortedSlots(installed) {
		entry, ok := parseSlot(slot)
		if !ok || entry.TenantID == "" || listed[slot] {
			continue
		}
		if err := a.removeMaterial(ctx, entry); err != nil {
			a.log.Error("cannot remove withdrawn signing material", "slot", slot, "error", err)
			continue
		}
		a.log.Info("withdrawn signing material removed", "slot", slot)
		delete(installed, slot)
		changed = true
	}
	return changed
}

// removeLegacyMaterial 删掉旧布局从清单装上的格：描述文件与上传 Key 删掉；证书只从记录里拿掉，
// 钥匙串里的身份不动——它可能与某个租户的是同一张，而构建已经按 SHA-1 钉的是租户那张。
func (a *agent) removeLegacyMaterial(ctx context.Context, installed map[string]int64) bool {
	changed := false
	for _, slot := range sortedSlots(installed) {
		entry, ok := parseSlot(slot)
		if !ok || entry.TenantID != "" {
			continue
		}
		if entry.Kind != iosmaterial.KindCertificate {
			if err := a.removeMaterial(ctx, entry); err != nil {
				a.log.Error("cannot remove per-team signing material", "slot", slot, "error", err)
				continue
			}
		}
		a.log.Info("per-team signing material retired", "slot", slot)
		delete(installed, slot)
		changed = true
	}
	return changed
}

// removeMaterial 请对应的角色账户撤掉本机的一格。
func (a *agent) removeMaterial(ctx context.Context, entry materialEntry) error {
	if entry.Kind == iosmaterial.KindUploadKey {
		return a.removeUploadKey(ctx, entry.TenantID, entry.TeamID)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	args := []string{"remove-ios-material", "--signing-dir", a.cfg.MachineEnv[jobspec.IOSSigningDirEnv]}
	if entry.TenantID != "" {
		args = append(args, "--tenant", entry.TenantID)
	}
	args = append(args, "--kind", entry.Kind, "--team", entry.TeamID)
	if entry.Scope != "" {
		args = append(args, "--scope", entry.Scope)
	}
	cmd := a.runnerReadCommand(ctx, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, truncate(runnerFailureDetail(stdout.String(), stderr.String()), 300))
	}
	var result struct {
		Removed bool `json:"removed"`
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || !result.Removed {
		return fmt.Errorf("the build runner did not confirm: %s", truncate(stdout.String(), 200))
	}
	return nil
}

// tenantProblems 是按 (租户, Team) 归好的安装问题，每条以种类开头（§12.3），随盘点报上去。
func (a *agent) tenantProblems() map[string][]string {
	out := map[string][]string{}
	for slot, problem := range a.materialProblems {
		entry, ok := parseSlot(slot)
		if !ok || entry.TenantID == "" {
			continue
		}
		key := jobspec.TenantCertificateKey(entry.TenantID, entry.TeamID)
		out[key] = append(out[key], entry.Kind+": "+problem.reason)
	}
	for _, problems := range out {
		sort.Strings(problems)
	}
	return out
}

// tenantMode：这台机器已经按租户落盘。读一次本机记录后记在内存里，切换发生在 syncIOSMaterial。
func (a *agent) tenantMode() bool {
	if a.layout == "" {
		a.layout = readMaterialRecord(a.cfg.StateDir).Layout
	}
	return a.layout == materialLayoutTenant
}

func sortedSlots(installed map[string]int64) []string {
	out := make([]string, 0, len(installed))
	for slot := range installed {
		out = append(out, slot)
	}
	sort.Strings(out)
	return out
}

// removeWithdrawnUploadKeys 删掉清单里已经没有的上传 Key，返回是否改了本机记录。
func (a *agent) removeWithdrawnUploadKeys(ctx context.Context, entries []materialEntry, installed map[string]int64) bool {
	listed := map[string]bool{}
	for _, entry := range entries {
		if entry.Kind == iosmaterial.KindUploadKey {
			listed[entry.TeamID] = true
		}
	}
	changed := false
	for slot := range installed {
		kind, rest, _ := strings.Cut(slot, "/")
		team, _, _ := strings.Cut(rest, "/")
		if kind != iosmaterial.KindUploadKey || listed[team] {
			continue
		}
		if err := a.removeUploadKey(ctx, "", team); err != nil {
			a.log.Error("cannot remove a withdrawn upload key", "team", team, "error", err)
			continue
		}
		a.log.Info("withdrawn upload key removed", "team", team)
		delete(installed, slot)
		changed = true
	}
	return changed
}

// removeUploadKey 请上传账户删掉一个 Team 的上传 Key（tenant 非空时是那个租户的那一份）。
func (a *agent) removeUploadKey(ctx context.Context, tenant, team string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	args := []string{"--remove-key"}
	if tenant != "" {
		args = append(args, "--tenant", tenant)
	}
	cmd := a.uploaderCommand(ctx, append(args, "--team", team, "--keys", a.cfg.IOSUploadKeys)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, truncate(strings.TrimSpace(stderr.String()), 300))
	}
	var result struct {
		Removed bool `json:"removed"`
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || !result.Removed {
		return fmt.Errorf("the upload program did not confirm: %s", truncate(stdout.String(), 200))
	}
	return nil
}

// materialDue 控制取清单的频率。
func (a *agent) materialDue() bool {
	now := a.now()
	if !a.lastMaterialSync.IsZero() && now.Sub(a.lastMaterialSync) < iosMaterialSyncEvery {
		return false
	}
	a.lastMaterialSync = now
	return true
}

// installMaterial 取一份密文，交给对应角色的程序装。按租户的格带上 --tenant（迁移过来的 v1 再带
// --legacy）：角色程序拿它与材料里自己写的租户比，不一致就不装。
func (a *agent) installMaterial(ctx context.Context, entry materialEntry) error {
	ciphertext, err := a.api.iosMaterialBox(ctx, entry)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var tenantArgs []string
	if entry.TenantID != "" {
		tenantArgs = append(tenantArgs, "--tenant", entry.TenantID)
		if entry.Legacy {
			tenantArgs = append(tenantArgs, "--legacy")
		}
	}
	var cmd = a.runnerReadCommand(ctx, append([]string{"install-ios-material",
		"--signing-dir", a.cfg.MachineEnv[jobspec.IOSSigningDirEnv]}, tenantArgs...)...)
	if entry.Purpose == iosmaterial.PurposeUploader {
		cmd = a.uploaderCommand(ctx, append([]string{"--install-key", "--keys", a.cfg.IOSUploadKeys}, tenantArgs...)...)
	}
	cmd.Stdin = bytes.NewReader(ciphertext)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		reason := truncate(runnerFailureDetail(stdout.String(), stderr.String()), 300)
		return installFailure{err: err, reason: reason, rejected: strings.HasPrefix(reason, rejectedPrefix)}
	}
	out := stdout.Bytes()
	var result struct {
		Installed bool   `json:"installed"`
		Warning   string `json:"warning"`
	}
	if json.Unmarshal(out, &result) != nil || !result.Installed {
		return fmt.Errorf("the installer did not confirm: %s", truncate(string(out), 200))
	}
	if result.Warning != "" {
		a.log.Warn("signing material installed with a warning", "slot", entry.slot(), "warning", result.Warning)
	}
	return nil
}

// ---- 本机记录 ----

// readMaterialRecord 读本机记录。旧格式（顶层就是 slot -> 版本）当作 layout=team；读不出来当作
// 什么都没装：重装一遍是幂等的，而拿着一份坏记录会永远跳过。
func readMaterialRecord(stateDir string) materialRecord {
	empty := materialRecord{Layout: materialLayoutTeam, Installed: map[string]int64{}}
	raw, err := os.ReadFile(filepath.Join(stateDir, installedMaterialFile))
	if err != nil {
		return empty
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return empty
	}
	if _, ok := probe["layout"]; ok {
		var record materialRecord
		if json.Unmarshal(raw, &record) != nil || (record.Layout != materialLayoutTeam && record.Layout != materialLayoutTenant) {
			return empty
		}
		if record.Installed == nil {
			record.Installed = map[string]int64{}
		}
		return record
	}
	installed := map[string]int64{}
	if json.Unmarshal(raw, &installed) != nil {
		return empty
	}
	return materialRecord{Layout: materialLayoutTeam, Installed: installed}
}

// writeInstalledMaterial 按旧格式写（顶层就是 slot -> 版本）：旧布局下本机记录与以前一模一样。
func writeInstalledMaterial(stateDir string, installed map[string]int64) error {
	raw, err := json.Marshal(installed)
	if err != nil {
		return err
	}
	return writeMaterialFile(stateDir, raw)
}

// writeMaterialRecord 按新格式写 {layout, installed}：切到按租户之后只写这一种。
func writeMaterialRecord(stateDir string, record materialRecord) error {
	if record.Installed == nil {
		record.Installed = map[string]int64{}
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeMaterialFile(stateDir, raw)
}

func writeMaterialFile(stateDir string, raw []byte) error {
	path := filepath.Join(stateDir, installedMaterialFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ---- 服务端那两条 ----

// iosMaterial 取这台机器该装的材料清单，带上能力 tenant-signing-material：认得它的服务端回按租户的
// 清单（layout=tenant），旧版服务端不认、照旧回按 Team 的。complete=服务端明说清单没被截断；旧版
// 服务端不带这个字段，按不完整处理——墓碑只在清单完整时做，宁可不删也不能误删。
func (c *client) iosMaterial(ctx context.Context) (materialManifest, error) {
	_, payload, err := c.send(ctx, "GET", "/v1/build-agent/ios-material?capability="+capabilityTenantMaterial, 0, nil)
	if err != nil {
		return materialManifest{}, err
	}
	var body materialManifest
	if err := json.Unmarshal(payload, &body); err != nil {
		return materialManifest{}, fmt.Errorf("the signing material list is not JSON: %w", err)
	}
	return body, nil
}

// iosMaterialBox 取一份密文，原样返回。控制进程不解析它，也解不开。按租户的格带上 tenantId。
func (c *client) iosMaterialBox(ctx context.Context, entry materialEntry) ([]byte, error) {
	query := url.Values{"kind": {entry.Kind}, "teamId": {entry.TeamID}, "scope": {entry.Scope}}
	if entry.TenantID != "" {
		query.Set("tenantId", entry.TenantID)
	}
	_, payload, err := c.send(ctx, "GET", "/v1/build-agent/ios-material/box?"+query.Encode(), 0, nil)
	return payload, err
}
