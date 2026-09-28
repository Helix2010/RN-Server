package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/internal/ipa"
)

// 签名材料盘点（设计 ios-mac-builders-home-network-2026-09-18 §5.2、§4.4）。
//
// Mac 是一个池子：每台都应该能打任何租户的包。所以服务端的机器登记里**没有**"这台能打
// 哪些 Apple Team"这一列——它的正确值永远是"全部"，维护它只会多一个能与实际不一致的
// 地方。真正要回答的是"这台现在缺哪个 Team 的材料"，而这件事只有这台机器自己知道：
// 证书在它的钥匙串里、描述文件在它的磁盘上、上传 Key 在它的目录下。
//
// 盘点的结果随每次认领报上去，服务端据它决定派不派这条 iOS 任务，控制台据它与全部租户的
// release.ios 求差集，标出"这台缺谁的材料"。**它是运维仪表，不是安全边界**：这台机器上
// 谎报一个 Team 只能骗到"领走一条它签不出来的任务，然后失败"。

const (
	// keychainFileName 与 profilesDirName 是装机脚本铺出来的固定布局（§4.2）。
	// 写死而不是配置：换一个名字只会让"材料在哪"多一处要对齐的地方。
	// 定义在 jobspec 里，因为取材料的是 build-runner（见那边的说明）
	keychainFileName = jobspec.IOSKeychainFileName
	profilesDirName  = jobspec.IOSProfilesDirName
	// uploadKeyFileName 是上传 Key 的元数据（issuerId / keyId），.p8 在它旁边。
	// 控制进程**不读**这两个文件，只看目录在不在：Key 是上传账户的东西
	uploadKeyFileName = "key.json"
	// profileSuffix 是描述文件的扩展名
	profileSuffix = jobspec.IOSProfileSuffix
)

var (
	// 钥匙串里的可签名身份。Apple Distribution 是现行类型，iPhone Distribution 是旧类型
	// （2021 年之前签发的证书还能用到它到期为止），两者都认
	signingIdentityPattern = regexp.MustCompile(`"(?:Apple|iPhone) Distribution: [^"]*\(([A-Z0-9]{10})\)"`)
	appleTeamIDPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	// 描述文件里 application-identifier 的形状：<TEAMID>.<bundle id>
	bundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	// identityHashPattern 是 find-identity 一行里的身份指纹："  1) <SHA-1> "Apple Distribution: …""
	identityHashPattern = regexp.MustCompile(`(?m)^\s*\d+\)\s+([0-9A-F]{40})\s+"`)
)

const (
	// maxTenantMaterialReports 与服务端收的上限一致（§12.3）
	maxTenantMaterialReports = 64
	// maxTenantProblems / maxTenantProblemRunes：一项最多几条原因、每条多长（§12.3）
	maxTenantProblems     = 8
	maxTenantProblemRunes = 300
	// maxBundleIDsPerTenantTeam 与服务端每个 Team 收的 bundle id 上限一致：超了整条认领会被拒
	maxBundleIDsPerTenantTeam = 64
)

// appleTeamMaterial 是一个 Team 在这台机器上的材料。
type appleTeamMaterial struct {
	TeamID    string
	BundleIDs []string
	// ExpiresAt 是这个 Team 里最早到期的证书或描述文件。零值=不知道
	ExpiresAt time.Time
	// UploadProbe 是上传 Key 的只读探测结果（ok / forbidden / error），missing=没装这个 Team 的
	// 上传 Key，空=没探（这台机器没开上传）
	UploadProbe string
}

// tenantMaterial 是一个租户的一个 Team 在这台机器上的材料（按租户落盘之后，§12.3）。
type tenantMaterial struct {
	TenantID string
	TeamID   string
	// BundleIDs 只列核对通过、没过期、而且包含本租户当前证书的描述文件
	BundleIDs []string
	// CertificateSHA1 是本机索引里这个 (租户, Team) 的证书；CertificateReady=它出现在签名钥匙串
	// `find-identity -v` 的结果里。就绪看钥匙串，不看装机记录（设计 §4.2）
	CertificateSHA1  string
	CertificateReady bool
	ExpiresAt        time.Time
	// UploadProbe 取值同 appleTeamMaterial.UploadProbe
	UploadProbe string
	// APSEnvironment 是描述文件 Entitlements 里的 aps-environment，只报不判
	APSEnvironment string
	// Problems 每条以种类开头（certificate: / profile: / upload-key: ）
	Problems []string
}

// iosInventory 是一次盘点的结果。
type iosInventory struct {
	Teams []appleTeamMaterial
	// Problems 是"看见了但用不了"的东西：过期的描述文件、有证书没描述文件的 Team、
	// 有描述文件没证书的 Team。它们不进自报（自报只说能干什么），但要打进日志——
	// 一台机器少报一个 Team 的时候，人需要知道少的是哪一片
	Problems []string
	// TenantLayout：这台机器按租户落盘。这时 Tenants 是按租户的盘点，Teams 只是从它汇总出来给
	// 控制台显示的；派活与领到后的复核都按 Tenants
	TenantLayout bool
	Tenants      []tenantMaterial
}

// coversTenant 回答"这台机器能不能签这个租户的 (Team, bundle id)"：证书就绪、描述文件合格。
func (inv iosInventory) coversTenant(tenantID, teamID, bundleID string) bool {
	for _, material := range inv.Tenants {
		if material.TenantID != tenantID || material.TeamID != strings.ToUpper(strings.TrimSpace(teamID)) || !material.CertificateReady {
			continue
		}
		for _, bundle := range material.BundleIDs {
			if bundle == strings.TrimSpace(bundleID) {
				return true
			}
		}
	}
	return false
}

// teamIDs 是盘点到的 Team，排序后返回，给日志用。
func (inv iosInventory) teamIDs() []string {
	out := make([]string, 0, len(inv.Teams))
	for _, team := range inv.Teams {
		out = append(out, team.TeamID)
	}
	return out
}

// tenantSummary 是按租户盘点的一行摘要，给日志用："<租户>/<TEAM> ready|not ready"。
func (inv iosInventory) tenantSummary() string {
	parts := make([]string, 0, len(inv.Tenants))
	for _, material := range inv.Tenants {
		state := "not ready"
		if material.CertificateReady && len(material.BundleIDs) > 0 {
			state = "ready (" + strings.Join(material.BundleIDs, ",") + ")"
		}
		parts = append(parts, material.TenantID+"/"+material.TeamID+" "+state)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}

// covers 回答"这台机器能不能签这个 (Team, bundle id)"。领到任务后再核一次用它：
// 盘点与认领之间可能有人动过钥匙串。
func (inv iosInventory) covers(teamID, bundleID string) bool {
	for _, team := range inv.Teams {
		if team.TeamID != strings.ToUpper(strings.TrimSpace(teamID)) {
			continue
		}
		for _, bundle := range team.BundleIDs {
			if bundle == strings.TrimSpace(bundleID) {
				return true
			}
		}
	}
	return false
}

// iosScanner 是盘点的输入。三个函数字段让这套逻辑在没有 Mac 的机器上也测得了：
// 生产实现起 `security` 子进程与上传探测，测试传假的。
type iosScanner struct {
	SigningDir string
	UploadKeys string
	// RequireUploadKey：这台机器开着上传（BUILD_AGENT_IOS_UPLOAD）。开着时逐 Team 查上传 Key：
	// 装了就探一次，没装报 missing。以前没装就干脆不报这个 Team，于是这台机器也领不到它的
	// 任务——自助上传的租户根本不交上传 Key，它们的任务照样要能派过来（设计
	// ios-tenant-delivery-tiers-2026-09-24 §3.3）。服务端按这个状态决定全托管的任务派不派
	RequireUploadKey bool
	Now              func() time.Time
	// Identities 返回钥匙串里有可签名身份（证书 + 私钥）的 Team
	Identities func(ctx context.Context, keychain string) (map[string]bool, error)
	// Certificates 返回每个 Team 最早到期的分发证书
	Certificates func(ctx context.Context, keychain string) (map[string]time.Time, error)
	// Material 一次子进程把签名区里的原文取回来（build-runner 以 _rnbuilder 的身份跑）。
	// 生产里非有它不可：签名区是 0700 _rnbuilder，控制进程连目录都 stat 不了。
	// nil = 直接读本地，用于测试与 BUILD_AGENT_RUNNER_USER=- 的本地形态
	Material func(ctx context.Context) (jobspec.IOSMaterial, error)
	// Profiles 返回 "<TEAMID>/<文件名>" -> 描述文件原文；nil = 自己走文件系统
	Profiles func() (map[string][]byte, []string)
	// Probe 是上传 Key 的只读探测，返回 ok / forbidden / error；nil = 不探。
	// 带上 bundle id 是因为这套端点挂在具体的 App 下（GET /v1/apps/{id}/buildUploads），
	// 而"这个 Team 有哪些 App"只有盘点知道
	Probe func(ctx context.Context, teamID string, bundleIDs []string) string
	// UploadKeyTeams 返回装好了上传 Key 的 Team（ios-upload --list-keys，以上传账户跑）。
	//
	// 生产里非有它不可：上传区是 0700 _rnuploader，控制进程连目录都 stat 不了——自己去看
	// 只会得到 EACCES，然后把每个 Team 都判成"没有上传 Key"，于是开着上传的机器一个 Team
	// 都报不出来（2026-09-20 真机）。nil = 直接读本地，用于测试与 RUNNER_USER=- 的本地形态
	UploadKeyTeams func(ctx context.Context) (map[string]bool, error)

	// ---- 按租户落盘之后（设计 ios-tenant-owned-signing-material-2026-09-25 §4.4、§12.3） ----

	// TenantLayout：按租户盘点，不再看旧布局
	TenantLayout bool
	// IdentityHashes 返回签名钥匙串里有效身份的 SHA-1
	IdentityHashes func(ctx context.Context, keychain string) (map[string]bool, error)
	// CertificateExpiry 返回钥匙串里每张证书（按 SHA-1）的到期日
	CertificateExpiry func(ctx context.Context, keychain string) (map[string]time.Time, error)
	// TenantProfiles 返回 "<租户>/<TEAMID>/<文件名>" -> 描述文件原文；TenantCertificates 返回证书索引。
	// nil = 自己读本地（测试与 RUNNER_USER=- 的本地形态）
	TenantProfiles     func() map[string][]byte
	TenantCertificates func() (map[string]string, error)
	// UploadKeyTenants 返回每个租户装好了上传 Key 的 Team；nil = 直接读本地
	UploadKeyTenants func(ctx context.Context) (map[string]map[string]bool, error)
	// ProbeTenant 是按租户目录的上传 Key 只读探测；nil = 不探
	ProbeTenant func(ctx context.Context, tenantID, teamID string, bundleIDs []string) string
	// InstallProblems 是控制进程装材料时记下的原因，键 "<租户>/<TEAMID>"，已带种类前缀
	InstallProblems map[string][]string
}

func newIOSScanner(cfg config) iosScanner {
	return iosScanner{
		SigningDir:        cfg.MachineEnv[jobspec.IOSSigningDirEnv],
		UploadKeys:        cfg.IOSUploadKeys,
		RequireUploadKey:  cfg.IOSUpload,
		Now:               time.Now,
		Identities:        keychainIdentities,
		Certificates:      keychainCertificates,
		IdentityHashes:    keychainIdentityHashes,
		CertificateExpiry: keychainCertificateExpiry,
	}
}

// iosMaterial 经 build-runner 取一次签名区原文。控制进程自己读不到那个目录（0700
// _rnbuilder），而 build-runner 是 sudoers 里唯一允许它以那个账户启动的程序——所以这件事
// 挂在它身上，既不用为盘点再开一条 sudo 规则，也不用放宽签名区的权限。
func (a *agent) iosMaterial(ctx context.Context) (jobspec.IOSMaterial, error) {
	dir := a.cfg.MachineEnv[jobspec.IOSSigningDirEnv]
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := a.runnerReadCommand(ctx, "ios-inventory", "--signing-dir", dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return jobspec.IOSMaterial{}, fmt.Errorf("%s ios-inventory: %w: %s", a.cfg.Runner, err,
			truncate(runnerFailureDetail(stdout.String(), stderr.String()), 300))
	}
	var material jobspec.IOSMaterial
	if err := json.Unmarshal(stdout.Bytes(), &material); err != nil {
		// 执行进程把失败原因写在标准输出上（build-runner: error: …），所以这一条不是
		// "格式坏了"，多半就是它拒绝了参数——把它的原话带出来
		return jobspec.IOSMaterial{}, fmt.Errorf("the build runner did not answer with JSON: %s", truncate(strings.TrimSpace(stdout.String()), 300))
	}
	return material, nil
}

// runnerFailureDetail 从一次只读调用的输出里挑出失败原因。
//
// 两个被调起的程序约定不一样：build-runner 把原因写在**标准输出**（"build-runner: error: …"，
// 见它的文件头注释），ios-upload 写在标准错误。只看标准错误的那一侧，build-runner 的失败
// 会退化成一句 "exit status 1:" ——2026-09-20 真机上证书装不上就是这样，security import
// 到底说了什么被整条丢掉，只能到机器上手工复现才知道。
func runnerFailureDetail(stdout, stderr string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if reason, ok := strings.CutPrefix(strings.TrimSpace(line), "build-runner: error: "); ok {
			return reason
		}
	}
	if detail := strings.TrimSpace(stderr); detail != "" {
		return detail
	}
	return strings.TrimSpace(stdout)
}

// runnerReadCommand 构造一条只读的执行进程调用：经 sudo 切到执行账户，环境只给 PATH
// 与 LANG。与 uploaderCommand 同一条路子。
func (a *agent) runnerReadCommand(ctx context.Context, args ...string) *exec.Cmd {
	env := []string{"PATH=" + a.cfg.MachineEnv["PATH"], "LANG=C"}
	if a.cfg.RunnerUser == directRunner {
		// 本地测试：不经 sudo。生产里 BUILD_AGENT_RUNNER_USER=- 已经在启动时大声告警过
		cmd := exec.CommandContext(ctx, a.cfg.Runner, args...)
		cmd.Env = env
		return cmd
	}
	sudo := append([]string{"-n", "-u", a.cfg.RunnerUser, a.cfg.Runner}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", sudo...)
	cmd.Env = env
	return cmd
}

func (s iosScanner) keychain() string { return filepath.Join(s.SigningDir, keychainFileName) }

// scan 盘点一次。子进程出错不是致命错误：盘点失败等于"这台机器这次什么都报不出来"，
// 它会安静地领不到 iOS 任务，而控制台上它的材料列表是空的——这正是要让人看见的状态。
func (s iosScanner) scan(ctx context.Context) iosInventory {
	var inv iosInventory
	if s.SigningDir == "" {
		return inv
	}
	if s.Material != nil {
		material, err := s.Material(ctx)
		if err != nil {
			// 取不到材料等于这一轮什么都不报：机器安静地领不到 iOS 任务，控制台上
			// 它的材料列表是空的——这正是要让人看见的状态
			inv.Problems = append(inv.Problems, "cannot read the signing material through the build runner: "+err.Error())
			return inv
		}
		s = s.withMaterial(material)
	}
	if s.TenantLayout {
		return s.scanTenants(ctx, inv)
	}
	identities, err := s.Identities(ctx, s.keychain())
	if err != nil {
		inv.Problems = append(inv.Problems, "cannot read the signing identities in "+s.keychain()+": "+err.Error())
		return inv
	}
	expiry := map[string]time.Time{}
	if s.Certificates != nil {
		if certificates, err := s.Certificates(ctx, s.keychain()); err != nil {
			// 证书到期日只影响"还剩几天"的提醒，读不出来不该让整次盘点作废
			inv.Problems = append(inv.Problems, "cannot read certificate expiry dates: "+err.Error())
		} else {
			expiry = certificates
		}
	}
	profiles, problems := s.scanProfiles()
	inv.Problems = append(inv.Problems, problems...)

	// 上传 Key 只问一次，问的是上传账户自己（见 UploadKeyTeams）。取不到就当一把都没有，
	// 但要把原因说出来——否则表现与"确实没装 Key"一模一样
	withUploadKey := map[string]bool{}
	keysListed := false
	if s.RequireUploadKey {
		var err error
		if withUploadKey, err = s.uploadKeyTeams(ctx); err != nil {
			inv.Problems = append(inv.Problems, "cannot read which teams have an upload key: "+err.Error())
			withUploadKey = map[string]bool{}
		} else {
			keysListed = true
		}
	}

	teams := map[string]bool{}
	for team := range identities {
		teams[team] = true
	}
	for team := range profiles {
		teams[team] = true
	}
	ordered := make([]string, 0, len(teams))
	for team := range teams {
		ordered = append(ordered, team)
	}
	sort.Strings(ordered)
	for _, team := range ordered {
		bundles := profiles[team]
		switch {
		case !identities[team]:
			// 证书在、却不是"有效身份"，与"根本没导进来"是两回事，给的下一步也完全不同。
			// 分不开的话，这条错读起来像"证书没装上"，而人刚刚才看着它装上（2026-09-20 真机）。
			// find-identity -v 的 -v 要求链能验到受信任的根，而归档里往往只有叶子证书——
			// 缺的是 Apple 的 WWDR 中间证书。expiry 是 find-certificate 解出来的，不看私钥，
			// 所以它有这个 Team 就说明证书确实在钥匙串里。
			detail := "team " + team + " has provisioning profiles but no Apple Distribution identity in the keychain"
			if _, inKeychain := expiry[team]; inKeychain {
				detail = "team " + team + " has an Apple Distribution certificate in the keychain but it is not a " +
					"valid code-signing identity; the usual cause is a missing Apple WWDR intermediate certificate " +
					"(rebuild the .p12 with openssl pkcs12 -export -certfile <WWDR>.pem and upload it again)"
			}
			inv.Problems = append(inv.Problems, detail)
			continue
		case len(bundles.ids) == 0:
			inv.Problems = append(inv.Problems,
				"team "+team+" has a signing identity but no usable provisioning profile")
			continue
		}
		material := appleTeamMaterial{TeamID: team, ExpiresAt: earliest(expiry[team], bundles.expiresAt)}
		material.BundleIDs = append(material.BundleIDs, bundles.ids...)
		sort.Strings(material.BundleIDs)
		switch {
		case s.RequireUploadKey && !keysListed:
			// 问不到上传账户：不能装作"没装 Key"（那和真的缺 Key 分不开），也不能装作有。
			// 报"没探"，服务端就不派全托管的任务过来；原因在 Problems 里
		case s.RequireUploadKey && !withUploadKey[team]:
			// 自助上传的租户本来就没有上传 Key：照样报这个 Team，只是说清楚没有 Key。
			// 全托管的租户缺 Key 时，服务端据此不派它的任务、排队时说出原因
			material.UploadProbe = uploadProbeMissing
		case s.Probe != nil:
			material.UploadProbe = s.Probe(ctx, team, material.BundleIDs)
		}
		inv.Teams = append(inv.Teams, material)
	}
	return inv
}

// teamProfiles 是一个 Team 下所有可用描述文件的汇总。
type teamProfiles struct {
	ids []string
	// expiresAt 是最早到期的那一份
	expiresAt time.Time
}

// scanProfiles 读 <signingDir>/profiles/<TEAMID>/*.mobileprovision。
//
// 目录名就是 Team ID，但**不采信它**：每份描述文件里的 application-identifier 自带
// Team ID，按文件里的那个归类。放错目录的文件因此只会被归对，不会让一个 Team 凭空出现。
func (s iosScanner) scanProfiles() (map[string]teamProfiles, []string) {
	out := map[string]teamProfiles{}
	root := filepath.Join(s.SigningDir, profilesDirName)
	files, problems := s.profileFiles()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	now := s.Now().UTC()
	for _, name := range names {
		path := filepath.Join(root, name)
		team, bundleID, expires, err := parseProvisioningProfile(files[name])
		if err != nil {
			problems = append(problems, "cannot read "+path+": "+err.Error())
			continue
		}
		// 过期的描述文件签出来的包 Apple 直接拒。报上去只会让服务端把任务派过来再失败
		if !expires.After(now) {
			problems = append(problems, path+" expired on "+expires.Format(time.RFC3339))
			continue
		}
		current := out[team]
		if !containsPlatform(current.ids, bundleID) {
			current.ids = append(current.ids, bundleID)
		}
		current.expiresAt = earliest(current.expiresAt, expires)
		out[team] = current
	}
	return out, problems
}

// profileFiles 取 profiles/<TEAMID>/*.mobileprovision 的原文，键是 "<TEAMID>/<文件名>"。
//
// 生产里由 build-runner 以 _rnbuilder 的身份取（Profiles 字段）：签名区是 0700 _rnbuilder，
// 控制进程读不到。这里这一份是本地实现，测试与 BUILD_AGENT_RUNNER_USER=- 的本地形态用。
func (s iosScanner) profileFiles() (map[string][]byte, []string) {
	if s.Profiles != nil {
		return s.Profiles()
	}
	out := map[string][]byte{}
	var problems []string
	root := filepath.Join(s.SigningDir, profilesDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, "cannot read "+root+": "+err.Error())
		}
		return out, problems
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			problems = append(problems, "cannot read "+dir+": "+err.Error())
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), profileSuffix) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, file.Name()))
			if err != nil {
				problems = append(problems, "cannot read "+filepath.Join(dir, file.Name())+": "+err.Error())
				continue
			}
			out[entry.Name()+"/"+file.Name()] = raw
		}
	}
	return out, problems
}

// parseProvisioningProfile 从一份 .mobileprovision 的原文里读出 Team ID、bundle id 与到期日。
func parseProvisioningProfile(raw []byte) (teamID, bundleID string, expires time.Time, err error) {
	profile, err := checkedProfile(raw)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return profile.TeamID, profile.BundleID, profile.ExpiresAt, nil
}

// checkedProfile 解析一份描述文件。
//
// 解析与服务端核对自助上传 .ipa 时共用一份（internal/ipa，**不验签**）。这里只需要读出
// "这台机器能签哪个 App"，所以在共用的那份之上再挡两件事：Team ID 形状不对，和通配描述文件。
func checkedProfile(raw []byte) (ipa.Profile, error) {
	profile, err := ipa.ParseProfile(raw)
	if err != nil {
		return ipa.Profile{}, err
	}
	identifier := profile.TeamID + "." + profile.BundleID
	if !appleTeamIDPattern.MatchString(profile.TeamID) {
		return ipa.Profile{}, fmt.Errorf("application-identifier %q is not <TEAMID>.<bundle id>", identifier)
	}
	// 通配描述文件（`TEAMID.*`）签不出一个确定的 App，报上去等于谎报能力
	if !bundleIDPattern.MatchString(profile.BundleID) {
		return ipa.Profile{}, fmt.Errorf("application-identifier %q is a wildcard or malformed bundle id", identifier)
	}
	if profile.ExpiresAt.IsZero() {
		return ipa.Profile{}, errors.New("the provisioning profile has no ExpirationDate")
	}
	return profile, nil
}

// uploadKeyTeams 问"哪些 Team 装好了上传 Key"。没有注入实现时直接读本地目录——
// 那条路只在测试与 BUILD_AGENT_RUNNER_USER=- 的本地形态下成立，真机上读不到。
func (s iosScanner) uploadKeyTeams(ctx context.Context) (map[string]bool, error) {
	if s.UploadKeyTeams != nil {
		return s.UploadKeyTeams(ctx)
	}
	entries, err := os.ReadDir(s.UploadKeys)
	if errors.Is(err, fs.ErrNotExist) {
		// 上传区还没建：一把 Key 都没有，不是"问不到"
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	teams := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.UploadKeys, entry.Name(), uploadKeyFileName)); err == nil {
			teams[entry.Name()] = true
		}
	}
	return teams, nil
}

// keychainIdentities 问钥匙串"哪些 Team 我既有证书又有私钥"。
// 只有身份（证书 + 私钥）才签得了名，光有证书不行，所以用 find-identity 而不是 find-certificate。
func keychainIdentities(ctx context.Context, keychain string) (map[string]bool, error) {
	out, err := securityOutput(ctx, "find-identity", "-v", "-p", "codesigning", keychain)
	if err != nil {
		return nil, err
	}
	return parseIdentities(out), nil
}

// parseIdentities 从 find-identity 的输出里挑出 Team ID。
func parseIdentities(out string) map[string]bool {
	teams := map[string]bool{}
	for _, match := range signingIdentityPattern.FindAllStringSubmatch(out, -1) {
		teams[match[1]] = true
	}
	return teams
}

// withMaterial 把三个取材料的口子换成"读这一份已经取回来的原文"。解析与判断一个字都没挪：
// 判断留在控制进程这一侧，见 jobspec.IOSMaterial 的说明。
func (s iosScanner) withMaterial(m jobspec.IOSMaterial) iosScanner {
	s.Identities = func(context.Context, string) (map[string]bool, error) {
		if m.IdentitiesError != "" {
			return nil, errors.New(m.IdentitiesError)
		}
		return parseIdentities(m.Identities), nil
	}
	s.Certificates = func(context.Context, string) (map[string]time.Time, error) {
		if m.CertificatesError != "" {
			return nil, errors.New(m.CertificatesError)
		}
		return parseCertificates(m.Certificates), nil
	}
	s.Profiles = func() (map[string][]byte, []string) { return m.Profiles, m.Problems }
	s.IdentityHashes = func(context.Context, string) (map[string]bool, error) {
		if m.IdentitiesError != "" {
			return nil, errors.New(m.IdentitiesError)
		}
		return parseIdentityHashes(m.Identities), nil
	}
	s.CertificateExpiry = func(context.Context, string) (map[string]time.Time, error) {
		if m.CertificatesError != "" {
			return nil, errors.New(m.CertificatesError)
		}
		return parseCertificateExpiry(m.Certificates), nil
	}
	s.TenantProfiles = func() map[string][]byte { return m.TenantProfiles }
	s.TenantCertificates = func() (map[string]string, error) { return m.TenantCertificates, nil }
	return s
}

// ---- 按租户的盘点 ----

// scanTenants 按租户盘点（§4.4、§12.3）：每个 (租户, Team) 一项。
//
// 出现在证书索引、租户描述文件、租户上传 Key、安装问题任何一处的 (租户, Team) 都报：服务端据
// certificateReady 与 bundleIds 决定派不派，控制台据 problems 告诉租户哪一片没过。
func (s iosScanner) scanTenants(ctx context.Context, inv iosInventory) iosInventory {
	inv.TenantLayout = true
	if s.Profiles != nil {
		// 执行账户取材料时"看见了但读不了"的东西（包括坏掉的证书索引）
		_, problems := s.Profiles()
		inv.Problems = append(inv.Problems, problems...)
	}
	hashes, err := s.IdentityHashes(ctx, s.keychain())
	if err != nil {
		inv.Problems = append(inv.Problems, "cannot read the signing identities in "+s.keychain()+": "+err.Error())
		return inv
	}
	expiry := map[string]time.Time{}
	if s.CertificateExpiry != nil {
		if certificates, err := s.CertificateExpiry(ctx, s.keychain()); err != nil {
			inv.Problems = append(inv.Problems, "cannot read certificate expiry dates: "+err.Error())
		} else {
			expiry = certificates
		}
	}
	index, err := s.tenantCertificates()
	if err != nil {
		inv.Problems = append(inv.Problems, "cannot read the tenant certificate index: "+err.Error())
		index = map[string]string{}
	}
	profiles := s.tenantProfileFiles()
	var keys map[string]map[string]bool
	keysListed := false
	if s.RequireUploadKey {
		if keys, err = s.uploadKeyTenants(ctx); err != nil {
			inv.Problems = append(inv.Problems, "cannot read which tenants have an upload key: "+err.Error())
		} else {
			keysListed = true
		}
	}

	pairs := map[string]bool{}
	for key := range index {
		pairs[key] = true
	}
	byPair := map[string][]string{}
	for name := range profiles {
		parts := strings.SplitN(name, "/", 3)
		if len(parts) != 3 {
			continue
		}
		key := jobspec.TenantCertificateKey(parts[0], parts[1])
		pairs[key] = true
		byPair[key] = append(byPair[key], name)
	}
	for tenant, teams := range keys {
		for team := range teams {
			pairs[jobspec.TenantCertificateKey(tenant, team)] = true
		}
	}
	for key := range s.InstallProblems {
		pairs[key] = true
	}
	ordered := make([]string, 0, len(pairs))
	for key := range pairs {
		tenant, team, ok := strings.Cut(key, "/")
		if ok && jobspec.ValidTenantID(tenant) && appleTeamIDPattern.MatchString(team) {
			ordered = append(ordered, key)
		}
	}
	sort.Strings(ordered)
	if len(ordered) > maxTenantMaterialReports {
		inv.Problems = append(inv.Problems, fmt.Sprintf("material for %d tenant teams; only the first %d are reported", len(ordered), maxTenantMaterialReports))
		ordered = ordered[:maxTenantMaterialReports]
	}
	now := s.Now().UTC()
	for _, key := range ordered {
		tenant, team, _ := strings.Cut(key, "/")
		material := tenantMaterial{TenantID: tenant, TeamID: team, BundleIDs: []string{}, CertificateSHA1: index[key]}
		problems := append([]string(nil), s.InstallProblems[key]...)
		material.CertificateReady = material.CertificateSHA1 != "" && hashes[material.CertificateSHA1]
		if material.CertificateSHA1 != "" && !material.CertificateReady {
			problems = append(problems, "certificate: identity "+material.CertificateSHA1+" is not a valid code-signing identity "+
				"in the signing keychain (expired, revoked, removed by hand, or the Apple WWDR G3 intermediate is missing)")
		}
		material.ExpiresAt = expiry[material.CertificateSHA1]
		names := byPair[key]
		sort.Strings(names)
		for _, name := range names {
			file := strings.SplitN(name, "/", 3)[2]
			profile, err := checkedProfile(profiles[name])
			switch {
			case err != nil:
				problems = append(problems, "profile: "+file+": "+err.Error())
			case profile.TeamID != team:
				problems = append(problems, "profile: "+file+" is for Team "+profile.TeamID+", not "+team)
			case !profile.ExpiresAt.After(now):
				problems = append(problems, "profile: "+file+" expired on "+profile.ExpiresAt.UTC().Format(time.RFC3339))
			case material.CertificateSHA1 == "":
				// 证书还没装：描述文件用不了，但原因是证书那一格，不在这里重复
			case !containsPlatform(profile.DeveloperCertificateSHA1s, material.CertificateSHA1):
				problems = append(problems, "profile: "+profile.BundleID+" does not include the tenant's current certificate "+
					material.CertificateSHA1+"; upload a profile generated with it")
			case len(material.BundleIDs) >= maxBundleIDsPerTenantTeam && !containsPlatform(material.BundleIDs, profile.BundleID):
				problems = append(problems, "profile: more than "+fmt.Sprint(maxBundleIDsPerTenantTeam)+" bundle ids; "+profile.BundleID+" is not reported")
			default:
				if !containsPlatform(material.BundleIDs, profile.BundleID) {
					material.BundleIDs = append(material.BundleIDs, profile.BundleID)
				}
				material.ExpiresAt = earliest(material.ExpiresAt, profile.ExpiresAt)
				// 只报服务端认得的两个值：别的值（手工改过的描述文件）报上去，整条认领都会被拒
				if aps := profile.APSEnvironment; material.APSEnvironment == "" && (aps == "development" || aps == "production") {
					material.APSEnvironment = aps
				}
			}
		}
		sort.Strings(material.BundleIDs)
		switch {
		case !s.RequireUploadKey, !keysListed:
			// 没开上传，或者问不到上传账户（原因在 inv.Problems）：报"没探"
		case !keys[tenant][team]:
			material.UploadProbe = uploadProbeMissing
		case s.ProbeTenant != nil && len(material.BundleIDs) > 0:
			material.UploadProbe = s.ProbeTenant(ctx, tenant, team, material.BundleIDs)
		}
		material.Problems = capProblems(problems)
		inv.Tenants = append(inv.Tenants, material)
	}
	inv.Teams = teamsFromTenants(inv.Tenants)
	return inv
}

// teamsFromTenants 把按租户的盘点按 Team 汇总一份，给认领里的 appleTeams（控制台显示与过渡用）。
// 只算证书就绪、有合格描述文件的那几项。
func teamsFromTenants(tenants []tenantMaterial) []appleTeamMaterial {
	byTeam := map[string]*appleTeamMaterial{}
	order := []string{}
	for _, material := range tenants {
		if !material.CertificateReady || len(material.BundleIDs) == 0 {
			continue
		}
		team, ok := byTeam[material.TeamID]
		if !ok {
			team = &appleTeamMaterial{TeamID: material.TeamID}
			byTeam[material.TeamID] = team
			order = append(order, material.TeamID)
		}
		for _, bundle := range material.BundleIDs {
			if !containsPlatform(team.BundleIDs, bundle) {
				team.BundleIDs = append(team.BundleIDs, bundle)
			}
		}
		team.ExpiresAt = earliest(team.ExpiresAt, material.ExpiresAt)
		if uploadProbeRank(material.UploadProbe) > uploadProbeRank(team.UploadProbe) {
			team.UploadProbe = material.UploadProbe
		}
	}
	sort.Strings(order)
	out := make([]appleTeamMaterial, 0, len(order))
	for _, id := range order {
		sort.Strings(byTeam[id].BundleIDs)
		out = append(out, *byTeam[id])
	}
	return out
}

// uploadProbeRank：同一个 Team 下几个租户的探测结果不同时，汇总显示最好的那个。
func uploadProbeRank(probe string) int {
	switch probe {
	case "ok":
		return 4
	case "error":
		return 3
	case "forbidden":
		return 2
	case uploadProbeMissing:
		return 1
	}
	return 0
}

// capProblems 按上限截：最多几条、每条多长（§12.3）。
func capProblems(problems []string) []string {
	out := []string{}
	for _, problem := range problems {
		if len(out) == maxTenantProblems {
			break
		}
		// firstRunes 截断时补一个省略号，所以少截一个字，合起来不超过上限
		out = append(out, firstRunes(problem, maxTenantProblemRunes-1))
	}
	return out
}

// tenantCertificates 取证书索引。没有注入实现时读本地（测试与 RUNNER_USER=- 的本地形态）。
func (s iosScanner) tenantCertificates() (map[string]string, error) {
	if s.TenantCertificates != nil {
		index, err := s.TenantCertificates()
		if index == nil {
			index = map[string]string{}
		}
		return index, err
	}
	raw, err := os.ReadFile(filepath.Join(s.SigningDir, jobspec.IOSTenantCertificatesFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	index := map[string]string{}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, err
	}
	return index, nil
}

// tenantProfileFiles 取按租户的描述文件原文。没有注入实现时读本地。
func (s iosScanner) tenantProfileFiles() map[string][]byte {
	if s.TenantProfiles != nil {
		return s.TenantProfiles()
	}
	out := map[string][]byte{}
	root := filepath.Join(s.SigningDir, profilesDirName, jobspec.IOSTenantsDirName)
	tenants, _ := os.ReadDir(root)
	for _, tenant := range tenants {
		teams, _ := os.ReadDir(filepath.Join(root, tenant.Name()))
		for _, team := range teams {
			files, _ := os.ReadDir(filepath.Join(root, tenant.Name(), team.Name()))
			for _, file := range files {
				if file.IsDir() || !strings.HasSuffix(file.Name(), profileSuffix) {
					continue
				}
				if raw, err := os.ReadFile(filepath.Join(root, tenant.Name(), team.Name(), file.Name())); err == nil {
					out[tenant.Name()+"/"+team.Name()+"/"+file.Name()] = raw
				}
			}
		}
	}
	return out
}

// uploadKeyTenants 问"每个租户哪些 Team 装好了上传 Key"。没有注入实现时直接读本地目录。
func (s iosScanner) uploadKeyTenants(ctx context.Context) (map[string]map[string]bool, error) {
	if s.UploadKeyTenants != nil {
		return s.UploadKeyTenants(ctx)
	}
	out := map[string]map[string]bool{}
	root := filepath.Join(s.UploadKeys, jobspec.IOSTenantsDirName)
	tenants, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, tenant := range tenants {
		teams, err := os.ReadDir(filepath.Join(root, tenant.Name()))
		if err != nil {
			return nil, err
		}
		for _, team := range teams {
			if _, err := os.Stat(filepath.Join(root, tenant.Name(), team.Name(), uploadKeyFileName)); err == nil {
				if out[tenant.Name()] == nil {
					out[tenant.Name()] = map[string]bool{}
				}
				out[tenant.Name()][team.Name()] = true
			}
		}
	}
	return out, nil
}

// keychainIdentityHashes 问签名钥匙串"哪些身份有效"，按 SHA-1。
func keychainIdentityHashes(ctx context.Context, keychain string) (map[string]bool, error) {
	out, err := securityOutput(ctx, "find-identity", "-v", "-p", "codesigning", keychain)
	if err != nil {
		return nil, err
	}
	return parseIdentityHashes(out), nil
}

// parseIdentityHashes 从 find-identity -v 的输出里取出身份的 SHA-1。
func parseIdentityHashes(out string) map[string]bool {
	hashes := map[string]bool{}
	for _, match := range identityHashPattern.FindAllStringSubmatch(out, -1) {
		hashes[match[1]] = true
	}
	return hashes
}

// keychainCertificateExpiry 读钥匙串里每张证书（按 SHA-1）的到期日。
func keychainCertificateExpiry(ctx context.Context, keychain string) (map[string]time.Time, error) {
	out, err := securityOutput(ctx, "find-certificate", "-a", "-p", keychain)
	if err != nil {
		return nil, err
	}
	return parseCertificateExpiry(out), nil
}

// parseCertificateExpiry 从一串 PEM 里读出每张证书的到期日，键是 DER 的 SHA-1（与 find-identity 同形）。
func parseCertificateExpiry(out string) map[string]time.Time {
	expiry := map[string]time.Time{}
	rest := []byte(out)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return expiry
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		digest := sha1.Sum(block.Bytes)
		expiry[strings.ToUpper(hex.EncodeToString(digest[:]))] = certificate.NotAfter.UTC()
	}
}

// keychainCertificates 读每个 Team 最早到期的分发证书。
// find-identity 不给到期日，所以另取一次 PEM 自己解析——证书是一年一换的，
// "还有几天到期"要能在控制台上提前一个月看见。
func keychainCertificates(ctx context.Context, keychain string) (map[string]time.Time, error) {
	out, err := securityOutput(ctx, "find-certificate", "-a", "-p", keychain)
	if err != nil {
		return nil, err
	}
	return parseCertificates(out), nil
}

// parseCertificates 从一串 PEM 里读出每个 Team 最早到期的分发证书。
func parseCertificates(out string) map[string]time.Time {
	expiry := map[string]time.Time{}
	rest := []byte(out)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		// Apple 把 Team ID 放在证书主体的 OU 里
		for _, unit := range certificate.Subject.OrganizationalUnit {
			if !appleTeamIDPattern.MatchString(unit) {
				continue
			}
			if !strings.Contains(certificate.Subject.CommonName, "Distribution") {
				continue
			}
			expiry[unit] = earliest(expiry[unit], certificate.NotAfter.UTC())
		}
	}
	return expiry
}

// securityOutput 跑一条 `security` 子命令并收标准输出。
// 超时是为了不让一次卡住的钥匙串把认领循环停住：认领每 10 秒一次，盘点不能比它慢。
func securityOutput(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("security %s: %w: %s", strings.Join(args, " "), err, truncate(strings.TrimSpace(stderr.String()), 200))
	}
	return stdout.String(), nil
}

// earliest 取两个时刻里早的那个，零值当作"没有"。
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	}
	return a
}
