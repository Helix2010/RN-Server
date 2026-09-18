package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
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
	// 写死而不是配置：换一个名字只会让"材料在哪"多一处要对齐的地方
	keychainFileName = "rn-signing.keychain-db"
	profilesDirName  = "profiles"
	// uploadKeyFileName 是上传 Key 的元数据（issuerId / keyId），.p8 在它旁边。
	// 控制进程**不读**这两个文件，只看目录在不在：Key 是上传账户的东西
	uploadKeyFileName = "key.json"
	// profileSuffix 是描述文件的扩展名
	profileSuffix = ".mobileprovision"
	// appleTeamIDLength：Apple Team ID 固定 10 位大写字母数字
	appleTeamIDLength = 10
)

var (
	// 钥匙串里的可签名身份。Apple Distribution 是现行类型，iPhone Distribution 是旧类型
	// （2021 年之前签发的证书还能用到它到期为止），两者都认
	signingIdentityPattern = regexp.MustCompile(`"(?:Apple|iPhone) Distribution: [^"]*\(([A-Z0-9]{10})\)"`)
	appleTeamIDPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	// 描述文件里 application-identifier 的形状：<TEAMID>.<bundle id>
	bundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
)

// appleTeamMaterial 是一个 Team 在这台机器上的材料。
type appleTeamMaterial struct {
	TeamID    string
	BundleIDs []string
	// ExpiresAt 是这个 Team 里最早到期的证书或描述文件。零值=不知道
	ExpiresAt time.Time
	// UploadProbe 是启动时那次只读探测的结果（ok / forbidden / error），空=没探
	UploadProbe string
}

// iosInventory 是一次盘点的结果。
type iosInventory struct {
	Teams []appleTeamMaterial
	// Problems 是"看见了但用不了"的东西：过期的描述文件、有证书没描述文件的 Team、
	// 有描述文件没证书的 Team。它们不进自报（自报只说能干什么），但要打进日志——
	// 一台机器少报一个 Team 的时候，人需要知道少的是哪一片
	Problems []string
}

// teamIDs 是盘点到的 Team，排序后返回，给日志用。
func (inv iosInventory) teamIDs() []string {
	out := make([]string, 0, len(inv.Teams))
	for _, team := range inv.Teams {
		out = append(out, team.TeamID)
	}
	return out
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
	// RequireUploadKey：只有开着上传的机器才要求上传 Key 在位。关着上传时包留在机器上
	// 由人传，缺 Key 不该让这台机器报不出这个 Team
	RequireUploadKey bool
	Now              func() time.Time
	// Identities 返回钥匙串里有可签名身份（证书 + 私钥）的 Team
	Identities func(ctx context.Context, keychain string) (map[string]bool, error)
	// Certificates 返回每个 Team 最早到期的分发证书
	Certificates func(ctx context.Context, keychain string) (map[string]time.Time, error)
	// Probe 是上传 Key 的只读探测，返回 ok / forbidden / error；nil = 不探
	Probe func(ctx context.Context, teamID string) string
}

func newIOSScanner(cfg config) iosScanner {
	return iosScanner{
		SigningDir:       cfg.MachineEnv[jobspec.IOSSigningDirEnv],
		UploadKeys:       cfg.IOSUploadKeys,
		RequireUploadKey: cfg.IOSUpload,
		Now:              time.Now,
		Identities:       keychainIdentities,
		Certificates:     keychainCertificates,
	}
}

func (s iosScanner) keychain() string { return filepath.Join(s.SigningDir, keychainFileName) }

// scan 盘点一次。子进程出错不是致命错误：盘点失败等于"这台机器这次什么都报不出来"，
// 它会安静地领不到 iOS 任务，而控制台上它的材料列表是空的——这正是要让人看见的状态。
func (s iosScanner) scan(ctx context.Context) iosInventory {
	var inv iosInventory
	if s.SigningDir == "" {
		return inv
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
			inv.Problems = append(inv.Problems,
				"team "+team+" has provisioning profiles but no Apple Distribution identity in the keychain")
			continue
		case len(bundles.ids) == 0:
			inv.Problems = append(inv.Problems,
				"team "+team+" has a signing identity but no usable provisioning profile")
			continue
		}
		if s.RequireUploadKey {
			if _, err := os.Stat(filepath.Join(s.UploadKeys, team, uploadKeyFileName)); err != nil {
				inv.Problems = append(inv.Problems,
					"team "+team+" has signing material but no upload key in "+filepath.Join(s.UploadKeys, team)+
						"; uploads are on, so this team is not reported")
				continue
			}
		}
		material := appleTeamMaterial{TeamID: team, ExpiresAt: earliest(expiry[team], bundles.expiresAt)}
		material.BundleIDs = append(material.BundleIDs, bundles.ids...)
		sort.Strings(material.BundleIDs)
		if s.Probe != nil {
			material.UploadProbe = s.Probe(ctx, team)
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
	var problems []string
	root := filepath.Join(s.SigningDir, profilesDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, "cannot read "+root+": "+err.Error())
		}
		return out, problems
	}
	now := s.Now().UTC()
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
			path := filepath.Join(dir, file.Name())
			team, bundleID, expires, err := readProvisioningProfile(path)
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
	}
	return out, problems
}

// readProvisioningProfile 从一份 .mobileprovision 里读出 Team ID、bundle id 与到期日。
//
// 文件是 CMS 签名块，里面包着一份 XML plist。**不验签**：这份材料是运维放上去的，
// 而真正的把关在别处——签不出 Apple 认的包，或者签出来 Apple 拒收。这里只需要读出
// "这台机器能签哪个 App"。
func readProvisioningProfile(path string) (teamID, bundleID string, expires time.Time, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", time.Time{}, err
	}
	start := bytes.Index(raw, []byte("<?xml"))
	end := bytes.LastIndex(raw, []byte("</plist>"))
	if start < 0 || end < start {
		return "", "", time.Time{}, errors.New("no XML plist inside the provisioning profile")
	}
	dict, err := parseXMLPlist(raw[start : end+len("</plist>")])
	if err != nil {
		return "", "", time.Time{}, err
	}
	// application-identifier 是 <TEAMID>.<bundle id>，Team ID 与 bundle id 一次给全
	identifier := plistString(plistDict(dict, "Entitlements"), "application-identifier")
	team, bundle, ok := strings.Cut(identifier, ".")
	if !ok || !appleTeamIDPattern.MatchString(team) {
		return "", "", time.Time{}, fmt.Errorf("application-identifier %q is not <TEAMID>.<bundle id>", identifier)
	}
	// 通配描述文件（`TEAMID.*`）签不出一个确定的 App，报上去等于谎报能力
	if !bundleIDPattern.MatchString(bundle) {
		return "", "", time.Time{}, fmt.Errorf("application-identifier %q is a wildcard or malformed bundle id", identifier)
	}
	expires = plistTime(dict, "ExpirationDate")
	if expires.IsZero() {
		return "", "", time.Time{}, errors.New("the provisioning profile has no ExpirationDate")
	}
	return team, bundle, expires, nil
}

// keychainIdentities 问钥匙串"哪些 Team 我既有证书又有私钥"。
// 只有身份（证书 + 私钥）才签得了名，光有证书不行，所以用 find-identity 而不是 find-certificate。
func keychainIdentities(ctx context.Context, keychain string) (map[string]bool, error) {
	out, err := securityOutput(ctx, "find-identity", "-v", "-p", "codesigning", keychain)
	if err != nil {
		return nil, err
	}
	teams := map[string]bool{}
	for _, match := range signingIdentityPattern.FindAllStringSubmatch(out, -1) {
		teams[match[1]] = true
	}
	return teams, nil
}

// keychainCertificates 读每个 Team 最早到期的分发证书。
// find-identity 不给到期日，所以另取一次 PEM 自己解析——证书是一年一换的，
// "还有几天到期"要能在控制台上提前一个月看见。
func keychainCertificates(ctx context.Context, keychain string) (map[string]time.Time, error) {
	out, err := securityOutput(ctx, "find-certificate", "-a", "-p", keychain)
	if err != nil {
		return nil, err
	}
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
	return expiry, nil
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
