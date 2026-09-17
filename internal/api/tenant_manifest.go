package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// 租户的 App 身份文件（打包机写进 worktree 的 tenants/<目录>/tenant.json）。
//
// 这份文件原先在 RN-App 仓库里，由人提交。2026-09-12 改成服务端合成、随任务下发：
// 开一个新租户不该需要改代码、推仓库。
//
// 代价是明确的，别假装没有：文件在仓库里时，改包名或签名指纹必须经过一次 code
// review；现在只需要控制台的写权限。`distributionChannel` 是 direct，没有应用商店
// 审核，「包名 + 签名证书」就是这个 App 的全部身份——所以每一次身份变更都要
// confirm + reason 并落审计，而且 queueBuild 会拿它和已发布的版本对一遍
// （tenantIdentityDrift）：包名变了，老用户升不上去，那是一个新 App 而不是新版本。
//
// 只有这几个字段由租户在控制台维护：appName / scheme / androidPackage /
// iosBundleId / apiBaseUrl / iconBackgroundColor。其余的服务端自己知道：
// bootstrapSignerAddress 取自该租户的 bootstrap 签名密钥，signerSha256 取自发布
// 身份，version 与 androidVersionCode 来自这次任务。这样"控制台里换了密钥、
// tenant.json 忘了改"这类漂移在结构上就不存在了。
type tenantManifest struct {
	Slug           string `json:"slug"`
	AppName        string `json:"appName"`
	Scheme         string `json:"scheme"`
	AndroidPackage string `json:"androidPackage"`
	IOSBundleID    string `json:"iosBundleId"`
	// AppleTeamID 只有配了 iOS 发布身份的租户才有。iOS 构建拿它当 DEVELOPMENT_TEAM，
	// Android 构建看都不看——省略比发一个空串好，空串会让 RN-App 那侧的格式校验失败
	AppleTeamID            string     `json:"appleTeamId,omitempty"`
	APIBaseURL             string     `json:"apiBaseUrl"`
	BootstrapSignerAddress string     `json:"bootstrapSignerAddress"`
	ApplicationID          string     `json:"applicationId"`
	DistributionChannel    string     `json:"distributionChannel"`
	OTAChannel             string     `json:"otaChannel"`
	Version                string     `json:"version"`
	AndroidVersionCode     int        `json:"androidVersionCode"`
	IOSBuildNumber         string     `json:"iosBuildNumber"`
	IconBackgroundColor    string     `json:"iconBackgroundColor"`
	Icon                   tenantIcon `json:"icon"`
	SignerSHA256           string     `json:"signerSha256"`
}

// 图标文件名是约定，不是配置：图片本身仍然在仓库的 assets/tenants/<slug>/ 下，
// 让控制台去改文件名只会制造"配置指向一个不存在的文件"这种构建期才发现的错
type tenantIcon struct {
	Icon              string `json:"icon"`
	AndroidForeground string `json:"androidForeground"`
	AndroidBackground string `json:"androidBackground"`
	AndroidMonochrome string `json:"androidMonochrome"`
}

func defaultTenantIcon() tenantIcon {
	return tenantIcon{
		Icon:              "icon.png",
		AndroidForeground: "android-icon-foreground.png",
		AndroidBackground: "android-icon-background.png",
		AndroidMonochrome: "android-icon-monochrome.png",
	}
}

const (
	tenantApplicationID       = "dex-mobile"
	tenantDistributionChannel = "direct"
	tenantOTAChannel          = "production"
	defaultIconBackground     = "#FFFFFF"
)

var (
	schemePattern    = regexp.MustCompile(`^[a-z][a-z0-9.+-]{1,31}$`)
	hexColorPattern  = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	ethAddressRegexp = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
)

// missingIdentity 列出还差哪些配置。逐条说清楚缺什么、去哪配——这条链路上的失败
// 全都发生在很后面，报错和根因对不上是它最贵的地方。
type missingIdentity struct {
	Fields []string
}

func (e *missingIdentity) Error() string {
	return "tenant app identity is incomplete: " + strings.Join(e.Fields, ", ")
}

// tenantManifestFor 合成这次构建要用的 tenant.json。
func (s *server) tenantManifestFor(ctx context.Context, tenant string, cfg buildConfig, version string, buildNumber int) (tenantManifest, error) {
	return s.composeTenantManifest(ctx, tenant, cfg, version, buildNumber, "")
}

// composeTenantManifest 是 tenantManifestFor 的实现。firstKeyPackage 非空、且租户还没有 release.android 时，
// 按"第一次在签名闸上生成签名密钥"合成：包名取生成请求里的，签名证书指纹此时还不存在，留空。
// 只有算包内信任根会这么调（信任根不含包名与证书指纹）；这份清单不会下发给构建机。
func (s *server) composeTenantManifest(ctx context.Context, tenant string, cfg buildConfig, version string, buildNumber int, firstKeyPackage string) (tenantManifest, error) {
	var missing []string
	add := func(field, hint string) { missing = append(missing, field+"（"+hint+"）") }

	identity := cfg.Identity
	if strings.TrimSpace(cfg.RepoDirectory) == "" {
		add("repoDirectory", "Android 打包与签名 → 构建位置")
	}
	if strings.TrimSpace(identity.AppName) == "" {
		add("appName", "Android 打包与签名 → App 参数")
	}
	if strings.TrimSpace(identity.Scheme) == "" {
		add("scheme", "Android 打包与签名 → App 参数")
	}
	if strings.TrimSpace(identity.APIBaseURL) == "" {
		add("apiBaseUrl", "Android 打包与签名 → App 参数")
	}

	// 客户端自 1.3.11 起强制验签。这把没配，包打出来照样成功，装上去却停在
	// "配置连接失败"——所以在这里挡住，而不是让它变成一个装不起来的 APK
	signer, err := s.bootstrapSigningRecord(ctx, tenant)
	if err != nil {
		return tenantManifest{}, err
	}
	if signer == nil || strings.TrimSpace(signer.Value.Address) == "" {
		add("bootstrapSignerAddress", "初始化引导 → bootstrap 响应签名密钥")
	}

	// 包名和签名指纹都取自发布身份——那是服务端校验上传的 APK 用的同一份记录。
	// 在 App 参数里再存一份包名，就有了两份可以对不上的真相：配歪了构建照样成功，
	// 产物却在入库那一步被拒，而报错看不出是两个页面填了不同的包名。
	release, err := s.androidReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		return tenantManifest{}, err
	}
	firstKey := release == nil && firstKeyPackage != ""
	if firstKey {
		release = &androidReleaseIdentityRecord{Value: androidReleaseIdentity{PackageName: firstKeyPackage}}
	}
	if release == nil || strings.TrimSpace(release.Value.PackageName) == "" {
		add("androidPackage", "Android 打包与签名 → 正式包身份")
	}
	if !firstKey && (release == nil || strings.TrimSpace(release.Value.SignerSHA256) == "") {
		add("signerSha256", "Android 打包与签名 → 签名密钥")
	}

	// google-services.json 的包名要和这个租户的包名一致。这条在保存 App 参数时已经
	// 拦过一次，这里再拦一次是因为两件事可以按任意顺序配：先传文件、后登记包名，
	// 那次保存时还没有包名可比。放过去的表现是推送在用户手机上静默不工作。
	if encoded := strings.TrimSpace(cfg.GoogleServicesJSON); encoded != "" && len(missing) == 0 {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return tenantManifest{}, fmt.Errorf("stored googleServicesJson is not base64: %w", err)
		}
		if detail := googleServicesPackageProblem(decoded, strings.TrimSpace(release.Value.PackageName)); detail != "" {
			add("google-services.json", detail+"；到「Android 打包与签名」重新上传")
		}
	}

	if len(missing) > 0 {
		return tenantManifest{}, &missingIdentity{Fields: missing}
	}

	background := strings.TrimSpace(identity.IconBackgroundColor)
	if background == "" {
		background = defaultIconBackground
	}
	// 配了 iOS 发布身份就用它的 bundleId 与 Team ID，没配就沿用 Android 包名——同一个
	// 反向域名是这套 App 的现状，不是规则。字段必须在：app.config.ts 读不到会直接抛。
	// 排 iOS 任务之前还会单独核一遍（iosBuildIdentityProblem），这里只负责合成
	bundleID := strings.TrimSpace(release.Value.PackageName)
	appleTeamID := ""
	if ios, err := s.iosReleaseIdentityRecord(ctx, tenant); err != nil {
		return tenantManifest{}, err
	} else if ios != nil {
		if strings.TrimSpace(ios.Value.BundleID) != "" {
			bundleID = strings.TrimSpace(ios.Value.BundleID)
		}
		appleTeamID = strings.TrimSpace(ios.Value.AppleTeamID)
	}

	return tenantManifest{
		Slug:                   cfg.RepoDirectory,
		AppName:                strings.TrimSpace(identity.AppName),
		Scheme:                 strings.TrimSpace(identity.Scheme),
		AndroidPackage:         strings.TrimSpace(release.Value.PackageName),
		IOSBundleID:            bundleID,
		AppleTeamID:            appleTeamID,
		APIBaseURL:             strings.TrimRight(strings.TrimSpace(identity.APIBaseURL), "/"),
		BootstrapSignerAddress: signer.Value.Address,
		ApplicationID:          tenantApplicationID,
		DistributionChannel:    tenantDistributionChannel,
		OTAChannel:             tenantOTAChannel,
		Version:                version,
		AndroidVersionCode:     buildNumber,
		IOSBuildNumber:         strconv.Itoa(buildNumber),
		IconBackgroundColor:    background,
		Icon:                   defaultTenantIcon(),
		SignerSHA256:           release.Value.SignerSHA256,
	}, nil
}

// tenantIdentityDrift 比对这次要编进包里的身份和该租户**已经在分发**的那一版。
//
// 包名或签名指纹变了不是"新版本"，是"另一个 App"：Android 按包名 + 签名证书认
// 身份，两者任一不同，装着旧版的设备升不上去，只能卸载重装——而 direct 分发下没有
// 商店帮忙做这件事。所以默认拦住，要改必须显式说明白。
func tenantIdentityDrift(manifest tenantManifest, activePackage, activeSigner string) []string {
	var drift []string
	if activePackage != "" && !strings.EqualFold(activePackage, manifest.AndroidPackage) {
		drift = append(drift, fmt.Sprintf("包名 %s → %s", activePackage, manifest.AndroidPackage))
	}
	if activeSigner != "" && !strings.EqualFold(activeSigner, manifest.SignerSHA256) {
		drift = append(drift, fmt.Sprintf("签名指纹 %s… → %s…", truncate(activeSigner, 12), truncate(manifest.SignerSHA256, 12)))
	}
	return drift
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
