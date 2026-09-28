package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/trustroots"
	"github.com/gin-gonic/gin"
)

// 每租户的构建配置（`app_configs` 的 `build.android`）。
//
// 存在的理由是 2026-09-11 部署时撞到的一件事：服务端的租户 slug 是 `Predict.Kim`，
// 而仓库里的租户目录叫 `anyfun`。两边是**两套命名**，代理拿 slug 去找
// `tenants/<slug>/tenant.json` 必然找不到。
//
// 不能靠"把某一边改成和另一边一样"来解决：slug 是本平台的身份，仓库目录是另一个
// 系统的目录名，两者恰好相等是现状不是规则（RN-Admin AGENTS.md 对外部系统 id 的
// 同一条约束）。所以对应关系必须是一条**显式配置**。
const buildConfigKey = "build.android"

var repoDirectoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type buildConfig struct {
	// RepoDirectory 是仓库里 tenants/ 下的目录名，不是本平台的 slug。
	RepoDirectory string `json:"repoDirectory"`
	// DefaultGitRef 保留是为了读得懂历史配置行。构建分支现在固定 main，不再由
	// 租户选：能选分支就意味着能从任意分支出一个用生产密钥签名的包。
	DefaultGitRef string `json:"defaultGitRef"`
	// GoogleServicesJSON 是 google-services.json 的 base64。它**不是机密**——
	// 同一份内容会原样编进每一个 APK——但它按租户不同，所以放在这里而不是放到
	// 每台打包机上。这样"新加一台打包机"仍然只需要一个封装口令。
	GoogleServicesJSON string `json:"googleServicesJson"`
	// Identity 是原先写在仓库 tenants/<目录>/tenant.json 里的那几个字段。搬过来的
	// 理由和代价见 tenant_manifest.go 顶部。
	Identity appIdentity `json:"identity"`
}

// appIdentity 只放**必须由人决定、而且别处没有**的字段。
//
// 包名和 bundleId 不在这里：它们已经是「发布身份」的内容（服务端拿它校验上传的
// APK 是不是这个租户的包），在这边再配一次就是两份可以对不上的真相——配歪了构建
// 会成功，产物却在入库那一步被拒，而报错完全看不出是"两个页面填了不同的包名"。
// 合成身份文件时从发布身份取，见 tenantManifestFor。
//
// 签名地址、签名指纹、版本号同理，服务端自己知道，不让人填也就不会填错。
type appIdentity struct {
	AppName             string `json:"appName"`
	Scheme              string `json:"scheme"`
	APIBaseURL          string `json:"apiBaseUrl"`
	IconBackgroundColor string `json:"iconBackgroundColor"`
}

// buildGitRef 是所有构建用的分支。固定值，不是默认值。
const buildGitRef = "main"

// validate 只挡住会让构建在很后面才失败、或者会产出一个身份不对的包的输入。
func (a appIdentity) validate() error {
	name := strings.TrimSpace(a.AppName)
	if name == "" || len([]rune(name)) > 64 {
		return errors.New("appName must be 1-64 characters")
	}
	if strings.TrimSpace(a.Scheme) != "" && !schemePattern.MatchString(a.Scheme) {
		// scheme 决定这个 App 认领哪些深链。写松了就是去抢别人的链接
		return errors.New("scheme must be lowercase letters, digits, . + - and start with a letter")
	}
	if err := validateAPIBaseURL(a.APIBaseURL); err != nil {
		return err
	}
	if color := strings.TrimSpace(a.IconBackgroundColor); color != "" && !hexColorPattern.MatchString(color) {
		return errors.New("iconBackgroundColor must be #RRGGBB")
	}
	return nil
}

// App 启动时拿这个地址取配置。允许 http 等于允许把整份配置放在明文链路上，而
// 客户端对这份配置的信任来自签名——签名挡不住"根本没连到我们"。
//
// 判据是 signing/trustroots.ValidateAPIBaseURL，与签名闸确认包内信任根用的是同一个函数：
// https、小写 DNS 名、不带路径，并且**不许显式写默认端口 :443**——RN-App 用 WHATWG URL 派生
// App Links host 时会去掉它，而 extra.apiBaseUrl 按原样编进包，同一个源两种写法会让服务端与
// 签名闸对 host 与信任根摘要得出不同结论。首尾空白与结尾的 / 先去掉（合成 tenant.json 时本来
// 就去掉），其余不做改写。
func validateAPIBaseURL(raw string) error {
	value := canonicalAPIBaseURL(raw)
	if value == "" {
		return errors.New("apiBaseUrl is required")
	}
	if err := trustroots.ValidateAPIBaseURL(value); err != nil {
		return err
	}
	return nil
}

// canonicalAPIBaseURL 去掉首尾空白与结尾的 /，与 tenantManifestFor 合成时的处理一致。
func canonicalAPIBaseURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func (s *server) buildConfigFor(ctx context.Context, tenant, fallbackSlug string) (buildConfig, int, error) {
	var raw []byte
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, buildConfigKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		// 没配过就退回 slug——两边名字恰好一样的租户不必为此专门配一条
		return buildConfig{RepoDirectory: fallbackSlug, DefaultGitRef: buildGitRef}, 0, nil
	}
	if err != nil {
		return buildConfig{}, 0, err
	}
	var cfg buildConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return buildConfig{}, version, err
	}
	if strings.TrimSpace(cfg.RepoDirectory) == "" {
		cfg.RepoDirectory = fallbackSlug
	}
	cfg.DefaultGitRef = buildGitRef
	return cfg, version, nil
}

func (s *server) getBuildConfig(c *gin.Context) {
	slug, err := s.tenantSlug(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_QUERY_FAILED", "Unable to resolve this tenant")
		return
	}
	cfg, version, err := s.buildConfigFor(c.Request.Context(), tenantID(c), slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"repoDirectory": cfg.RepoDirectory,
		"defaultGitRef": cfg.DefaultGitRef,
		// 只报有没有配、多大，不把整段 base64 塞进每一次列表请求
		"googleServicesConfigured": cfg.GoogleServicesJSON != "",
		// 界面上要能说出"现在这份文件是给哪个包名的"。只回包名，不回整段 base64
		"googleServicesPackages": storedGoogleServicesPackages(cfg.GoogleServicesJSON),
		"tenantSlug":             slug,
		"version":                version,
		"identity": gin.H{
			"appName":             cfg.Identity.AppName,
			"scheme":              cfg.Identity.Scheme,
			"apiBaseUrl":          cfg.Identity.APIBaseURL,
			"iconBackgroundColor": cfg.Identity.IconBackgroundColor,
		},
		"identityConfigured": cfg.Identity.validate() == nil,
	})
}

func (s *server) saveBuildConfig(c *gin.Context) {
	var body struct {
		RepoDirectory      string      `json:"repoDirectory"`
		GoogleServicesJSON string      `json:"googleServicesJson"`
		Identity           appIdentity `json:"identity"`
		ExpectedVersion    int         `json:"expectedVersion"`
		Reason             string      `json:"reason"`
		Confirm            bool        `json:"confirm"`
		// AcknowledgeIdentityChange：改包名或 scheme 时必须显式带上。见下面的说明。
		AcknowledgeIdentityChange bool `json:"acknowledgeIdentityChange"`
	}
	// 解码失败和字段没填是两种完全不同的毛病，报同一句话会把人送去查错的地方。
	// 真踩过：控制台挪走了 identity.androidPackage，浏览器里还是旧包，发上来的
	// 多余字段让 DisallowUnknownFields 拒了整个请求，而报错说的是"缺 reason"。
	if err := decode(c, &body); err != nil {
		problem(c, http.StatusBadRequest, "MALFORMED_BUILD_CONFIG",
			"Request body was rejected: "+err.Error()+"。如果提到 unknown field，多半是浏览器里还开着旧版控制台，强制刷新一次。")
		return
	}
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "repoDirectory, expectedVersion, reason and confirm=true are required")
		return
	}
	// slug 是仓库目录的默认值，读取那一侧本来就这么回退（buildConfigFor）。写入这一侧
	// 原先要求必填，于是"默认值"只对从没保存过的租户成立——存过一次之后就必须有人
	// 手抄一个系统已经知道的名字。默认值由服务端声明，前端只负责把它显示出来。
	slug, err := s.tenantSlug(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to resolve this tenant")
		return
	}
	directory := strings.TrimSpace(body.RepoDirectory)
	if directory == "" {
		directory = strings.TrimSpace(slug)
	}
	// 这个值会被代理拼进文件路径。放开一点点就等于给一条"跳出 tenants/ 目录"的路。
	if !repoDirectoryPattern.MatchString(directory) || strings.Contains(directory, "..") {
		detail := "repoDirectory must be a plain directory name under tenants/"
		if strings.TrimSpace(body.RepoDirectory) == "" {
			// 留空是允许的，但这个租户的 slug 本身当不了目录名。说清楚是哪一个不行，
			// 否则运维会盯着一个自己没填的字段看
			detail = "repoDirectory was left empty and this tenant's slug (" + slug + ") is not usable as a directory name under tenants/; set it explicitly"
		}
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", detail)
		return
	}
	// 仓库目录决定打包机从 App 仓库的哪个目录取租户文件，是平台的部署结构，不归租户管：在平台控制台
	// 「租户打包目录」里改（设计 service-and-console-split-2026-09-27 §7 第 1 条），这里只能原样带回现在的值
	stored, _, err := s.buildConfigFor(c.Request.Context(), tenantID(c), strings.TrimSpace(slug))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	if directory != stored.RepoDirectory {
		problem(c, http.StatusForbidden, "REPO_DIRECTORY_PLATFORM_ONLY", "Only the platform administrator can change repoDirectory")
		return
	}
	// 存规范写法：读的人（控制台、合成 tenant.json、信任根）看到的都是同一个字符串
	body.Identity.APIBaseURL = canonicalAPIBaseURL(body.Identity.APIBaseURL)
	if err := body.Identity.validate(); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_APP_IDENTITY", err.Error())
		return
	}
	googleServices := strings.TrimSpace(body.GoogleServicesJSON)
	if googleServices != "" {
		decoded, err := base64.StdEncoding.DecodeString(googleServices)
		if err != nil || !json.Valid(decoded) {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "googleServicesJson must be base64-encoded JSON")
			return
		}
		if len(decoded) > 256*1024 {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "googleServicesJson is too large")
			return
		}
		if err := rejectServiceAccountJSON(decoded); err != nil {
			problem(c, http.StatusBadRequest, "SECRET_IN_BUILD_CONFIG", err.Error())
			return
		}
		// 包名一致性在这里就挡住。放过去的话，唯一的表现是推送在用户手机上静默
		// 不工作——没有任何一步会报错，而排查会从推送服务一路查到证书。
		// 还没登记包名的租户不拦：这一页可以先配 google-services 再配身份，
		// 那种顺序下的错漏由排队时的同一条检查兜底（tenantManifestFor）。
		if release, err := s.androidReleaseIdentityRecord(c.Request.Context(), tenantID(c)); err == nil && release != nil {
			if detail := googleServicesPackageProblem(decoded, release.Value.PackageName); detail != "" {
				problem(c, http.StatusBadRequest, "GOOGLE_SERVICES_PACKAGE_MISMATCH", detail)
				return
			}
		}
		// 项目一致性是同一条缝的另一半：这份文件（编进 APK）和服务端那把服务账号
		// 必须属于同一个 Firebase 项目。先配了凭据、后换一份别的项目的文件，是这
		// 条链路上最容易发生的顺序。
		if detail := s.pushCredentialProjectProblem(c.Request.Context(), tenantID(c), googleServicesProjectID(decoded)); detail != "" {
			problem(c, http.StatusUnprocessableEntity, "GOOGLE_SERVICES_PROJECT_MISMATCH", detail)
			return
		}
	}
	value, _ := json.Marshal(buildConfig{
		RepoDirectory:      directory,
		DefaultGitRef:      buildGitRef,
		GoogleServicesJSON: googleServices,
		Identity:           body.Identity,
	})
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	defer tx.Rollback()
	var current int
	err = tx.QueryRowContext(c.Request.Context(), `SELECT version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenantID(c), buildConfigKey).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	if current != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_CONFIG", "Build configuration changed; refresh and retry")
		return
	}
	// 改包名或 scheme 不是改配置，是换一个 App：Android 按「包名 + 签名证书」认
	// 身份，装着旧包的设备升不上去，只能卸载重装——direct 分发下没有商店替我们
	// 处理这件事。所以要显式带 acknowledgeIdentityChange，不给它一个默认值。
	previous, _, err := s.buildConfigFor(c.Request.Context(), tenantID(c), directory)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	changed := identityBreakingChanges(previous.Identity, body.Identity)
	if len(changed) > 0 && !body.AcknowledgeIdentityChange {
		problem(c, http.StatusConflict, "APP_IDENTITY_CHANGE",
			"Changing "+strings.Join(changed, " and ")+" makes this a different app; existing installs cannot upgrade into it. Resend with acknowledgeIdentityChange=true.")
		return
	}
	var result sql.Result
	newVersion := current + 1
	if current == 0 {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), buildConfigKey, value, actor(c), now, tenantID(c), buildConfigKey)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, tenantID(c), buildConfigKey, current)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_BUILD_CONFIG", "Build configuration changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "build_config_update", "app-config", buildConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{
			"repoDirectory": directory, "gitRef": buildGitRef,
			"googleServicesConfigured": googleServices != "",
			"scheme":                   body.Identity.Scheme,
			// 身份真的变了才记，事后翻审计时这一条要显眼
			"identityBreakingChanges": changed,
			"databaseVersion":         newVersion,
		})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"repoDirectory":            directory,
		"defaultGitRef":            buildGitRef,
		"googleServicesConfigured": googleServices != "",
		"googleServicesPackages":   storedGoogleServicesPackages(googleServices),
		"tenantSlug":               slug,
		"identity": gin.H{
			"appName":             body.Identity.AppName,
			"scheme":              body.Identity.Scheme,
			"apiBaseUrl":          body.Identity.APIBaseURL,
			"iconBackgroundColor": body.Identity.IconBackgroundColor,
		},
		"identityConfigured": true,
		"version":            newVersion,
	})
}

// rejectServiceAccountJSON 挡住把 Firebase **服务账号**当 google-services.json 传
// 上来这件事。
//
// 两个文件都从 Firebase 控制台下载、都叫 json、名字还长得像，但性质相反：
// google-services.json 是客户端配置，本来就会原样编进每一个 APK；
// service-account.json 里有 private_key，是服务端发推送用的凭据。
//
// 传错的后果不是"配置不生效"，而是**那把私钥会被编进 APK 发给所有用户**——而且
// 装出去之后没有任何补救办法，只能吊销密钥重发。所以这里判死，不做兼容。
func rejectServiceAccountJSON(raw []byte) error {
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		// 顶层不是对象的 JSON 走不到这里的判断，交给后面的形状校验
		return nil
	}
	if _, hasPrivateKey := probe["private_key"]; hasPrivateKey {
		return errors.New("这个文件里有 private_key，是 Firebase 服务账号凭据，不是 google-services.json。它会被原样编进 APK 发给所有用户——不要上传。google-services.json 的顶层是 project_info 和 client")
	}
	if kind, _ := probe["type"].(string); kind == "service_account" {
		return errors.New("这是 Firebase 服务账号凭据（type=service_account），不是 google-services.json")
	}
	// 正品的形状：project_info + client。缺了就是选错了文件，早点说比让构建跑完再说便宜
	if _, ok := probe["project_info"]; !ok {
		return errors.New("这不像 google-services.json：顶层没有 project_info。请从 Firebase 控制台的「项目设置 → 你的应用 → Android」下载")
	}
	return nil
}

// googleServicesFile 只声明我们要看的那一部分。这份文件里还有一堆 Firebase 自己的
// 字段，逐个建模没有意义，也会让"多了一个新字段"变成解析失败。
type googleServicesFile struct {
	// ProjectInfo 是另一半的接缝：编进 APK 的这份文件和留在服务端的服务账号
	// 必须属于同一个 Firebase 项目，否则 token 注册得上、推送发不出去。
	ProjectInfo struct {
		ProjectID     string `json:"project_id"`
		ProjectNumber string `json:"project_number"`
	} `json:"project_info"`
	Client []struct {
		ClientInfo struct {
			AndroidClientInfo struct {
				PackageName string `json:"package_name"`
			} `json:"android_client_info"`
		} `json:"client_info"`
	} `json:"client"`
}

// googleServicesPackages 列出这份文件为哪些 Android 包名注册过。
//
// 一个 Firebase 项目下可以有多个 Android 应用（正式、测试、不同租户），下载下来的
// 文件里 client 是个数组，每一项对应一个包名。所以"文件对不对"这个问题的答案是
// "它的 client 里有没有我们这个包名"，不是"它的第一个 client 是不是我们"。
func googleServicesPackages(raw []byte) []string {
	var parsed googleServicesFile
	if json.Unmarshal(raw, &parsed) != nil {
		return nil
	}
	var packages []string
	for _, client := range parsed.Client {
		if name := strings.TrimSpace(client.ClientInfo.AndroidClientInfo.PackageName); name != "" {
			packages = append(packages, name)
		}
	}
	return packages
}

// googleServicesProjectID 取这份文件所属的 Firebase 项目。
func googleServicesProjectID(raw []byte) string {
	var parsed googleServicesFile
	if json.Unmarshal(raw, &parsed) != nil {
		return ""
	}
	return strings.TrimSpace(parsed.ProjectInfo.ProjectID)
}

// googleServicesProjectIDFromBase64 是它的 base64 入口，给推送凭据那一侧用。
func googleServicesProjectIDFromBase64(encoded string) string {
	if strings.TrimSpace(encoded) == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return googleServicesProjectID(decoded)
}

// googleServicesPackageProblem 检查这份文件是不是这个包名的。空串表示没问题。
//
// 这是这条链路上最沉默的一种配错：包名对不上，构建照样成功，APK 照样能装，
// 只有推送在运行时静默失效——Firebase SDK 初始化时发现 applicationId 与文件里
// 的不符，就不注册。没有任何一步会报错。
func googleServicesPackageProblem(raw []byte, packageName string) string {
	packages := googleServicesPackages(raw)
	if len(packages) == 0 {
		return "这份 google-services.json 里没有任何 Android 应用（client[].client_info.android_client_info.package_name）"
	}
	for _, name := range packages {
		if name == packageName {
			return ""
		}
	}
	return "这份 google-services.json 是给 " + strings.Join(packages, "、") + " 的，本租户的包名是 " + packageName +
		"。请到 Firebase 控制台用这个包名注册一个 Android 应用，再下载它的 google-services.json"
}

// storedGoogleServicesPackages 是 googleServicesPackages 的 base64 入口，给两个
// 接口回参用。解不开就当没有——存进来的时候校验过，这里不该再报错。
func storedGoogleServicesPackages(encoded string) []string {
	packages := []string{}
	if encoded == "" {
		return packages
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return packages
	}
	return append(packages, googleServicesPackages(decoded)...)
}

// identityBreakingChanges 只列真正会让已装设备升不上去、或者会改变这个 App 认领
// 什么的字段。appName 改了不算——那只是显示名。
// 包名变更不在这里判：它归发布身份管，而真正的闸在排队那一刻——queueBuild 会拿
// 要打的包和**正在分发**的那一版对一遍，无论是谁在哪个页面改的都拦得住。
func identityBreakingChanges(before, after appIdentity) []string {
	var changed []string
	// scheme 决定这个 App 认领哪些深链。改了它，已经发出去的链接会打不开
	if b := strings.TrimSpace(before.Scheme); b != "" && b != strings.TrimSpace(after.Scheme) {
		changed = append(changed, "scheme")
	}
	return changed
}

func (s *server) tenantSlug(ctx context.Context, tenant string) (string, error) {
	var slug string
	err := s.db.QueryRowContext(ctx, `SELECT slug FROM tenants WHERE id=? LIMIT 1`, tenant).Scan(&slug)
	return slug, err
}
