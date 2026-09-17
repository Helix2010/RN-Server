// Package jobspec 是构建控制进程（build-agent，用户 rn-build-agent）与构建执行进程
// （build-runner，用户 builder）之间唯一的约定：任务目录的布局、任务说明文件、子进程
// 环境白名单、执行结果文件。
//
// 两边各自校验同一份规则。控制进程按它构造，执行进程按它拒收——执行进程是经 sudo
// 启动的另一个用户，参数与文件都不能因为"是控制进程写的"就放过。反过来，执行进程
// 写回的结果文件对控制进程同样是不可信数据。
//
// 设计见 docs/design/android-signing-gate-2026-09-16.md「构建机」。
package jobspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Helix2010/RN-Server/signing/ident"
)

// 任务目录布局：<jobsRoot>/<jobId>/
//
//	spec.json   控制进程写，执行进程只读
//	src/        控制进程检出的单提交仓库（带 .git），执行进程只读
//	work/       执行进程的一次性空间：app/ 是 src 的副本，home、gradle-home、pnpm-store、tmp
//	out/        执行进程交回的产物与 result.json，控制进程当不可信数据读
const (
	SpecFileName   = "spec.json"
	SrcDirName     = "src"
	WorkDirName    = "work"
	OutDirName     = "out"
	ResultFileName = "result.json"

	// 产物在 out/ 里的固定文件名。执行进程不决定文件名，控制进程也不采信它报的名字。
	UnsignedFileName = "app-release-unsigned.apk"
	SBOMFileName     = "sbom.cdx.json"
	OTAFileName      = "ota.zip"
	// iOS 的产物是一个**已签名**的 .ipa：签名在 xcodebuild -exportArchive 里就发生了，
	// 没有"未签名包交给签名闸"这一步（设计 ios-testflight-distribution §4.2）。
	// 它不上传服务端——TestFlight 的包在 Apple 那边，而且不是这一份（Apple 会重签、瘦身）。
	// 交到 out/ 只为让控制进程自己算一遍摘要记进审计，以及让人能在机器上找到它。
	IPAFileName = "app-release.ipa"

	// 执行进程检出副本里的相对路径。它们会进 expo config，从而进原生指纹，所以只能是相对的。
	OTACertificateRelPath = "./ota-certificate.pem"
	GoogleServicesRelPath = "./google-services.json"

	MaxSpecSize     = 256 << 10
	MaxResultSize   = 64 << 10
	MaxUnsignedSize = 2 << 30
	MaxSBOMSize     = 16 << 20
	MaxOTASize      = 2 << 30
	MaxIPASize      = 2 << 30
)

// 目标平台。与服务端 build_jobs.platform 同一套取值。
const (
	PlatformAndroid = "android"
	PlatformIOS     = "ios"
)

// ValidPlatform 只认 android 与 ios。
func ValidPlatform(p string) bool { return p == PlatformAndroid || p == PlatformIOS }

// Kind 是任务种类。
type Kind string

const (
	KindAPK Kind = "apk"
	KindOTA Kind = "ota"
)

// ParseKind 只认 apk 与 ota。
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindAPK, KindOTA:
		return Kind(s), nil
	}
	return "", fmt.Errorf("kind must be apk or ota")
}

var (
	tenantDirectoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	versionPattern         = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)
	commitPattern          = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	channelPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	runtimeVersionPattern  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)
	applicationIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	apiBaseURLPattern      = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	langPattern            = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	nativeFingerprintRe    = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
)

// ValidJobID 判断任务 id。它会被拼进路径，所以规则和服务端 id 一致，天然不含 / 与 ..
func ValidJobID(id string) bool { return ident.ValidServerID(id) }

// ValidTenantDirectory 判断仓库 tenants/ 下的目录名（与服务端 repoDirectoryPattern 相同）。
func ValidTenantDirectory(dir string) bool {
	return tenantDirectoryPattern.MatchString(dir) && !strings.Contains(dir, "..")
}

// ValidVersion 判断版本号。它会进产物文件名。
func ValidVersion(v string) bool { return versionPattern.MatchString(v) && !strings.Contains(v, "..") }

// ValidCommit 判断 git 对象 id。
func ValidCommit(sha string) bool { return commitPattern.MatchString(sha) }

// ValidNativeFingerprint 与 signing/provenance 对原生指纹的格式要求一致。
func ValidNativeFingerprint(fp string) bool { return nativeFingerprintRe.MatchString(fp) }

// ValidRoot 判断任务根目录：绝对、已规范化、不是 /、没有 .. 段。
func ValidRoot(root string) error {
	switch {
	case root == "" || !filepath.IsAbs(root):
		return errors.New("jobs root must be an absolute path")
	case filepath.Clean(root) != root:
		return errors.New("jobs root must be a clean path (no trailing slash, no . or .. segments)")
	case root == "/":
		return errors.New("jobs root cannot be /")
	}
	for _, part := range strings.Split(root, "/") {
		if part == ".." {
			return errors.New("jobs root cannot contain ..")
		}
	}
	return nil
}

// Layout 是一个任务目录里各路径的唯一算法。两边都从 (root, jobId) 推出路径，
// 不接受对方传来的路径字符串。
type Layout struct {
	Root  string
	JobID string
}

// NewLayout 校验后返回布局。
func NewLayout(root, jobID string) (Layout, error) {
	if err := ValidRoot(root); err != nil {
		return Layout{}, err
	}
	if !ValidJobID(jobID) {
		return Layout{}, errors.New("job id is malformed")
	}
	return Layout{Root: root, JobID: jobID}, nil
}

func (l Layout) Dir() string                { return filepath.Join(l.Root, l.JobID) }
func (l Layout) Spec() string               { return filepath.Join(l.Dir(), SpecFileName) }
func (l Layout) Src() string                { return filepath.Join(l.Dir(), SrcDirName) }
func (l Layout) Work() string               { return filepath.Join(l.Dir(), WorkDirName) }
func (l Layout) App() string                { return filepath.Join(l.Work(), "app") }
func (l Layout) Home() string               { return filepath.Join(l.Work(), "home") }
func (l Layout) GradleUserHome() string     { return filepath.Join(l.Work(), "gradle-home") }
func (l Layout) PnpmStore() string          { return filepath.Join(l.Work(), "pnpm-store") }
func (l Layout) Tmp() string                { return filepath.Join(l.Work(), "tmp") }
func (l Layout) AndroidUserHome() string    { return filepath.Join(l.Home(), ".android") }
func (l Layout) Out() string                { return filepath.Join(l.Dir(), OutDirName) }
func (l Layout) OutFile(name string) string { return filepath.Join(l.Out(), name) }

// ---- 子进程环境白名单 ----

// 机器级变量：值来自控制进程自己的环境（systemd unit / env 文件），是这台机器的拓扑，不是机密。
// ASC_KEY_ID / ASC_ISSUER_ID 是上传 TestFlight 用的标识，不是机密——真正的机密是 .p8，
// 它留在这台 Mac 的 ~/.appstoreconnect/private_keys/ 下，由 altool 自己去找，既不经过
// 服务端也不进这个环境。
var machineEnvKeys = []string{"PATH", "LANG", "JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "GRADLE_RO_DEP_CACHE",
	"ASC_KEY_ID", "ASC_ISSUER_ID"}

// MachineEnvKeys 返回机器级变量名的副本。
func MachineEnvKeys() []string { return append([]string(nil), machineEnvKeys...) }

// 任务专用变量：值由任务决定。App 的 expo config 会读它们，所以取值不能含任务目录路径。
var taskEnvKeys = []string{
	"EXPO_PUBLIC_TENANT",
	"EXPO_PUBLIC_API_BASE_URL",
	"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE",
	"EXPO_REQUIRE_OTA_SIGNING",
	"GOOGLE_SERVICES_JSON",
}

// 每任务一份的目录。执行进程按布局核对，取值必须恰好是本任务的路径。
func jobPathEnv(l Layout) map[string]string {
	return map[string]string{
		"HOME":                 l.Home(),
		"GRADLE_USER_HOME":     l.GradleUserHome(),
		"npm_config_store_dir": l.PnpmStore(),
		"TMPDIR":               l.Tmp(),
		"ANDROID_USER_HOME":    l.AndroidUserHome(),
	}
}

// TaskEnv 是构造任务专用变量的输入。
type TaskEnv struct {
	TenantDirectory string
	APIBaseURL      string
	GoogleServices  bool
}

// BuildEnv 构造执行进程给子进程用的完整环境，按键名排序。安装包与热更新两条链路
// 必须调用同一个函数：原生指纹把 expo config 整份算进去，两边环境差一个变量，
// 热更新就永远和基线对不上。
//
// machine 里只取白名单里的机器级变量，其它一概忽略——调用方传 os.Environ() 进来也
// 不会把令牌带过去。
func BuildEnv(l Layout, machine map[string]string, task TaskEnv) ([]string, error) {
	env := map[string]string{}
	for _, key := range machineEnvKeys {
		if value := machine[key]; value != "" {
			env[key] = value
		}
	}
	for key, value := range jobPathEnv(l) {
		env[key] = value
	}
	if !ValidTenantDirectory(task.TenantDirectory) {
		return nil, errors.New("tenant directory is malformed")
	}
	if !apiBaseURLPattern.MatchString(task.APIBaseURL) {
		return nil, errors.New("apiBaseUrl must be a plain https URL")
	}
	env["EXPO_PUBLIC_TENANT"] = task.TenantDirectory
	env["EXPO_PUBLIC_API_BASE_URL"] = task.APIBaseURL
	env["EXPO_UPDATES_CODE_SIGNING_CERTIFICATE"] = OTACertificateRelPath
	env["EXPO_REQUIRE_OTA_SIGNING"] = "1"
	if task.GoogleServices {
		env["GOOGLE_SERVICES_JSON"] = GoogleServicesRelPath
	}
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, key+"="+value)
	}
	sort.Strings(out)
	if err := CheckEnv(l, out); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckEnv 是执行进程拒收环境的规则：只允许白名单里的键；每任务目录必须恰好是本任务的；
// PATH 必填且每一段是绝对路径；机器级路径变量是绝对路径；不许重复、不许控制字符。
func CheckEnv(l Layout, env []string) error {
	allowed := map[string]string{}
	for _, key := range machineEnvKeys {
		allowed[key] = "machine"
	}
	for _, key := range taskEnvKeys {
		allowed[key] = "task"
	}
	paths := jobPathEnv(l)
	for key := range paths {
		allowed[key] = "job"
	}
	seen := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return errors.New("environment entry is not KEY=VALUE")
		}
		class, known := allowed[key]
		if !known {
			return fmt.Errorf("environment variable %s is not on the allow list", key)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("environment variable %s appears twice", key)
		}
		if strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("environment variable %s contains a control character", key)
		}
		seen[key] = value
		switch class {
		case "job":
			if value != paths[key] {
				return fmt.Errorf("environment variable %s must be this job's own directory", key)
			}
		case "task":
			if strings.Contains(value, l.Root) {
				return fmt.Errorf("environment variable %s must not point into the job directory (it would change the native fingerprint)", key)
			}
		case "machine":
			switch key {
			case "PATH":
				for _, dir := range strings.Split(value, ":") {
					if !filepath.IsAbs(dir) {
						return errors.New("every PATH entry must be an absolute directory")
					}
				}
			case "LANG":
				if !langPattern.MatchString(value) {
					return errors.New("LANG is malformed")
				}
			default:
				if !filepath.IsAbs(value) || filepath.Clean(value) != value {
					return fmt.Errorf("%s must be a clean absolute path", key)
				}
			}
		}
	}
	for _, required := range []string{"PATH", "HOME", "GRADLE_USER_HOME", "npm_config_store_dir", "TMPDIR",
		"EXPO_PUBLIC_TENANT", "EXPO_PUBLIC_API_BASE_URL", "EXPO_UPDATES_CODE_SIGNING_CERTIFICATE", "EXPO_REQUIRE_OTA_SIGNING"} {
		if _, ok := seen[required]; !ok {
			return fmt.Errorf("environment variable %s is required", required)
		}
	}
	return nil
}

// EnvValue 取环境列表里某个键的值。
func EnvValue(env []string, key string) string {
	for _, entry := range env {
		if k, v, ok := strings.Cut(entry, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// ---- 任务说明 ----

// OTAArgs 是热更新构建的参数，逐个交给 `pnpm ota:build`。
type OTAArgs struct {
	Channel        string `json:"channel"`
	ApplyStrategy  string `json:"applyStrategy"`
	RuntimeVersion string `json:"runtimeVersion"`
	APIBaseURL     string `json:"apiBaseUrl"`
	ApplicationID  string `json:"applicationId"`
}

// Spec 是控制进程写给执行进程的任务说明。
type Spec struct {
	Version int    `json:"v"`
	JobID   string `json:"jobId"`
	Kind    Kind   `json:"kind"`
	// Platform 决定执行进程走哪条构建路径。安装包任务在 Android 上出未签名 APK + SBOM，
	// 在 iOS 上出一个已签名的 .ipa——两者的交付物、后续状态流转都不一样
	Platform        string `json:"platform"`
	TenantDirectory string `json:"tenantDirectory"`
	AppVersion      string `json:"version"`
	BuildNumber     int    `json:"buildNumber"`
	CommitSHA       string `json:"commitSha"`
	// IOSUpload：构建完把 .ipa 传进 App Store Connect。由装这台 Mac 的人在
	// BUILD_AGENT_IOS_UPLOAD 里打开，不由"排了一条 iOS 任务"隐含决定——上传是一个
	// 对外可见的动作，包一旦进了 ASC 就撤不回来，只能再出一个 build 顶掉它
	IOSUpload bool     `json:"iosUpload,omitempty"`
	OTA       *OTAArgs `json:"ota"`
	Env       []string `json:"env"`
}

// SpecVersion 是 Spec.Version 唯一允许的值。
const SpecVersion = 1

// Validate 按布局校验说明。
func (s Spec) Validate(l Layout) error {
	switch {
	case s.Version != SpecVersion:
		return fmt.Errorf("spec v must be %d", SpecVersion)
	case s.JobID != l.JobID:
		return errors.New("spec jobId does not match the job directory")
	case !ValidPlatform(s.Platform):
		return errors.New("spec platform must be android or ios")
	case s.Platform == PlatformIOS && s.Kind != KindAPK:
		// 热更新包与平台无关，由 Android 那台机器构建；iOS 只做安装包
		return errors.New("only installable-package jobs are built on ios")
	case s.IOSUpload && s.Platform != PlatformIOS:
		return errors.New("only an ios job uploads to App Store Connect")
	case !ValidTenantDirectory(s.TenantDirectory):
		return errors.New("spec tenantDirectory is malformed")
	case !ValidVersion(s.AppVersion):
		return errors.New("spec version is malformed")
	case s.BuildNumber < 1 || s.BuildNumber > 2100000000:
		return errors.New("spec buildNumber is out of range")
	case !ValidCommit(s.CommitSHA):
		return errors.New("spec commitSha is malformed")
	}
	if _, err := ParseKind(string(s.Kind)); err != nil {
		return err
	}
	switch s.Kind {
	case KindAPK:
		if s.OTA != nil {
			return errors.New("an apk spec cannot carry OTA arguments")
		}
	case KindOTA:
		if s.OTA == nil {
			return errors.New("an ota spec needs OTA arguments")
		}
		o := s.OTA
		switch {
		case !channelPattern.MatchString(o.Channel):
			return errors.New("spec ota.channel is malformed")
		case o.ApplyStrategy != "next_launch" && o.ApplyStrategy != "immediate":
			return errors.New("spec ota.applyStrategy must be next_launch or immediate")
		case !runtimeVersionPattern.MatchString(o.RuntimeVersion):
			return errors.New("spec ota.runtimeVersion is malformed")
		case !apiBaseURLPattern.MatchString(o.APIBaseURL):
			return errors.New("spec ota.apiBaseUrl must be a plain https URL")
		case !applicationIDPattern.MatchString(o.ApplicationID):
			return errors.New("spec ota.applicationId is malformed")
		}
	}
	if err := CheckEnv(l, s.Env); err != nil {
		return err
	}
	if EnvValue(s.Env, "EXPO_PUBLIC_TENANT") != s.TenantDirectory {
		return errors.New("EXPO_PUBLIC_TENANT must equal the spec tenantDirectory")
	}
	if s.OTA != nil && EnvValue(s.Env, "EXPO_PUBLIC_API_BASE_URL") != s.OTA.APIBaseURL {
		return errors.New("EXPO_PUBLIC_API_BASE_URL must equal the spec ota.apiBaseUrl")
	}
	return nil
}

// EncodeSpec 序列化说明。
func EncodeSpec(s Spec) ([]byte, error) {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// DecodeSpec 严格解析说明：大小上限、未知字段、尾随数据一律拒收。
func DecodeSpec(r io.Reader) (Spec, error) {
	var s Spec
	return s, decodeStrict(r, MaxSpecSize, &s)
}

// ---- 执行结果 ----

// Result 是执行进程写回 out/result.json 的内容。原生指纹是执行进程自报的，
// 控制进程只校验格式，签名闸复核。
type Result struct {
	Version           int    `json:"v"`
	Kind              Kind   `json:"kind"`
	NativeFingerprint string `json:"nativeFingerprint,omitempty"`
	// UploadedToAppStoreConnect 只用于 iOS：这次有没有真的把 .ipa 传上去。
	// "包打出来了"和"TestFlight 上有这一版"是两件事，运营要能分辨
	UploadedToAppStoreConnect bool `json:"uploadedToAppStoreConnect,omitempty"`
}

// ResultVersion 是 Result.Version 唯一允许的值。
const ResultVersion = 1

// Validate 按任务种类与平台校验结果。
//
// 原生指纹只有 Android 的安装包才有：它是签名闸复核未签名包用的，而 iOS 没有签名闸
// 这一环（签名在 Mac 上的 xcodebuild 里就发生了）。
func (r Result) Validate(kind Kind, platform string) error {
	androidPackage := kind == KindAPK && platform == PlatformAndroid
	switch {
	case r.Version != ResultVersion:
		return fmt.Errorf("result v must be %d", ResultVersion)
	case r.Kind != kind:
		return errors.New("result kind does not match the job")
	case androidPackage && !ValidNativeFingerprint(r.NativeFingerprint):
		return errors.New("result nativeFingerprint must be 32-128 lowercase hex characters")
	case !androidPackage && r.NativeFingerprint != "":
		return errors.New("only an android installable-package result carries a native fingerprint")
	case r.UploadedToAppStoreConnect && platform != PlatformIOS:
		return errors.New("only an ios result reports an App Store Connect upload")
	}
	return nil
}

// DecodeResult 严格解析结果并校验。
func DecodeResult(r io.Reader, kind Kind, platform string) (Result, error) {
	var out Result
	if err := decodeStrict(r, MaxResultSize, &out); err != nil {
		return Result{}, err
	}
	return out, out.Validate(kind, platform)
}

func decodeStrict(r io.Reader, limit int64, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("document is larger than %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("document is not valid: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("document has trailing data")
	}
	return nil
}

// ArtifactName 是 RN-App `pnpm android:release` 复制到 artifacts/ 下的未签名包文件名
// （scripts/build-android-release.mjs）。SBOM 里的 rn-app:artifact 属性写的也是它。
func ArtifactName(tenantDirectory, version string, buildNumber int) string {
	return fmt.Sprintf("%s-%s-build%d-release-unsigned.apk", tenantDirectory, version, buildNumber)
}

// IPAArtifactName 是 RN-App scripts/build-ios-release.mjs 写进 artifacts/ 的文件名。
// 两边必须一致：执行进程按这个名字去找产物，找不到就判这次构建没出东西。
func IPAArtifactName(tenantDirectory, version string, buildNumber int) string {
	return fmt.Sprintf("%s-%s-build%d.ipa", tenantDirectory, version, buildNumber)
}
