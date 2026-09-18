package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/machinesetup"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/machinekey"
	"github.com/gin-gonic/gin"
)

// 新机器的一次性注册（设计 android-signing-gate-automation-2026-09-16「2. 新机器」、ADR-0020）。
//
// 控制台新建机器只签发一个注册码（rne_ + 32 字节随机数，只存 sha256，60 分钟，一次性）。运维在
// 新机器本机执行 install.sh：用注册码查出这台机器是谁（describe，不消耗）、下载并核对安装包、
// 在本机生成密钥后调 enroll。enroll 在**一个写事务**里核对并消耗注册码、挂上待接受的公钥、签发
// 长期机器令牌——令牌直接写进那台机器的 env 文件，不经过屏幕、控制台与对话。
//
// 这几条接口不走机器令牌（机器此时还没有令牌），靠注册码；describe、安装包、enroll 都按来源 IP
// 限速。注册码无效、过期、已用一律同一句 404，不区分。
//
// 服务端被攻破能做的，是在新装机器时下发篡改过的安装包或给出错误的主签名闸公钥（首次信任）；
// 已在运行的机器不从这里升级，签名闸也不采信这里给的任何公钥之外的东西（见 ADR-0020）。

const (
	enrollmentCodeTTL    = 60 * time.Minute
	enrollmentCodeHeader = "x-enrollment-code"
	machineSetupActor    = "system-machine-setup"
	// machineSetupPerMinute 是 describe、安装包、enroll 各自按来源 IP 每分钟的上限。装一台机器
	// 要 describe 两次（install.sh 与 enroll 各一次）、下载一次、enroll 一次；同一出口 IP 后面
	// 同时装几台也碰不到。碰到了多半是在扫注册码
	machineSetupPerMinute = 20

	machineBundleManifestFormat = "rn-machine-bundles/v1"
	// defaultMachineBundleDir 是安装包目录（rn-foundation-apply bundles 原子切换 current 软链）。
	// 不是配置项：它和服务端二进制一起由同一个部署脚本放下，路径是部署约定
	defaultMachineBundleDir = "/opt/rn-foundation/machine-bundles/current"
	machineBundleManifest   = "manifest.json"
	maxMachineBundleFiles   = 256
)

var (
	bundleCommitPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	// 签名闸的 unit 模板按实例名渲染，文件名里带 @（templates/rn-signer-@INSTANCE@-check@.service）
	bundleFileNamePattern = regexp.MustCompile(`^[A-Za-z0-9@._-]+(/[A-Za-z0-9@._-]+)*$`)
)

// validBundleFileName：归档里的相对路径。不收绝对路径、空段、. 与 .. 段——安装脚本会按它逐个核对解出来的文件。
func validBundleFileName(name string) bool {
	if len(name) > 255 || !bundleFileNamePattern.MatchString(name) {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// machineSetupLimiter 是 machine-setup 三条接口按来源 IP 的每分钟计数。零值可用。
type machineSetupLimiter struct {
	describe, bundle, enroll windowCounter
}

func throttleMachineSetup(step string, counter *windowCounter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !counter.allow(c.ClientIP(), machineSetupPerMinute, time.Minute, time.Now().UTC()) {
			slog.Warn("machine setup step throttled", "step", step, "clientIp", c.ClientIP(), "requestId", requestID(c))
			problem(c, http.StatusTooManyRequests, "MACHINE_SETUP_RATE_LIMITED", "Too many enrollment attempts from this address; wait a minute and retry")
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---- 注册码 ----

// machineByEnrollmentCode 找注册码还能用的、待注册的机器。
func (d buildMachinesDoc) machineByEnrollmentCode(code string, now time.Time) (int, bool) {
	if !machinekey.ValidEnrollmentCode(code) {
		return -1, false
	}
	digest := sha256Hex(code)
	for i, m := range d.Machines {
		if m.Status == machineStatusPendingEnrollment && m.Enrollment != nil && m.Enrollment.CodeSHA256 == digest && m.Enrollment.usable(now) {
			return i, true
		}
	}
	return -1, false
}

func enrollmentCodeInvalid(c *gin.Context) {
	problem(c, http.StatusNotFound, "ENROLLMENT_CODE_INVALID",
		"This enrollment code is not valid: it may be mistyped, expired (60 minutes) or already used. Issue a new one for this machine in the console")
}

// enrollmentView 是新建与重发响应里的 enrollment：注册码原文、有效期、服务端拼好的安装命令。
func (s *server) enrollmentView(c *gin.Context, m buildMachine, code string) gin.H {
	origin := s.externalOrigin(c)
	if m.osOf() == machineOSDarwin {
		return gin.H{"code": code, "expiresAt": m.Enrollment.ExpiresAt, "installCommand": macOSInstallCommand(origin, code)}
	}
	command := "curl -fsSL " + origin + "/v1/machine-setup/install.sh | sudo bash -s -- --server " + origin + " --code " + code
	if m.Role == machineRoleSigner {
		// 恢复公钥指纹由运维从密码管理器粘贴，不取控制台的值：签名闸要 pin 的正是"服务端说了不算"的那把
		command += " --recovery-sha256 <从密码管理器粘贴恢复公钥指纹>"
	}
	return gin.H{"code": code, "expiresAt": m.Enrollment.ExpiresAt, "installCommand": command}
}

// macOSInstallCommand 是 Mac 打包机的装机命令（设计 §4.5）。
//
// 它**不是**一条 `curl … | sudo bash`：首次装机是一次对服务端的信任，而这台机器将要
// 持有全部租户的签名材料。脚本先落地、由人按带外渠道核对它的摘要，再执行；三个 sha256
// 参数（安装包归档、发布公钥、allowed_signers）都是尖括号占位——它们的正确值在 CI 日志
// 和密码管理器里，控制台替人填等于让这台 Mac 把服务端说的话当成信任根。
func macOSInstallCommand(origin, code string) string {
	return strings.Join([]string{
		"curl -fsSLo install-macos.sh " + origin + "/v1/machine-setup/install-macos.sh",
		"shasum -a 256 install-macos.sh   # 与 CI「Build machine bundles」那一步打印的值比对",
		"sudo bash install-macos.sh --server " + origin + " --code " + code + " \\",
		"     --expect-sha256 <从 CI 日志粘贴 builder-darwin-arm64.tar.gz 的 sha256> \\",
		"     --release-key-sha256 <从密码管理器粘贴发布公钥指纹> \\",
		"     --allowed-signers-sha256 <从密码管理器粘贴 allowed_signers 指纹>",
	}, "\n")
}

// externalOrigin 是这次请求的外部源（scheme://host）。https 的判据：TLS 直连；或直连对端是
// TRUSTED_PROXIES 里的代理且它说 X-Forwarded-Proto: https；生产环境一律 https（与 absoluteURL 一致）。
// 不可信来源自报的 X-Forwarded-Proto 不采信。
func (s *server) externalOrigin(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || s.cfg.Environment == "production" ||
		(strings.EqualFold(strings.TrimSpace(c.GetHeader("x-forwarded-proto")), "https") && s.fromTrustedProxy(c)) {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

func (s *server) fromTrustedProxy(c *gin.Context) bool {
	peer := net.ParseIP(c.RemoteIP())
	if peer == nil {
		return false
	}
	for _, entry := range s.cfg.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(peer) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil && ip.Equal(peer) {
			return true
		}
	}
	return false
}

// ---- 安装包 ----

// machineBundleBuilderDarwin 是 Mac 打包机那一组安装包的名字。归档名与它一致
// （builder-darwin-arm64.tar.gz）。
//
// Apple Silicon 是唯一被支持的 Mac 架构：Intel Mac 跑不了新版 Xcode，而这条链路的前提
// 就是一台能装当前 Xcode 的机器。真要支持 x86_64 时再加一个并列的名字，不要把架构
// 从名字里抹掉——运维核对 sha256 时要能一眼看出自己下的是哪一个。
const machineBundleBuilderDarwin = "builder-darwin-arm64"

type machineBundleFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type machineBundle struct {
	Archive       string              `json:"archive"`
	ArchiveSHA256 string              `json:"archiveSha256"`
	ArchiveSize   int64               `json:"archiveSize"`
	Files         []machineBundleFile `json:"files"`
}

type machineBundleManifestDoc struct {
	Format  string                   `json:"format"`
	Commit  string                   `json:"commit"`
	Bundles map[string]machineBundle `json:"bundles"`
}

// machineBundles 读当前安装包目录。current 是被原子切换的软链：先解析成真实目录，清单与归档都从
// 同一个目录读，切换发生在两次读之间也不会拿到"新清单 + 旧归档"。
func (s *server) machineBundles() (string, machineBundleManifestDoc, error) {
	var doc machineBundleManifestDoc
	dir := s.machineBundleDir
	if dir == "" {
		dir = defaultMachineBundleDir
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", doc, err
	}
	raw, err := os.ReadFile(filepath.Join(resolved, machineBundleManifest))
	if err != nil {
		return "", doc, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return "", doc, fmt.Errorf("%s is malformed: %w", machineBundleManifest, err)
	}
	if doc.Format != machineBundleManifestFormat || !bundleCommitPattern.MatchString(doc.Commit) {
		return "", doc, fmt.Errorf("%s has an unexpected format or commit", machineBundleManifest)
	}
	return resolved, doc, nil
}

// bundleFor 取某个角色的安装包清单并校验形状。
func (doc machineBundleManifestDoc) bundleFor(role string) (machineBundle, error) {
	bundle, ok := doc.Bundles[role]
	switch {
	case !ok:
		return bundle, fmt.Errorf("%s has no %s bundle", machineBundleManifest, role)
	case bundle.Archive != role+".tar.gz" || !fingerprint.Valid(bundle.ArchiveSHA256) || bundle.ArchiveSize < 1:
		return bundle, fmt.Errorf("%s bundle %s has a malformed archive entry", machineBundleManifest, role)
	case len(bundle.Files) == 0 || len(bundle.Files) > maxMachineBundleFiles:
		return bundle, fmt.Errorf("%s bundle %s lists no files or too many", machineBundleManifest, role)
	}
	for _, file := range bundle.Files {
		if !validBundleFileName(file.Name) || file.Size < 0 || !fingerprint.Valid(file.SHA256) {
			return bundle, fmt.Errorf("%s bundle %s lists a malformed file", machineBundleManifest, role)
		}
	}
	return bundle, nil
}

func bundleUnavailable(c *gin.Context, role string, err error) {
	slog.Error("machine bundle is unavailable", "role", role, "error", err)
	problem(c, http.StatusServiceUnavailable, "MACHINE_BUNDLE_UNAVAILABLE",
		"The installation bundle for this machine role is not available on the server; deploy the machine bundles and retry")
}

// ---- 接口 ----

// machineInstallScript GET /v1/machine-setup/install.sh：原样下发嵌进服务端二进制的安装脚本。
func (s *server) machineInstallScript(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/x-shellscript; charset=utf-8", machinesetup.InstallScript)
}

// machineInstallMacOSScript GET /v1/machine-setup/install-macos.sh：Mac 打包机那一份。
//
// 单独一条路由而不是按 User-Agent 分：装机的人要能先把脚本下下来、与 CI 日志里的 sha256
// 核对过再执行（§4.5 第一步）。一条会按请求方变内容的地址核对不了。
func (s *server) machineInstallMacOSScript(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/x-shellscript; charset=utf-8", machinesetup.InstallMacOSScript)
}

type enrollmentCodeBody struct {
	Code string `json:"code"`
}

// describeEnrollment POST /v1/machine-setup/describe：按注册码说出这台机器是谁、该装哪个安装包。
// 不消耗注册码。
func (s *server) describeEnrollment(c *gin.Context) {
	var body enrollmentCodeBody
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_ENROLLMENT_REQUEST", "Request body must be {\"code\": \"rne_…\"}")
		return
	}
	ctx := c.Request.Context()
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		slog.Error("machine registry is unavailable", "error", err)
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	index, ok := registry.machineByEnrollmentCode(strings.TrimSpace(body.Code), time.Now().UTC())
	if !ok {
		enrollmentCodeInvalid(c)
		return
	}
	m := registry.Machines[index]
	_, manifest, err := s.machineBundles()
	if err != nil {
		bundleUnavailable(c, m.Role, err)
		return
	}
	// 装哪一组包由登记里的 os 决定：Mac 打包机要的是 darwin/arm64 那一组
	bundleName := m.bundleName()
	bundle, err := manifest.bundleFor(bundleName)
	if err != nil {
		bundleUnavailable(c, bundleName, err)
		return
	}
	response := gin.H{
		"machineId": m.ID, "name": m.Name, "role": m.Role, "os": m.osOf(),
		"signerRole": nullableString(string(m.SignerRole)),
		"bundle": gin.H{
			"role": bundleName, "commit": manifest.Commit, "archive": bundle.Archive, "archiveSha256": bundle.ArchiveSHA256,
			"archiveSize": bundle.ArchiveSize, "files": bundle.Files,
		},
		"recoveryKeys": []gin.H{}, "primarySigner": nil,
	}
	if m.Role == machineRoleSigner {
		recovery, err := readRecoveryKeys(ctx, s.db, false)
		if err != nil {
			slog.Error("cannot read the recovery keys", "error", err)
			problem(c, http.StatusServiceUnavailable, "RECOVERY_KEYS_UNAVAILABLE", "Recovery keys cannot be read")
			return
		}
		keys := []gin.H{}
		for _, key := range recovery.Doc.live() {
			keys = append(keys, gin.H{"name": key.Name, "x25519PublicKey": key.X25519PublicKey, "x25519PublicKeySha256": key.X25519PublicKeySHA256})
		}
		response["recoveryKeys"] = keys
		// 备签名闸在本机首次信任当前的主签名闸（用来验证它的生成签名）；主签名闸自己没有这一项
		if m.SignerRole == signerRoleStandby {
			if primary, ok := registry.activePrimary(); ok {
				response["primarySigner"] = signerPeerKeys(primary)
			}
		}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, response)
}

// signerPeerKeys 是一台签名闸已接受的两把公钥（给本机命令显示与首次信任；签名闸按本机粘贴的指纹核对）。
func signerPeerKeys(m buildMachine) gin.H {
	return gin.H{
		"machineId": m.ID, "name": m.Name,
		"x25519PublicKey": string(m.PublicKey), "x25519PublicKeySha256": string(m.PublicKeySHA256),
		"ed25519PublicKey": string(m.Ed25519PublicKey), "ed25519PublicKeySha256": string(m.Ed25519PublicKeySHA256),
	}
}

// downloadMachineBundle GET /v1/machine-setup/bundle/{role}.tar.gz：头 x-enrollment-code 必须是这台
// 机器还能用的注册码，只给这台机器角色的安装包。流式返回，按路由精确豁免数据库超时。
func (s *server) downloadMachineBundle(c *gin.Context) {
	archive := c.Param("archive")
	name := strings.TrimSuffix(archive, ".tar.gz")
	if name == archive || (name != machineRoleBuilder && name != machineRoleSigner && name != machineBundleBuilderDarwin) {
		problem(c, http.StatusNotFound, "MACHINE_BUNDLE_NOT_FOUND",
			"Bundles are signer.tar.gz, builder.tar.gz and "+machineBundleBuilderDarwin+".tar.gz")
		return
	}
	// 这条路由整体豁免了数据库超时（流式下载），查登记这一步自己带上超时
	lookup, cancel := context.WithTimeout(c.Request.Context(), time.Duration(max(s.cfg.MySQLQueryTimeout, 1))*time.Second)
	registry, err := s.machineRegistry(lookup)
	cancel()
	if err != nil {
		slog.Error("machine registry is unavailable", "error", err)
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	index, ok := registry.machineByEnrollmentCode(strings.TrimSpace(c.GetHeader(enrollmentCodeHeader)), time.Now().UTC())
	if !ok {
		enrollmentCodeInvalid(c)
		return
	}
	// 按注册码那台机器**该装的那一组**核对，不只核对角色：一台登记成 macOS 的机器
	// 下 linux 那一组，只会在第一次启动时以"这不是本机架构的可执行文件"失败，
	// 而那条错误读起来完全不像"下错了包"
	if registry.Machines[index].bundleName() != name {
		problem(c, http.StatusForbidden, "MACHINE_ROLE_FORBIDDEN",
			"This enrollment code belongs to a machine that installs another bundle")
		return
	}
	dir, manifest, err := s.machineBundles()
	if err != nil {
		bundleUnavailable(c, name, err)
		return
	}
	bundle, err := manifest.bundleFor(name)
	if err != nil {
		bundleUnavailable(c, name, err)
		return
	}
	file, err := os.Open(filepath.Join(dir, bundle.Archive))
	if err != nil {
		bundleUnavailable(c, name, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != bundle.ArchiveSize {
		bundleUnavailable(c, name, errors.New("the archive is missing, not a regular file, or its size differs from the manifest"))
		return
	}
	// sha256 在清单里（describe 已经给了），安装脚本下载后自己算、对不上拒绝安装
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
	c.Header("Content-Disposition", `attachment; filename="`+bundle.Archive+`"`)
	c.Header("x-content-sha256", bundle.ArchiveSHA256)
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, file); err != nil {
		slog.Error("machine bundle download stream failed", "bundle", name, "error", err)
	}
}

// enrollMachine POST /v1/machine-setup/enroll：消耗注册码、挂上待接受的公钥、签发长期机器令牌。
//
// 核对与消耗在同一个写事务里（锁住 build.machines 那一行）：同一个注册码并发注册只有一个成功，
// 另一个读到的已经是"已用"。令牌只在这个响应里出现一次，只存 sha256，不进审计与日志。
func (s *server) enrollMachine(c *gin.Context) {
	var body struct {
		Code             string  `json:"code"`
		X25519PublicKey  *string `json:"x25519PublicKey"`
		Ed25519PublicKey string  `json:"ed25519PublicKey"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_ENROLLMENT_REQUEST", "code, x25519PublicKey (null for builders) and ed25519PublicKey are required")
		return
	}
	code := strings.TrimSpace(body.Code)
	if !machinekey.ValidEnrollmentCode(code) {
		enrollmentCodeInvalid(c)
		return
	}
	signing, okSigning := decodeMachinePublicKey(body.Ed25519PublicKey)
	if !okSigning {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "ed25519PublicKey must be the standard base64 of a 32-byte public key")
		return
	}
	var x25519 []byte
	if body.X25519PublicKey != nil {
		var ok bool
		if x25519, ok = decodeMachinePublicKey(*body.X25519PublicKey); !ok {
			problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "x25519PublicKey must be the standard base64 of a 32-byte public key, or null for a builder")
			return
		}
	}
	token, err := newMachineToken()
	if err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to issue a machine token")
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to enroll this machine")
		return
	}
	defer tx.Rollback()
	snapshot, err := readMachineRegistry(ctx, tx, true)
	if err != nil {
		slog.Error("cannot read the machine registry", "error", err)
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	now := time.Now().UTC()
	index, ok := snapshot.Doc.machineByEnrollmentCode(code, now)
	if !ok {
		enrollmentCodeInvalid(c)
		return
	}
	m := &snapshot.Doc.Machines[index]
	// 构建机只有一把 Ed25519 出处公钥（记进 publicKey）；签名闸两把都要：X25519 收件人 + Ed25519 记录签名
	var key reportedMachineKey
	switch {
	case m.Role == machineRoleBuilder && x25519 != nil:
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "A builder has a single Ed25519 provenance key: send it as ed25519PublicKey and x25519PublicKey as null")
		return
	case m.Role == machineRoleBuilder:
		key = reportedMachineKey{primary: signing, primarySHA256: fingerprint.SHA256Hex(signing)}
	case x25519 == nil:
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "A signer enrolls with both x25519PublicKey and ed25519PublicKey")
		return
	default:
		key = reportedMachineKey{primary: x25519, primarySHA256: fingerprint.SHA256Hex(x25519), ed25519: signing, ed25519SHA256: fingerprint.SHA256Hex(signing)}
	}
	if other, taken := snapshot.Doc.keyInUse(m.ID, key.primarySHA256, key.ed25519SHA256); taken {
		problem(c, http.StatusConflict, "MACHINE_KEY_IN_USE", "Machine "+other+" already uses this key")
		return
	}
	m.Status = machineStatusPendingKey
	m.TokenSHA256 = sha256Hex(token)
	m.Enrollment.UsedAt = optString(iso(now))
	m.Pending = &machinePendingKey{PublicKey: base64.StdEncoding.EncodeToString(key.primary), PublicKeySHA256: key.primarySHA256, ReportedAt: iso(now)}
	if key.ed25519 != nil {
		m.Pending.Ed25519PublicKey = optString(base64.StdEncoding.EncodeToString(key.ed25519))
		m.Pending.Ed25519PublicKeySHA256 = optString(key.ed25519SHA256)
	}
	enrolled := *m
	applied, err := writeMachineRegistry(ctx, tx, snapshot.Doc, snapshot.Version, machineSetupActor, now)
	if err != nil || !applied {
		// 带锁读之后版本不会变；走到这里是库出了问题
		slog.Error("cannot record a machine enrollment", "machineId", enrolled.ID, "applied", applied, "error", err)
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to enroll this machine")
		return
	}
	// 审计记机器身份、报上来的公钥指纹与来源地址，不记令牌、令牌 sha256 与注册码
	event := newAudit(platformTenantID, machineSetupActor, "machine_enrolled", machineAuditTargetType, enrolled.ID,
		"a machine enrolled with its one-time enrollment code", requestID(c),
		map[string]any{"machineId": enrolled.ID, "role": enrolled.Role, "name": enrolled.Name, "signerRole": nullableString(string(enrolled.SignerRole)),
			"publicKeySha256": key.primarySHA256, "ed25519PublicKeySha256": nullableString(key.ed25519SHA256), "clientIp": c.ClientIP()})
	if err := insertAudit(ctx, tx, event); err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to enroll this machine")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to enroll this machine")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"machineId": enrolled.ID, "token": token, "status": enrolled.Status})
}
