package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Helix2010/RN-Server/internal/chain"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/mod/semver"
)

type server struct {
	cfg      config.Config
	db       *sql.DB
	mu       sync.Mutex
	attempts map[string]attempt
	objects  objectstore.Factory
	tenant   *tenantResolver
	secrets  *secretbox.Box
	// tokens 只从平台默认端点读代币元数据；测试用假实现替换
	tokens tokenMetadataReader
	// verifyFCM 真去 Google 换一次访问令牌。做成字段是因为保存推送凭据这条路
	// **必须**联网验证（见 pushcreds.Verify 的注释），而测试不该联网。
	verifyFCM func(context.Context, pushcreds.ServiceAccount) error
	// adminIPs 限制 x-admin-key 自动化通道的来源；nil = 未配置，不限制
	adminIPs *ipAllowlist
	// diagnosticIPs 是一键上报按来源 IP 的小时窗口计数；零值可用
	diagnosticIPs diagnosticIPLimiter
}

type attempt struct {
	Failures int
	ResetsAt time.Time
}

type release struct {
	ID              string              `json:"id"`
	Platform        string              `json:"platform"`
	Version         string              `json:"version"`
	BuildNumber     int                 `json:"buildNumber"`
	RuntimeVersion  string              `json:"runtimeVersion"`
	Status          string              `json:"status"`
	ReleaseNotes    map[string][]string `json:"releaseNotes"`
	FileName        *string             `json:"fileName"`
	ContentType     *string             `json:"contentType"`
	ExpectedSize    *int64              `json:"expectedSize"`
	FileSize        *int64              `json:"fileSize"`
	SHA256          *string             `json:"sha256"`
	FileMetadata    map[string]any      `json:"fileMetadata"`
	RejectionReason *string             `json:"rejectionReason"`
	// Mandatory 表示这一版上线后用户不可跳过
	Mandatory   bool    `json:"mandatory"`
	VerifiedAt  *string `json:"verifiedAt"`
	PublishedAt *string `json:"publishedAt"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
	LastAction  *string `json:"lastAction"`
	// CanaryInstallations 是灰度名单；只有 status='canary' 的记录会带上它，
	// 其它状态下这一列即使有残留值也不该被当成"生效中的范围"
	CanaryInstallations []string `json:"canaryInstallations,omitempty"`
}

type simplifiedActiveRelease struct {
	ID           string
	Version      string
	ReleaseNotes map[string][]string
	SHA256       *string
	FileSize     *int64
	// Mandatory 表示这个版本不可跳过
	Mandatory bool
	// Status 是 active 或 canary：拿到灰度版本时客户端要知道自己在灰度里
	Status string
	// SignerSHA256 是入库时记下的签名证书指纹（`file_metadata.signerSha256`）。
	// 2026-09-10 之前入库的记录没有这个键，取到空串，调用方按"不知道"处理。
	SignerSHA256 string
}

type auditEvent struct {
	ID         string         `json:"id"`
	ActorID    string         `json:"actorId"`
	Action     string         `json:"action"`
	TargetType string         `json:"targetType"`
	TargetID   string         `json:"targetId"`
	Reason     string         `json:"reason"`
	RequestID  string         `json:"requestId"`
	CreatedAt  string         `json:"createdAt"`
	Summary    map[string]any `json:"summary"`
	TenantID   string         `json:"tenantId"`
}

func New(cfg config.Config, storage *store.Store) http.Handler {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	box, _ := secretbox.New(cfg.StorageMasterKey)
	// 配了 IP 白名单却没配可信代理，白名单就是装饰——来源地址整个是请求方说了算。
	// 这种情况下不要"尽力而为"地启动，否则运维会以为这件事做完了（安全评审 N17）。
	if err := validateAdminIPConfiguration(cfg.AdminAPIAllowedIPs, cfg.TrustedProxies); err != nil {
		panic(err)
	}
	allowlist, err := parseIPAllowlist(cfg.AdminAPIAllowedIPs)
	if err != nil {
		panic(err)
	}
	s := &server{cfg: cfg, db: storage.DB, attempts: map[string]attempt{}, objects: objectstore.AWSFactory{}, tenant: newTenantResolver(storage.DB), secrets: box, tokens: chain.NewReader(nil), adminIPs: allowlist, verifyFCM: pushcreds.Verify}
	r := gin.New()
	// 不配就谁都不信：ClientIP 取直连对端，而不是任何人都能写的 X-Forwarded-For。
	// 这同时让下面的登录限流按真实来源计数（在此之前它也是可绕过的）。
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		panic(err)
	}
	r.Use(gin.Recovery(), s.requestContext(), s.databaseTimeout(), s.securityHeaders(), s.cors())
	r.GET("/health/live", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "live"}) })
	r.GET("/health/ready", s.ready)
	r.GET("/openapi.json", func(c *gin.Context) { c.File("contracts/openapi.json") })
	r.GET("/docs", s.docs)
	r.GET("/v1/mobile/bootstrap", s.bootstrap)
	r.POST("/v1/mobile/installations/heartbeat", s.domainTenantScope(), s.installationHeartbeat)
	r.POST("/v1/mobile/installations/register", s.domainTenantScope(), s.registerInstallation)
	r.POST("/v1/mobile/push-tokens", s.domainTenantScope(), s.registerPushToken)
	// 一键上报：先元数据拿参考号，再传日志正文（设计 diagnostic-report-2026-09-14）
	r.POST("/v1/mobile/diagnostics/reports", s.domainTenantScope(), s.createDiagnosticReport)
	r.PUT("/v1/mobile/diagnostics/reports/:reportId/log", s.domainTenantScope(), s.uploadDiagnosticLog)
	r.POST("/v1/mobile/auth/nonce", s.domainTenantScope(), s.walletAuthNonce)
	r.POST("/v1/mobile/auth/verify", s.domainTenantScope(), s.walletAuthVerify)
	r.GET("/v1/mobile/auth/session", s.domainTenantScope(), s.walletAuthSession)
	r.POST("/v1/mobile/auth/logout", s.domainTenantScope(), s.walletAuthLogout)
	r.GET("/v1/mobile/wallet/transfers", s.domainTenantScope(), s.walletTransfers)
	r.GET("/v1/mobile/languages/:languageCode/document", s.mobileLanguageDocument)
	r.GET("/v1/mobile/branding/assets/:id", s.domainTenantScope(), s.brandingAsset)
	r.GET("/v1/ota/manifest", s.domainTenantScope(), s.otaManifest)
	r.GET("/v1/ota/assets/:id/*path", s.domainTenantScope(), s.otaAsset)
	// Android App Links 的域名归属声明（安全评审 N13）。系统会匿名来拉它，
	// 所以放在公开路由上，按 Host 解析租户。
	r.GET("/.well-known/assetlinks.json", s.domainTenantScope(), s.wellKnownAssetLinks)
	// Apple 要求这个文件没有 .json 后缀，且必须直出 application/json
	r.GET("/.well-known/apple-app-site-association", s.domainTenantScope(), s.wellKnownAppleAppSiteAssociation)
	r.GET("/v1/public/releases/latest", s.domainTenantScope(), s.publicLatestReleaseFromDomain)
	// 固定下载入口：二维码、官网链接、群公告贴一次就不用再换。发布 ID 每发一版都变，
	// 这条路由内部按同一套可见性挑出"现在该给你的那一版"再 302 过去。
	r.GET("/v1/public/releases/latest/download", s.domainTenantScope(), s.publicLatestReleaseDownload)
	r.GET("/v1/public/releases/:id/download", s.domainTenantScope(), s.publicReleaseDownload)
	admin := r.Group("/v1/admin")
	admin.POST("/auth/login", s.login)
	protected := admin.Group("")
	protected.Use(s.authenticate())
	protected.GET("/auth/session", s.session)
	protected.POST("/auth/logout", s.logout)
	// 平台级路由：不按租户过滤，只对 PLATFORM_ADMIN_USERNAMES 里的账号开放
	platform := protected.Group("/platform")
	platform.Use(s.requirePlatformAdmin())
	// 打包机公钥是平台级的一把，不属于任何租户；换它要人核对指纹后接受
	platform.GET("/build-agent/public-key", s.getBuildAgentKey)
	platform.POST("/build-agent/public-key/accept", s.acceptBuildAgentKey)
	platform.POST("/password-hash", s.generateAdminPasswordHash)
	// 平台默认的推送凭据：所有没单独配的租户都继承它，所以改它和删它是平台级动作
	platform.PUT("/push/credentials/fcm", s.updatePlatformPushCredentialsFCM)
	platform.DELETE("/push/credentials/fcm", s.deletePlatformPushCredentialsFCM)
	platform.GET("/scan/chains", s.scanChains)
	platform.PUT("/scan/chains/:chain", s.saveScanChain)
	platform.POST("/scan/chains/:chain/probe", s.probeScanChain)
	platform.POST("/scan/chains/:chain/pause", s.toggleScanChain(true))
	platform.POST("/scan/chains/:chain/resume", s.toggleScanChain(false))
	platform.POST("/scan/chains/:chain/jobs", s.createScanJob)
	platform.POST("/scan/chains/:chain/jobs/:id/cancel", s.cancelScanJob)
	platform.GET("/scan/transfers", s.scanTransfers)
	platform.GET("/wallet/lookup", s.platformWalletLookup)
	platform.GET("/devices/:id", s.platformDeviceLookup)
	platform.GET("/wallet/blocks", s.listPlatformWalletBlocks)
	platform.POST("/wallet/blocks", s.createPlatformWalletBlock)
	platform.POST("/wallet/blocks/:id/revoke", s.revokePlatformWalletBlock)
	// 打包机代理通道：与管理端**完全分开**的一条凭据，也不按域名解析租户——
	// 任务里带着租户，代理本来就跨租户工作。一台构建机被拿下时，拿到的应该只是
	// 构建队列，不是整个管理面。
	agent := r.Group("/v1/build-agent")
	agent.Use(s.buildAgentAuth())
	agent.POST("/claim", s.claimBuildJob)
	// 封装口令只在打包机上，所以只有它能回答"这个盒子开不开得了"（见
	// build_keystore_check.go）
	// 打包机启动时登记自己的公钥；签名密钥从此加密给它，没有人需要敲封装口令
	agent.POST("/public-key", s.registerBuildAgentKey)
	agent.GET("/keystore-checks", s.pendingKeystoreChecks)
	agent.POST("/keystore-checks", s.reportKeystoreCheck)
	// 图标一张一张取，不塞进领取响应——那条响应在代理那边有 1 MiB 上限，
	// 真图标（2048 见方，四张 3.8MB）会把它截断成半截 JSON
	agent.GET("/jobs/:id/icons/:name", s.buildAgentJobScope(s.buildJobIcon))
	agent.POST("/jobs/:id/heartbeat", s.buildJobHeartbeat)
	// 走任务作用域是为了拿到 kind：热更新任务的产物 id 要落到 ota_release_id
	agent.POST("/jobs/:id/complete", s.buildAgentJobScope(s.completeBuildJob))
	agent.POST("/jobs/:id/fail", s.failBuildJob)
	// 产物回传：三条都先用任务把租户定下来，再交给与人工上传完全相同的处理函数
	agent.POST("/jobs/:id/artifact-uploads", s.buildAgentJobScope(s.createReleaseArtifactUpload))
	agent.PUT("/jobs/:id/artifact", s.buildAgentJobScope(s.uploadReleaseArtifact))
	agent.POST("/jobs/:id/release", s.buildAgentJobScope(s.buildAgentReleaseFromArtifact))
	// 热更新包：票据与修订都取任务行上的参数，代理不带 base / channel / 生效方式
	agent.POST("/jobs/:id/ota-uploads", s.buildAgentJobScope(s.buildJobOTAUpload))
	agent.PUT("/jobs/:id/ota-artifact", s.buildAgentJobScope(s.uploadOTAArtifact))
	agent.POST("/jobs/:id/ota-release", s.buildAgentJobScope(s.buildJobOTARelease))
	current := protected.Group("")
	current.Use(s.domainTenantScope())
	current.GET("/tenant", s.currentTenant)
	s.registerTenantRoutes(current)
	return r
}

func (s *server) currentTenant(c *gin.Context) {
	item, ok := c.Get("tenant")
	if !ok {
		problem(c, 404, "TENANT_NOT_FOUND", "Tenant not found")
		return
	}
	c.JSON(200, gin.H{"tenant": item})
}

func (s *server) registerTenantRoutes(group *gin.RouterGroup) {
	group.GET("/overview", s.overview)
	group.GET("/installations/overview", s.installationOverview)
	group.GET("/installations", s.listInstallations)
	group.GET("/installations/:id", s.installationDetail)
	group.POST("/installations/:id/revoke", s.revokeInstallation)
	// 一键上报（设计 diagnostic-report-2026-09-14 §5.8）。按安装实例查用列表的 installationId 筛选，不另开接口
	group.GET("/diagnostics/reports", s.listDiagnosticReports)
	group.GET("/diagnostics/reports/:id", s.diagnosticReportDetail)
	group.GET("/diagnostics/reports/:id/log", s.diagnosticReportLog)
	group.GET("/diagnostics/reports/:id/log/raw", s.diagnosticReportRawLog)
	group.POST("/diagnostics/reports/:id/status", s.updateDiagnosticReportStatus)
	group.DELETE("/diagnostics/reports/:id", s.deleteDiagnosticReports)
	group.POST("/diagnostics/reports/bulk-delete", s.deleteDiagnosticReports)
	group.GET("/wallet/users", s.listWalletUsers)
	group.GET("/wallet/users/:id", s.walletUserDetail)
	group.POST("/wallet/users/:id/block", s.blockWalletUser(true))
	group.POST("/wallet/users/:id/unblock", s.blockWalletUser(false))
	group.POST("/wallet/sessions/:id/revoke", s.revokeWalletSession)
	group.GET("/push/outbox", s.listPushOutbox)
	group.GET("/push/deliveries", s.listPushDeliveries)
	group.GET("/releases", s.listReleases)
	group.POST("/releases", s.createReleaseFromArtifact)
	group.GET("/releases/:id", s.releaseDetail)
	group.POST("/releases/:id/:action", s.releaseAction)
	// 清理历史产物。不是状态迁移：发布记录一旦删掉就不在升级决策里了，所以正在下发的
	// 版本删不掉，且必须先清掉建在它上面的 OTA。见 release_purge.go
	group.DELETE("/releases/:id", s.purgeRelease)
	group.GET("/audit-events", s.listAudits)
	group.GET("/wallet/index-status", s.tenantIndexStatus)
	group.GET("/app-config", s.getAppConfig)
	group.PATCH("/app-config", s.updateAppConfig)
	group.POST("/predict/probe", s.probePredictService)
	group.GET("/branding", s.getBranding)
	group.PATCH("/branding", s.updateBranding)
	group.GET("/tokens", s.listTokens)
	group.POST("/tokens/preview", s.previewToken)
	group.POST("/tokens", s.createToken)
	group.PATCH("/tokens/:id", s.patchToken)
	group.POST("/tokens/:id/resync", s.resyncToken)
	group.DELETE("/tokens/:id", s.deleteToken)
	group.GET("/localization", s.getLocalization)
	group.PUT("/localization/languages", s.updateLocalizationLanguages)
	group.PUT("/localization/documents", s.updateLocalizationDocuments)
	group.POST("/localization/publish", s.publishLocalization)
	group.GET("/release-storage", s.getReleaseStorage)
	group.PUT("/release-storage", s.updateReleaseStorage)
	group.GET("/release-storage/cors", s.bucketCORSRequirements)
	group.POST("/release-storage/test", s.testReleaseStorage)
	group.GET("/release-identity/android", s.getAndroidReleaseIdentity)
	group.PUT("/release-identity/android", s.updateAndroidReleaseIdentity)
	group.GET("/release-identity/ios", s.getIOSReleaseIdentity)
	group.PUT("/release-identity/ios", s.updateIOSReleaseIdentity)
	group.GET("/ota/signing-key", s.getOTASigningKey)
	group.PUT("/ota/signing-key", s.updateOTASigningKey)
	group.POST("/ota/signing-key/generate", s.generateOTASigningKey)
	// bootstrap 响应签名（N3）。与 OTA 那把分开：共用一把等于把两个信任域焊在一起。
	group.GET("/bootstrap/signing-key", s.getBootstrapSigningKey)
	group.POST("/bootstrap/signing-key/generate", s.generateBootstrapSigningKey)
	group.GET("/builds", s.listBuildJobs)
	group.POST("/builds", s.createBuildJob)
	group.GET("/builds/:id", s.buildJobDetail)
	group.POST("/builds/:id/cancel", s.cancelBuildJob)
	// 服务端合成的 tenant.json：打包任务下发的是同一份。构建 OTA 的人要拿它，
	// 仓库里那份早就不是权威来源了（见 app_identity.go）
	group.GET("/app-identity", s.getAppIdentity)
	group.GET("/build-config", s.getBuildConfig)
	group.PUT("/build-config", s.saveBuildConfig)
	// 启动图标：租户自己维护，随任务下发，不再放在 App 仓库里
	group.GET("/build-icons", s.getBuildIcons)
	group.GET("/build-icons/:name", s.getBuildIcon)
	// 一张一个请求。四张一起发的话，请求体要按"四张都取满"来放上限，那是 33 MB
	// 的 JSON——为了一张 600 KB 的图给每个请求留那么大的口子不值得。
	group.PUT("/build-icons/:name", s.updateBuildIcon)
	group.DELETE("/build-icons/:name", s.deleteBuildIcon)
	// 推送凭据：google-services.json 的服务端另一半，所以挨着 build-config 放。
	// 两者必须属于同一个 Firebase 项目，视图里直接给出比对结果。
	group.GET("/push/credentials", s.getPushCredentials)
	group.PUT("/push/credentials/fcm", s.updatePushCredentialsFCM)
	group.DELETE("/push/credentials/fcm", s.deletePushCredentialsFCM)
	group.POST("/push/credentials/fcm/test", s.testPushCredentialsFCM)
	group.GET("/build-keystore", s.getBuildKeystore)
	group.PUT("/build-keystore", s.saveBuildKeystore)
	// 在服务端生成签名密钥。它不削弱"服务端打不开已存密钥"这条性质——生成出来
	// 立刻用管理员的封装口令封盒，明文只在这一次响应里回给浏览器。
	group.POST("/build-keystore/generate", s.generateBuildKeystore)
	group.POST("/release-artifacts/uploads", s.createReleaseArtifactUpload)
	group.PUT("/release-artifacts/upload", s.uploadReleaseArtifact)
	group.DELETE("/release-artifacts/upload", s.deleteReleaseArtifact)
	group.GET("/ota/base-releases", s.listOTABaseReleases)
	group.GET("/ota/releases", s.listOTAReleases)
	group.GET("/ota/releases/:id", s.otaReleaseDetail)
	group.POST("/ota/artifacts/uploads", s.createOTAUploader)
	group.PUT("/ota/artifacts/upload", s.uploadOTAArtifact)
	group.DELETE("/ota/artifacts/upload", s.deleteOTAArtifact)
	group.POST("/ota/releases", s.saveOTARelease)
	group.POST("/ota/releases/:id/:action", s.otaAction)
	group.DELETE("/ota/releases/:id", s.purgeOTARelease)
	group.POST("/upload-sessions", s.createUploadSession)
	group.POST("/upload-sessions/cleanup-expired", s.cleanupExpiredUploadSessions)
	group.GET("/upload-sessions/:id", s.getUploadSession)
	group.PUT("/upload-sessions/:id/parts/:partNumber", s.uploadSessionPart)
	group.POST("/upload-sessions/:id/parts/:partNumber/presign", s.presignUploadSessionPart)
	group.POST("/upload-sessions/:id/complete", s.completeUploadSession)
	group.DELETE("/upload-sessions/:id", s.cancelUploadSession)
	group.POST("/branding/assets/uploads", s.createBrandingAssetUpload)
	group.PUT("/branding/assets/upload", s.uploadBrandingAsset)
	group.DELETE("/branding/assets/upload", s.deleteBrandingAsset)
}

func (s *server) domainTenantScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		item, err := s.tenant.resolve(c.Request.Context(), c.Request.Host)
		if err != nil {
			problem(c, 404, "TENANT_DOMAIN_NOT_FOUND", "Request domain is not mapped to an active tenant")
			c.Abort()
			return
		}
		c.Set("tenantId", item.ID)
		c.Set("tenant", item)
		c.Next()
	}
}

func (s *server) databaseTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		multipartPartUpload := c.Request.Method == http.MethodPut && strings.Contains(c.Request.URL.Path, "/v1/admin/upload-sessions/") && strings.Contains(c.Request.URL.Path, "/parts/")
		if strings.HasSuffix(c.Request.URL.Path, "/upload") || multipartPartUpload || strings.HasSuffix(c.Request.URL.Path, "/finalize") || strings.HasSuffix(c.Request.URL.Path, "/release-storage/test") || strings.HasSuffix(c.Request.URL.Path, "/download") || readsTokenChain(c.Request) {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.MySQLQueryTimeout)*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// readsTokenChain 识别要去链上读元数据的三个代币接口。它们跟 /release-storage/test
// 一样要等外部系统：最多五次 RPC、每次 5 秒，套在数据库超时里会被误杀。
func readsTokenChain(r *http.Request) bool {
	path := r.URL.Path
	return strings.HasSuffix(path, "/tokens/preview") ||
		(r.Method == http.MethodPost && strings.HasSuffix(path, "/tokens")) ||
		strings.HasSuffix(path, "/resync")
}

func (s *server) requestContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := strings.TrimSpace(c.GetHeader("x-request-id"))
		if requestID == "" {
			requestID = "req_" + randomID(12)
		}
		c.Set("requestId", requestID)
		c.Header("x-request-id", requestID)
		c.Next()
	}
}

func (s *server) securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

func (s *server) cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && s.originAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Expose-Headers", "ETag,X-Request-Id")
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS")
			c.Header("Access-Control-Allow-Headers", "content-type,x-admin-key,x-admin-id,x-request-id,x-release-artifact-token,x-ota-artifact-token,x-branding-asset-token,x-upload-session-token,x-part-sha256,expo-platform,expo-runtime-version,expo-channel-name,expo-protocol-version,expo-expect-signature")
		}
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			c.Abort()
			return
		}
		c.Next()
	}
}

// originAllowed 先看配置里的白名单，再问租户域名表。
//
// 加一个租户原本要改 CORS_ORIGINS 并重启服务端——而那份名单和 tenant_domain 说的
// 是同一件事：哪些域名属于这个平台。两处维护迟早会漂，漏了就是控制台打不开而且
// 报错只体现为浏览器被 CORS 拦下，看不出是配置少了一行。
//
// 复用 tenantResolver 而不是另起一套查询：它本来就有 60s 正向缓存和 5s 负向缓存，
// 未知来源不会反复打数据库；租户域名改动时 invalidate 也已经接好了。
//
// 只认 https：这条通道会带上 Access-Control-Allow-Credentials，明文来源拿到凭证
// 等于把会话交给链路上任何人。
func (s *server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.CORSOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return s.originIsTenantDomain(origin)
}

func (s *server) originIsTenantDomain(origin string) bool {
	if s.tenant == nil {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	// Origin 头里不带路径；带了就不是一个正常的 Origin，不要猜
	if parsed.Path != "" || parsed.RawQuery != "" {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = s.tenant.resolve(ctx, host)
	return err == nil
}

func (s *server) ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		problem(c, 503, "NOT_READY", "Database is unavailable")
		return
	}
	c.JSON(200, gin.H{"status": "ready", "database": "mysql"})
}

func (s *server) docs(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(200, `<!doctype html><html><head><title>RN Foundation API</title></head><body><h1>RN Foundation API</h1><p><a href="/openapi.json">OpenAPI contract</a></p></body></html>`)
}

func (s *server) authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if cookie, err := c.Cookie("rn_admin_session"); err == nil && cookie != "" {
			hash := sha256Hex(cookie)
			var actor string
			var expires time.Time
			err := s.db.QueryRowContext(c.Request.Context(), `SELECT actor_id, expires_at FROM admin_sessions WHERE token_hash=? AND expires_at>? LIMIT 1`, hash, time.Now().UTC()).Scan(&actor, &expires)
			if err == nil {
				if !safeMethod(c.Request.Method) && !s.originAllowed(c.GetHeader("Origin")) {
					problem(c, 403, "UNTRUSTED_ORIGIN", "Untrusted admin request origin")
					c.Abort()
					return
				}
				c.Set("actorId", actor)
				c.Set("authMethod", "session")
				c.Set("expiresAt", iso(expires))
				c.Next()
				return
			}
		}
		// x-admin-key 自动化通道：身份来自配置里绑定的 actor，不是请求自报的 x-admin-id。
		// 自报身份任何持钥者都能随便写，写进 audit_events 的 actor 就成了攻击者可控的字段，
		// 事后追责等于没有依据（安全评审 N17）。请求仍然可以带那个头，只是不再被采纳。
		if key := c.GetHeader("x-admin-key"); s.cfg.AdminAPIKey != "" && constantEqual(key, s.cfg.AdminAPIKey) {
			// 密钥对了还要看来源：这把密钥长期有效、没有账号绑定，泄露之后
			// 唯一还能拦住它的就是"不是从我们的机器发出来的"（安全评审 N17）
			if !s.adminIPs.allows(c.ClientIP()) {
				slog.Warn("admin api key used from an address outside the allowlist", "clientIp", c.ClientIP(), "path", c.Request.URL.Path)
				problem(c, http.StatusForbidden, "ADMIN_SOURCE_NOT_ALLOWED", "This automation credential is not accepted from this address")
				c.Abort()
				return
			}
			if claimed := strings.TrimSpace(c.GetHeader("x-admin-id")); claimed != "" && claimed != s.cfg.AdminAPIActor {
				slog.Warn("ignoring self-declared admin identity on api-key request", "claimed", claimed, "actor", s.cfg.AdminAPIActor, "path", c.Request.URL.Path)
			}
			c.Set("actorId", s.cfg.AdminAPIActor)
			c.Set("authMethod", "api-key")
			c.Set("expiresAt", nil)
			c.Next()
			return
		}
		problem(c, 401, "ADMIN_AUTH_REQUIRED", "Admin authentication required")
		c.Abort()
	}
}

func (s *server) login(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(c, &input); err != nil || input.Username == "" || input.Password == "" || len(input.Password) > 1024 {
		problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	if s.rateLimited(c.ClientIP()) {
		problem(c, 429, "LOGIN_RATE_LIMITED", "Too many login attempts")
		return
	}
	valid := constantEqual(strings.TrimSpace(input.Username), s.cfg.AdminUsername) && verifyPassword(input.Password, s.cfg.AdminPasswordHash)
	if !valid {
		s.failedLogin(c.ClientIP())
		problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	s.mu.Lock()
	delete(s.attempts, c.ClientIP())
	s.mu.Unlock()
	token := randomID(32)
	now := time.Now().UTC()
	expires := now.Add(time.Duration(s.cfg.AdminSessionTTL) * time.Second)
	if _, err := s.db.ExecContext(c.Request.Context(), `INSERT INTO admin_sessions (token_hash,actor_id,expires_at,created_at) VALUES (?,?,?,?)`, sha256Hex(token), s.cfg.AdminUsername, expires, now); err != nil {
		problem(c, 500, "SESSION_CREATE_FAILED", "Unable to create admin session")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "rn_admin_session", Value: token, Path: "/v1/admin", MaxAge: s.cfg.AdminSessionTTL, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"authenticated": true, "platformAdmin": s.isPlatformAdmin(s.cfg.AdminUsername), "actorId": s.cfg.AdminUsername, "expiresAt": iso(expires), "method": "session"})
}

func (s *server) session(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"authenticated": true, "actorId": actor(c), "expiresAt": valueFrom(c, "expiresAt"), "method": valueFrom(c, "authMethod"), "platformAdmin": s.isPlatformAdmin(actor(c))})
}

func (s *server) logout(c *gin.Context) {
	if token, err := c.Cookie("rn_admin_session"); err == nil {
		_, _ = s.db.ExecContext(c.Request.Context(), `DELETE FROM admin_sessions WHERE token_hash=?`, sha256Hex(token))
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "rn_admin_session", Value: "", Path: "/v1/admin", MaxAge: -1, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	c.JSON(200, gin.H{"authenticated": false})
}

func (s *server) rateLimited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[ip]
	if !ok || time.Now().After(a.ResetsAt) {
		delete(s.attempts, ip)
		return false
	}
	return a.Failures >= s.cfg.AdminLoginMax
}
func (s *server) failedLogin(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attempts[ip]
	if time.Now().After(a.ResetsAt) {
		a = attempt{ResetsAt: time.Now().Add(time.Duration(s.cfg.AdminLoginWindow) * time.Second)}
	}
	a.Failures++
	s.attempts[ip] = a
}

func (s *server) listReleases(c *gin.Context) {
	releases, err := s.queryReleases(c.Request.Context(), tenantID(c), c.Query("platform"), c.Query("status"))
	if err != nil {
		problem(c, 500, "RELEASE_QUERY_FAILED", "Unable to load releases")
		return
	}
	c.JSON(200, gin.H{"items": releases, "nextCursor": nil, "hasMore": false})
}

func (s *server) queryReleases(ctx context.Context, tenant, platform, status string) ([]release, error) {
	query := `SELECT id,platform,version,build_number,runtime_version,status,canary_installations,release_notes,file_name,content_type,expected_size,file_size,sha256,file_metadata,rejection_reason,mandatory,verified_at,published_at,last_action,created_at,updated_at FROM app_releases WHERE tenant_id=? AND (?='' OR platform=?) AND (?='' OR status=?) ORDER BY build_number DESC, updated_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, tenant, platform, platform, status, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []release{}
	for rows.Next() {
		item, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanRelease(row scanner) (release, error) {
	var r release
	var notes, metadata, audience []byte
	var fileName, contentType, sha, rejection sql.NullString
	var expectedSize, fileSize sql.NullInt64
	var verifiedAt, publishedAt sql.NullTime
	var action sql.NullString
	var created, updated time.Time
	err := row.Scan(&r.ID, &r.Platform, &r.Version, &r.BuildNumber, &r.RuntimeVersion, &r.Status, &audience, &notes, &fileName, &contentType, &expectedSize, &fileSize, &sha, &metadata, &rejection, &r.Mandatory, &verifiedAt, &publishedAt, &action, &created, &updated)
	if err != nil {
		return r, err
	}
	if r.Status == "canary" {
		r.CanaryInstallations = canaryAudienceOf(audience)
	}
	_ = json.Unmarshal(notes, &r.ReleaseNotes)
	_ = json.Unmarshal(metadata, &r.FileMetadata)
	if fileName.Valid {
		r.FileName = &fileName.String
	}
	if contentType.Valid {
		r.ContentType = &contentType.String
	}
	if expectedSize.Valid {
		r.ExpectedSize = &expectedSize.Int64
	}
	if fileSize.Valid {
		r.FileSize = &fileSize.Int64
	}
	if sha.Valid {
		r.SHA256 = &sha.String
	}
	if rejection.Valid {
		r.RejectionReason = &rejection.String
	}
	r.CreatedAt = iso(created)
	r.UpdatedAt = iso(updated)
	if verifiedAt.Valid {
		v := iso(verifiedAt.Time)
		r.VerifiedAt = &v
	}
	if publishedAt.Valid {
		v := iso(publishedAt.Time)
		r.PublishedAt = &v
	}
	if action.Valid {
		r.LastAction = &action.String
	}
	return r, nil
}

func (s *server) releaseDetail(c *gin.Context) {
	r, err := s.findRelease(c.Request.Context(), tenantID(c), c.Param("id"))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "RELEASE_NOT_FOUND", "Release not found")
		return
	}
	if err != nil {
		problem(c, 500, "RELEASE_QUERY_FAILED", "Unable to load release")
		return
	}
	audits, _ := s.queryAudits(c.Request.Context(), tenantID(c), r.ID)
	c.JSON(200, gin.H{"release": r, "audits": audits})
}

func (s *server) findRelease(ctx context.Context, tenant, id string) (release, error) {
	return scanRelease(s.db.QueryRowContext(ctx, `SELECT id,platform,version,build_number,runtime_version,status,canary_installations,release_notes,file_name,content_type,expected_size,file_size,sha256,file_metadata,rejection_reason,mandatory,verified_at,published_at,last_action,created_at,updated_at FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id))
}

// transitions 是全量发布的状态机。灰度（canary）与 active 平行，两条主干互不干涉：
//
//	verified --publish--> active      verified --canary-------> canary
//	active   --pause----> paused      canary   --promote------> active
//	paused   --publish--> active      canary   --cancel-canary-> rejected
//
// publish / promote 都收尾同平台其它 active 行（那句 UPDATE 只扫 status='active'，
// 天然不会碰到灰度行）；转灰度不收尾任何东西。promote 与 publish 分开是为了审计能
// 看出"灰度转正"和"直接全量"的区别，不是状态机上的区别。
var transitions = map[string]map[string]string{
	"publish":       {"verified": "active", "paused": "active"},
	"pause":         {"active": "paused"},
	"canary":        {"verified": "canary"},
	"promote":       {"canary": "active"},
	"cancel-canary": {"canary": "rejected"},
}

// releaseFlagEditable 判断一个全量版本的"升级类型"（mandatory）现在还能不能改：
// 只有还会影响客户端升级决策的状态才允许——待发布、活跃、暂停。已被新版本取代
// （completed）或被拒绝 / 回滚的版本改了也不会有任何效果，直接拒绝，免得运营以为生效了。
func releaseFlagEditable(status string) bool {
	return status == "verified" || status == "active" || status == "paused"
}

func (s *server) releaseAction(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
		// set-mandatory 专用：目标值；其它动作忽略
		Mandatory *bool `json:"mandatory"`
		// canary / set-canary-audience 专用：灰度名单（installation_id）
		Installations []string `json:"installations"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "CONFIRMATION_REQUIRED", "reason and confirm=true are required")
		return
	}
	r, err := s.findRelease(c.Request.Context(), tenantID(c), c.Param("id"))
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Release not found")
		return
	}
	if c.Param("action") == "set-mandatory" {
		s.setReleaseMandatory(c, r, body.Mandatory, body.Reason)
		return
	}
	if c.Param("action") == "set-canary-audience" {
		s.setReleaseCanaryAudience(c, r, body.Installations, body.Reason)
		return
	}
	target, ok := transitions[c.Param("action")][r.Status]
	if !ok {
		problem(c, 409, "INVALID_TRANSITION", fmt.Sprintf("Cannot apply %s to %s", c.Param("action"), r.Status))
		return
	}
	if target == "active" || target == "canary" {
		var verified bool
		_ = s.db.QueryRowContext(c.Request.Context(), `SELECT object_key IS NOT NULL AND sha256 IS NOT NULL AND verified_at IS NOT NULL FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), r.ID).Scan(&verified)
		if !verified {
			problem(c, 409, "VERIFIED_ARTIFACT_REQUIRED", "The bound APK artifact is no longer publishable")
			return
		}
	}
	// 转灰度要一并写名单：空名单的灰度行对谁都不可见，允许它存在只会让运营以为发出去了
	audience := []string(nil)
	if target == "canary" {
		if r.Mandatory {
			// 强制升级影响的是全量用户的决策口径；只发给几台测试机的版本设它没有意义，
			// 而且 resolveUpdateDecision 会把它抬成所有人的最低版本
			problem(c, 409, "CANARY_MANDATORY_FORBIDDEN", "A mandatory release cannot be moved to canary; clear the mandatory flag first")
			return
		}
		var code, detail string
		if audience, code, detail = normalizeCanaryAudience(body.Installations); code != "" {
			problem(c, 422, code, detail)
			return
		}
		if code, detail := s.rejectUnknownCanaryInstallations(c, r.Platform, audience); code != "" {
			problem(c, 422, code, detail)
			return
		}
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	defer tx.Rollback()
	if target == "active" {
		_, _ = tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET status='completed',last_action='completed',updated_at=? WHERE tenant_id=? AND id<>? AND platform=? AND status='active'`, now, tenantID(c), r.ID, r.Platform)
	}
	// 名单只在灰度状态下有意义：转灰度写入，离开灰度（转正 / 取消）清空，
	// 免得一条 completed 记录上留着看起来还在生效的范围
	audienceValue, _ := json.Marshal(audience)
	if target != "canary" {
		audienceValue = nil
	}
	_, err = tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET status=?,canary_installations=?,last_action=?,updated_at=?,published_at=CASE WHEN ?='active' THEN ? ELSE published_at END WHERE tenant_id=? AND id=?`, target, audienceValue, c.Param("action"), now, target, now, tenantID(c), r.ID)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	summary := map[string]any{"version": r.Version, "platform": r.Platform, "status": target}
	if target == "canary" {
		summary["canaryAudience"] = canaryAudienceDigest(audience)
	}
	if r.Status == "canary" {
		summary["previousCanaryAudience"] = canaryAudienceDigest(r.CanaryInstallations)
	}
	event := newAudit(tenantID(c), actor(c), c.Param("action"), "release", r.ID, body.Reason, requestID(c), summary)
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	if target == "active" {
		if err := enqueuePushEvent(c.Request.Context(), tx, tenantID(c), "app_update_available", map[string]any{"releaseId": r.ID, "platform": r.Platform, "version": r.Version, "buildNumber": r.BuildNumber}); err != nil {
			problem(c, 500, "TRANSITION_FAILED", "Unable to enqueue update notification")
			return
		}
	}
	if tx.Commit() != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	r.Status = target
	r.UpdatedAt = iso(now)
	lastAction := c.Param("action")
	r.LastAction = &lastAction
	r.CanaryInstallations = audience
	if target == "active" {
		v := iso(now)
		r.PublishedAt = &v
	}
	c.JSON(201, gin.H{"release": r})
}

// setReleaseMandatory 事后修改"强制升级"标记（管理端列表里的开关）。语义与登记时勾选完全一样：
// 只是把最低版本抬到这一版，且只升不降（见 resolveUpdateDecision）。客户端在下一次拉 bootstrap
// 时看到新决策，没有推送。
func (s *server) setReleaseMandatory(c *gin.Context, r release, mandatory *bool, reason string) {
	if mandatory == nil {
		problem(c, 400, "INVALID_RELEASE_FLAG", "mandatory is required")
		return
	}
	if !releaseFlagEditable(r.Status) {
		problem(c, 409, "RELEASE_FLAG_LOCKED", fmt.Sprintf("Cannot change the upgrade type of a %s release", r.Status))
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET mandatory=?,last_action='set-mandatory',updated_at=? WHERE tenant_id=? AND id=? AND status=?`, *mandatory, now, tenantID(c), r.ID, r.Status)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "RELEASE_STATE_CHANGED", "Release changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "release_set_mandatory", "release", r.ID, reason, requestID(c), map[string]any{"version": r.Version, "platform": r.Platform, "status": r.Status, "mandatory": *mandatory, "previous": r.Mandatory})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	r.Mandatory = *mandatory
	r.UpdatedAt = iso(now)
	last := "set-mandatory"
	r.LastAction = &last
	c.JSON(201, gin.H{"release": r})
}

// rejectUnknownCanaryInstallations 把"这个租户下不存在的安装 ID"变成入口处的拒绝。
// 名单里拼错一个字符不会报错，只会让那台设备永远匹配不上——运营看到的现象是
// "发了但没收到"，查起来很贵。返回空串表示全部认识。
func (s *server) rejectUnknownCanaryInstallations(c *gin.Context, platform string, audience []string) (string, string) {
	unknown, err := s.unknownCanaryInstallations(c.Request.Context(), tenantID(c), platform, audience)
	if err != nil {
		return "CANARY_AUDIENCE_LOOKUP_FAILED", "Unable to verify the canary audience"
	}
	if len(unknown) > 0 {
		return "CANARY_INSTALLATION_UNKNOWN", "Unknown installations for this platform: " + strings.Join(unknown, ", ")
	}
	return "", ""
}

// setReleaseCanaryAudience 改一条已经在灰度里的记录的名单，不动状态。
// 与转灰度同样的校验：名单不能为空，ID 必须存在。
func (s *server) setReleaseCanaryAudience(c *gin.Context, r release, installations []string, reason string) {
	if r.Status != "canary" {
		problem(c, 409, "INVALID_TRANSITION", fmt.Sprintf("Cannot change the canary audience of a %s release", r.Status))
		return
	}
	audience, code, detail := normalizeCanaryAudience(installations)
	if code != "" {
		problem(c, 422, code, detail)
		return
	}
	if code, detail := s.rejectUnknownCanaryInstallations(c, r.Platform, audience); code != "" {
		problem(c, 422, code, detail)
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	defer tx.Rollback()
	audienceValue, _ := json.Marshal(audience)
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET canary_installations=?,last_action='set-canary-audience',updated_at=? WHERE tenant_id=? AND id=? AND status='canary'`, audienceValue, now, tenantID(c), r.ID)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "RELEASE_STATE_CHANGED", "Release changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "release_set_canary_audience", "release", r.ID, reason, requestID(c), map[string]any{"version": r.Version, "platform": r.Platform, "status": r.Status, "canaryAudience": canaryAudienceDigest(audience), "previousCanaryAudience": canaryAudienceDigest(r.CanaryInstallations)})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	r.UpdatedAt = iso(now)
	last := "set-canary-audience"
	r.LastAction = &last
	r.CanaryInstallations = audience
	c.JSON(201, gin.H{"release": r})
}

func (s *server) overview(c *gin.Context) {
	items, err := s.queryReleases(c.Request.Context(), tenantID(c), "", "")
	if err != nil {
		problem(c, 500, "OVERVIEW_FAILED", "Unable to load overview")
		return
	}
	counts := map[string]int{"uploaded": 0, "verified": 0, "active": 0, "canary": 0, "paused": 0, "completed": 0, "rejected": 0, "rolled_back": 0}
	current := map[string]any{"android": nil, "ios": nil, "harmony": nil}
	for _, r := range items {
		counts[r.Status]++
		if r.Status == "active" {
			if current[r.Platform] == nil {
				current[r.Platform] = r
			}
		}
	}
	c.JSON(200, gin.H{"generatedAt": iso(time.Now()), "current": current, "counts": counts, "signals": gin.H{"crashFreeSessions": nil, "updateSuccessRate": nil, "note": "Connect telemetry provider before production SLO decisions"}})
}

func (s *server) listAudits(c *gin.Context) {
	items, err := s.queryAudits(c.Request.Context(), tenantID(c), "")
	if err != nil {
		problem(c, 500, "AUDIT_QUERY_FAILED", "Unable to load audit events")
		return
	}
	c.JSON(200, gin.H{"items": items, "nextCursor": nil, "hasMore": false})
}
func (s *server) queryAudits(ctx context.Context, tenant, target string) ([]auditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at FROM audit_events WHERE tenant_id=? AND (?='' OR target_id=?) ORDER BY created_at DESC LIMIT 1000`, tenant, target, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []auditEvent{}
	for rows.Next() {
		var a auditEvent
		var summary []byte
		var created time.Time
		if err := rows.Scan(&a.ID, &a.ActorID, &a.Action, &a.TargetType, &a.TargetID, &a.Reason, &a.RequestID, &summary, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(summary, &a.Summary)
		a.TenantID = tenant
		a.CreatedAt = iso(created)
		items = append(items, a)
	}
	return items, rows.Err()
}

func (s *server) getAppConfig(c *gin.Context) {
	view, err := s.appConfigView(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "CONFIG_QUERY_FAILED", "Unable to load app config")
		return
	}
	c.JSON(200, view)
}
func (s *server) appConfigView(ctx context.Context, tenant string) (gin.H, error) {
	var raw []byte
	var version int
	var sourceTenant string
	var updatedBy string
	var updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`, tenant, tenant).Scan(&sourceTenant, &raw, &version, &updatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		raw = []byte(initialConfig)
		now := time.Now().UTC()
		_, err = s.db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(0,'mobile-bootstrap',?,1,'system-bootstrap',?)`, raw, now)
		if err != nil {
			return nil, err
		}
		version = 1
		sourceTenant = "0"
		updatedBy = "system-bootstrap"
		updated = now
	} else if err != nil {
		return nil, err
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	value["modules"] = normalizeModules(object(value["modules"]))
	value["wallet"] = normalizeWallet(object(value["wallet"]))
	value["services"] = normalizeServices(value["services"])
	return gin.H{"summary": configSummary(value), "config": value, "metadata": gin.H{"databaseVersion": version, "updatedBy": updatedBy, "updatedAt": iso(updated), "inherited": sourceTenant == "0", "walletCatalog": walletCatalog()}}, nil
}
func (s *server) updateAppConfig(c *gin.Context) {
	var body struct {
		Reason          string         `json:"reason"`
		Confirm         bool           `json:"confirm"`
		ExpectedVersion int            `json:"expectedVersion"`
		Config          map[string]any `json:"config"`
	}
	if decode(c, &body) != nil || !body.Confirm || body.ExpectedVersion < 1 || len(strings.TrimSpace(body.Reason)) < 3 || !validConfig(body.Config) {
		problem(c, 400, "INVALID_APP_CONFIG", "config, expectedVersion, reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	defer tx.Rollback()
	var stored []byte
	var storedVersion int
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT config_value,version FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1 FOR UPDATE`, tenantID(c), tenantID(c)).Scan(&stored, &storedVersion); err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	// 版本对不上要在校验内容**之前**判。否则拿着一份过期的配置提交，撞到的是内容
	// 校验的报错（"predict 模块开着但没配服务"），而那说的是他浏览器里那份旧配置的
	// 毛病，不是库里的现状——人会照着去修一个已经不存在的问题。真踩过：一条迁移
	// 刚把默认配置里的 predict 关掉，页面还开着旧的，保存就一直报 predict 没配。
	if storedVersion > 0 && body.ExpectedVersion != storedVersion {
		problem(c, http.StatusConflict, "STALE_APP_CONFIG",
			fmt.Sprintf("这份配置在你打开之后被改过（你的版本 %d，当前 %d）。刷新页面拿到最新的再改。", body.ExpectedVersion, storedVersion))
		return
	}
	if incoming, present := body.Config["wallet"]; present && incoming != nil {
		if err := validateWalletSection(incoming); err != nil {
			problem(c, 400, "INVALID_WALLET_CONFIG", err.Error())
			return
		}
	} else if carried := storedWalletSection(stored); carried != nil {
		// 客户端不带 wallet 段时保留库里已有的：否则一次改颜色就会把租户的
		// projectId 和链端点顺手清空。沿用的值不再校验——它已经在库里，
		// 读路径会把不合法的部分归一化掉
		body.Config["wallet"] = carried
	}
	if incoming, present := body.Config["services"]; present && incoming != nil {
		section, err := parseServicesSection(incoming)
		if err != nil {
			problem(c, 400, "INVALID_SERVICES_CONFIG", err.Error())
			return
		}
		body.Config["services"] = section
	} else if carried := storedServicesSection(stored); carried != nil {
		// 同 wallet：不带这一段就沿用库里的，改一次主题色不能把预测平台的关联清掉
		body.Config["services"] = carried
	}
	// predict 模块开着就必须有完整合法的平台配置，链还得在租户启用的链里；
	// 在这里拦下比让 bootstrap 503 早得多
	if _, err := predictServiceFor(normalizeModules(object(body.Config["modules"])), object(body.Config["services"]), normalizeWallet(object(body.Config["wallet"]))); err != nil {
		problem(c, 400, "INVALID_SERVICES_CONFIG", err.Error())
		return
	}
	raw, _ := json.Marshal(body.Config)
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key='mobile-bootstrap' AND version=?`, raw, actor(c), now, tenantID(c), body.ExpectedVersion)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	affected, _ := result.RowsAffected()
	newVersion := body.ExpectedVersion + 1
	if affected == 0 {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
			SELECT ?, 'mobile-bootstrap', ?, 1, ?, ? FROM app_configs global_config
			WHERE global_config.tenant_id=0 AND global_config.config_key='mobile-bootstrap' AND global_config.version=?
			AND NOT EXISTS (SELECT 1 FROM app_configs tenant_config WHERE tenant_config.tenant_id=? AND tenant_config.config_key='mobile-bootstrap')`, tenantID(c), raw, actor(c), now, body.ExpectedVersion, tenantID(c))
		if err == nil {
			affected, _ = result.RowsAffected()
			newVersion = 1
		}
	}
	if affected != 1 {
		problem(c, 409, "STALE_APP_CONFIG", "App config changed since it was loaded; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "config_update", "app-config", "mobile-bootstrap", body.Reason, requestID(c), map[string]any{"status": "active", "databaseVersionBefore": body.ExpectedVersion, "databaseVersionAfter": newVersion, "configVersion": body.Config["configVersion"]})
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config audit")
		return
	}
	if err := enqueuePushEvent(c.Request.Context(), tx, tenantID(c), "bootstrap_updated", map[string]any{"configVersion": body.Config["configVersion"]}); err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to enqueue config notification")
		return
	}
	if tx.Commit() != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	view, _ := s.appConfigView(c.Request.Context(), tenantID(c))
	view["status"] = "active"
	view["savedAt"] = iso(now)
	view["actorId"] = actor(c)
	view["requestId"] = requestID(c)
	c.JSON(200, view)
}

// supportedNetworks is the EVM chain catalog this platform can talk to. The
// EIP-155 id and the default endpoints live here so a tenant only overrides
// what it actually wants to change.
//
// RPC endpoints are delivered to every client, so they are public by
// definition: use endpoints that are safe to expose (domain-restricted or
// rate-limited keys), or proxy RPC through this server. Never put a bearer
// secret in an rpcUrl.
type evmNetwork struct {
	ID          string
	Name        string
	ChainID     int
	RPCUrls     []any
	ExplorerURL string
	// Testnet 上的币没有价值。混进主网列表里，运营会误开给生产租户、用户会
	// 把它当成真链，所以这个标记要一路传到管理端和 App 的界面上。
	Testnet bool
	// NativeSymbol / NativeDecimals 描述原生币。原生币没有合约、读不了链，
	// 它的符号与精度只能来自这里；管理端也靠这两项显示原生币行。
	NativeSymbol   string
	NativeDecimals int
	// MinBuild 认识这条链的最低 App 构建号；bootstrap 只把链下发给构建号 ≥ 门槛的安装
	// （设计 §4.8：新链先出 App 构建再进目录，旧 App 看不到新链就不会解析失败）。
	MinBuild minBuild
}

// minBuild Android / iOS 各自的构建号门槛；0 表示所有构建都认识这条链。
type minBuild struct {
	Android int
	IOS     int
}

// forPlatform 取该平台的门槛；harmony 装的是 Android 包，按 Android 算。
func (m minBuild) forPlatform(platform string) int {
	if platform == "ios" {
		return m.IOS
	}
	return m.Android
}

// buildNumberOf 请求头 x-build-number 的整数值；解析不出按 0（最老的构建）。
func buildNumberOf(c *gin.Context) int {
	number, err := strconv.Atoi(strings.TrimSpace(c.GetHeader("x-build-number")))
	if err != nil || number < 0 {
		return 0
	}
	return number
}

// filterWalletForBuild 去掉这个安装的构建号还不认识的链（chains / networks 同步删），
// 返回被去掉的链 id。代币目录在这之后按 chains 附加，自然也不会带上。
func filterWalletForBuild(wallet map[string]any, platform string, build int) []string {
	keep := map[string]bool{}
	for _, network := range supportedNetworks {
		if network.MinBuild.forPlatform(platform) <= build {
			keep[network.ID] = true
		}
	}
	var hidden []string
	chains := []any{}
	for _, raw := range asList(wallet["chains"]) {
		id, _ := raw.(string)
		if keep[id] {
			chains = append(chains, id)
		} else {
			hidden = append(hidden, id)
		}
	}
	networks := []any{}
	for _, raw := range asList(wallet["networks"]) {
		if id, _ := object(raw)["id"].(string); keep[id] {
			networks = append(networks, raw)
		}
	}
	wallet["chains"], wallet["networks"] = chains, networks
	return hidden
}

func asList(value any) []any {
	items, _ := value.([]any)
	return items
}

// 目前五条链所有已发布构建都认识（MinBuild 0）。以后加链：先出带该链的 App 构建，
// 再在这里写上 Android / iOS 的构建号。
var supportedNetworks = []evmNetwork{
	{"bsc", "BNB Smart Chain", 56, []any{"https://bsc-dataseed.bnbchain.org"}, "https://bscscan.com", false, "BNB", 18, minBuild{}},
	{"eth", "Ethereum", 1, []any{"https://ethereum-rpc.publicnode.com"}, "https://etherscan.io", false, "ETH", 18, minBuild{}},
	{"base", "Base", 8453, []any{"https://mainnet.base.org"}, "https://basescan.org", false, "ETH", 18, minBuild{}},
	{"op-sepolia", "OP Sepolia", 11155420, []any{"https://sepolia.optimism.io"}, "https://sepolia-optimism.etherscan.io", true, "ETH", 18, minBuild{}},
	// 预测市场平台（pm-cup2026）的默认主网；2026-09-02 经 rpc.monad.xyz 实测 chainId 0x8f
	{"monad", "Monad", 143, []any{"https://rpc.monad.xyz"}, "https://monadvision.com", false, "MON", 18, minBuild{}},
}

// walletCatalog tells the admin console which chains this platform can talk to
// and what the platform defaults are. Without it the console would have to keep
// its own copy of the chain list, which is exactly how the two lists drift.
func walletCatalog() []any {
	items := []any{}
	for _, network := range supportedNetworks {
		items = append(items, map[string]any{
			"id":                 network.ID,
			"name":               network.Name,
			"chainId":            network.ChainID,
			"defaultRpcUrls":     network.RPCUrls,
			"defaultExplorerUrl": network.ExplorerURL,
			"testnet":            network.Testnet,
			"nativeSymbol":       network.NativeSymbol,
			"nativeDecimals":     network.NativeDecimals,
			"minBuild":           map[string]any{"android": network.MinBuild.Android, "ios": network.MinBuild.IOS},
		})
	}
	return items
}

// supportedNetworkIDs 拼出报错里要展示的链清单。硬编码成 "bsc / eth / base"
// 的话，每加一条链就会多一处对不上的文案。
func supportedNetworkIDs() string {
	ids := make([]string, 0, len(supportedNetworks))
	for _, network := range supportedNetworks {
		ids = append(ids, network.ID)
	}
	return strings.Join(ids, " / ")
}

func supportedNetwork(id string) (int, bool) {
	network, ok := platformNetwork(id)
	return network.ChainID, ok
}

// NetworkName 链目录里的显示名（推送文案用）；不在目录返回 id 本身。
func NetworkName(id string) string {
	if network, ok := platformNetwork(id); ok {
		return network.Name
	}
	return id
}

func platformNetwork(id string) (evmNetwork, bool) {
	for _, network := range supportedNetworks {
		if network.ID == id {
			return network, true
		}
	}
	return evmNetwork{}, false
}

// walletProjectIDPattern matches a WalletConnect / Reown project id: a hex
// client identifier, not a secret. Validated loosely on purpose — the point is
// to catch a pasted URL or a copied-with-quotes value, not to guess the vendor's
// future id format.
var walletProjectIDPattern = regexp.MustCompile(`^[0-9a-zA-Z]{16,64}$`)

// validateWalletSection rejects a wallet section the admin console should never
// have sent. Everything the bootstrap path later reads is validated here, on the
// write path: an operator who pastes an http:// endpoint must be told, not have
// it quietly dropped and wonder why nothing changed. The read path never repairs
// stored data — see normalizeWallet and the 503 in the bootstrap handler.
func validateWalletSection(raw any) error {
	section, ok := raw.(map[string]any)
	if !ok {
		return errors.New("wallet 必须是一个对象")
	}
	for key := range section {
		if !oneOf(key, "walletConnectProjectId", "chains", "networks", "onchainSends") {
			return fmt.Errorf("wallet.%s 不是可配置项", key)
		}
	}
	if value, present := section["onchainSends"]; present {
		if _, ok := value.(bool); !ok {
			return errors.New("onchainSends 必须是布尔值")
		}
	}
	if value, present := section["walletConnectProjectId"]; present {
		projectID, ok := value.(string)
		if !ok {
			return errors.New("walletConnectProjectId 必须是字符串")
		}
		trimmed := strings.TrimSpace(projectID)
		if trimmed != "" && !walletProjectIDPattern.MatchString(trimmed) {
			return errors.New("walletConnectProjectId 格式不对：应为 cloud.reown.com 上的 Project ID（16-64 位字母数字），不要填入完整链接")
		}
	}
	if value, present := section["chains"]; present {
		chains, ok := value.([]any)
		if !ok {
			return errors.New("chains 必须是数组")
		}
		if len(chains) == 0 {
			return errors.New("至少要启用一条链，否则 App 里的钱包无链可用")
		}
		for _, item := range chains {
			id, ok := item.(string)
			if !ok {
				return errors.New("chains 只能包含链 id 字符串")
			}
			if _, supported := supportedNetwork(id); !supported {
				return fmt.Errorf("不支持的链 %q：当前平台支持 %s", id, supportedNetworkIDs())
			}
		}
	}
	if value, present := section["networks"]; present {
		networks, ok := value.([]any)
		if !ok {
			return errors.New("networks 必须是数组")
		}
		for _, item := range networks {
			network := object(item)
			if network == nil {
				return errors.New("networks 的每一项都必须是对象")
			}
			id, ok := network["id"].(string)
			if !ok {
				return errors.New("networks 的每一项都要有 id")
			}
			chainID, supported := supportedNetwork(id)
			if !supported {
				return fmt.Errorf("不支持的链 %q：当前平台支持 %s", id, supportedNetworkIDs())
			}
			// chainId 由平台目录决定：填错会让签名打到另一条链上
			if raw, present := network["chainId"]; present {
				value, ok := raw.(float64)
				if !ok || int(value) != chainID {
					return fmt.Errorf("%s 的 chainId 固定为 %d，不可修改", id, chainID)
				}
			}
			if raw, present := network["rpcUrls"]; present {
				urls, ok := raw.([]any)
				if !ok {
					return fmt.Errorf("%s 的 rpcUrls 必须是数组", id)
				}
				if len(urls) > maxEndpointsPerChain {
					return fmt.Errorf("%s 最多配置 %d 个 RPC 端点", id, maxEndpointsPerChain)
				}
				for _, entry := range urls {
					endpoint, ok := entry.(string)
					if !ok || !isHTTPSURL(endpoint) {
						return fmt.Errorf("%s 的 RPC 端点必须是 https:// 开头、不含账号密码和空格的完整地址：明文 RPC 会泄露用户查询的每个地址和余额，而 bootstrap 对所有客户端公开", id)
					}
				}
			}
			if raw, present := network["explorerUrl"]; present {
				explorer, ok := raw.(string)
				if !ok || (strings.TrimSpace(explorer) != "" && !isHTTPSURL(explorer)) {
					return fmt.Errorf("%s 的区块浏览器地址必须是 https:// 开头的完整地址", id)
				}
			}
		}
	}
	return nil
}

// storedWalletSection reads the wallet section already in the database, so a
// config that arrives without one carries it over instead of erasing it. Any
// client that round-trips the config through a schema that does not know about
// `wallet` would otherwise wipe the tenant's project id and endpoints as a side
// effect of an unrelated edit.
func storedWalletSection(stored []byte) any {
	var current map[string]any
	if len(stored) == 0 || json.Unmarshal(stored, &current) != nil {
		return nil
	}
	return current["wallet"]
}

// normalizeWallet fills in the wallet section a client needs at startup:
// the WalletConnect project id (a client identifier, not a secret) and the
// per-chain endpoints. Both are tenant configuration rather than build
// parameters, so changing them never requires a new app build.
func normalizeWallet(raw map[string]any) map[string]any {
	enabled := map[string]bool{}
	overrides := map[string]map[string]any{}
	projectID := ""
	// onchainSends 是"转出是否真的上链"的租户级开关，默认关。
	// 不能用"有没有 RPC 端点"当开关：没配过端点的租户也会拿到平台默认端点，
	// 那样新版本一发布，所有租户的主网转出就同时变成真钱。
	onchainSends := false
	if raw != nil {
		if value, ok := raw["onchainSends"].(bool); ok {
			onchainSends = value
		}
		if value, ok := raw["walletConnectProjectId"].(string); ok {
			projectID = strings.TrimSpace(value)
		}
		if chains, ok := raw["chains"].([]any); ok {
			for _, item := range chains {
				if name, ok := item.(string); ok {
					enabled[name] = true
				}
			}
		}
		if networks, ok := raw["networks"].([]any); ok {
			for _, item := range networks {
				network := object(item)
				if network == nil {
					continue
				}
				if id, ok := network["id"].(string); ok {
					overrides[id] = network
					// networks 里出现即视为启用，省得两处都要配
					if _, listed := raw["chains"]; !listed {
						enabled[id] = true
					}
				}
			}
		}
	}
	// 声明式默认：租户还没配过钱包段时启用全部**主网**——管理端钱包页显示的就是这个
	// 结果。测试链必须由运营显式勾选，否则新增一条测试链就会自动出现在所有租户里。
	// 租户配了链却没有一条在目录里（目录下线了一条链），下发的就是空列表：这是
	// 需要迁移租户配置的事故，不在运行时替它换成别的链。
	if len(enabled) == 0 {
		for _, network := range supportedNetworks {
			if network.Testnet {
				continue
			}
			enabled[network.ID] = true
		}
	}

	chains := []any{}
	networks := []any{}
	for _, network := range supportedNetworks {
		if !enabled[network.ID] {
			continue
		}
		entry := map[string]any{
			"id":          network.ID,
			"chainId":     network.ChainID,
			"rpcUrls":     network.RPCUrls,
			"explorerUrl": network.ExplorerURL,
			"testnet":     network.Testnet,
		}
		if override := overrides[network.ID]; override != nil {
			if urls := httpsList(override["rpcUrls"]); len(urls) > 0 {
				entry["rpcUrls"] = urls
			}
			if explorer, ok := override["explorerUrl"].(string); ok && isHTTPSURL(explorer) {
				entry["explorerUrl"] = strings.TrimRight(strings.TrimSpace(explorer), "/")
			}
		}
		chains = append(chains, network.ID)
		networks = append(networks, entry)
	}
	return map[string]any{
		"walletConnectProjectId": projectID,
		// chains 保留为启用链的 id 列表：老客户端只认它，别为了整洁把它删掉
		"chains":       chains,
		"networks":     networks,
		"onchainSends": onchainSends,
	}
}

// maxEndpointLength caps a single RPC / explorer URL; anything longer is not
// a URL an operator typed, it is a mistake or an attack on the bootstrap size.
const maxEndpointLength = 512

// maxEndpointsPerChain caps the fallback list; a client tries them in order and
// nobody benefits from a fiftieth fallback.
const maxEndpointsPerChain = 8

// isHTTPSURL is the single definition of "an endpoint we will deliver".
//
// A prefix check is not enough: the app validates with a real URL parser, so
// anything this accepts that the parser rejects makes the whole bootstrap fail
// to parse on every device of that tenant. Credentials in the URL are refused
// outright — bootstrap is public to every client.
func isHTTPSURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > maxEndpointLength {
		return false
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Hostname() != ""
}

// httpsList keeps only https endpoints; a cleartext RPC would leak every
// address and balance the app looks up. Duplicates collapse to one: the client
// tries endpoints in order and a repeated entry is just a wasted retry.
func httpsList(raw any) []any {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	urls := []any{}
	seen := map[string]bool{}
	for _, item := range items {
		value, ok := item.(string)
		if !ok || !isHTTPSURL(value) {
			continue
		}
		trimmed := strings.TrimSpace(value)
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		urls = append(urls, trimmed)
		if len(urls) >= maxEndpointsPerChain {
			break
		}
	}
	return urls
}

type updateDecisionInput struct {
	// Current 是客户端上报的版本（x-app-version）
	Current string
	// Minimum 来自租户配置 updatePolicy.minSupportedVersion
	Minimum string
	Latest  string
	// Distribution 是分发渠道：store / direct / mdm / development
	Distribution string
	// ActionURL 空表示这个渠道拿不到安装入口
	ActionURL string
	// MandatoryVersion 是 active 发布声明"必须升级"时的版本号，空表示没声明
	MandatoryVersion string
}

// resolveUpdateDecision 决定客户端看到 none / recommended / required。
//
// 强制升级有两个来源：租户配置里的最低支持版本，以及 active 发布记录自己的
// mandatory 标记。后者等效于"把最低版本提到这一版"，但**只升不降**——把老版本
// 标成强制再激活，不该让所有人被要求"升级"到更老的包。两者都仍然走 semver
// 比较，而不是让某个布尔位直接决定结果（见 docs/RELIABILITY_AND_RELEASE.md）。
func resolveUpdateDecision(in updateDecisionInput) string {
	minimum := in.Minimum
	if in.MandatoryVersion != "" && compareVersion(in.MandatoryVersion, minimum) > 0 {
		minimum = in.MandatoryVersion
	}
	if compareVersion(in.Current, minimum) < 0 {
		// 以前这里只要拿不到 actionURL 就一律降级成 recommended，结果是运营以为
		// 强更生效了、装了正式包的用户却看到带"稍后再说"的软更。现在只对
		// development 这种本来就没有安装入口的渠道降级，别把自己人锁在外面。
		if in.ActionURL == "" && in.Distribution == "development" {
			return "recommended"
		}
		return "required"
	}
	if compareVersion(in.Current, in.Latest) < 0 {
		return "recommended"
	}
	return "none"
}

func (s *server) bootstrap(c *gin.Context) {
	tenant, err := s.tenant.resolve(c.Request.Context(), c.Request.Host)
	if err != nil {
		problem(c, 404, "TENANT_NOT_FOUND", "Tenant not found")
		return
	}
	view, err := s.appConfigView(c.Request.Context(), tenant.ID)
	if err != nil {
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	cfg := view["config"].(map[string]any)
	modules := normalizeModules(object(cfg["modules"]))
	wallet := normalizeWallet(object(cfg["wallet"]))
	// 租户配了链却没有一条还在平台目录里（目录下线了一条链）：这是要迁移租户配置的事故，
	// 不下发一个"零条链"的钱包段让 App 悄悄变成空壳
	if chains, _ := wallet["chains"].([]any); len(chains) == 0 {
		slog.Error("wallet section resolves to no supported chain", "tenant", tenant.ID, "configured", object(cfg["wallet"])["chains"])
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	// 构建号门禁（设计 §4.8）：这个安装还不认识的链不下发。过滤后一条不剩说明构建太旧，
	// 只能升级——不下发空钱包段让 App 悄悄变成空壳
	if hidden := filterWalletForBuild(wallet, strings.ToLower(c.GetHeader("x-platform")), buildNumberOf(c)); len(hidden) > 0 {
		slog.Info("chains hidden from an older app build", "tenant", tenant.ID, "platform", c.GetHeader("x-platform"), "build", c.GetHeader("x-build-number"), "hidden", hidden)
		if chains, _ := wallet["chains"].([]any); len(chains) == 0 {
			problem(c, 426, "APP_BUILD_TOO_OLD", "This app build does not support any chain enabled for the tenant; update the app")
			return
		}
	}
	// 预测模块开着就必须下发完整的平台关联；缺了或不合法是配置事故，不下发半段
	predict, err := predictServiceFor(modules, normalizeServices(cfg["services"]), wallet)
	if err != nil {
		slog.Error("services.predict cannot be delivered", "tenant", tenant.ID, "error", err)
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	services := gin.H{}
	if predict != nil {
		services["predict"] = predict.asMap()
	}
	// 代币目录只在这里下发：管理端的配置视图不带 tokens，它不是通过配置 PATCH 写的
	if err := s.attachWalletTokens(c.Request.Context(), tenant.ID, wallet); err != nil {
		slog.Error("wallet tokens could not be loaded for bootstrap", "tenant", tenant.ID, "error", err)
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	requestedLocale := strings.TrimSpace(c.Query("locale"))
	if requestedLocale != "" && !validLanguageCode(requestedLocale) {
		problem(c, 400, "INVALID_LANGUAGE_CODE", "Language code must use canonical BCP 47 format")
		return
	}
	// 语言设置解析不出来（存储的配置被改坏、刷新间隔越界、fallback 语言被停用）是
	// 要人去修的配置事故。此前这里会静默跳过，下发一个缺刷新间隔、缺语言目录的
	// localization 段；App 按"缺了就失败"的原则严格解析，那样只会在客户端炸得更远
	settings, _, _, settingsErr := s.effectiveLanguageSettings(c.Request.Context(), tenant.ID)
	if settingsErr != nil {
		slog.Error("language settings could not be resolved for bootstrap", "tenant", tenant.ID, "error", settingsErr)
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	// 默认语言就是管理端「多语言管理」里设的回退语言：App 没指定语言、或指定的语言没开启，
	// 都用它。以前没指定时先落到应用配置里旧的 localization.fallbackLocale（种子里是 zh-CN），
	// 管理端改了回退语言也不生效；更新说明也在语言定下来之前就按 zh-CN 取了
	locale := requestedLocale
	if language, supported := settings.Languages[locale]; !supported || !language.Enabled {
		locale = settings.FallbackLanguage
	}
	platform := strings.ToLower(c.GetHeader("x-platform"))
	if !oneOf(platform, "android", "ios", "harmony") {
		platform = "android"
	}
	distribution := c.GetHeader("x-distribution-channel")
	if !oneOf(distribution, "store", "direct", "mdm") {
		distribution = "development"
	}
	version := normalizeVersion(c.GetHeader("x-app-version"))
	buildNumber := text(c.GetHeader("x-build-number"), "0")
	updatePolicy := object(cfg["updatePolicy"])
	latest := text(updatePolicy["latestVersion"], "1.1.0")
	minimum := text(updatePolicy["minSupportedVersion"], "0.9.0")
	// 下载地址是按租户的：有可见发布时由下面的 /v1/public/releases/{id}/download
	// 填上。商店 / MDM 渠道没有直装包，留空。从前这里读 env 里的四个全局链接，
	// 那是错的——一个全局值不可能同时对四个租户都对，而且它总会被下面覆盖掉。
	actionURL := ""
	var releaseID any
	var artifactSHA any
	var artifactSize any
	releaseNotes := []string{"远程语言与主题配置", "统一升级决策"}
	// 可选鉴权：带上有效安装凭证的设备才有身份参与灰度匹配。校验失败不影响
	// bootstrap 本身——它是启动门禁，配置必须照发，只是不给灰度（设计 §8.1）
	audience := s.canaryAudienceID(c, tenant.ID)
	canaryRelease := false
	// 目标包与已装包的签名者：用来决定应用内直装会不会被系统安装器拒掉
	targetSigner, installedSigner := "", ""
	if platform == "android" && distribution == "direct" {
		if visible, findErr := s.visibleSimplifiedRelease(c.Request.Context(), tenant.ID, platform, audience); findErr == nil {
			latest = visible.Version
			releaseNotes = releaseNotesForLocale(visible.ReleaseNotes, locale)
			releaseID = visible.ID
			artifactSHA = visible.SHA256
			artifactSize = visible.FileSize
			actionURL = s.absoluteURL(c, "/v1/public/releases/"+visible.ID+"/download")
			canaryRelease = visible.Status == "canary"
			targetSigner = visible.SignerSHA256
			if targetSigner != "" {
				installedSigner = s.installedReleaseSigner(c.Request.Context(), tenant.ID, platform, version, buildNumber)
			}
		}
	}

	// 商店 / MDM 渠道拿不到直装包，但运营勾的"强制升级"仍然要生效：
	// 否则管理端显示的强制徽章对 iOS 是假的。强制版本只认 active 记录
	mandatoryVersion := s.activeMandatoryVersion(c.Request.Context(), tenant.ID, platform)
	// OTA 的 manifest 请求由原生侧在 JS 起来之前发出，带不了 Authorization。
	// 这里给已验明身份的安装下发一个 24 小时的灰度令牌，客户端存进 expo-updates 的
	// extra params，下次启动那一次原生请求就会捎上它。身份没验过就不发，
	// 客户端据此清掉旧令牌。注意：不管当前有没有灰度包都要发——extra params 要到
	// 下次启动才生效，等看见灰度包再发就永远慢一拍
	var canaryOTAToken any
	if audience != "" {
		if token, tokenErr := s.encodeCanaryToken(tenant.ID, audience, time.Now().UTC()); tokenErr == nil {
			canaryOTAToken = token
		} else {
			slog.Error("canary token could not be issued", "tenant", tenant.ID, "error", tokenErr)
		}
	}
	decision := resolveUpdateDecision(updateDecisionInput{
		Current:          version,
		Minimum:          minimum,
		Latest:           latest,
		Distribution:     distribution,
		ActionURL:        actionURL,
		MandatoryVersion: mandatoryVersion,
	})
	localeCatalog, _ := languageCatalog(settings)
	var localization map[string]any
	{
		localization = map[string]any{"fallbackLocale": settings.FallbackLanguage, "supportedLocales": enabledLanguageCodes(settings), "localeCatalog": localeCatalog, "messagesVersion": cfg["configVersion"], "refreshIntervalSeconds": settings.RefreshIntervalSeconds}
		if compiled, compileErr := s.compiledMessages(c.Request.Context(), tenant.ID, locale, settings.FallbackLanguage); compileErr == nil {
			localization["messages"] = map[string]any{locale: compiled}
		} else {
			localization["messages"] = map[string]any{locale: map[string]string{}}
		}
		if language, exists := settings.Languages[locale]; exists && language.Resource != nil {
			localization["resource"] = language.Resource
		} else {
			localization["resource"] = nil
		}
	}
	messages := object(localization["messages"])
	theme := object(cfg["theme"])
	features := object(cfg["features"])
	// 换签名密钥之后，老密钥签的装机装不上新包：把直装按钮收掉，让客户端退回下载页
	directUpdateEnabled := directInstallAllowed(truth(features["directUpdateEnabled"]), platform, installedSigner, targetSigner)
	brandingConfig, _, _, _, _, brandingErr := s.brandingRecord(c.Request.Context(), tenant.ID)
	if brandingErr != nil {
		brandingConfig = cloneMap(defaultBrandingConfig)
	}
	brandingMessages := map[string]string{}
	if compiled, compileErr := s.compiledMessages(c.Request.Context(), tenant.ID, locale, text(localization["fallbackLocale"], "zh-CN")); compileErr == nil {
		brandingMessages = compiled
	}
	branding := resolveBranding(brandingConfig, locale, text(localization["fallbackLocale"], "zh-CN"), brandingMessages)
	runtime := text(c.GetHeader("x-runtime-version"), "embedded")
	otaChannel := text(updatePolicy["otaChannel"], tenantOTAChannel)
	ota := gin.H{"enabled": features["otaEnabled"], "channel": otaChannel, "runtimeVersion": runtime, "revision": nil, "updateId": nil, "baseReleaseId": nil, "applyStrategy": nil, "releaseNotes": []string{}}
	if runtime != "embedded" && truth(features["otaEnabled"]) {
		var otaRevision int
		var otaID, baseID, applyStrategy string
		var otaNotes []byte
		// 与 manifest 同一套可见性：否则灰度设备在"升级中心"里看到的修订号
		// 和它真正会下到的那一个对不上
		if err := s.db.QueryRowContext(c.Request.Context(), `SELECT o.revision,o.update_id,o.base_release_id,o.apply_strategy,o.release_notes FROM ota_releases o WHERE o.tenant_id=? AND o.platform=? AND o.channel=? AND o.runtime_version=? AND `+canaryVisibleOTASQL+` ORDER BY o.revision DESC LIMIT 1`, tenant.ID, platform, otaChannel, runtime, audience, audience).Scan(&otaRevision, &otaID, &baseID, &applyStrategy, &otaNotes); err == nil {
			var notes map[string][]string
			_ = json.Unmarshal(otaNotes, &notes)
			ota["revision"], ota["updateId"], ota["baseReleaseId"], ota["applyStrategy"], ota["releaseNotes"] = otaRevision, otaID, baseID, applyStrategy, releaseNotesForLocale(notes, locale)
		}
	}
	// issuedAt 是给客户端做重放判定的：签名本身挡不住"把昨天那份合法响应再发一遍"
	// 把更新策略或链配置回滚回去。客户端记住见过的最大值，拒绝更小的（安全评审 N3）。
	issuedAt := time.Now()
	s.writeSignedBootstrap(c, tenant.ID, gin.H{"schemaVersion": 1, "issuedAt": issuedAt.UnixMilli(), "configVersion": cfg["configVersion"], "generatedAt": iso(issuedAt), "ttlSeconds": cfg["ttlSeconds"], "requestId": requestID(c), "localization": gin.H{"selectedLocale": locale, "fallbackLocale": localization["fallbackLocale"], "supportedLocales": localization["supportedLocales"], "localeCatalog": localeCatalog, "messagesVersion": localization["messagesVersion"], "refreshIntervalSeconds": localization["refreshIntervalSeconds"], "messages": messages[locale], "resource": localization["resource"]}, "theme": theme, "modules": gin.H{"predict": truth(modules["predict"]), "dex": truth(modules["dex"])}, "wallet": wallet, "services": services, "features": bootstrapFeatures(features, directUpdateEnabled), "branding": branding, "app": gin.H{"version": version, "buildNumber": buildNumber, "platform": platform, "distribution": distribution, "runtimeVersion": runtime}, "update": gin.H{"decision": decision, "minSupportedVersion": minimum, "latestVersion": latest, "releaseNotes": releaseNotes, "ota": ota, "full": gin.H{"channel": distribution, "actionUrl": nullableString(actionURL), "releaseId": releaseID, "sha256": artifactSHA, "size": artifactSize}, "canary": gin.H{"enrolled": canaryRelease, "otaToken": canaryOTAToken}}, "support": gin.H{"diagnosticId": requestID(c), "statusPageUrl": object(cfg["support"])["statusPageUrl"]}})
}

func enabledLanguageCodes(settings effectiveLanguagesConfig) []string {
	codes := make([]string, 0, len(settings.Languages))
	for code, item := range settings.Languages {
		if item.Enabled {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	return codes
}

// bootstrapFeatures 是下发给 App 的 features 段。App 侧每一项都是必填布尔，缺一项整份配置无效。
//
// crashAutoReport 用 truth()：它会让 App 在用户不操作的情况下上传崩溃日志，默认必须是关。
// 迁移 v46 已把它补进所有配置；这里不是兜底，是和 modules 同样的规范化写法。
func bootstrapFeatures(features map[string]any, directUpdateEnabled bool) gin.H {
	return gin.H{
		"updateCenter":        features["updateCenter"],
		"otaEnabled":          features["otaEnabled"],
		"directUpdateEnabled": directUpdateEnabled,
		"diagnosticsEnabled":  features["diagnosticsEnabled"],
		"crashAutoReport":     truth(features["crashAutoReport"]),
	}
}

func insertAudit(ctx context.Context, tx *sql.Tx, a auditEvent) error {
	summary, _ := json.Marshal(a.Summary)
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, a.ID, a.TenantID, a.ActorID, a.Action, a.TargetType, a.TargetID, a.Reason, a.RequestID, summary, time.Now().UTC())
	return err
}
func newAudit(tenant, actor, action, targetType, targetID, reason, requestID string, summary map[string]any) auditEvent {
	return auditEvent{ID: "audit_" + randomID(16), TenantID: tenant, ActorID: actor, Action: action, TargetType: targetType, TargetID: targetID, Reason: reason, RequestID: requestID, CreatedAt: iso(time.Now()), Summary: summary}
}
func validConfig(v map[string]any) bool {
	if v == nil {
		return false
	}
	_, ok1 := v["configVersion"].(string)
	ttl, ok2 := v["ttlSeconds"].(float64)
	policy := object(v["updatePolicy"])
	// 版本号不是 semver 时，compareVersion 会把非法值当成 "1.0.0"，强制升级静默失效
	policyValid := policy != nil && validVersion(text(policy["minSupportedVersion"], "")) && validVersion(text(policy["latestVersion"], ""))
	return ok1 && ok2 && ttl >= 30 && ttl <= 86400 && object(v["localization"]) != nil && object(v["theme"]) != nil && object(v["features"]) != nil && policyValid && object(v["support"]) != nil
}

// normalizeModules 把 modules 段收敛成两个布尔。
//
// 四种组合都是正式形态，包括 00（Wallet-only）——那是一个可独立售卖的纯钱包产品。
// 这里**不能**把 00 改写成 11：那会把管理员的显式选择悄悄换掉，管理端看到的和
// App 拿到的从此不是一回事。
//
// value == nil 只在整段缺失时出现（v23 的 app_modules_config 迁移已给存量行补齐，
// initialConfig 也显式声明），此时用平台默认值双开——这是文档化、管理端可见的
// 声明式默认，不是"坏了换一个值顶上"。
func normalizeModules(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{"predict": true, "dex": true}
	}
	return map[string]any{"predict": truth(value["predict"]), "dex": truth(value["dex"])}
}
func configSummary(v map[string]any) gin.H {
	l := object(v["localization"])
	t := object(v["theme"])
	f := object(v["features"])
	enabled := []string{}
	for k, val := range f {
		if truth(val) {
			enabled = append(enabled, k)
		}
	}
	wallet := object(v["wallet"])
	projectID, _ := wallet["walletConnectProjectId"].(string)
	chains, ok := wallet["chains"].([]any)
	if !ok {
		chains = []any{}
	}
	return gin.H{"configVersion": v["configVersion"], "localization": gin.H{"supportedLocales": l["supportedLocales"], "messagesVersion": l["messagesVersion"]}, "theme": gin.H{"paletteVersion": t["paletteVersion"], "modes": []string{"light", "dark"}}, "featureFlags": enabled, "updatePolicy": gin.H{"source": "mysql", "approvalRequired": false}, "wallet": gin.H{"chains": chains, "walletConnectConfigured": strings.TrimSpace(projectID) != ""}}
}
func decode(c *gin.Context, v any) error {
	return decodeLimited(c, v, 1<<20)
}

// decodeLimited 和 decode 一样，只是请求体上限由调用方给。
//
// 1 MiB 对配置 JSON 是合适的默认值，但对"正文里塞着一张 base64 图片"的接口不是。
// 2026-09-13 的故障就是这么来的：图标校验器的单张上限抬到了 6 MiB，而所有接口共用
// 的 decode 还卡在 1 MiB，于是校验器接受的图永远送不进来。把全局上限抬上去也不对
// ——那等于给每一个接口都开一个更大的内存口子。
func decodeLimited(c *gin.Context, v any, limit int64) error {
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, limit))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// requestTooLarge 区分"请求体超限"和别的解码错误。
// 不区分的代价是运营看到的永远是一句"数据不合法"，只会去换图片格式，不会想到大小。
func requestTooLarge(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}
func problem(c *gin.Context, status int, code, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.JSON(status, gin.H{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": detail, "requestId": requestID(c)})
}
func requestID(c *gin.Context) string          { v, _ := c.Get("requestId"); return fmt.Sprint(v) }
func actor(c *gin.Context) string              { v, _ := c.Get("actorId"); return fmt.Sprint(v) }
func tenantID(c *gin.Context) string           { v, _ := c.Get("tenantId"); return fmt.Sprint(v) }
func valueFrom(c *gin.Context, key string) any { v, _ := c.Get(key); return v }

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
func sha256Hex(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func constantEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	n, e1 := strconv.Atoi(parts[1])
	r, e2 := strconv.Atoi(parts[2])
	p, e3 := strconv.Atoi(parts[3])
	if e1 != nil || e2 != nil || e3 != nil || n < 16384 || n > 32768 || r < 8 || r > 16 || p < 1 || p > 4 {
		return false
	}
	salt, e4 := base64.RawURLEncoding.DecodeString(parts[4])
	expected, e5 := base64.RawURLEncoding.DecodeString(parts[5])
	if e4 != nil || e5 != nil {
		return false
	}
	actual, e6 := scrypt.Key([]byte(password), salt, n, r, p, len(expected))
	return e6 == nil && subtle.ConstantTimeCompare(actual, expected) == 1
}
func safeMethod(m string) bool { return m == "GET" || m == "HEAD" || m == "OPTIONS" }
func iso(t time.Time) string   { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func oneOf(v string, options ...string) bool {
	for _, o := range options {
		if v == o {
			return true
		}
	}
	return false
}
func truth(v any) bool            { b, _ := v.(bool); return b }
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

// normalizeReleaseNotes 把写入侧收到的发布说明收敛成唯一的正式形状：语言 -> 行数组，
// 语言码与每一行都去掉首尾空白后存库。读取侧（bootstrap 下发、管理端列表）都按这个形状
// 解析，所以写入时就必须挡住别的形状——曾经有人用管理接口直接写进字符串，管理端整份
// 列表因此校验失败。允许缺省（nil / 空对象）；给了就必须是数组，每一项是非空字符串。
// 返回 (problem code, detail)，两个写入路径共用同一个错误码，不各自抄一份字面量。
func normalizeReleaseNotes(raw map[string]any) (map[string][]string, string, string) {
	notes := make(map[string][]string, len(raw))
	for language, value := range raw {
		code := strings.TrimSpace(language)
		if code == "" {
			return nil, "INVALID_RELEASE_NOTES", "releaseNotes keys must be non-empty language codes"
		}
		if _, duplicate := notes[code]; duplicate {
			return nil, "INVALID_RELEASE_NOTES", "releaseNotes keys must be distinct once trimmed"
		}
		items, ok := value.([]any)
		if !ok {
			return nil, "INVALID_RELEASE_NOTES", "releaseNotes values must be arrays of strings, one entry per line"
		}
		lines := make([]string, 0, len(items))
		for _, item := range items {
			line, ok := item.(string)
			if !ok {
				return nil, "INVALID_RELEASE_NOTES", "releaseNotes values must be arrays of strings, one entry per line"
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				return nil, "INVALID_RELEASE_NOTES", "releaseNotes lines must not be blank"
			}
			lines = append(lines, trimmed)
		}
		if len(lines) == 0 {
			return nil, "INVALID_RELEASE_NOTES", "releaseNotes languages must carry at least one line"
		}
		notes[code] = lines
	}
	return notes, "", ""
}

func releaseNotesForLocale(notes map[string][]string, locale string) []string {
	if selected := notes[locale]; len(selected) > 0 {
		return selected
	}
	if fallback := notes["zh-CN"]; len(fallback) > 0 {
		return fallback
	}
	// 既没有请求的语言也没有 zh-CN：按语言码排序取第一个，
	// 否则 map 迭代顺序会让同一份数据在不同请求里返回不同语言
	languages := make([]string, 0, len(notes))
	for language := range notes {
		if len(notes[language]) > 0 {
			languages = append(languages, language)
		}
	}
	if len(languages) == 0 {
		return []string{}
	}
	sort.Strings(languages)
	return notes[languages[0]]
}
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// absoluteURL 拼给客户端用的绝对地址（下载、OTA 资源、上传入口）。
// 生产环境一律 https：代理没设 x-forwarded-proto 时也不能把 http:// 地址烘进 manifest 或 bootstrap，
// 只记一次 warning 提醒修代理配置。开发环境按请求实际协议。
func (s *server) absoluteURL(c *gin.Context, path string) string {
	forwarded := c.GetHeader("x-forwarded-proto")
	scheme := "http"
	if forwarded == "https" || c.Request.TLS != nil {
		scheme = "https"
	}
	if s.cfg.Environment == "production" && scheme != "https" {
		missingForwardedProtoWarning.Do(func() {
			slog.Warn("x-forwarded-proto is not https in production; forcing https in generated URLs, fix the proxy configuration", "host", c.Request.Host, "xForwardedProto", forwarded)
		})
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host + path
}

var missingForwardedProtoWarning sync.Once

func nullableInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}
func nullableSQLString(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "1.0.0"
	}
	if semver.IsValid("v" + v) {
		return v
	}
	return "1.0.0"
}
func validVersion(v string) bool     { return semver.IsValid("v" + v) }
func compareVersion(a, b string) int { return semver.Compare("v"+a, "v"+b) }

const initialConfig = `{"configVersion":"2026.08.24.1","ttlSeconds":300,"localization":{"fallbackLocale":"zh-CN","supportedLocales":["zh-CN","en-US"],"messagesVersion":"2026.08.24.1","messages":{"zh-CN":{"app.name":"RN 应用基座","home.title":"远程配置中心"},"en-US":{"app.name":"RN App Foundation","home.title":"Remote configuration center"}}},"theme":{"defaultMode":"system","allowUserOverride":true,"paletteVersion":"ocean-1","light":{"primary":"#3157D5","onPrimary":"#FFFFFF","background":"#F4F7FB","surface":"#FFFFFF","surfaceVariant":"#EAF0F8","text":"#101828","textMuted":"#5A687C","border":"#D5DDE9","success":"#147A50","warning":"#9A5C00","danger":"#B42318","info":"#2962A3","pricePositive":"#0E8A5F","priceNegative":"#D03C45","risk":"#7A4D00","focus":"#7293FF","backdrop":"rgba(11,18,32,.56)"},"dark":{"primary":"#AFC6FF","onPrimary":"#082B78","background":"#0B1220","surface":"#121C2D","surfaceVariant":"#1D2A3E","text":"#F0F4FA","textMuted":"#A9B7CA","border":"#35445A","success":"#61D6A3","warning":"#F4BD68","danger":"#FFB4AB","info":"#A8CAFF","pricePositive":"#5CDBA8","priceNegative":"#FF7B86","risk":"#F4BD68","focus":"#AFC6FF","backdrop":"rgba(0,0,0,.72)"}},"modules":{"predict":true,"dex":true},"features":{"updateCenter":true,"otaEnabled":true,"directUpdateEnabled":true,"diagnosticsEnabled":true,"crashAutoReport":false},"updatePolicy":{"minSupportedVersion":"0.9.0","latestVersion":"1.1.0","otaChannel":"production"},"support":{"statusPageUrl":"https://status.example.com"}}`
