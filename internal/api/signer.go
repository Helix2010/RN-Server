package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/gin-gonic/gin"
)

// 签名闸通道 /v1/signer（设计 android-signing-gate-2026-09-16「签名闸」「接口」、约定 5.3）。
//
// 签名闸不采信服务端：它只信本机记录里确认过的证书指纹、包内信任根、受信构建机与签过的
// 版本号。服务端这边做的是路由与记账——只把就绪租户的最小在途 build 号派给 active 的主
// 签名闸，只给它发给本机的那份密文，签完在一个事务里落发布记录并完成任务。
//
// 签名闸的每个上报都带签名编号（x-sign-attempt），与任务行的 sign_attempt、
// signing_machine_id 对不上一律 409 SIGN_ATTEMPT_STALE：任务被回收或强制判失败之后，
// 迟到的上报不能再改它。

const (
	signAttemptHeader    = "x-sign-attempt"
	signedAPKObjectName  = "app-release.apk"
	maxSignerListItems   = 1000
	signerDetailMaxRunes = 500
	signerErrorMaxRunes  = 300
	apkContentType       = "application/vnd.android.package-archive"
	// signDeferralCooldown：签名闸对一条任务说"暂不能签"（release，sign_outcome.kind=deferred）之后，
	// 这么久之内不再把这条任务派给**同一台**签名闸。暂不能签的原因（本机没确认、信任根刚改）
	// 不会在一秒内自己消失；不冷却的话签名闸认领、退回、再认领，端到端实测每秒一百多次，
	// sign_attempt 半分钟涨到几千。别的签名闸不受影响。
	signDeferralCooldown = 60 * time.Second
)

var signerCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// sanitizeSignerText 清洗签名闸送来的说明（见 sanitizeReportedText）并截断：它会显示在控制台上、写进审计。
func sanitizeSignerText(text string, max int) string {
	return clipRunes(strings.TrimSpace(sanitizeReportedText(text)), max)
}

// ---- 签名密钥检查 ----

// signerKeystoreChecks 列出发给本机的密文，以及服务端算出的当前信任根（只作对照）。
// 主备两台都调：备签名闸同样要试解、确认，才能随时接手。
//
// 自动化（ADR-0020）之后每项还带：
//   - generator / generationSignature / generationRequestId / upload：当前密钥由签名闸生成时给出（离线导入的为 null），
//     备签名闸据此验证"是本机信任的签名闸生成的"后自动确认；
//   - publishedMaxBuildNumber：该租户 Android 发布记录里最大的 build 号（没有为 0），首次确认时定首签上限；
//   - generationRequest：只给 active 的路由主签名闸、且请求仍在等待时。租户此时可能还没有发给本机的密文
//     （新租户、旧格式记录、密钥没加密给这台主签名闸）：这种项 box、packageName、certificateSha256、keyAlias 为 null，
//     只用来领生成请求，签名闸不对它上报检查结论（服务端也不收）。
func (s *server) signerKeystoreChecks(c *gin.Context) {
	machine, _ := machineFromContext(c)
	ctx := c.Request.Context()
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT k.tenant_id FROM app_configs k JOIN tenants t ON t.id=k.tenant_id WHERE k.config_key IN (?,?) ORDER BY k.tenant_id`,
		buildKeystoreConfigKey, buildKeystoreRequestConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_QUERY_FAILED", "Unable to list keystores")
		return
	}
	tenants := []string{}
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_QUERY_FAILED", "Unable to list keystores")
			return
		}
		tenants = append(tenants, tenant)
	}
	rows.Close()
	items := []gin.H{}
	for _, tenant := range tenants {
		item, err := s.signerCheckItem(ctx, machine, tenant)
		if err != nil {
			// 一个租户的记录坏了不能挡住其它租户的检查；这个租户在控制台上会直接报错
			slog.Error("skipping a tenant in the signer keystore checks", "tenant", tenant, "machineId", machine.ID, "error", err)
			continue
		}
		if item != nil {
			items = append(items, item)
		}
	}
	c.JSON(http.StatusOK, gin.H{"machineId": machine.ID, "signerRole": nullableString(string(machine.SignerRole)), "items": items})
}

// signerCheckItem 拼一个租户给这台签名闸的检查项；nil = 这个租户没有要给它的东西。
func (s *server) signerCheckItem(ctx context.Context, machine buildMachine, tenant string) (gin.H, error) {
	state, err := s.buildKeystoreStateFor(ctx, s.db, tenant)
	if err != nil {
		return nil, err
	}
	if state.Invalid != "" {
		// 记录用不了（控制台就绪问题 KEYSTORE_RECORD_INVALID）：不下发密文，留一条日志
		slog.Warn("not sending an unusable build.keystore to a signer", "tenant", tenant, "machineId", machine.ID, "reason", state.Invalid)
	}
	var box *keystorebox.Box
	if state.configured() && containsString(state.Record.Recipients, string(machine.PublicKeySHA256)) {
		if found, ok := boxFor(*state.Upload, string(machine.PublicKeySHA256)); ok {
			box = &found
		}
	}
	var generation gin.H
	firstKeyPackage := ""
	if machine.isActivePrimary() {
		request, err := s.generationRequestFor(ctx, s.db, tenant)
		if err != nil {
			return nil, err
		}
		if request != nil && request.Status == generationPending {
			generation, firstKeyPackage = gin.H{"requestId": request.RequestID, "packageName": request.PackageName, "alias": request.Alias}, request.PackageName
		}
	}
	if box == nil && generation == nil {
		return nil, nil
	}
	slug, err := s.tenantSlug(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var published int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(build_number),0) FROM app_releases WHERE tenant_id=? AND platform='android'`, tenant).Scan(&published); err != nil {
		return nil, err
	}
	item := gin.H{
		"tenantSlug": slug, "keystoreVersion": state.Version, "packageName": nil, "certificateSha256": nil, "keyAlias": nil, "box": nil,
		"trustRoots": nil, "trustRootsDigest": nil, "publishedMaxBuildNumber": published,
		"generator": nil, "generationSignature": nil, "generationRequestId": nil, "upload": nil, "generationRequest": nil,
	}
	if box != nil {
		record := state.Record
		item["tenantSlug"], item["packageName"], item["certificateSha256"], item["keyAlias"], item["box"] = record.TenantSlug, record.PackageName, record.CertificateSHA256, record.KeyAlias, *box
		if record.Generator != nil {
			item["generator"] = gin.H{"machineId": record.Generator.MachineID, "name": record.Generator.Name,
				"ed25519PublicKey": record.Generator.Ed25519PublicKey, "ed25519PublicKeySha256": record.Generator.Ed25519PublicKeySHA256}
			item["generationSignature"], item["generationRequestId"], item["upload"] = record.GenerationSignature, record.GenerationRequestID, *state.Upload
		}
	}
	roots, digest, problems, err := s.trustRootsWith(ctx, tenant, firstKeyPackage)
	if err != nil {
		slog.Error("cannot compose trust roots for a keystore check", "tenant", tenant, "error", err)
	} else if roots != nil {
		item["trustRoots"], item["trustRootsDigest"] = roots, digest
	}
	if generation != nil {
		// 生成请求带着首次信任要用的信任根；算不出来（生成请求之后改坏了 App 参数或 OTA 证书）就不下发，
		// 控制台上的就绪问题会说缺什么
		if roots == nil {
			slog.Warn("not sending a key generation request whose trust roots cannot be composed", "tenant", tenant, "problems", problems)
		} else {
			generation["trustRoots"], generation["trustRootsDigest"], generation["publishedMaxBuildNumber"] = roots, digest, published
			item["generationRequest"] = generation
		}
	}
	if box == nil && item["generationRequest"] == nil {
		return nil, nil
	}
	return item, nil
}

type signerCheckReport struct {
	TenantSlug                string  `json:"tenantSlug"`
	KeystoreVersion           int     `json:"keystoreVersion"`
	Decrypt                   string  `json:"decrypt"`
	Confirmed                 bool    `json:"confirmed"`
	ConfirmedTrustRootsDigest *string `json:"confirmedTrustRootsDigest"`
	TrialSign                 string  `json:"trialSign"`
	Error                     *string `json:"error"`
}

// reportSignerKeystoreChecks 收下签名闸对每个租户当前密钥的试解、确认、试签状态，按机器 id
// 用 JSON_SET 只改自己那个键。只收当前版本的结论：密钥在检查期间被重新上传时，旧结论不能
// 盖在新版本上。签名闸每轮轮询都会报一遍：结论没变就不写库（不加 version），变了才写库并写审计。
func (s *server) reportSignerKeystoreChecks(c *gin.Context) {
	machine, _ := machineFromContext(c)
	var body struct {
		// LocalRole 是签名闸本机记录里的角色，每轮都带；签名闸与服务端同一次发布，缺了就是 400
		LocalRole *string `json:"localRole"`
		// Trust 是签名闸本机记录里的信任列表，新版本每轮都带。可以缺：迁移时 CI 先把服务端推上线，旧签名闸
		// 二进制要等人工升级，那几个小时里它的检查结论与就绪不能停更。缺了就把登记里的 reportedTrust 记成
		// null（"这个版本不上报信任"，不保留旧值），控制台显示为未上报；它只用来提示，没有判断依赖它
		Trust *machineReportedTrust `json:"trust"`
		Items []signerCheckReport   `json:"items"`
	}
	if decode(c, &body) != nil || len(body.Items) > maxSignerListItems {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_CHECK", fmt.Sprintf("items must be an array of at most %d check results", maxSignerListItems))
		return
	}
	if body.LocalRole == nil || (*body.LocalRole != signerRolePrimary && *body.LocalRole != signerRoleStandby) {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_CHECK", "localRole (primary or standby, from this signer's local record) is required")
		return
	}
	var trust *machineReportedTrust
	if body.Trust != nil {
		normalized, err := body.Trust.normalize()
		if err != nil {
			problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_CHECK", "trust is malformed: "+err.Error())
			return
		}
		trust = &normalized
	}
	for _, item := range body.Items {
		digestOK := item.ConfirmedTrustRootsDigest == nil || fingerprint.Valid(*item.ConfirmedTrustRootsDigest)
		if !ident.ValidTenantSlug(item.TenantSlug) || item.KeystoreVersion < 1 || (item.Decrypt != "ok" && item.Decrypt != "failed") ||
			!oneOf(item.TrialSign, "pending", "ok", "failed") || !digestOK || (item.Confirmed && item.ConfirmedTrustRootsDigest == nil) {
			problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_CHECK",
				"each item needs tenantSlug, keystoreVersion >= 1, decrypt ok|failed, confirmed, confirmedTrustRootsDigest (64 hex, required when confirmed), trialSign pending|ok|failed and error")
			return
		}
	}
	ctx := c.Request.Context()
	now := time.Now().UTC()
	if err := s.recordSignerLocalState(c, machine, *body.LocalRole, trust, now); err != nil {
		slog.Error("cannot record a signer's local role and trust", "machineId", machine.ID, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_SAVE_FAILED", "Unable to store the reported local role and trust")
		return
	}
	for _, item := range body.Items {
		var tenant string
		switch err := s.db.QueryRowContext(ctx, `SELECT id FROM tenants WHERE slug=? LIMIT 1`, item.TenantSlug).Scan(&tenant); {
		case errors.Is(err, sql.ErrNoRows):
			continue
		case err != nil:
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_SAVE_FAILED", "Unable to store the check results")
			return
		}
		state, err := s.buildKeystoreStateFor(ctx, s.db, tenant)
		// 只收发给本机的密钥的结论：主签名闸为生成请求拿到的"没有密文的项"不是一次检查
		if err != nil || !state.configured() || state.Version != item.KeystoreVersion || state.Record.TenantSlug != item.TenantSlug ||
			!containsString(state.Record.Recipients, string(machine.PublicKeySHA256)) {
			continue
		}
		check := keystoreMachineCheck{
			KeystoreVersion: item.KeystoreVersion, Decrypt: item.Decrypt, Confirmed: item.Confirmed, TrialSign: item.TrialSign, CheckedAt: iso(now),
		}
		if item.ConfirmedTrustRootsDigest != nil {
			check.ConfirmedTrustRootsDigest = optString(*item.ConfirmedTrustRootsDigest)
		}
		if item.Error != nil {
			check.Error = optString(sanitizeSignerText(*item.Error, signerErrorMaxRunes))
		}
		previousChecks, err := s.keystoreChecksFor(ctx, s.db, tenant)
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_SAVE_FAILED", "Unable to store the check results")
			return
		}
		previous, existed := previousChecks[machine.ID]
		changed := !existed || previous.KeystoreVersion != check.KeystoreVersion || previous.Decrypt != check.Decrypt ||
			previous.Confirmed != check.Confirmed || previous.ConfirmedTrustRootsDigest != check.ConfirmedTrustRootsDigest ||
			previous.TrialSign != check.TrialSign || previous.Error != check.Error
		// 签名闸每一轮轮询都会把结论报一遍。没变就不写：不加 version、不刷 updated_at，
		// 控制台上的 checkedAt 是"结论最近一次变化的时间"
		if !changed {
			continue
		}
		value, _ := json.Marshal(check)
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
			 VALUES(?,?,JSON_OBJECT('format',2,'machines',JSON_OBJECT(?,CAST(? AS JSON))),1,?,?)
			 ON DUPLICATE KEY UPDATE
			   config_value=IF(JSON_EXTRACT(app_configs.config_value,'$.format')=2 AND JSON_TYPE(JSON_EXTRACT(app_configs.config_value,'$.machines'))='OBJECT',
			                   JSON_SET(app_configs.config_value,CONCAT('$.machines.',JSON_QUOTE(?)),CAST(? AS JSON)),
			                   VALUES(config_value)),
			   version=app_configs.version+1,updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
			tenant, buildKeystoreCheckConfigKey, machine.ID, string(value), signerActor, now, machine.ID, string(value)); err != nil {
			slog.Error("cannot store a signer keystore check", "tenant", tenant, "machineId", machine.ID, "error", err)
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_SAVE_FAILED", "Unable to store the check results")
			return
		}
		s.auditNow(newAudit(tenant, signerActor, "build_keystore_check_update", "app-config", buildKeystoreCheckConfigKey,
			"a signer reported a change in its keystore check", requestID(c),
			map[string]any{"machineId": machine.ID, "name": machine.Name, "keystoreVersion": check.KeystoreVersion, "decrypt": check.Decrypt,
				"confirmed": check.Confirmed, "confirmedTrustRootsDigest": nullableString(string(check.ConfirmedTrustRootsDigest)),
				"trialSign": check.TrialSign, "error": nullableString(string(check.Error))}))
	}
	c.Status(http.StatusNoContent)
}

// machineReportedTrust 是签名闸本机记录里信任的签名闸（含本机）、构建机与恢复公钥（约定 3.4）。
// 服务端只存下来给控制台提示（"主签名闸还没信任备签名闸"之类），不据此做任何判断。
type machineReportedTrust struct {
	Signers      []reportedTrustedSigner  `json:"signers"`
	Builders     []reportedTrustedBuilder `json:"builders"`
	RecoveryKeys []string                 `json:"recoveryKeys"`
}

type reportedTrustedSigner struct {
	Name          string `json:"name"`
	X25519SHA256  string `json:"x25519Sha256"`
	Ed25519SHA256 string `json:"ed25519Sha256"`
}

type reportedTrustedBuilder struct {
	BuilderID     string `json:"builderId"`
	Ed25519SHA256 string `json:"ed25519Sha256"`
}

// withArrays 把三个列表里的 nil 换成空数组，只在渲染视图时用（库里可能有修复前写下的 null）。
func (t machineReportedTrust) withArrays() machineReportedTrust {
	if t.Signers == nil {
		t.Signers = []reportedTrustedSigner{}
	}
	if t.Builders == nil {
		t.Builders = []reportedTrustedBuilder{}
	}
	if t.RecoveryKeys == nil {
		t.RecoveryKeys = []string{}
	}
	return t
}

// normalize 校验形状并排序：同一份信任列表不管签名闸按什么顺序报，存下来都一样，"只在变化时写"才成立。
func (t machineReportedTrust) normalize() (machineReportedTrust, error) {
	if t.Signers == nil || t.Builders == nil || t.RecoveryKeys == nil {
		return t, errors.New("signers, builders and recoveryKeys must all be arrays")
	}
	if len(t.Signers) > maxRegisteredMachines || len(t.Builders) > maxRegisteredMachines || len(t.RecoveryKeys) > maxRecoveryKeys {
		return t, errors.New("too many entries")
	}
	// 空列表要存成 []，不能是 nil：机器视图里 reportedTrust 的三个字段按约定是数组，
	// 控制台按数组校验整份机器列表，出现 null 会把整页顶掉（本地端到端实测）
	out := machineReportedTrust{
		Signers:      append(make([]reportedTrustedSigner, 0, len(t.Signers)), t.Signers...),
		Builders:     append(make([]reportedTrustedBuilder, 0, len(t.Builders)), t.Builders...),
		RecoveryKeys: append(make([]string, 0, len(t.RecoveryKeys)), t.RecoveryKeys...),
	}
	for _, signer := range out.Signers {
		if !ident.ValidMachineName(signer.Name) || !fingerprint.Valid(signer.X25519SHA256) || !fingerprint.Valid(signer.Ed25519SHA256) {
			return t, errors.New("each signer needs name, x25519Sha256 and ed25519Sha256")
		}
	}
	for _, builder := range out.Builders {
		if !ident.ValidServerIDWithPrefix(builder.BuilderID, machineIDPrefix) || !fingerprint.Valid(builder.Ed25519SHA256) {
			return t, errors.New("each builder needs builderId and ed25519Sha256")
		}
	}
	for _, digest := range out.RecoveryKeys {
		if !fingerprint.Valid(digest) {
			return t, errors.New("recoveryKeys must be 64-character sha256 values")
		}
	}
	sort.Slice(out.Signers, func(i, j int) bool {
		a, b := out.Signers[i], out.Signers[j]
		return a.Name+a.X25519SHA256+a.Ed25519SHA256 < b.Name+b.X25519SHA256+b.Ed25519SHA256
	})
	sort.Slice(out.Builders, func(i, j int) bool {
		return out.Builders[i].BuilderID+out.Builders[i].Ed25519SHA256 < out.Builders[j].BuilderID+out.Builders[j].Ed25519SHA256
	})
	sort.Strings(out.RecoveryKeys)
	return out, nil
}

func (t *machineReportedTrust) equal(other *machineReportedTrust) bool {
	if t == nil || other == nil {
		return t == other
	}
	a, _ := json.Marshal(t)
	b, _ := json.Marshal(other)
	return bytes.Equal(a, b)
}

// recordSignerLocalState 把签名闸报的本机角色与信任列表记进 build.machines 它自己那一项。两样都没变
// 就不写（每轮轮询都会报，写一次加一次 version，控制台上正在编辑的机器登记就会不停地版本冲突）；
// 变了合成一次写，各自写审计；并发写冲突时重读重试。trust 为 nil（旧版本签名闸不上报）时 reportedTrust 与
// reportedTrustAt 记成 null。
func (s *server) recordSignerLocalState(c *gin.Context, machine buildMachine, role string, trust *machineReportedTrust, now time.Time) error {
	ctx := c.Request.Context()
	for attempt := 0; attempt < machineWriteRetries; attempt++ {
		snapshot, err := readMachineRegistry(ctx, s.db, false)
		if err != nil {
			return err
		}
		index, found := snapshot.Doc.find(machine.ID)
		if !found {
			return errors.New("the signer is no longer registered")
		}
		m := &snapshot.Doc.Machines[index]
		roleChanged := string(m.ReportedLocalRole) != role
		trustChanged := !m.ReportedTrust.equal(trust)
		if !roleChanged && !trustChanged {
			return nil
		}
		events := []auditEvent{}
		if roleChanged {
			previous := string(m.ReportedLocalRole)
			m.ReportedLocalRole, m.ReportedLocalRoleAt = optString(role), optString(iso(now))
			events = append(events, newAudit(platformTenantID, signerActor, "build_machine_local_role_report", machineAuditTargetType, machine.ID,
				"a signer reported a change of its local role", requestID(c),
				map[string]any{"machineId": machine.ID, "name": machine.Name, "reportedLocalRole": role, "previousReportedLocalRole": nullableString(previous),
					"signerRole": nullableString(string(m.SignerRole))}))
		}
		if trustChanged {
			reason := "a signer reported a change of its local trust"
			if trust == nil {
				m.ReportedTrust, m.ReportedTrustAt = nil, ""
				reason = "a signer reported without its local trust (an older signer version); the reported trust is cleared"
			} else {
				reported := *trust
				m.ReportedTrust, m.ReportedTrustAt = &reported, optString(iso(now))
			}
			events = append(events, newAudit(platformTenantID, signerActor, "build_machine_trust_report", machineAuditTargetType, machine.ID,
				reason, requestID(c), map[string]any{"machineId": machine.ID, "name": machine.Name, "reportedTrust": m.ReportedTrust}))
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		applied, err := writeMachineRegistry(ctx, tx, snapshot.Doc, snapshot.Version, signerActor, now)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if !applied {
			_ = tx.Rollback()
			continue
		}
		for _, event := range events {
			if err := insertAudit(ctx, tx, event); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		return tx.Commit()
	}
	return errors.New("the machine registry kept changing while recording the local role and trust")
}

// ---- 认领 ----

type signerReadyItem struct {
	TenantSlug        string `json:"tenantSlug"`
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	TrustRootsDigest  string `json:"trustRootsDigest"`
}

func (r signerReadyItem) key() string {
	return r.TenantSlug + "\n" + r.PackageName + "\n" + r.CertificateSHA256 + "\n" + r.TrustRootsDigest
}

// claimSigningJob 给主签名闸派一条待签名的任务。
//
// 只派：状态 built 的安装包任务；它是同租户同平台在途任务里 build 号最小的那条（不然大号
// 先签出来，小号就再也发不出去）；租户就绪（与排队门禁同一个判断）；签名闸报上来的就绪
// 列表里有一项与服务端当前的 (slug, 包名, 证书, 信任根摘要) 完全一致。本机不是 active 的
// 主签名闸时直接 204：服务端的主备登记只用来路由，签名闸自己还会再核对本机角色。
func (s *server) claimSigningJob(c *gin.Context) {
	machine, _ := machineFromContext(c)
	var body struct {
		Ready []signerReadyItem `json:"ready"`
	}
	if decode(c, &body) != nil || body.Ready == nil || len(body.Ready) > maxSignerListItems {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_CLAIM", fmt.Sprintf("ready must be an array of at most %d items", maxSignerListItems))
		return
	}
	ready := map[string]bool{}
	slugs := map[string]bool{}
	for _, item := range body.Ready {
		if !ident.ValidTenantSlug(item.TenantSlug) || !ident.ValidPackageName(item.PackageName) ||
			!fingerprint.Valid(item.CertificateSHA256) || !fingerprint.Valid(item.TrustRootsDigest) {
			problem(c, http.StatusBadRequest, "INVALID_SIGN_CLAIM", "each ready item needs tenantSlug, packageName, certificateSha256 and trustRootsDigest")
			return
		}
		ready[item.key()] = true
		slugs[item.TenantSlug] = true
	}
	if !machine.isActivePrimary() || len(ready) == 0 {
		c.Status(http.StatusNoContent)
		return
	}
	ctx := c.Request.Context()
	// 候选是"签名闸报了就绪的租户里，各自在途 build 号最小、且已经构建完的那一条"：NOT EXISTS 保证
	// 每个租户每个平台至多一条，所以候选数不超过就绪列表里的租户数（至多 maxSignerListItems），
	// 不设 LIMIT。以前按创建时间取前 50 条：排在前面的租户长期不就绪时，后面的租户永远轮不到。
	slugArgs := make([]any, 0, len(slugs))
	for slug := range slugs {
		slugArgs = append(slugArgs, slug)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT j.id FROM build_jobs j JOIN tenants t ON t.id=j.tenant_id
		  WHERE j.kind='apk' AND j.platform='android' AND j.status='built'
		    AND t.slug IN (`+strings.TrimSuffix(strings.Repeat("?,", len(slugArgs)), ",")+`)
		    AND NOT EXISTS (SELECT 1 FROM build_jobs o WHERE o.tenant_id=j.tenant_id AND o.platform=j.platform AND o.kind='apk'
		                     AND o.status IN (`+sqlInFlight+`) AND o.build_number<j.build_number)
		  ORDER BY j.created_at,j.id`, slugArgs...)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to look for builds to sign")
		return
	}
	candidates := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to look for builds to sign")
			return
		}
		candidates = append(candidates, id)
	}
	rows.Close()
	for _, id := range candidates {
		job, err := scanBuildJob(s.db.QueryRowContext(ctx, `SELECT `+buildJobColumns+` FROM build_jobs WHERE id=?`, id))
		if err != nil {
			continue
		}
		if deferredRecentlyBy(job, machine.ID, time.Now().UTC()) {
			continue
		}
		response, ok := s.signingDispatch(ctx, job, machine, ready)
		if !ok {
			continue
		}
		claimed, err := s.claimForSigning(ctx, c, job, machine)
		if err != nil {
			slog.Error("cannot claim a build to sign", "job", job.ID, "error", err)
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build to sign")
			return
		}
		if !claimed {
			continue
		}
		response["job"].(gin.H)["signAttempt"] = job.SignAttempt + 1
		c.JSON(http.StatusOK, response)
		return
	}
	c.Status(http.StatusNoContent)
}

// deferredRecentlyBy：这条任务最近一次没签成的原因是这台签名闸在冷却期内说的"暂不能签"。
func deferredRecentlyBy(job buildJob, machineID string, now time.Time) bool {
	if len(job.SignOutcome) == 0 {
		return false
	}
	var outcome buildJobSignOutcome
	if json.Unmarshal(job.SignOutcome, &outcome) != nil || outcome.Kind != "deferred" || outcome.MachineID != machineID {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, outcome.At)
	if err != nil {
		return false
	}
	return now.Sub(at) < signDeferralCooldown
}

// claimForSigning 在发布序列锁（与手工上传、签名完成同一把）里认领一条签名任务：先比对已有
// 发布，再把任务改为 signing。claimed=false 表示这一轮没派出去（被别人抢先、锁忙或已判失败）。
//
// 手工上传只在该租户有 built/signing 任务时被挡（RELEASE_SIGNING_IN_FLIGHT），任务还在排队或
// 构建时照常放行。放进来的版本不低于这条任务时，任务签出来也入不了库（完成时
// RELEASE_VERSION_NOT_INCREASING），而签名闸已经在本机记录里占掉了这个 versionCode。所以这种
// 任务不派，当场判失败并写明原因。比对与认领在同一把锁里：手工上传的在途检查和入库也在这把锁
// 里，两边谁先谁后都不会漏。
func (s *server) claimForSigning(ctx context.Context, c *gin.Context, job buildJob, machine buildMachine) (bool, error) {
	claimed := false
	var overtaken *latestRelease
	reason := ""
	now := time.Now().UTC()
	// 提交之后要删的对象：认领时是上一次签名认领交回的已签名包；判失败时是全部交付
	var abandoned []string
	rejection, err := s.withReleaseSequence(ctx, job.TenantID, job.Platform, func(tx *sql.Tx) (*releaseRejection, error) {
		var keys jobObjectKeys
		switch err := tx.QueryRowContext(ctx,
			`SELECT `+jobObjectKeyColumns+` FROM build_jobs WHERE id=? AND kind='apk' AND status IN (`+sqlStatusList(buildJobEventFrom(eventSignerClaim, jobKindAPK))+`) AND sign_attempt=? FOR UPDATE`,
			job.ID, job.SignAttempt).Scan(&keys.Unsigned, &keys.SBOM, &keys.Signed); {
		case errors.Is(err, sql.ErrNoRows):
			return nil, nil
		case err != nil:
			return nil, err
		}
		latest, err := latestReleaseFor(ctx, tx, job.TenantID, job.Platform)
		if err != nil {
			return nil, err
		}
		if !latest.increasedBy(job.Version, job.BuildNumber) {
			reason = clipRunes(fmt.Sprintf("构建期间该平台已经发布了版本 %s（build %d），这个任务的版本 %s（build %d）不再递增，签出来也入不了库，没有派给签名闸。用更高的版本号与 build 号重新排一个任务。",
				latest.Version.String, latest.BuildNumber, job.Version, job.BuildNumber), 500)
			if _, err := tx.ExecContext(ctx, `UPDATE build_jobs SET status='failed',failure_reason=?,updated_at=?`+releaseAllDeliveries.clearColumns()+` WHERE id=?`,
				reason, now, job.ID); err != nil {
				return nil, err
			}
			overtaken, abandoned = &latest, keys.pick(releaseAllDeliveries)
			return nil, nil
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE build_jobs SET status='signing',sign_attempt=sign_attempt+1,signing_machine_id=?,signing_claimed_at=?,signing_heartbeat_at=?,signed_object_key=NULL,updated_at=? WHERE id=?`,
			machine.ID, now, now, now, job.ID); err != nil {
			return nil, err
		}
		claimed, abandoned = true, keys.pick(releaseSigned)
		return nil, nil
	})
	if err != nil {
		return false, err
	}
	if rejection != nil {
		// 发布序列锁忙（正在入库）：这一轮不派，签名闸下一轮再来
		return false, nil
	}
	s.deleteDeliveryObjects(job.TenantID, job.ID, abandoned)
	if overtaken != nil {
		slog.Warn("failed a build overtaken by a newer release before signing", "job", job.ID, "tenant", job.TenantID,
			"version", job.Version, "buildNumber", job.BuildNumber, "latestVersion", overtaken.Version.String, "latestBuildNumber", overtaken.BuildNumber)
		s.auditNow(newAudit(job.TenantID, builderSystemActor, "build_job_sign_overtaken", "build-job", job.ID, reason, requestID(c),
			map[string]any{"jobId": job.ID, "version": job.Version, "buildNumber": job.BuildNumber,
				"latestVersion": overtaken.Version.String, "latestBuildNumber": overtaken.BuildNumber}))
	}
	return claimed, nil
}

// signingDispatch 判断一条候选任务能不能派给这台签名闸，能的话把响应拼好（认领之前拼，
// 拼不出来就不认领，不留下一条没人在签的 signing）。
func (s *server) signingDispatch(ctx context.Context, job buildJob, machine buildMachine, ready map[string]bool) (gin.H, bool) {
	readiness, err := s.signerReadinessFor(ctx, job.TenantID)
	if err != nil {
		slog.Error("cannot evaluate signer readiness for a build to sign", "job", job.ID, "tenant", job.TenantID, "error", err)
		return nil, false
	}
	if !readiness.Ready || readiness.Primary == nil || readiness.Primary.ID != machine.ID || readiness.Box == nil || readiness.Roots == nil {
		return nil, false
	}
	record := readiness.Keystore.Record
	if !ready[signerReadyItem{TenantSlug: record.TenantSlug, PackageName: record.PackageName, CertificateSHA256: record.CertificateSHA256, TrustRootsDigest: readiness.Digest}.key()] {
		return nil, false
	}
	var provenanceRecord buildProvenanceRecord
	if err := json.Unmarshal(job.Provenance, &provenanceRecord); err != nil || provenanceRecord.Statement == "" {
		slog.Error("a built job has no readable provenance", "job", job.ID, "error", err)
		return nil, false
	}
	if !job.UnsignedSHA256.Valid || !job.SBOMSHA256.Valid || !job.NativeFingerprint.Valid || !job.CommitSHA.Valid {
		slog.Error("a built job is missing its delivery", "job", job.ID)
		return nil, false
	}
	return gin.H{
		"job": gin.H{
			"id": job.ID, "tenantSlug": record.TenantSlug, "platform": job.Platform, "version": job.Version, "buildNumber": job.BuildNumber,
			"attempt": job.Attempt, "signAttempt": job.SignAttempt, "commitSha": job.CommitSHA.String,
			"unsignedSha256": job.UnsignedSHA256.String, "unsignedSize": job.UnsignedSize.Int64,
			"sbomSha256": job.SBOMSHA256.String, "nativeFingerprint": job.NativeFingerprint.String,
		},
		"provenance": gin.H{
			"statement": provenanceRecord.Statement, "signature": provenanceRecord.Signature, "builderId": provenanceRecord.BuilderID,
			"builderPublicKey": provenanceRecord.BuilderPublicKey, "builderPublicKeySha256": provenanceRecord.BuilderPublicKeySHA256,
		},
		// 服务端给的 keyAlias 与 trustRoots 只作对照，签名闸不采信
		"keystore": gin.H{
			"keystoreVersion": readiness.Keystore.Version, "packageName": record.PackageName,
			"certificateSha256": record.CertificateSHA256, "keyAlias": record.KeyAlias, "box": *readiness.Box,
		},
		"trustRoots":       *readiness.Roots,
		"trustRootsDigest": readiness.Digest,
	}, true
}

// ---- 任务作用域 ----

// signerJobScope 校验"这台签名闸、这次签名认领、这条任务还在签名中"。
func (s *server) signerJobScope(next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		job, ok := s.currentSigningJob(c)
		if !ok {
			return
		}
		c.Set("tenantId", job.TenantID)
		c.Set("signingJob", job)
		next(c)
	}
}

func (s *server) currentSigningJob(c *gin.Context) (buildJob, bool) {
	machine, _ := machineFromContext(c)
	attempt, ok := attemptFromHeader(c, signAttemptHeader)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_ATTEMPT", "x-sign-attempt must carry the sign attempt number returned by claim")
		return buildJob{}, false
	}
	job, err := s.loadBuildJob(c, "", c.Param("id"))
	if err != nil {
		return buildJob{}, false
	}
	if job.Kind != jobKindAPK || !buildJobTransitionAllowed(eventSignerHeartbeat, job.Kind, job.Status) ||
		job.SignAttempt != attempt || job.SigningMachineID.String != machine.ID {
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return buildJob{}, false
	}
	return job, true
}

func signingJobFromContext(c *gin.Context) buildJob {
	item, _ := c.Get("signingJob")
	job, _ := item.(buildJob)
	return job
}

// signingGuard 是签名闸所有状态更新共用的 WHERE：状态、编号、机器都要对得上。
const signingGuard = ` WHERE ` + signingCondition

const signingCondition = `id=? AND kind='apk' AND status='signing' AND sign_attempt=? AND signing_machine_id=?`

// refreshSigningHeartbeat 刷新签名心跳。只改心跳时间：同一毫秒里重复刷新时值不变、RowsAffected 是 0，
// 用 rowsMatched 复查条件，免得把一次正常的心跳判成 SIGN_ATTEMPT_STALE。
func (s *server) refreshSigningHeartbeat(ctx context.Context, jobID string, attempt int, machineID string) (bool, error) {
	now := s.now()
	result, err := s.db.ExecContext(ctx, `UPDATE build_jobs SET signing_heartbeat_at=?,updated_at=?`+signingGuard, now, now, jobID, attempt, machineID)
	if err != nil {
		return false, err
	}
	return rowsMatched(ctx, s.db, result, "build_jobs", signingCondition, jobID, attempt, machineID)
}

func (s *server) signingHeartbeat(c *gin.Context) {
	machine, _ := machineFromContext(c)
	attempt, ok := attemptFromHeader(c, signAttemptHeader)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_ATTEMPT", "x-sign-attempt must carry the sign attempt number returned by claim")
		return
	}
	matched, err := s.refreshSigningHeartbeat(c.Request.Context(), c.Param("id"), attempt, machine.ID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record signing progress")
		return
	}
	if !matched {
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- 取未签名包、交已签名包 ----

func (s *server) downloadUnsignedForSigning(c *gin.Context) {
	job := signingJobFromContext(c)
	if !job.UnsignedObjectKey.Valid || !job.UnsignedSize.Valid || !job.UnsignedSHA256.Valid {
		problem(c, http.StatusConflict, "UNSIGNED_ARTIFACT_MISSING", "This build has no unsigned package recorded")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	info, err := client.Stat(c.Request.Context(), job.UnsignedObjectKey.String)
	if err != nil || info.Size != job.UnsignedSize.Int64 {
		problem(c, http.StatusFailedDependency, "UNSIGNED_ARTIFACT_MISSING", "The unsigned package in storage is missing or has an unexpected size")
		return
	}
	body, err := client.Get(c.Request.Context(), job.UnsignedObjectKey.String)
	if err != nil {
		problem(c, http.StatusFailedDependency, "UNSIGNED_ARTIFACT_MISSING", "Unable to read the unsigned package")
		return
	}
	defer body.Close()
	// sha256 是服务端收流时算的；签名闸下载后自己再算一遍，不采信这个头
	c.Header("Content-Type", octetStream)
	c.Header("Content-Length", strconv.FormatInt(job.UnsignedSize.Int64, 10))
	c.Header("x-content-sha256", job.UnsignedSHA256.String)
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, body); err != nil {
		slog.Error("unsigned package download stream failed", "job", job.ID, "error", err)
	}
}

func (s *server) uploadSignedArtifact(c *gin.Context) {
	job := signingJobFromContext(c)
	machine, _ := machineFromContext(c)
	client, prefix, err := s.storageClientForTenant(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	// 每次上传一个新键（见 deliveryObjectSegment）：迟到的上传覆盖不了、也删不掉已经落进发布记录的包
	key := buildJobObjectKey(prefix, job.TenantID, job.ID, deliveryObjectSegment("s", job.SignAttempt), signedAPKObjectName)
	received, status, code, detail := s.receiveStreamToObject(c, client, key, s.cfg.ArtifactMaxSizeBytes)
	if status != 0 {
		problem(c, status, code, detail)
		return
	}
	received.cleanup()
	now := time.Now().UTC()
	// 收流期间任务被回收、强制判失败或已经完成时认领不再有效：只删自己刚写的对象
	replaced, current, err := s.recordDeliveredObject(context.Background(),
		`SELECT signed_object_key FROM build_jobs`+signingGuard, []any{job.ID, job.SignAttempt, machine.ID},
		`UPDATE build_jobs SET signed_object_key=?,signing_heartbeat_at=?,updated_at=? WHERE id=?`, []any{key, now, now, job.ID})
	if err != nil {
		slog.Error("cannot record a signed package", "job", job.ID, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the signed package")
		return
	}
	if !current {
		_ = client.Delete(context.Background(), key)
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return
	}
	// 替换下来的旧包还没落进发布记录：complete 在事务里核对键没变，正在复核旧包的那次 complete 会被 409
	deleteReplacedObject(client, replaced, key, job.ID)
	c.JSON(http.StatusOK, gin.H{"sha256": received.sha256, "size": received.size})
}

// ---- 完成 ----

// 故障注入点（只给测试）：完成事务里各个会崩的位置
const (
	faultAfterVerification   = "after-verification"
	faultBeforeReleaseInsert = "before-release-insert"
	faultAfterReleaseInsert  = "after-release-insert"
	faultAfterJobUpdate      = "after-job-update"
	faultAfterCommit         = "after-commit"
)

func (s *server) injectSignFault(point string) error {
	if s.signCompleteFault == nil {
		return nil
	}
	return s.signCompleteFault(point)
}

// completeSigning 落发布记录并完成任务，**同一个事务**，幂等。
//
// 事务外：取回签名闸交回的已签名包，走与手工上传同一套入库校验（签名者 = 登记证书 = 请求值、
// 包名、versionName/Code、非公开 debug、非作废指纹）。事务内：锁住任务行，校验状态、编号、
// 机器，版本递增校验，写 app_releases，任务改为 succeeded 并写 release_id 与 artifact_sha256。
//
// 落发布记录与完成任务不在一个事务里时，崩在两步之间的任务永远签不出来：签名闸本机记录
// 里这个 versionCode 已经预留，再签一次会被本机拒绝，而服务端这边任务还停在 signing。
// 任务已是 succeeded 且已签名包 sha256 相同，按幂等成功返回同一个 releaseId——签名闸没收到
// 响应时会重试。
func (s *server) completeSigning(c *gin.Context) {
	machine, _ := machineFromContext(c)
	attempt, ok := attemptFromHeader(c, signAttemptHeader)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_ATTEMPT", "x-sign-attempt must carry the sign attempt number returned by claim")
		return
	}
	var body struct {
		SignedSHA256      string `json:"signedSha256"`
		SignedSize        int64  `json:"signedSize"`
		CertificateSHA256 string `json:"certificateSha256"`
		UnsignedSHA256    string `json:"unsignedSha256"`
		NativeFingerprint string `json:"nativeFingerprint"`
	}
	if decode(c, &body) != nil || !fingerprint.Valid(body.SignedSHA256) || body.SignedSize < 1 || !fingerprint.Valid(body.CertificateSHA256) ||
		!fingerprint.Valid(body.UnsignedSHA256) || !nativeFingerprintPattern.MatchString(body.NativeFingerprint) {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_RESULT", "signedSha256, signedSize, certificateSha256, unsignedSha256 and nativeFingerprint are required as lowercase hex")
		return
	}
	ctx := c.Request.Context()
	job, err := s.loadBuildJob(c, "", c.Param("id"))
	if err != nil {
		return
	}
	if job.Kind != jobKindAPK {
		problem(c, http.StatusConflict, "BUILD_KIND_MISMATCH", "Only installable-package builds are signed")
		return
	}
	// 幂等重试只认同一台签名闸、同一次签名认领交回的同一个包：别的签名闸或过期编号拿着同一个
	// sha256 来，不能从这里拿到"成功"
	if job.Status == jobSucceeded && job.ArtifactSHA256.String == body.SignedSHA256 && job.ReleaseID.Valid &&
		job.SignAttempt == attempt && job.SigningMachineID.String == machine.ID {
		c.JSON(http.StatusOK, gin.H{"releaseId": job.ReleaseID.String})
		return
	}
	// 同一台签名闸、同一次签名认领已经完成过，这次交来的却是另一个包：不是过期认领，而是
	// 结果冲突——已经落库的发布记录是另一个 sha256，不会被替换
	if job.Status == jobSucceeded && job.ReleaseID.Valid && job.SignAttempt == attempt && job.SigningMachineID.String == machine.ID {
		problem(c, http.StatusConflict, "SIGN_RESULT_CONFLICT", "This signing claim already completed with a different signed package; the recorded release is not replaced")
		return
	}
	if job.Status != jobSigning || job.SignAttempt != attempt || job.SigningMachineID.String != machine.ID {
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return
	}
	if !job.SignedObjectKey.Valid || job.SignedObjectKey.String == "" {
		problem(c, http.StatusConflict, "SIGNED_ARTIFACT_MISSING", "Upload the signed package for this signing claim before completing it")
		return
	}
	// 下载与复核大包可能要几分钟：先刷新签名心跳，免得复核还没做完任务就被回收器退回待签名
	if matched, err := s.refreshSigningHeartbeat(ctx, job.ID, attempt, machine.ID); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record signing progress")
		return
	} else if !matched {
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return
	}
	rejectedBySigner := func(status int, code, detail string, summary map[string]any) {
		audit := map[string]any{"code": code, "jobId": job.ID, "signAttempt": attempt, "signerMachineId": machine.ID, "signedSha256": body.SignedSHA256}
		for key, value := range summary {
			audit[key] = value
		}
		s.auditNow(newAudit(job.TenantID, signerActor, "release_rejected", "build-job", job.ID, detail, requestID(c), audit))
		problem(c, status, code, detail)
	}
	if body.UnsignedSHA256 != job.UnsignedSHA256.String {
		rejectedBySigner(http.StatusUnprocessableEntity, "SIGN_RESULT_MISMATCH", "unsignedSha256 does not match the unsigned package the builder delivered for this job", nil)
		return
	}
	// 原生指纹不能从已签名包里读出来（包里没有 assets/fingerprint），服务端记的是构建机上报、
	// 经出处声明核对过的值；签名闸带来的必须与它一致，说明两边说的是同一个构建
	if body.NativeFingerprint != job.NativeFingerprint.String {
		rejectedBySigner(http.StatusUnprocessableEntity, "SIGN_RESULT_MISMATCH", "nativeFingerprint does not match the value in the builder's verified provenance for this job", nil)
		return
	}
	if code, detail := androidSignerRetirement(body.CertificateSHA256); code != "" {
		rejectedBySigner(http.StatusUnprocessableEntity, code, detail, nil)
		return
	}
	keystore, err := s.buildKeystoreStateFor(ctx, s.db, job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Stored build.keystore configuration cannot be read")
		return
	}
	if !keystore.configured() || keystore.Record.CertificateSHA256 != body.CertificateSHA256 {
		rejectedBySigner(http.StatusUnprocessableEntity, "RELEASE_SIGNER_MISMATCH", "certificateSha256 is not the certificate of this tenant's registered signing keystore", nil)
		return
	}
	client, _, err := s.storageClientForTenant(ctx, job.TenantID)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	// 只从任务行记下的键取包：键由上传时写入，不按编号现拼（同一次认领可能重传过）
	key := job.SignedObjectKey.String
	verifyCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	stored, rejection := s.downloadStoredArtifact(verifyCtx, client, key, body.SignedSize)
	if rejection != nil {
		problem(c, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	defer os.Remove(stored.Path)
	if stored.SHA256 != body.SignedSHA256 {
		rejectedBySigner(http.StatusUnprocessableEntity, "SIGNED_ARTIFACT_MISMATCH", "The signed package in storage does not have the reported sha256", map[string]any{"storedSha256": stored.SHA256})
		return
	}
	verified, rejection, err := s.verifyAndroidArtifact(verifyCtx, job.TenantID, stored.Path, job.Version, job.BuildNumber)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
		return
	}
	if rejection != nil {
		rejectedBySigner(rejection.Status, rejection.Code, rejection.Detail, rejection.Summary)
		return
	}
	if normalizeFingerprint(verified.APK.SignerSHA256) != body.CertificateSHA256 {
		rejectedBySigner(http.StatusUnprocessableEntity, "RELEASE_SIGNER_MISMATCH", "The package is not signed with the reported certificate", nil)
		return
	}
	if err := s.injectSignFault(faultAfterVerification); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to record the signed release; retry with the same signed package")
		return
	}
	slug, err := s.tenantSlug(ctx, job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to resolve the tenant of this build")
		return
	}
	metadata := map[string]any{}
	for k, v := range verified.Metadata {
		metadata[k] = v
	}
	fileName := fmt.Sprintf("%s-%s-build%d-release.apk", strings.ToLower(slug), job.Version, job.BuildNumber)
	metadata["fileName"], metadata["size"], metadata["sha256"], metadata["objectEtag"] = fileName, stored.Size, stored.SHA256, stored.ETag
	// 发布元数据记全链路：未签名包、SBOM、原生指纹、自报的 commit、哪台构建机、哪台签名闸。
	// 原生指纹取任务行上经出处声明核对过的构建机上报值，并注明来源：它不是从包里读出来的
	metadata["unsignedSha256"] = job.UnsignedSHA256.String
	metadata["sbom"] = map[string]any{"fileName": sbomObjectName, "objectKey": job.SBOMObjectKey.String, "size": job.SBOMSize.Int64, "sha256": job.SBOMSHA256.String, "format": "cyclonedx-json"}
	metadata["nativeFingerprint"] = job.NativeFingerprint.String
	metadata["nativeFingerprintSource"] = nativeFingerprintFromProvenance
	metadata["commitSha"] = job.CommitSHA.String
	metadata["commitSelfReported"] = true
	metadata["buildJobId"] = job.ID
	metadata["builderId"] = job.ClaimedMachineID.String
	metadata["signerMachineId"] = machine.ID
	notes := buildJobReleaseNotes(job)
	now := time.Now().UTC()
	insert := releaseInsert{
		ID: "rel_" + randomID(16), Tenant: job.TenantID, Platform: job.Platform, Version: job.Version, BuildNumber: job.BuildNumber,
		RuntimeVersion: verified.RuntimeVersion, ObjectKey: key, FileName: fileName, ContentType: apkContentType,
		ExpectedSize: body.SignedSize, FileSize: stored.Size, SHA256: stored.SHA256, Metadata: metadata, Notes: notes,
		Actor: signerActor, RequestID: requestID(c), AuditReason: "the primary signer delivered a signed package",
		AuditSummary: map[string]any{"buildJobId": job.ID, "signerMachineId": machine.ID, "signAttempt": attempt},
	}
	releaseID := ""
	rejection, err = s.withReleaseSequence(ctx, job.TenantID, job.Platform, func(tx *sql.Tx) (*releaseRejection, error) {
		var status string
		var lockedAttempt int
		var lockedMachine, lockedArtifact, lockedRelease, lockedKey sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT status,sign_attempt,signing_machine_id,artifact_sha256,release_id,signed_object_key FROM build_jobs WHERE id=? FOR UPDATE`, job.ID).
			Scan(&status, &lockedAttempt, &lockedMachine, &lockedArtifact, &lockedRelease, &lockedKey); err != nil {
			return nil, err
		}
		if status == jobSucceeded && lockedArtifact.String == body.SignedSHA256 && lockedRelease.Valid &&
			lockedAttempt == attempt && lockedMachine.String == machine.ID {
			releaseID = lockedRelease.String
			return nil, nil
		}
		if status == jobSucceeded && lockedRelease.Valid && lockedAttempt == attempt && lockedMachine.String == machine.ID {
			return &releaseRejection{Status: http.StatusConflict, Code: "SIGN_RESULT_CONFLICT", Detail: "This signing claim already completed with a different signed package; the recorded release is not replaced"}, nil
		}
		if status != jobSigning || lockedAttempt != attempt || lockedMachine.String != machine.ID {
			return &releaseRejection{Status: http.StatusConflict, Code: "SIGN_ATTEMPT_STALE", Detail: "This signing claim is no longer current for this signer; stop working on the job"}, nil
		}
		// 复核期间签名闸又传了一次：复核的那个对象已经被替换删除，按新键重来
		if lockedKey.String != key {
			return &releaseRejection{Status: http.StatusConflict, Code: "SIGNED_ARTIFACT_REPLACED", Detail: "The signed package was uploaded again while this completion was being verified; call complete again"}, nil
		}
		// 鉴权只在请求开始时做过一次，而事务外的下载与复核可能要几分钟：落库前再看一眼这台
		// 签名闸有没有在这期间被吊销
		registry, err := readMachineRegistry(ctx, tx, false)
		if err != nil {
			return nil, err
		}
		if index, found := registry.Doc.find(machine.ID); !found || registry.Doc.Machines[index].Status != machineStatusActive || registry.Doc.Machines[index].Role != machineRoleSigner {
			return &releaseRejection{Status: http.StatusUnauthorized, Code: "MACHINE_REVOKED", Detail: "This signer was revoked while its package was being verified"}, nil
		}
		// 事务外的复核读的是那一刻的发布身份与签名密钥。复核期间管理员换了密钥或改了登记的
		// 证书指纹，这个包就不再是"用登记证书签的"：在事务里带共享锁再读一次（挡住并发的保存
		// 提交到本事务结束），对不上就拒绝，签名闸重试时按新登记重新复核
		if changed, err := signingIdentityChanged(ctx, tx, job.TenantID, verified.APK.PackageName, body.CertificateSHA256); err != nil {
			return nil, err
		} else if changed {
			return &releaseRejection{Status: http.StatusConflict, Code: "RELEASE_IDENTITY_CHANGED",
				Detail: "The registered release identity or signing keystore changed while this package was being verified; call complete again"}, nil
		}
		if err := s.injectSignFault(faultBeforeReleaseInsert); err != nil {
			return nil, err
		}
		if rejection, err := insertReleaseInTx(ctx, tx, insert, now); err != nil || rejection != nil {
			return rejection, err
		}
		if err := s.injectSignFault(faultAfterReleaseInsert); err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE build_jobs SET status='succeeded',release_id=?,artifact_sha256=?,signing_heartbeat_at=?,updated_at=?`+signingGuard,
			insert.ID, stored.SHA256, now, now, job.ID, attempt, machine.ID)
		if err != nil {
			return nil, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, errors.New("the locked build job did not accept the completion")
		}
		if err := s.injectSignFault(faultAfterJobUpdate); err != nil {
			return nil, err
		}
		if err := insertAudit(ctx, tx, newAudit(job.TenantID, signerActor, "build_job_signed", "build-job", job.ID, "the primary signer signed this build", requestID(c),
			map[string]any{"jobId": job.ID, "releaseId": insert.ID, "signAttempt": attempt, "signerMachineId": machine.ID, "builderId": job.ClaimedMachineID.String,
				"signedSha256": stored.SHA256, "unsignedSha256": job.UnsignedSHA256.String, "certificateSha256": body.CertificateSHA256})); err != nil {
			return nil, err
		}
		releaseID = insert.ID
		return nil, nil
	})
	if err != nil {
		slog.Error("cannot complete a signed build", "job", job.ID, "error", err)
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to record the signed release; retry with the same signed package")
		return
	}
	if rejection != nil {
		if rejection.Code == "RELEASE_IDENTITY_CHANGED" {
			rejectedBySigner(rejection.Status, rejection.Code, rejection.Detail, nil)
			return
		}
		problem(c, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	if err := s.injectSignFault(faultAfterCommit); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to record the signed release; retry with the same signed package")
		return
	}
	c.JSON(http.StatusOK, gin.H{"releaseId": releaseID})
}

// nativeFingerprintFromProvenance 是发布记录 file_metadata.nativeFingerprintSource 的值：原生指纹
// 来自构建机的出处声明（服务端验过签名、与任务行一致），不是从已签名包里读出来的。
const nativeFingerprintFromProvenance = "builder-provenance"

// signingIdentityChanged 在完成事务里带共享锁重读 release.android 与 build.keystore，判断复核之后
// 登记的包名、证书指纹或签名密钥是否已经变了。
func signingIdentityChanged(ctx context.Context, tx *sql.Tx, tenant, packageName, certificateSHA256 string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT config_key,config_value FROM app_configs WHERE tenant_id=? AND config_key IN (?,?) FOR SHARE`,
		tenant, releaseAndroidIdentityConfigKey, buildKeystoreConfigKey)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	values := map[string][]byte{}
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return false, err
		}
		values[key] = raw
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	identityRaw, hasIdentity := values[releaseAndroidIdentityConfigKey]
	keystoreRaw, hasKeystore := values[buildKeystoreConfigKey]
	if !hasIdentity || !hasKeystore {
		return true, nil
	}
	identity, err := parseAndroidReleaseIdentity(identityRaw)
	if err != nil {
		return false, err
	}
	record, legacy, err := parseBuildKeystoreValue(keystoreRaw)
	if err != nil {
		return false, err
	}
	return legacy || identity.PackageName != packageName || identity.SignerSHA256 != certificateSHA256 ||
		record.PackageName != packageName || record.CertificateSHA256 != certificateSHA256, nil
}

// ---- 暂不能签与拒签 ----

func decodeSignerOutcome(c *gin.Context, withKind bool) (buildJobSignOutcome, bool) {
	var body struct {
		Kind   string `json:"kind"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	var err error
	if withKind {
		err = decode(c, &body)
	} else {
		var plain struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		err = decode(c, &plain)
		body.Code, body.Detail = plain.Code, plain.Detail
	}
	if err != nil || !signerCodePattern.MatchString(body.Code) || (withKind && body.Kind != "violation" && body.Kind != "transient") {
		return buildJobSignOutcome{}, false
	}
	return buildJobSignOutcome{Kind: body.Kind, Code: body.Code, Detail: sanitizeSignerText(body.Detail, signerDetailMaxRunes)}, true
}

// releaseSigningJob：暂不能签（本机未确认该租户、信任根刚改未重新确认、本机是备），
// 任务退回待签名，不计失败次数。
func (s *server) releaseSigningJob(c *gin.Context) {
	machine, _ := machineFromContext(c)
	attempt, ok := attemptFromHeader(c, signAttemptHeader)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_ATTEMPT", "x-sign-attempt must carry the sign attempt number returned by claim")
		return
	}
	outcome, ok := decodeSignerOutcome(c, false)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_OUTCOME", "code (UPPER_SNAKE_CASE) and detail are required")
		return
	}
	now := time.Now().UTC()
	outcome.Kind, outcome.MachineID, outcome.At = "deferred", machine.ID, iso(now)
	raw, _ := json.Marshal(outcome)
	// 退回待签名：这一次签名认领交回的包（如果有）作废，下一次认领重新签
	_, matched, err := s.transitionBuildJob(c.Request.Context(), c.Param("id"), jobTransition{
		Where: signingGuard, WhereArgs: []any{c.Param("id"), attempt, machine.ID},
		Set: `status='built',sign_outcome=?,signing_heartbeat_at=?,updated_at=?`, SetArgs: []any{raw, now, now},
		Release: releaseSigned,
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to release the build")
		return
	}
	if !matched {
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return
	}
	c.Status(http.StatusNoContent)
}

// rejectSigningJob：violation 是策略不过（出处、包结构、身份、版本、权限、信任根），任务终态失败
// 并写审计；transient 是网络、服务端 5xx、RELEASE_SEQUENCE_BUSY 这类临时错误重试后放弃，
// 计一次签名失败，到上限判失败，否则退回待签名。
func (s *server) rejectSigningJob(c *gin.Context) {
	job, ok := s.currentSigningJob(c)
	if !ok {
		return
	}
	machine, _ := machineFromContext(c)
	outcome, ok := decodeSignerOutcome(c, true)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_SIGN_OUTCOME", "kind (violation or transient), code (UPPER_SNAKE_CASE) and detail are required")
		return
	}
	ctx := c.Request.Context()
	now := time.Now().UTC()
	outcome.MachineID, outcome.At = machine.ID, iso(now)
	raw, _ := json.Marshal(outcome)
	failed := outcome.Kind == "violation" || job.SignFailures+1 >= maxSignFailures
	nextStatus := jobBuilt
	reason := sql.NullString{}
	failures := job.SignFailures
	if outcome.Kind == "transient" {
		failures++
	}
	if failed {
		nextStatus = jobFailed
		if outcome.Kind == "violation" {
			reason = sql.NullString{Valid: true, String: clipRunes("签名闸拒签（"+outcome.Code+"）："+outcome.Detail, 500)}
		} else {
			reason = sql.NullString{Valid: true, String: clipRunes(fmt.Sprintf("签名闸已经 %d 次没签成，最近一次是临时错误（%s）：%s", failures, outcome.Code, outcome.Detail), 500)}
		}
	}
	release := releaseSigned
	if failed {
		release = releaseAllDeliveries
	}
	_, matched, err := s.transitionBuildJob(ctx, job.ID, jobTransition{
		Where:     signingGuard + ` AND sign_failures=?`,
		WhereArgs: []any{job.ID, job.SignAttempt, machine.ID, job.SignFailures},
		Set:       `status=?,failure_reason=COALESCE(?,failure_reason),sign_outcome=?,sign_failures=?,signing_heartbeat_at=?,updated_at=?`,
		SetArgs:   []any{nextStatus, reason, raw, failures, now, now},
		Release:   release,
		After: func(tx *sql.Tx, _ lockedJob) error {
			if !failed {
				return nil
			}
			action := "build_job_sign_rejected"
			if outcome.Kind == "transient" {
				action = "build_job_sign_failed"
			}
			return insertAudit(ctx, tx, newAudit(job.TenantID, signerActor, action, "build-job", job.ID, reason.String, requestID(c),
				map[string]any{"jobId": job.ID, "kind": outcome.Kind, "code": outcome.Code, "detail": outcome.Detail, "signAttempt": job.SignAttempt,
					"signFailures": failures, "signerMachineId": machine.ID}))
		},
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the rejection")
		return
	}
	if !matched {
		problem(c, http.StatusConflict, "SIGN_ATTEMPT_STALE", "This signing claim is no longer current for this signer; stop working on the job")
		return
	}
	c.Status(http.StatusNoContent)
}
