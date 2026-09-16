package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/machinekey"
	"github.com/gin-gonic/gin"
)

// 机器登记与鉴权（设计 android-signing-gate-2026-09-16「机器登记与鉴权」、ADR 0019）。
//
// 构建机与签名闸各有一个本机令牌，取代全局唯一的 BUILD_AGENT_TOKEN。登记放在
// app_configs 平台级 build.machines（tenant_id=0）：条目少、只在新建、吊销、接受公钥、
// 切换主备时变，自带 version / updated_by / updated_at；机器在不在干活看任务行心跳，
// 不在这里记高频写的"最近上线"。
//
// **这份登记只用来鉴权和路由**。签名闸与离线工具不采信它：能写库的人能改这里的一切，
// 所以签名闸只信本机 pin 的构建机、离线工具只加密给离线 pin 文件里的签名闸。
const buildMachinesConfigKey = "build.machines"

// 平台级配置挂在 tenant 0：机器是全平台共用的，不属于任何租户
const platformTenantID = "0"

const (
	machineRoleBuilder = "builder"
	machineRoleSigner  = "signer"

	signerRolePrimary = "primary"
	signerRoleStandby = "standby"

	machineStatusPendingKey = "pending_key"
	machineStatusActive     = "active"
	machineStatusRevoked    = "revoked"

	machineTokenHeader       = "x-machine-token"
	legacyAgentTokenHeader   = "x-build-agent-token"
	machineTokenPrefix       = "rnm_"
	machineTokenRandomBytes  = 32
	machineIDPrefix          = "mch"
	maxRegisteredMachines    = 64
	machineWriteRetries      = 3
	buildAgentActor          = "build-agent"
	signerActor              = "system-signer"
	builderSystemActor       = "system-build"
	machineContextKey        = "machine"
	machineAuditTargetType   = "build-machine"
	machineReasonMinLength   = 3
	machineRevokeReasonLimit = 500
)

// optString 是 JSON 里可以为 null 的字符串：空串序列化成 null，null 读回空串。
// 登记里有十来个可空字段，全用 *string 写起来到处是判空。
type optString string

func (v optString) MarshalJSON() ([]byte, error) {
	if v == "" {
		return []byte("null"), nil
	}
	return json.Marshal(string(v))
}

func (v *optString) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		*v = ""
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	*v = optString(text)
	return nil
}

// machinePendingKey 是机器自己报上来、还没被平台管理员接受的公钥。
type machinePendingKey struct {
	PublicKey              string    `json:"publicKey"`
	PublicKeySHA256        string    `json:"publicKeySha256"`
	Ed25519PublicKey       optString `json:"ed25519PublicKey"`
	Ed25519PublicKeySHA256 optString `json:"ed25519PublicKeySha256"`
	ReportedAt             string    `json:"reportedAt"`
}

// buildMachine 是 build.machines 里的一项（约定 4.2）。
//
// 构建机：publicKey 是 Ed25519 出处公钥，ed25519* 恒为空。
// 签名闸：publicKey 是 X25519（收件人），ed25519PublicKey 用于本机记录签名与换钥证明。
type buildMachine struct {
	ID                     string             `json:"id"`
	Role                   string             `json:"role"`
	SignerRole             optString          `json:"signerRole"`
	Name                   string             `json:"name"`
	Status                 string             `json:"status"`
	TokenSHA256            string             `json:"tokenSha256"`
	PublicKey              optString          `json:"publicKey"`
	PublicKeySHA256        optString          `json:"publicKeySha256"`
	Ed25519PublicKey       optString          `json:"ed25519PublicKey"`
	Ed25519PublicKeySHA256 optString          `json:"ed25519PublicKeySha256"`
	Pending                *machinePendingKey `json:"pending"`
	AcceptedBy             optString          `json:"acceptedBy"`
	AcceptedAt             optString          `json:"acceptedAt"`
	CreatedBy              string             `json:"createdBy"`
	CreatedAt              string             `json:"createdAt"`
	RevokedBy              optString          `json:"revokedBy"`
	RevokedAt              optString          `json:"revokedAt"`
	RevokeReason           optString          `json:"revokeReason"`
}

type buildMachinesDoc struct {
	Machines []buildMachine `json:"machines"`
}

// isActivePrimary：只有它能领签名任务。
func (m buildMachine) isActivePrimary() bool {
	return m.Role == machineRoleSigner && m.Status == machineStatusActive && string(m.SignerRole) == signerRolePrimary
}

func (d buildMachinesDoc) find(id string) (int, bool) {
	for i, m := range d.Machines {
		if m.ID == id {
			return i, true
		}
	}
	return -1, false
}

func (d buildMachinesDoc) byTokenSHA256(digest string) (buildMachine, bool) {
	for _, m := range d.Machines {
		if m.TokenSHA256 == digest {
			return m, true
		}
	}
	return buildMachine{}, false
}

// activePrimary 返回 active 的主签名闸。登记里同时最多一台非吊销的 primary。
func (d buildMachinesDoc) activePrimary() (buildMachine, bool) {
	for _, m := range d.Machines {
		if m.isActivePrimary() {
			return m, true
		}
	}
	return buildMachine{}, false
}

// signerByRecipient 按 X25519 公钥 sha256 找非吊销的签名闸（只认已接受的公钥）。
func (d buildMachinesDoc) signerByRecipient(recipient string) (buildMachine, bool) {
	for _, m := range d.Machines {
		if m.Role == machineRoleSigner && m.Status != machineStatusRevoked && string(m.PublicKeySHA256) == recipient {
			return m, true
		}
	}
	return buildMachine{}, false
}

func (d buildMachinesDoc) names() map[string]string {
	out := make(map[string]string, len(d.Machines))
	for _, m := range d.Machines {
		out[m.ID] = m.Name
	}
	return out
}

// validate 是登记的不变量。库里出现不满足的值就是事故：鉴权直接失败，不猜。
func (d buildMachinesDoc) validate() error {
	ids := map[string]bool{}
	tokens := map[string]bool{}
	liveNames := map[string]bool{}
	primaries := 0
	for _, m := range d.Machines {
		switch {
		case !ident.ValidServerIDWithPrefix(m.ID, machineIDPrefix) || ids[m.ID]:
			return fmt.Errorf("machine id %q is malformed or duplicated", m.ID)
		case m.Role != machineRoleBuilder && m.Role != machineRoleSigner:
			return fmt.Errorf("machine %s has an unknown role", m.ID)
		case m.Status != machineStatusPendingKey && m.Status != machineStatusActive && m.Status != machineStatusRevoked:
			return fmt.Errorf("machine %s has an unknown status", m.ID)
		case !fingerprint.Valid(m.TokenSHA256) || tokens[m.TokenSHA256]:
			return fmt.Errorf("machine %s has a malformed or duplicated token digest", m.ID)
		case m.Role == machineRoleBuilder && m.SignerRole != "":
			return fmt.Errorf("builder %s carries a signer role", m.ID)
		// 吊销的签名闸没有主备角色（吊销时置空；更早吊销的记录可能还留着原角色）
		case m.Role == machineRoleSigner && m.SignerRole != signerRolePrimary && m.SignerRole != signerRoleStandby &&
			!(m.Status == machineStatusRevoked && m.SignerRole == ""):
			return fmt.Errorf("signer %s has no valid signer role", m.ID)
		case m.Status == machineStatusActive && (m.PublicKey == "" || !fingerprint.Valid(string(m.PublicKeySHA256))):
			return fmt.Errorf("active machine %s has no accepted key", m.ID)
		case m.Status == machineStatusActive && m.Role == machineRoleSigner && (m.Ed25519PublicKey == "" || !fingerprint.Valid(string(m.Ed25519PublicKeySHA256))):
			return fmt.Errorf("active signer %s has no accepted ed25519 key", m.ID)
		}
		ids[m.ID], tokens[m.TokenSHA256] = true, true
		if m.Status != machineStatusRevoked {
			if liveNames[m.Name] {
				return fmt.Errorf("machine name %q is used twice", m.Name)
			}
			liveNames[m.Name] = true
			if m.SignerRole == signerRolePrimary {
				primaries++
			}
		}
	}
	if primaries > 1 {
		return errors.New("more than one live primary signer is registered")
	}
	return nil
}

// ---- 读取与缓存 ----

// machineRegistryCache 按 app_configs 那一行的 (version, updated_at) 缓存解析结果。
//
// 每个机器请求都先做一次主键查询拿版本：版本没变用缓存，变了重读。这样吊销是即时
// 生效的——控制台点了吊销，下一个请求就查到新版本——而不必每个请求都解析整份 JSON。
type machineRegistryCache struct {
	mu        sync.Mutex
	loaded    bool
	version   int
	updatedAt time.Time
	doc       buildMachinesDoc
}

type machineRegistrySnapshot struct {
	Doc       buildMachinesDoc
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

// readMachineRegistry 直接读库，不走缓存。写路径用它。
func readMachineRegistry(ctx context.Context, q rowQuerier, forUpdate bool) (machineRegistrySnapshot, error) {
	var snapshot machineRegistrySnapshot
	var raw []byte
	query := `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=?`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query, platformTenantID, buildMachinesConfigKey).Scan(&raw, &snapshot.Version, &snapshot.UpdatedBy, &snapshot.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return machineRegistrySnapshot{Doc: buildMachinesDoc{Machines: []buildMachine{}}}, nil
	}
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(raw, &snapshot.Doc); err != nil {
		return snapshot, fmt.Errorf("build.machines is not valid JSON: %w", err)
	}
	if snapshot.Doc.Machines == nil {
		snapshot.Doc.Machines = []buildMachine{}
	}
	if err := snapshot.Doc.validate(); err != nil {
		return snapshot, fmt.Errorf("build.machines is invalid: %w", err)
	}
	return snapshot, nil
}

// machineRegistry 是鉴权路径的读取：先查版本，版本没变用缓存。
func (s *server) machineRegistry(ctx context.Context) (buildMachinesDoc, error) {
	var version int
	var updatedAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT version,updated_at FROM app_configs WHERE tenant_id=? AND config_key=?`,
		platformTenantID, buildMachinesConfigKey).Scan(&version, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return buildMachinesDoc{Machines: []buildMachine{}}, nil
	}
	if err != nil {
		return buildMachinesDoc{}, err
	}
	s.machines.mu.Lock()
	if s.machines.loaded && s.machines.version == version && s.machines.updatedAt.Equal(updatedAt) {
		doc := s.machines.doc
		s.machines.mu.Unlock()
		return doc, nil
	}
	s.machines.mu.Unlock()

	snapshot, err := readMachineRegistry(ctx, s.db, false)
	if err != nil {
		return buildMachinesDoc{}, err
	}
	s.machines.mu.Lock()
	s.machines.loaded, s.machines.version, s.machines.updatedAt, s.machines.doc = true, snapshot.Version, snapshot.UpdatedAt, snapshot.Doc
	s.machines.mu.Unlock()
	return snapshot.Doc, nil
}

// ---- 鉴权 ----

// machineAuth 是构建机与签名闸通道的鉴权：按令牌 sha256 查登记、校验角色、吊销即时生效。
// allowPendingKey 只给各自的 public-key 接口：公钥还没被接受的机器只能登记公钥。
func (s *server) machineAuth(role string, allowPendingKey bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimSpace(c.GetHeader(machineTokenHeader))
		if token == "" {
			// 新服务端对旧构建机回一个明确的"要升级"，而不是和令牌错了一样的 401：
			// 升级窗口里运维看到 401 会去查令牌，而令牌根本没错
			if strings.TrimSpace(c.GetHeader(legacyAgentTokenHeader)) != "" {
				problem(c, http.StatusUpgradeRequired, "MACHINE_AUTH_UPGRADE_REQUIRED",
					"x-build-agent-token is no longer accepted: upgrade this machine to a version that authenticates with x-machine-token, issued when the machine is created in the console")
				c.Abort()
				return
			}
			problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
			c.Abort()
			return
		}
		if !validMachineTokenShape(token) {
			problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
			c.Abort()
			return
		}
		registry, err := s.machineRegistry(c.Request.Context())
		if err != nil {
			slog.Error("machine registry is unavailable", "error", err)
			problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
			c.Abort()
			return
		}
		machine, ok := registry.byTokenSHA256(sha256Hex(token))
		if !ok {
			problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
			c.Abort()
			return
		}
		// 吊销与"令牌不对"分开说：签名闸与构建机认出 MACHINE_REVOKED 就停止重试并退出，
		// 而不是把它当成配置错误一直重连。令牌 sha256 本身就是凭据的证明，说出"已吊销"不泄露什么
		if machine.Status == machineStatusRevoked {
			problem(c, http.StatusUnauthorized, "MACHINE_REVOKED", "This machine has been revoked in the console; stop and ask a platform administrator")
			c.Abort()
			return
		}
		if machine.Role != role {
			problem(c, http.StatusForbidden, "MACHINE_ROLE_FORBIDDEN", "This machine token is not allowed on this channel")
			c.Abort()
			return
		}
		if machine.Status == machineStatusPendingKey && !allowPendingKey {
			problem(c, http.StatusForbidden, "MACHINE_KEY_NOT_ACCEPTED", "This machine's public key has not been accepted in the console yet")
			c.Abort()
			return
		}
		c.Set(machineContextKey, machine)
		if role == machineRoleSigner {
			c.Set("actorId", signerActor)
		} else {
			c.Set("actorId", buildAgentActor)
		}
		c.Next()
	}
}

func validMachineTokenShape(token string) bool {
	if !strings.HasPrefix(token, machineTokenPrefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, machineTokenPrefix))
	return err == nil && len(raw) == machineTokenRandomBytes
}

func machineFromContext(c *gin.Context) (buildMachine, bool) {
	item, ok := c.Get(machineContextKey)
	if !ok {
		return buildMachine{}, false
	}
	machine, ok := item.(buildMachine)
	return machine, ok
}

func newMachineToken() (string, error) {
	raw := make([]byte, machineTokenRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return machineTokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// ---- 写入 ----

// writeMachineRegistry 带乐观锁写整份登记。expectedVersion 为 0 表示这一行还不存在。
func writeMachineRegistry(ctx context.Context, tx *sql.Tx, doc buildMachinesDoc, expectedVersion int, actor string, now time.Time) (bool, error) {
	if err := doc.validate(); err != nil {
		return false, err
	}
	value, err := json.Marshal(doc)
	if err != nil {
		return false, err
	}
	var result sql.Result
	if expectedVersion == 0 {
		result, err = tx.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			platformTenantID, buildMachinesConfigKey, value, actor, now, platformTenantID, buildMachinesConfigKey)
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor, now, platformTenantID, buildMachinesConfigKey, expectedVersion)
	}
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, errors.New("cannot tell whether the machine registry write applied")
	}
	return affected == 1, nil
}

// ---- 视图 ----

// machineView 不含令牌 sha256、不含公钥原文（约定 5.4）。
func machineView(m buildMachine) gin.H {
	view := gin.H{
		"id":                            m.ID,
		"role":                          m.Role,
		"signerRole":                    nullableString(string(m.SignerRole)),
		"name":                          m.Name,
		"status":                        m.Status,
		"publicKeySha256":               nullableString(string(m.PublicKeySHA256)),
		"ed25519PublicKeySha256":        nullableString(string(m.Ed25519PublicKeySHA256)),
		"pendingPublicKeySha256":        nil,
		"pendingEd25519PublicKeySha256": nil,
		"pendingReportedAt":             nil,
		"acceptedBy":                    nullableString(string(m.AcceptedBy)),
		"acceptedAt":                    nullableString(string(m.AcceptedAt)),
		"createdBy":                     m.CreatedBy,
		"createdAt":                     m.CreatedAt,
		"revokedBy":                     nullableString(string(m.RevokedBy)),
		"revokedAt":                     nullableString(string(m.RevokedAt)),
		"revokeReason":                  nullableString(string(m.RevokeReason)),
	}
	if m.Pending != nil {
		view["pendingPublicKeySha256"] = m.Pending.PublicKeySHA256
		view["pendingEd25519PublicKeySha256"] = nullableString(string(m.Pending.Ed25519PublicKeySHA256))
		view["pendingReportedAt"] = m.Pending.ReportedAt
	}
	return view
}

func machineViews(doc buildMachinesDoc) []gin.H {
	items := make([]gin.H, 0, len(doc.Machines))
	for _, m := range doc.Machines {
		items = append(items, machineView(m))
	}
	return items
}

// ---- 管理端（平台管理员） ----

func (s *server) listMachines(c *gin.Context) {
	snapshot, err := readMachineRegistry(c.Request.Context(), s.db, false)
	if err != nil {
		slog.Error("cannot read the machine registry", "error", err)
		problem(c, http.StatusInternalServerError, "MACHINE_REGISTRY_INVALID", "Stored build.machines configuration cannot be read")
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": snapshot.Version, "items": machineViews(snapshot.Doc)})
}

type machineWriteCommon struct {
	ExpectedVersion *int   `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

func (b machineWriteCommon) valid() bool {
	return b.Confirm && b.ExpectedVersion != nil && *b.ExpectedVersion >= 0 && len([]rune(strings.TrimSpace(b.Reason))) >= machineReasonMinLength
}

// mutateMachines 是管理端写登记的公共部分：读、校验版本、改、带锁写、同一事务写审计。
// mutate 返回 (状态码, 错误码, 说明)；状态码为 0 表示可以写。
func (s *server) mutateMachines(c *gin.Context, expectedVersion int, mutate func(doc *buildMachinesDoc, now time.Time) (int, string, string, []auditEvent)) (machineRegistrySnapshot, bool) {
	ctx := c.Request.Context()
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to save the machine registry")
		return machineRegistrySnapshot{}, false
	}
	defer tx.Rollback()
	snapshot, err := readMachineRegistry(ctx, tx, true)
	if err != nil {
		slog.Error("cannot read the machine registry", "error", err)
		problem(c, http.StatusInternalServerError, "MACHINE_REGISTRY_INVALID", "Stored build.machines configuration cannot be read")
		return snapshot, false
	}
	if snapshot.Version != expectedVersion {
		problem(c, http.StatusConflict, "MACHINES_VERSION_CONFLICT", "The machine registry changed; refresh and retry")
		return snapshot, false
	}
	status, code, detail, events := mutate(&snapshot.Doc, now)
	if status != 0 {
		problem(c, status, code, detail)
		return snapshot, false
	}
	applied, err := writeMachineRegistry(ctx, tx, snapshot.Doc, snapshot.Version, actor(c), now)
	if err != nil {
		slog.Error("cannot write the machine registry", "error", err)
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to save the machine registry")
		return snapshot, false
	}
	if !applied {
		problem(c, http.StatusConflict, "MACHINES_VERSION_CONFLICT", "The machine registry changed; refresh and retry")
		return snapshot, false
	}
	for _, event := range events {
		if err := insertAudit(ctx, tx, event); err != nil {
			problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to save the machine registry audit")
			return snapshot, false
		}
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to save the machine registry")
		return snapshot, false
	}
	snapshot.Version++
	snapshot.UpdatedBy, snapshot.UpdatedAt = actor(c), now
	return snapshot, true
}

func (s *server) createMachine(c *gin.Context) {
	var body struct {
		Role       string  `json:"role"`
		Name       string  `json:"name"`
		SignerRole *string `json:"signerRole"`
		machineWriteCommon
	}
	if decode(c, &body) != nil || !body.valid() {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "role, name, signerRole, expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	role := strings.TrimSpace(body.Role)
	name := strings.TrimSpace(body.Name)
	signerRole := ""
	if body.SignerRole != nil {
		signerRole = strings.TrimSpace(*body.SignerRole)
	}
	switch {
	case role != machineRoleBuilder && role != machineRoleSigner:
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "role must be builder or signer")
		return
	case !ident.ValidMachineName(name):
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "name must match ^[a-z0-9][a-z0-9-]{1,39}$")
		return
	case role == machineRoleBuilder && signerRole != "":
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "a builder has no signerRole; send null")
		return
	case role == machineRoleSigner && signerRole != signerRolePrimary && signerRole != signerRoleStandby:
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "a signer needs signerRole primary or standby")
		return
	}
	token, err := newMachineToken()
	if err != nil {
		problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to issue a machine token")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	var created buildMachine
	snapshot, ok := s.mutateMachines(c, *body.ExpectedVersion, func(doc *buildMachinesDoc, now time.Time) (int, string, string, []auditEvent) {
		if len(doc.Machines) >= maxRegisteredMachines {
			return http.StatusConflict, "MACHINE_LIMIT_REACHED", fmt.Sprintf("At most %d machines can be registered, including revoked ones", maxRegisteredMachines), nil
		}
		for _, m := range doc.Machines {
			if m.Status == machineStatusRevoked {
				continue
			}
			if m.Name == name {
				return http.StatusConflict, "MACHINE_NAME_TAKEN", "Another machine that is not revoked already uses this name", nil
			}
			if signerRole == signerRolePrimary && m.SignerRole == signerRolePrimary {
				return http.StatusConflict, "SIGNER_PRIMARY_EXISTS", "A primary signer is already registered; create this one as standby and switch roles once it has confirmed every tenant", nil
			}
		}
		created = buildMachine{
			ID: machineIDPrefix + "_" + randomID(16), Role: role, SignerRole: optString(signerRole), Name: name,
			Status: machineStatusPendingKey, TokenSHA256: sha256Hex(token),
			CreatedBy: actor(c), CreatedAt: iso(now),
		}
		doc.Machines = append(doc.Machines, created)
		// 审计记机器身份，不记令牌也不记令牌 sha256
		return 0, "", "", []auditEvent{newAudit(platformTenantID, actor(c), "build_machine_create", machineAuditTargetType, created.ID, reason, requestID(c),
			map[string]any{"machineId": created.ID, "role": role, "name": name, "signerRole": nullableString(signerRole)})}
	})
	if !ok {
		return
	}
	// 令牌只在这一个响应里出现。之后任何接口都拿不回来，丢了就吊销重建
	c.JSON(http.StatusCreated, gin.H{"version": snapshot.Version, "machine": machineView(created), "token": token})
}

func (s *server) revokeMachine(c *gin.Context) {
	var body machineWriteCommon
	if decode(c, &body) != nil || !body.valid() {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	reason := clipRunes(strings.TrimSpace(body.Reason), machineRevokeReasonLimit)
	var revoked buildMachine
	snapshot, ok := s.mutateMachines(c, *body.ExpectedVersion, func(doc *buildMachinesDoc, now time.Time) (int, string, string, []auditEvent) {
		index, found := doc.find(id)
		if !found {
			return http.StatusNotFound, "MACHINE_NOT_FOUND", "Machine not found", nil
		}
		m := &doc.Machines[index]
		if m.Status == machineStatusRevoked {
			return http.StatusConflict, "MACHINE_ALREADY_REVOKED", "This machine is already revoked", nil
		}
		previous, previousSignerRole := m.Status, string(m.SignerRole)
		m.Status = machineStatusRevoked
		// 吊销的签名闸不再有主备角色：留着的话，切换主备之后登记里会同时出现两条 primary，其中一条已吊销
		m.SignerRole = ""
		m.RevokedBy, m.RevokedAt, m.RevokeReason = optString(actor(c)), optString(iso(now)), optString(reason)
		revoked = *m
		return 0, "", "", []auditEvent{newAudit(platformTenantID, actor(c), "build_machine_revoke", machineAuditTargetType, m.ID, reason, requestID(c),
			map[string]any{"machineId": m.ID, "role": m.Role, "name": m.Name, "signerRole": nullableString(previousSignerRole), "previousStatus": previous,
				"publicKeySha256": nullableString(string(m.PublicKeySHA256))})}
	})
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": snapshot.Version, "machine": machineView(revoked)})
}

func (s *server) acceptMachineKey(c *gin.Context) {
	var body struct {
		PublicKeySHA256        string  `json:"publicKeySha256"`
		Ed25519PublicKeySHA256 *string `json:"ed25519PublicKeySha256"`
		machineWriteCommon
	}
	if decode(c, &body) != nil || !body.valid() {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "publicKeySha256, expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	// 指纹要人从那台机器上抄过来：这是"确实核对过是哪一把"的唯一证据。完整 64 位，不收截短的
	typed, valid := fingerprint.Normalize(strings.TrimSpace(body.PublicKeySHA256))
	if !valid {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "publicKeySha256 must be the full 64-character sha256")
		return
	}
	// 签名闸的第二把钥（Ed25519）决定以后谁能证明换钥。只核对 X25519 时，偷到令牌的人可以在
	// 待接受期间报上"真机的 X25519 + 自己的 Ed25519"。所以签名闸必须同时带上从本机抄来的
	// Ed25519 指纹（下面按角色判）；构建机只有一把钥，带了就必须一致
	typedEd25519 := ""
	if body.Ed25519PublicKeySHA256 != nil {
		if typedEd25519, valid = fingerprint.Normalize(strings.TrimSpace(*body.Ed25519PublicKeySHA256)); !valid {
			problem(c, http.StatusBadRequest, "INVALID_MACHINE", "ed25519PublicKeySha256 must be the full 64-character sha256")
			return
		}
	}
	id := strings.TrimSpace(c.Param("id"))
	reason := strings.TrimSpace(body.Reason)
	var accepted buildMachine
	snapshot, ok := s.mutateMachines(c, *body.ExpectedVersion, func(doc *buildMachinesDoc, now time.Time) (int, string, string, []auditEvent) {
		index, found := doc.find(id)
		if !found {
			return http.StatusNotFound, "MACHINE_NOT_FOUND", "Machine not found", nil
		}
		m := &doc.Machines[index]
		if m.Status == machineStatusRevoked {
			return http.StatusConflict, "MACHINE_REVOKED", "A revoked machine cannot have its key accepted", nil
		}
		if m.Pending == nil {
			return http.StatusConflict, "MACHINE_KEY_NOT_PENDING", "This machine has no key waiting to be accepted", nil
		}
		if typed != m.Pending.PublicKeySHA256 {
			return http.StatusConflict, "MACHINE_KEY_MISMATCH", "The fingerprint does not match the key waiting to be accepted; read it on the machine itself", nil
		}
		if m.Role == machineRoleSigner && typedEd25519 == "" {
			return http.StatusBadRequest, "INVALID_MACHINE", "Accepting a signer's keys requires ed25519PublicKeySha256 as well, read on the signer itself", nil
		}
		if typedEd25519 != "" && (m.Role != machineRoleSigner || typedEd25519 != string(m.Pending.Ed25519PublicKeySHA256)) {
			return http.StatusConflict, "MACHINE_KEY_MISMATCH", "The ed25519 fingerprint does not match the key waiting to be accepted; read it on the signer itself", nil
		}
		if other, taken := doc.keyInUse(m.ID, m.Pending.PublicKeySHA256, string(m.Pending.Ed25519PublicKeySHA256)); taken {
			return http.StatusConflict, "MACHINE_KEY_IN_USE", "Machine " + other + " already uses this key", nil
		}
		previous := string(m.PublicKeySHA256)
		m.PublicKey, m.PublicKeySHA256 = optString(m.Pending.PublicKey), optString(m.Pending.PublicKeySHA256)
		m.Ed25519PublicKey, m.Ed25519PublicKeySHA256 = m.Pending.Ed25519PublicKey, m.Pending.Ed25519PublicKeySHA256
		m.Pending = nil
		m.Status = machineStatusActive
		m.AcceptedBy, m.AcceptedAt = optString(actor(c)), optString(iso(now))
		accepted = *m
		return 0, "", "", []auditEvent{newAudit(platformTenantID, actor(c), "build_machine_key_accept", machineAuditTargetType, m.ID, reason, requestID(c),
			map[string]any{"machineId": m.ID, "role": m.Role, "name": m.Name, "publicKeySha256": string(m.PublicKeySHA256),
				"ed25519PublicKeySha256": nullableString(string(m.Ed25519PublicKeySHA256)), "previousPublicKeySha256": nullableString(previous)})}
	})
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": snapshot.Version, "machine": machineView(accepted)})
}

func (s *server) setSignerRole(c *gin.Context) {
	var body struct {
		SignerRole string `json:"signerRole"`
		machineWriteCommon
	}
	if decode(c, &body) != nil || !body.valid() {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "signerRole, expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	role := strings.TrimSpace(body.SignerRole)
	if role != signerRolePrimary && role != signerRoleStandby {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE", "signerRole must be primary or standby")
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	reason := strings.TrimSpace(body.Reason)
	snapshot, ok := s.mutateMachines(c, *body.ExpectedVersion, func(doc *buildMachinesDoc, now time.Time) (int, string, string, []auditEvent) {
		index, found := doc.find(id)
		if !found {
			return http.StatusNotFound, "MACHINE_NOT_FOUND", "Machine not found", nil
		}
		m := &doc.Machines[index]
		if m.Role != machineRoleSigner {
			return http.StatusBadRequest, "INVALID_MACHINE", "Only signers have a signer role", nil
		}
		if m.Status == machineStatusRevoked {
			return http.StatusConflict, "MACHINE_REVOKED", "A revoked signer cannot take a role", nil
		}
		previous := string(m.SignerRole)
		demoted := []string{}
		if role == signerRolePrimary {
			// 原 primary 在同一次写里降为 standby：登记里任何时刻最多一台 primary
			for i := range doc.Machines {
				other := &doc.Machines[i]
				if other.ID != m.ID && other.Status != machineStatusRevoked && other.SignerRole == signerRolePrimary {
					other.SignerRole = signerRoleStandby
					demoted = append(demoted, other.ID)
				}
			}
		}
		m.SignerRole = optString(role)
		return 0, "", "", []auditEvent{newAudit(platformTenantID, actor(c), "build_machine_signer_role", machineAuditTargetType, m.ID, reason, requestID(c),
			map[string]any{"machineId": m.ID, "name": m.Name, "signerRole": role, "previousSignerRole": previous, "demoted": demoted})}
	})
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": snapshot.Version, "items": machineViews(snapshot.Doc)})
}

// keyInUse：同一把公钥不能出现在两台非吊销的机器上（当前或待接受的都算）。
// 收件人指纹到机器是一对一的映射，重了就不知道一份密文是给谁的。
func (d buildMachinesDoc) keyInUse(selfID, primarySHA256, ed25519SHA256 string) (string, bool) {
	for _, m := range d.Machines {
		if m.ID == selfID || m.Status == machineStatusRevoked {
			continue
		}
		digests := []string{string(m.PublicKeySHA256), string(m.Ed25519PublicKeySHA256)}
		if m.Pending != nil {
			digests = append(digests, m.Pending.PublicKeySHA256, string(m.Pending.Ed25519PublicKeySHA256))
		}
		for _, digest := range digests {
			if digest != "" && (digest == primarySHA256 || (ed25519SHA256 != "" && digest == ed25519SHA256)) {
				return m.Name, true
			}
		}
	}
	return "", false
}

// ---- 机器自己登记公钥 ----

// reportedMachineKey 是机器报上来的公钥。构建机只有 primary（Ed25519 出处公钥）；
// 签名闸 primary 是 X25519、ed25519 是记录签名公钥。
type reportedMachineKey struct {
	primary       []byte
	ed25519       []byte
	primarySHA256 string
	ed25519SHA256 string
}

func decodeMachinePublicKey(encoded string) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) {
		return nil, false
	}
	return raw, true
}

func (s *server) registerBuilderKey(c *gin.Context) {
	var body struct {
		PublicKey         string  `json:"publicKey"`
		RotationSignature *string `json:"rotationSignature"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "publicKey (base64 Ed25519) and rotationSignature are required")
		return
	}
	primary, ok := decodeMachinePublicKey(body.PublicKey)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "publicKey must be the standard base64 of a 32-byte Ed25519 public key")
		return
	}
	s.registerMachineKey(c, reportedMachineKey{primary: primary, primarySHA256: fingerprint.SHA256Hex(primary)}, body.RotationSignature)
}

func (s *server) registerSignerKey(c *gin.Context) {
	var body struct {
		X25519PublicKey   string  `json:"x25519PublicKey"`
		Ed25519PublicKey  string  `json:"ed25519PublicKey"`
		RotationSignature *string `json:"rotationSignature"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "x25519PublicKey, ed25519PublicKey and rotationSignature are required")
		return
	}
	primary, okPrimary := decodeMachinePublicKey(body.X25519PublicKey)
	signing, okSigning := decodeMachinePublicKey(body.Ed25519PublicKey)
	if !okPrimary || !okSigning {
		problem(c, http.StatusBadRequest, "INVALID_MACHINE_KEY", "x25519PublicKey and ed25519PublicKey must each be the standard base64 of 32 bytes")
		return
	}
	s.registerMachineKey(c, reportedMachineKey{
		primary: primary, primarySHA256: fingerprint.SHA256Hex(primary),
		ed25519: signing, ed25519SHA256: fingerprint.SHA256Hex(signing),
	}, body.RotationSignature)
}

// registerMachineKey 把机器报上来的公钥挂成待接受。
//
//   - 同一把已接受的公钥、或同一把已在等待接受的公钥：幂等，不写库；
//   - 还没有已接受公钥的机器（pending_key）：直接挂成待接受，由平台管理员核对指纹后接受；
//   - 已 active 的机器换公钥：必须带用**当前**私钥对 machinekey.RotationMessage 的签名。
//     偷到令牌的人没有私钥，换不掉公钥，也就不能让已有密文作废或把出处换成自己的。
//     旧公钥在新公钥被接受之前一直有效。
func (s *server) registerMachineKey(c *gin.Context, key reportedMachineKey, rotationSignature *string) {
	self, ok := machineFromContext(c)
	if !ok {
		problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
		return
	}
	ctx := c.Request.Context()
	auditActor := builderSystemActor
	if self.Role == machineRoleSigner {
		auditActor = signerActor
	}
	for attempt := 0; attempt < machineWriteRetries; attempt++ {
		snapshot, err := readMachineRegistry(ctx, s.db, false)
		if err != nil {
			slog.Error("cannot read the machine registry", "error", err)
			problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
			return
		}
		index, found := snapshot.Doc.find(self.ID)
		if !found || snapshot.Doc.Machines[index].Status == machineStatusRevoked {
			problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
			return
		}
		m := &snapshot.Doc.Machines[index]
		sameAsCurrent := string(m.PublicKeySHA256) == key.primarySHA256 && string(m.Ed25519PublicKeySHA256) == key.ed25519SHA256
		sameAsPending := m.Pending != nil && m.Pending.PublicKeySHA256 == key.primarySHA256 && string(m.Pending.Ed25519PublicKeySHA256) == key.ed25519SHA256
		if sameAsCurrent || sameAsPending {
			c.JSON(http.StatusOK, machineKeyResponse(*m))
			return
		}
		rotation := m.Status == machineStatusActive
		if rotation {
			current := []byte(nil)
			if m.Role == machineRoleSigner {
				current, _ = base64.StdEncoding.DecodeString(string(m.Ed25519PublicKey))
			} else {
				current, _ = base64.StdEncoding.DecodeString(string(m.PublicKey))
			}
			signature := []byte(nil)
			if rotationSignature != nil {
				signature, _ = base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(*rotationSignature))
			}
			if len(signature) == 0 || !machinekey.VerifyRotation(ed25519.PublicKey(current), m.ID, key.primarySHA256, key.ed25519SHA256, signature) {
				problem(c, http.StatusForbidden, "MACHINE_KEY_ROTATION_UNPROVEN",
					"This machine already has an accepted key; a new key must be signed with the current private key (rotationSignature)")
				return
			}
		}
		if other, taken := snapshot.Doc.keyInUse(m.ID, key.primarySHA256, key.ed25519SHA256); taken {
			problem(c, http.StatusConflict, "MACHINE_KEY_IN_USE", "Machine "+other+" already uses this key")
			return
		}
		now := time.Now().UTC()
		m.Pending = &machinePendingKey{
			PublicKey: base64.StdEncoding.EncodeToString(key.primary), PublicKeySHA256: key.primarySHA256, ReportedAt: iso(now),
		}
		if key.ed25519 != nil {
			m.Pending.Ed25519PublicKey = optString(base64.StdEncoding.EncodeToString(key.ed25519))
			m.Pending.Ed25519PublicKeySHA256 = optString(key.ed25519SHA256)
		}
		reported := *m
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to record the reported key")
			return
		}
		applied, err := writeMachineRegistry(ctx, tx, snapshot.Doc, snapshot.Version, auditActor, now)
		if err != nil {
			_ = tx.Rollback()
			slog.Error("cannot record a reported machine key", "machineId", self.ID, "error", err)
			problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to record the reported key")
			return
		}
		if !applied {
			_ = tx.Rollback()
			continue
		}
		event := newAudit(platformTenantID, auditActor, "build_machine_key_report", machineAuditTargetType, self.ID,
			"a machine reported a public key waiting to be accepted", requestID(c),
			map[string]any{"machineId": self.ID, "role": self.Role, "name": self.Name, "rotation": rotation,
				"publicKeySha256": key.primarySHA256, "ed25519PublicKeySha256": nullableString(key.ed25519SHA256),
				"currentPublicKeySha256": nullableString(string(reported.PublicKeySHA256))})
		if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
			_ = tx.Rollback()
			problem(c, http.StatusInternalServerError, "MACHINE_SAVE_FAILED", "Unable to record the reported key")
			return
		}
		c.JSON(http.StatusOK, machineKeyResponse(reported))
		return
	}
	problem(c, http.StatusConflict, "MACHINES_VERSION_CONFLICT", "The machine registry kept changing; retry")
}

// machineKeyResponse 带上 machineId：机器换钥时要把自己的 id 签进 machinekey.RotationMessage，
// 而令牌里没有 id，登记公钥是它唯一能拿到 id 的接口。
func machineKeyResponse(m buildMachine) gin.H {
	out := gin.H{
		"machineId":              m.ID,
		"status":                 m.Status,
		"publicKeySha256":        nullableString(string(m.PublicKeySHA256)),
		"pendingPublicKeySha256": nil,
	}
	if m.Pending != nil {
		out["pendingPublicKeySha256"] = m.Pending.PublicKeySHA256
	}
	if m.Role == machineRoleSigner {
		out["ed25519PublicKeySha256"] = nullableString(string(m.Ed25519PublicKeySHA256))
	}
	return out
}
