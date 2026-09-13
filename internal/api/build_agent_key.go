package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
	"github.com/gin-gonic/gin"
)

// 打包机的公钥。签名密钥从此加密给它，而不是用人敲的口令封。
//
// 为什么换：口令那条路要求把**一个保护所有租户密钥的平台秘密**敲进控制台的表单。
// 租户不可能知道它，知道了更糟；而即使是平台运维，那也是一串 64 字符的东西，抄错
// 的表现是存下去一切正常、构建必然失败（2026-09-12 到 09-13 连着错了三次）。
// 换成公钥之后没有任何人需要输入任何秘密，服务端仍然只有公钥、照样打不开。
//
// **公钥是固定的（pinned）。** 第一次登记之后，代理再报一把不同的公钥不会自动生效
// ——只会挂成待确认，由平台管理员核对指纹后接受。理由：持有代理令牌的人本来就能领
// 走盒子，但开不开得了要看私钥；如果换公钥不需要人确认，那么偷到令牌的人只要登记
// 自己的公钥，此后每一把新密钥都直接加密给他。
const buildAgentKeyConfigKey = "build.agent.recipient"

// 平台级配置挂在 tenant 0：打包机是全平台一台，不属于任何租户
const platformTenantID = "0"

type buildAgentKeyRecord struct {
	// Current 是正在用的那把公钥，服务端加密给它
	Current buildkeystore.Recipient `json:"current"`
	// Pending 是代理报上来但还没被人接受的那把
	Pending      *buildkeystore.Recipient `json:"pending,omitempty"`
	Agent        string                   `json:"agent"`
	RegisteredAt string                   `json:"registeredAt"`
	PendingAgent string                   `json:"pendingAgent,omitempty"`
	PendingAt    string                   `json:"pendingAt,omitempty"`
}

func (s *server) buildAgentKey(ctx context.Context) (*buildAgentKeyRecord, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, buildAgentKeyConfigKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record buildAgentKeyRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *server) saveBuildAgentKey(ctx context.Context, record buildAgentKeyRecord, actor string) error {
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=app_configs.version+1,updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		platformTenantID, buildAgentKeyConfigKey, value, actor, time.Now().UTC())
	return err
}

// registerBuildAgentKey 让打包机登记自己的公钥。
func (s *server) registerBuildAgentKey(c *gin.Context) {
	var body struct {
		PublicKey string `json:"publicKey"`
		Agent     string `json:"agent"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.PublicKey) == "" {
		problem(c, http.StatusBadRequest, "INVALID_AGENT_KEY", "publicKey is required")
		return
	}
	incoming := buildkeystore.Recipient{PublicKey: strings.TrimSpace(body.PublicKey)}
	if incoming.Fingerprint() == "" {
		problem(c, http.StatusBadRequest, "INVALID_AGENT_KEY", "publicKey is not a usable X25519 public key")
		return
	}
	agent := clipRunes(strings.TrimSpace(body.Agent), 120)
	now := iso(time.Now().UTC())

	record, err := s.buildAgentKey(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "AGENT_KEY_QUERY_FAILED", "Unable to read the registered build agent key")
		return
	}
	switch {
	case record == nil:
		// 第一次：直接定下来。这台机器此刻还没有任何密钥加密给它，没什么可保护的
		if err := s.saveBuildAgentKey(c.Request.Context(), buildAgentKeyRecord{
			Current: incoming, Agent: agent, RegisteredAt: now,
		}, "build-agent"); err != nil {
			problem(c, http.StatusInternalServerError, "AGENT_KEY_SAVE_FAILED", "Unable to register the build agent key")
			return
		}
		s.auditNow(newAudit(platformTenantID, "build-agent", "build_agent_key_register", "app-config", buildAgentKeyConfigKey,
			"first build agent public key", requestID(c), map[string]any{"fingerprint": incoming.Fingerprint(), "agent": agent}))
		c.JSON(http.StatusOK, gin.H{"status": "registered", "fingerprint": incoming.Fingerprint()})
	case record.Current.PublicKey == incoming.PublicKey:
		c.JSON(http.StatusOK, gin.H{"status": "unchanged", "fingerprint": incoming.Fingerprint()})
	default:
		// 换公钥要人确认。自动接受的话，偷到代理令牌的人登记自己的公钥就够了——
		// 此后每一把新密钥都直接加密给他，而现场看不出任何异常。
		if record.Pending == nil || record.Pending.PublicKey != incoming.PublicKey {
			record.Pending = &incoming
			record.PendingAgent = agent
			record.PendingAt = now
			if err := s.saveBuildAgentKey(c.Request.Context(), *record, "build-agent"); err != nil {
				problem(c, http.StatusInternalServerError, "AGENT_KEY_SAVE_FAILED", "Unable to record the new build agent key")
				return
			}
			s.auditNow(newAudit(platformTenantID, "build-agent", "build_agent_key_pending", "app-config", buildAgentKeyConfigKey,
				"a build agent reported a different public key", requestID(c),
				map[string]any{"fingerprint": incoming.Fingerprint(), "current": record.Current.Fingerprint(), "agent": agent}))
		}
		c.JSON(http.StatusOK, gin.H{"status": "pending_acceptance", "fingerprint": incoming.Fingerprint(),
			"currentFingerprint": record.Current.Fingerprint()})
	}
}

// getBuildAgentKey 给平台管理员看：现在加密给哪一台，有没有待确认的。
func (s *server) getBuildAgentKey(c *gin.Context) {
	record, err := s.buildAgentKey(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "AGENT_KEY_QUERY_FAILED", "Unable to read the registered build agent key")
		return
	}
	if record == nil {
		c.JSON(http.StatusOK, gin.H{"registered": false, "fingerprint": nil, "pending": nil})
		return
	}
	out := gin.H{
		"registered":   true,
		"fingerprint":  record.Current.Fingerprint(),
		"agent":        nullableString(record.Agent),
		"registeredAt": nullableString(record.RegisteredAt),
		"pending":      nil,
	}
	if record.Pending != nil {
		out["pending"] = gin.H{
			"fingerprint": record.Pending.Fingerprint(),
			"agent":       nullableString(record.PendingAgent),
			"reportedAt":  nullableString(record.PendingAt),
		}
	}
	c.JSON(http.StatusOK, out)
}

// acceptBuildAgentKey 接受待确认的那把公钥。
//
// 接受之后，**已经存在的密钥仍然是加密给旧公钥的**——服务端没有明文，换不了。所以
// 这里同时把每个租户的验证结果作废：代理会用新私钥再试一遍，打不开的会立刻显示出来，
// 那些租户需要重新上传或重新生成密钥。这件事必须让人看见，而不是等下一次构建。
func (s *server) acceptBuildAgentKey(c *gin.Context) {
	var body struct {
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
		Confirm     bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_AGENT_KEY_ACCEPT", "fingerprint, reason and confirm=true are required")
		return
	}
	record, err := s.buildAgentKey(c.Request.Context())
	if err != nil || record == nil || record.Pending == nil {
		problem(c, http.StatusConflict, "NO_PENDING_AGENT_KEY", "There is no build agent key waiting to be accepted")
		return
	}
	// 指纹要人抄一遍：这是"你确实核对过那台机器上是哪一把"的唯一证据
	if strings.TrimSpace(body.Fingerprint) != record.Pending.Fingerprint() {
		problem(c, http.StatusConflict, "AGENT_KEY_FINGERPRINT_MISMATCH",
			"The fingerprint does not match the key waiting to be accepted; check it on the build machine itself")
		return
	}
	previous := record.Current.Fingerprint()
	record.Current = *record.Pending
	record.Agent = record.PendingAgent
	record.RegisteredAt = record.PendingAt
	record.Pending = nil
	record.PendingAgent = ""
	record.PendingAt = ""
	if err := s.saveBuildAgentKey(c.Request.Context(), *record, actor(c)); err != nil {
		problem(c, http.StatusInternalServerError, "AGENT_KEY_SAVE_FAILED", "Unable to accept the new build agent key")
		return
	}
	// 已有的盒子还是加密给旧公钥的，服务端没有明文所以换不了。把验证结果清掉，
	// 让代理用新私钥重新验一遍——打不开的租户会立刻显示出来
	if _, err := s.db.ExecContext(c.Request.Context(),
		`DELETE FROM app_configs WHERE config_key=?`, buildKeystoreCheckConfigKey); err != nil {
		problem(c, http.StatusInternalServerError, "AGENT_KEY_SAVE_FAILED", "Unable to invalidate the previous verification results")
		return
	}
	s.auditNow(newAudit(platformTenantID, actor(c), "build_agent_key_accept", "app-config", buildAgentKeyConfigKey,
		strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"fingerprint": record.Current.Fingerprint(), "previous": previous}))
	c.JSON(http.StatusOK, gin.H{"accepted": true, "fingerprint": record.Current.Fingerprint()})
}
