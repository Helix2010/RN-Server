package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 打包机验一遍盒子开不开得了。
//
// 封装口令**只在打包机上**——服务端从头到尾没有它，这正是把签名密钥放进数据库还能
// 成立的原因。代价是服务端没有任何办法判断刚存进来的那个盒子是不是用对口令封的：
// 存的时候一切正常，指纹也登记了，控制台上看着是配好的。
//
// 2026-09-12 predict-kim 就是这样：23:15 在控制台生成密钥，23:44 发起构建，那时才
// 拿到 "cannot open the sealed keystore: wrong passphrase"。中间隔了 29 分钟，而且
// 是在占用了打包机之后才失败。
//
// 所以让唯一有口令的那一方去验：代理轮询时领走"还没验过的"盒子，试着开一下，把
// 结果报回来。开不了不阻断任何东西——它只是把一个要等到构建才暴露的错误，提前到
// 密钥存下来的几秒之内，并且写在控制台上。
const buildKeystoreCheckConfigKey = "build.keystore.check"

// keystoreCheck 记的是"哪一版盒子、验的结果如何"。version 对应 build.keystore 那行
// 的 app_configs.version：密钥一旦被重写，版本号就变了，这条结果随即失效，控制台
// 显示"待打包机验证"而不是拿旧结论糊弄人。
type keystoreCheck struct {
	Version   int    `json:"version"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Agent     string `json:"agent"`
	CheckedAt string `json:"checkedAt"`
}

// clipRunes 按**字符**截断，不是按字节。
//
// 按字节切会把一个多字节字符切成两半，JSON 编码时那半个字符变成 U+FFFD——三个字节，
// 比切掉的还长，结果是"限长 300"的字段存进去 304 字节。这段文字几乎一定是中文。
func clipRunes(text string, max int) string {
	runes := []rune(text)
	if len(runes) <= max {
		return text
	}
	return string(runes[:max])
}

func (s *server) keystoreCheckFor(ctx context.Context, tenant string) (*keystoreCheck, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		tenant, buildKeystoreCheckConfigKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var check keystoreCheck
	if err := json.Unmarshal(raw, &check); err != nil {
		return nil, nil // 坏掉的记录当成"没验过"，不是错误
	}
	return &check, nil
}

// keystoreCheckView 把验证结果翻译成控制台要显示的三态。
func keystoreCheckView(check *keystoreCheck, keystoreVersion int) gin.H {
	if check == nil || check.Version != keystoreVersion {
		// 还没验，或者验的是上一版盒子
		return gin.H{"status": "pending", "checkedAt": nil, "agent": nil, "error": nil}
	}
	status := "failed"
	if check.OK {
		status = "ok"
	}
	return gin.H{
		"status":    status,
		"checkedAt": nullableString(check.CheckedAt),
		"agent":     nullableString(check.Agent),
		"error":     nullableString(check.Error),
	}
}

// pendingKeystoreChecks 给代理领活：哪些租户的盒子还没验过。
//
// 返回盒子本身——和领构建任务时下发的是同一样东西，凭据也是同一个，没有扩大代理
// 能看到的范围。
func (s *server) pendingKeystoreChecks(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT k.tenant_id, k.version, k.config_value, c.config_value
		   FROM app_configs k
		   LEFT JOIN app_configs c ON c.tenant_id=k.tenant_id AND c.config_key=?
		  WHERE k.config_key=?
		  ORDER BY k.updated_at DESC
		  LIMIT 20`, buildKeystoreCheckConfigKey, buildKeystoreConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_QUERY_FAILED", "Unable to list keystores to verify")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var tenant string
		var version int
		var keystoreRaw []byte
		var checkRaw []byte
		if err := rows.Scan(&tenant, &version, &keystoreRaw, &checkRaw); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_QUERY_FAILED", "Unable to list keystores to verify")
			return
		}
		if len(checkRaw) > 0 {
			var check keystoreCheck
			if json.Unmarshal(checkRaw, &check) == nil && check.Version == version {
				continue // 这一版已经验过了
			}
		}
		sealed, _, err := s.sealedBuildKeystoreFor(c.Request.Context(), tenant)
		if err != nil || len(sealed) == 0 {
			continue
		}
		items = append(items, gin.H{"tenant": tenant, "version": version, "sealedKeystore": sealed})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// reportKeystoreCheck 收下代理的验证结果。
func (s *server) reportKeystoreCheck(c *gin.Context) {
	var body struct {
		Tenant  string `json:"tenant"`
		Version int    `json:"version"`
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Agent   string `json:"agent"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.Tenant) == "" || body.Version < 1 {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_CHECK", "tenant and version are required")
		return
	}
	// 代理报回来的文字会显示在控制台上，截断并且不让它换行搅乱版面
	detail := clipRunes(strings.TrimSpace(strings.ReplaceAll(body.Error, "\n", " ")), 300)
	agent := clipRunes(strings.TrimSpace(body.Agent), 120)
	// 只对还存在的那一版写结果：密钥在验证期间被重写时，旧结论不该盖上去
	var current int
	err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		body.Tenant, buildKeystoreConfigKey).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && current != body.Version) {
		c.JSON(http.StatusOK, gin.H{"stored": false, "reason": "keystore changed while it was being verified"})
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_SAVE_FAILED", "Unable to store the verification result")
		return
	}
	now := time.Now().UTC()
	value, _ := json.Marshal(keystoreCheck{Version: body.Version, OK: body.OK, Error: detail, Agent: agent, CheckedAt: iso(now)})
	if _, err := s.db.ExecContext(c.Request.Context(),
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=app_configs.version+1,updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		body.Tenant, buildKeystoreCheckConfigKey, value, "build-agent", now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CHECK_SAVE_FAILED", "Unable to store the verification result")
		return
	}
	if !body.OK {
		// 这条要能在服务端日志里查到：它意味着这个租户现在一个包都出不来
		slog.Warn("the build machine cannot open this tenant's sealed keystore",
			"tenant", body.Tenant, "version", body.Version, "agent", agent, "error", detail)
	}
	c.JSON(http.StatusOK, gin.H{"stored": true})
}

// sealedKeystoreTenantCount 数的是全平台已经封了密钥的租户数。
//
// 给控制台用，回答"这个口令是不是已经被别人定下了"。**只数行数，不碰内容**——
// 服务端本来就打不开那些盒子。
func (s *server) sealedKeystoreTenantCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_configs WHERE config_key=?`, buildKeystoreConfigKey).Scan(&count)
	return count, err
}
