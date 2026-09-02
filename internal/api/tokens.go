package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/chain"
	"github.com/Helix2010/RN-Server/internal/siwe"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/gin-gonic/gin"
)

// tokensConfigKey 是代币目录在 app_configs 里的版本锚点。代币本身在
// chain_token_catalog 表里，这一行只承担乐观锁：管理端拿到 databaseVersion，写操作
// 带回 expectedVersion，成功后 +1——与 localization 用 languages 键的做法一致。
// 不复用 mobile-bootstrap 的版本：那会让还在继承全局配置的租户因为加了一个币
// 就被迫复制一份配置，之后再也跟不上全局更新。
const tokensConfigKey = "tokens"

const nativeTokenAddress = "native"

// tokenMetadataReader 抽象读链，测试用假实现。
type tokenMetadataReader interface {
	ReadToken(ctx context.Context, network chain.Network, address string) (chain.Metadata, error)
}

// 头像底色只认 #RRGGBB：管理端取色器与 App 的背景色都只处理这一种写法，三端一致。
var logoColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// allowlistedTokens 是 App 客户端白名单的服务端副本，键为 chain|小写地址。
// 来源就是迁移预置的五个合约（store.ChainTokenSeed），测试保证它与 App 那份一致。
var allowlistedTokens = func() map[string]bool {
	result := map[string]bool{}
	for _, row := range store.ChainTokenSeed {
		if row.Address != nativeTokenAddress {
			result[tokenKey(row.Chain, row.Address)] = true
		}
	}
	return result
}()

func tokenKey(chainID, address string) string { return chainID + "|" + strings.ToLower(address) }

// tokenAllowlisted 回答"这个地址在 App 里会显示成已验证吗"。原生币不来自合约，
// App 的 verifyAgainstAllowlist 对它直接返回 verified，这里保持一致。
func tokenAllowlisted(chainID, address string) bool {
	if address == nativeTokenAddress {
		return true
	}
	return allowlistedTokens[tokenKey(chainID, address)]
}

type tokenRecord struct {
	ID               int64
	TenantID         string
	Chain            string
	Address          string
	Symbol           string
	Name             string
	Decimals         int
	DisplayDecimals  int
	LogoColor        string
	SortWeight       int
	Enabled          bool
	MetadataSyncedAt time.Time // 零值表示 NULL
	UpdatedAt        time.Time
	Deleted          bool
}

func (t tokenRecord) scope() string {
	if t.TenantID == "0" {
		return "global"
	}
	return "tenant"
}

func (t tokenRecord) key() string { return tokenKey(t.Chain, t.Address) }

// tokenView 是管理端接口里的完整代币对象（契约第 1 节）。
func tokenView(t tokenRecord) gin.H {
	return gin.H{
		"id":               t.ID,
		"scope":            t.scope(),
		"chain":            t.Chain,
		"address":          t.Address,
		"symbol":           t.Symbol,
		"name":             t.Name,
		"decimals":         t.Decimals,
		"displayDecimals":  t.DisplayDecimals,
		"logoColor":        t.LogoColor,
		"sortWeight":       t.SortWeight,
		"enabled":          t.Enabled,
		"allowlisted":      tokenAllowlisted(t.Chain, t.Address),
		"metadataSyncedAt": nullableTime(t.MetadataSyncedAt),
		"updatedAt":        iso(t.UpdatedAt),
	}
}

// bootstrapTokenView 是下发给 App 的形态（契约第 2 节）：不带 id / scope / verified。
// verified 只能由 App 自己的白名单授予——被攻破的服务端最想控制的就是这个字段。
func bootstrapTokenView(t tokenRecord) gin.H {
	return gin.H{
		"chain":           t.Chain,
		"address":         t.Address,
		"symbol":          t.Symbol,
		"name":            t.Name,
		"decimals":        t.Decimals,
		"displayDecimals": t.DisplayDecimals,
		"logoColor":       t.LogoColor,
	}
}

// validateDeliveredTokens 是下发前的完整性检查。写入路径已经拒绝这些状态，出现在库里
// 就是事故：不在读路径上截断或补值，而是让整份 bootstrap 失败（503），App 继续用上次
// 快照，日志里留下坏行。同时检查不变量"每条启用的链都有一条启用的原生币"——App 的手续费
// 与原生币余额都按它显示。
func validateDeliveredTokens(merged []tokenRecord, chains []any) error {
	nativeSeen := map[string]bool{}
	for _, row := range merged {
		if !row.Enabled {
			continue
		}
		if row.Symbol == "" {
			return fmt.Errorf("token %d (%s %s) has an empty symbol", row.ID, row.Chain, row.Address)
		}
		if row.DisplayDecimals < 0 || row.DisplayDecimals > row.Decimals {
			return fmt.Errorf("token %d (%s %s) has displayDecimals %d outside 0..%d", row.ID, row.Chain, row.Address, row.DisplayDecimals, row.Decimals)
		}
		if !logoColorPattern.MatchString(row.LogoColor) {
			return fmt.Errorf("token %d (%s %s) has an invalid logoColor %q", row.ID, row.Chain, row.Address, row.LogoColor)
		}
		if row.Address == nativeTokenAddress {
			nativeSeen[row.Chain] = true
		}
	}
	for _, item := range chains {
		id, ok := item.(string)
		if ok && !nativeSeen[id] {
			return fmt.Errorf("enabled chain %q has no enabled native token", id)
		}
	}
	return nil
}

// mergeTokenRecords 把全局行与租户行合成一份视图：同 (chain, address) 只留租户行，
// 再按 sortWeight DESC, symbol ASC 排序。合并只在服务端做这一次，App 只拿结果。
func mergeTokenRecords(rows []tokenRecord) []tokenRecord {
	byKey := map[string]tokenRecord{}
	for _, row := range rows {
		if row.Deleted {
			continue
		}
		current, exists := byKey[row.key()]
		if exists && current.scope() == "tenant" && row.scope() == "global" {
			continue
		}
		byKey[row.key()] = row
	}
	merged := make([]tokenRecord, 0, len(byKey))
	for _, row := range byKey {
		merged = append(merged, row)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		left, right := merged[i], merged[j]
		if left.SortWeight != right.SortWeight {
			return left.SortWeight > right.SortWeight
		}
		if left.Symbol != right.Symbol {
			return left.Symbol < right.Symbol
		}
		if left.Chain != right.Chain {
			return left.Chain < right.Chain
		}
		return left.Address < right.Address
	})
	return merged
}

// bootstrapTokens 从合并视图里挑出要下发的：只要 enabled，且所在链在租户已启用的
// chains 里——停用一条链时它上面的币也不该再出现在 App 里。
func bootstrapTokens(merged []tokenRecord, chains []any) []any {
	enabled := map[string]bool{}
	for _, item := range chains {
		if id, ok := item.(string); ok {
			enabled[id] = true
		}
	}
	items := []any{}
	for _, row := range merged {
		if !row.Enabled || !enabled[row.Chain] {
			continue
		}
		items = append(items, bootstrapTokenView(row))
	}
	return items
}

// attachWalletTokens 把代币目录放进 bootstrap 的 wallet 段。
//
// 读库失败就是整份 bootstrap 失败（503）：App 会继续用上一次成功的快照。不能
// 省略 tokens 让 App 按"没有代币"理解——那是把故障伪装成一份合法的空目录。
func (s *server) attachWalletTokens(ctx context.Context, tenant string, wallet map[string]any) error {
	rows, err := s.queryTokens(ctx, tenant, "")
	if err != nil {
		return err
	}
	chains, _ := wallet["chains"].([]any)
	merged := mergeTokenRecords(rows)
	if err := validateDeliveredTokens(merged, chains); err != nil {
		return err
	}
	wallet["tokens"] = bootstrapTokens(merged, chains)
	return nil
}

// ---- 数据访问 ----

type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

const tokenColumns = `id,CAST(tenant_id AS CHAR),chain,contract_address,symbol,name,decimals,display_decimals,logo_color,sort_weight,enabled,metadata_synced_at,mtime,deleted`

func scanToken(scanner interface{ Scan(dest ...any) error }) (tokenRecord, error) {
	var row tokenRecord
	var synced sql.NullTime
	err := scanner.Scan(&row.ID, &row.TenantID, &row.Chain, &row.Address, &row.Symbol, &row.Name, &row.Decimals, &row.DisplayDecimals, &row.LogoColor, &row.SortWeight, &row.Enabled, &synced, &row.UpdatedAt, &row.Deleted)
	if synced.Valid {
		row.MetadataSyncedAt = synced.Time
	}
	return row, err
}

// queryTokens 取全局与本租户未删除的行；chain 为空表示全部链。
func (s *server) queryTokens(ctx context.Context, tenant, chainID string) ([]tokenRecord, error) {
	query := `SELECT ` + tokenColumns + ` FROM chain_token_catalog WHERE tenant_id IN (0,?) AND deleted=0`
	args := []any{tenant}
	if chainID != "" {
		query += ` AND chain=?`
		args = append(args, chainID)
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []tokenRecord{}
	for rows.Next() {
		row, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

// findToken 按 id 取一条本租户可见（全局或自己的）未删除的行。
func findToken(ctx context.Context, db dbExecutor, tenant string, id int64) (tokenRecord, bool, error) {
	row, err := scanToken(db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM chain_token_catalog WHERE id=? AND tenant_id IN (0,?) AND deleted=0`, id, tenant))
	if errors.Is(err, sql.ErrNoRows) {
		return tokenRecord{}, false, nil
	}
	return row, err == nil, err
}

// findTokenPair 取同 (chain, address) 的全局行（未删除）与本租户自己的行。租户行
// 连已软删除的也取出来：唯一键把删除行也算在内，重新添加时要复活它而不是再插一条。
func findTokenPair(ctx context.Context, db dbExecutor, tenant, chainID, address string) (global, own *tokenRecord, err error) {
	rows, err := db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM chain_token_catalog WHERE chain=? AND contract_address=? AND tenant_id IN (0,?)`, chainID, address, tenant)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		row, err := scanToken(rows)
		if err != nil {
			return nil, nil, err
		}
		copied := row
		if row.TenantID == "0" {
			if !row.Deleted {
				global = &copied
			}
		} else {
			own = &copied
		}
	}
	return global, own, rows.Err()
}

func insertToken(ctx context.Context, tx dbExecutor, tenant string, row tokenRecord) (int64, error) {
	result, err := tx.ExecContext(ctx, `INSERT INTO chain_token_catalog(tenant_id,chain,contract_address,symbol,name,decimals,display_decimals,logo_color,sort_weight,enabled,metadata_synced_at,ctime,mtime,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		tenant, row.Chain, row.Address, row.Symbol, row.Name, row.Decimals, row.DisplayDecimals, row.LogoColor, row.SortWeight, row.Enabled, nullableSQLTime(row.MetadataSyncedAt), time.Now().UTC(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// updateToken 覆写一行的全部可写字段并取消软删除；symbol/decimals 只在 create
// 复活与 resync 里变化，其余路径传入的就是原值。
func updateToken(ctx context.Context, tx dbExecutor, tenant string, row tokenRecord) error {
	result, err := tx.ExecContext(ctx, `UPDATE chain_token_catalog SET symbol=?,name=?,decimals=?,display_decimals=?,logo_color=?,sort_weight=?,enabled=?,metadata_synced_at=?,mtime=?,deleted=0 WHERE id=? AND tenant_id=?`,
		row.Symbol, row.Name, row.Decimals, row.DisplayDecimals, row.LogoColor, row.SortWeight, row.Enabled, nullableSQLTime(row.MetadataSyncedAt), time.Now().UTC(), row.ID, tenant)
	if err != nil {
		return err
	}
	return requireOneRow(result)
}

// requireOneRow 把"UPDATE 命中 0 行"当成冲突：行在读取之后被别人删了，
// 静默返回 200 会让运营以为改成功了。按乐观锁冲突处理，管理端会刷新重来。
func requireOneRow(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errTokenVersionConflict
	}
	return nil
}

func nullableSQLTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

// tokenConfigVersion 读版本锚点；没有行即 0，与 localization 的 tenantVersion 一致。
func tokenConfigVersion(ctx context.Context, db dbExecutor, tenant string) (int, error) {
	var version int
	err := db.QueryRowContext(ctx, `SELECT version FROM app_configs WHERE tenant_id=? AND config_key=?`, tenant, tokensConfigKey).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return version, err
}

var errTokenVersionConflict = errors.New("token catalog changed since it was loaded")

// bumpTokenConfigVersion 把版本 +1：首次写入插入 version=1，否则按 expected 条件更新。
func bumpTokenConfigVersion(ctx context.Context, tx dbExecutor, tenant string, expected int, updatedBy string) (int, error) {
	now := time.Now().UTC()
	if expected == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`, tenant, tokensConfigKey, `{"schemaVersion":1}`, 1, updatedBy, now); err != nil {
			if isDuplicateEntry(err) {
				return 0, errTokenVersionConflict
			}
			return 0, err
		}
		return 1, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE app_configs SET version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, updatedBy, now, tenant, tokensConfigKey, expected)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, errTokenVersionConflict
	}
	return expected + 1, nil
}

// ---- 请求校验 ----

// tokenError 是 handler 内部往外传的 problem：状态码、错误码、给运营看的说明。
type tokenError struct {
	status int
	code   string
	detail string
}

func (e *tokenError) Error() string { return e.code + ": " + e.detail }

func badTokenRequest(detail string) *tokenError {
	return &tokenError{status: http.StatusBadRequest, code: "INVALID_TOKEN_REQUEST", detail: detail}
}

func writeTokenProblem(c *gin.Context, err error) {
	var typed *tokenError
	if errors.As(err, &typed) {
		problem(c, typed.status, typed.code, typed.detail)
		return
	}
	if errors.Is(err, errTokenVersionConflict) {
		problem(c, http.StatusConflict, "CONFIG_VERSION_CONFLICT", "代币目录已被其他人修改，请刷新后重试")
		return
	}
	slog.Error("token catalog request failed", "error", err)
	problem(c, http.StatusInternalServerError, "TOKEN_SAVE_FAILED", "Unable to save token")
}

// tokenChainProblem 把读链的失败分类映射到契约里的错误码。节点的原话不外泄，
// 只记日志。
func tokenChainProblem(err error) *tokenError {
	switch chain.KindOf(err) {
	case chain.KindNotAContract:
		return &tokenError{status: http.StatusBadRequest, code: "TOKEN_NOT_A_CONTRACT", detail: "这个地址上没有合约代码，转给它的代币会永久丢失"}
	case chain.KindChainMismatch:
		return &tokenError{status: http.StatusBadRequest, code: "TOKEN_CHAIN_MISMATCH", detail: "平台端点报告的链与所选链不符，请联系平台核对端点"}
	case chain.KindMetadataInvalid:
		return &tokenError{status: http.StatusBadRequest, code: "TOKEN_METADATA_INVALID", detail: "链上返回的 symbol 或 decimals 不合法，这个合约不是规范的 ERC-20"}
	default:
		return &tokenError{status: http.StatusBadGateway, code: "TOKEN_CHAIN_UNAVAILABLE", detail: "链上节点暂时无法访问，请稍后重试"}
	}
}

// normalizeTokenAddress 把合约地址规范成 EIP-55：全小写 / 全大写按规则转换，混合
// 大小写但校验和不符的是抄错了，直接拒绝——唯一键按字面比较，放过一个大小写不同
// 的同一地址就会出现两条 USDT。
func normalizeTokenAddress(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if !addressPattern.MatchString(value) {
		return "", errors.New("合约地址必须是 0x 开头的 40 位十六进制")
	}
	hexPart := value[2:]
	checksummed := siwe.ChecksumAddress(value)
	mixed := hexPart != strings.ToLower(hexPart) && hexPart != strings.ToUpper(hexPart)
	if mixed && value != checksummed {
		return "", errors.New("合约地址的 EIP-55 校验和不符，请从区块浏览器重新复制")
	}
	return checksummed, nil
}

func validateTokenName(raw string) (string, error) {
	name, err := chain.SanitizeText(raw, chain.MaxNameLength)
	if err != nil {
		return "", fmt.Errorf("name 只能包含可打印字符且不超过 %d 个字符", chain.MaxNameLength)
	}
	if name == "" {
		return "", errors.New("name 是必填项")
	}
	return name, nil
}

func validateLogoColor(raw string) (string, error) {
	color := strings.TrimSpace(raw)
	if !logoColorPattern.MatchString(color) {
		return "", errors.New("logoColor 是必填项，必须是 #RRGGBB 形式的颜色")
	}
	return color, nil
}

func validateReasonAndVersion(reason string, expectedVersion int) error {
	if len(strings.TrimSpace(reason)) < 3 {
		return badTokenRequest("reason 至少 3 个字")
	}
	if expectedVersion < 0 {
		return badTokenRequest("expectedVersion 不能为负")
	}
	return nil
}

// tokenReadOnlyFields 是 PATCH 里出现即拒绝的字段：symbol / decimals 是链上事实，
// chain / address 是身份，其余是服务端派生。
var tokenReadOnlyFields = map[string]bool{
	"symbol": true, "decimals": true, "chain": true, "contractAddress": true, "address": true,
	"id": true, "scope": true, "allowlisted": true, "metadataSyncedAt": true, "updatedAt": true,
}

var tokenPatchFields = map[string]bool{
	"name": true, "displayDecimals": true, "logoColor": true, "sortWeight": true, "enabled": true,
	"reason": true, "expectedVersion": true,
}

// checkTokenPatchFields 先按字段名做权限判断，再交给结构体解码：DisallowUnknownFields
// 只会说"未知字段"，运营看不出是自己动了不该动的列。
func checkTokenPatchFields(fields map[string]json.RawMessage) *tokenError {
	for name := range fields {
		if tokenReadOnlyFields[name] {
			return &tokenError{status: http.StatusBadRequest, code: "TOKEN_FIELD_READONLY", detail: name + " 不可编辑：symbol/decimals 只能重新从链上读取，链与地址是代币身份"}
		}
		if !tokenPatchFields[name] {
			return badTokenRequest(name + " 不是可编辑字段")
		}
	}
	return nil
}

type tokenPatch struct {
	Name            *string `json:"name"`
	DisplayDecimals *int    `json:"displayDecimals"`
	LogoColor       *string `json:"logoColor"`
	SortWeight      *int    `json:"sortWeight"`
	Enabled         *bool   `json:"enabled"`
	Reason          string  `json:"reason"`
	ExpectedVersion int     `json:"expectedVersion"`
}

func decodeTokenPatch(c *gin.Context) (tokenPatch, error) {
	var patch tokenPatch
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	if err != nil {
		return patch, badTokenRequest("请求体无法读取")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return patch, badTokenRequest("请求体必须是 JSON 对象")
	}
	if typed := checkTokenPatchFields(fields); typed != nil {
		return patch, typed
	}
	if err := json.Unmarshal(raw, &patch); err != nil {
		return patch, badTokenRequest("字段类型不对")
	}
	return patch, nil
}

// applyTokenPatch 把补丁落到一行上并校验；displayDecimals 的上限是这一行的链上精度。
func applyTokenPatch(row tokenRecord, patch tokenPatch) (tokenRecord, error) {
	if patch.Name != nil {
		name, err := validateTokenName(*patch.Name)
		if err != nil {
			return row, badTokenRequest(err.Error())
		}
		row.Name = name
	}
	if patch.LogoColor != nil {
		color, err := validateLogoColor(*patch.LogoColor)
		if err != nil {
			return row, badTokenRequest(err.Error())
		}
		row.LogoColor = color
	}
	if patch.SortWeight != nil {
		row.SortWeight = *patch.SortWeight
	}
	if patch.Enabled != nil {
		// 启用一条链即启用它的原生币：App 的手续费、原生币余额都按目录里这一条显示，
		// 停用它等于让一条启用的链没有原生币——那不是一个合法状态
		if !*patch.Enabled && row.Address == nativeTokenAddress {
			return row, badTokenRequest("原生币不能停用：要停用它，请在钱包配置里关闭这条链")
		}
		row.Enabled = *patch.Enabled
	}
	if patch.DisplayDecimals != nil {
		row.DisplayDecimals = *patch.DisplayDecimals
	}
	if row.DisplayDecimals < 0 || row.DisplayDecimals > row.Decimals {
		return row, badTokenRequest(fmt.Sprintf("displayDecimals 必须在 0～%d 之间（不能超过链上精度）", row.Decimals))
	}
	// 头像底色是必填项：App 直接把它落到背景色上，没有"没有颜色"的展示形态
	if _, err := validateLogoColor(row.LogoColor); err != nil {
		return row, badTokenRequest(err.Error())
	}
	return row, nil
}

func tokenIDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", "代币 id 必须是正整数")
		return 0, false
	}
	return id, true
}

func (s *server) tokenNetwork(chainID string) (chain.Network, bool) {
	network, ok := platformNetwork(chainID)
	if !ok {
		return chain.Network{}, false
	}
	endpoints := make([]string, 0, len(network.RPCUrls))
	for _, item := range network.RPCUrls {
		if url, ok := item.(string); ok {
			endpoints = append(endpoints, url)
		}
	}
	// 只用平台默认端点：租户能配 RPC，就能配一个返回假 decimals 的节点
	return chain.Network{ID: network.ID, ChainID: network.ChainID, Endpoints: endpoints}, true
}

// tokenTransaction 把一次写操作的固定骨架串起来：核对 expectedVersion → 业务写入 →
// version+1 → 审计 → 提交。fn 返回审计的目标 id 与摘要。失败时已经写好 problem。
func (s *server) tokenTransaction(c *gin.Context, expectedVersion int, action, reason string, fn func(ctx context.Context, tx *sql.Tx) (string, map[string]any, error)) (int, bool) {
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		writeTokenProblem(c, err)
		return 0, false
	}
	defer tx.Rollback()
	current, err := tokenConfigVersion(ctx, tx, tenantID(c))
	if err != nil {
		writeTokenProblem(c, err)
		return 0, false
	}
	if current != expectedVersion {
		writeTokenProblem(c, errTokenVersionConflict)
		return 0, false
	}
	targetID, summary, err := fn(ctx, tx)
	if err != nil {
		writeTokenProblem(c, err)
		return 0, false
	}
	newVersion, err := bumpTokenConfigVersion(ctx, tx, tenantID(c), current, actor(c))
	if err != nil {
		writeTokenProblem(c, err)
		return 0, false
	}
	summary["databaseVersionBefore"], summary["databaseVersionAfter"] = current, newVersion
	if err := insertAudit(ctx, tx, newAudit(tenantID(c), actor(c), action, "token", targetID, reason, requestID(c), summary)); err != nil {
		writeTokenProblem(c, err)
		return 0, false
	}
	if err := tx.Commit(); err != nil {
		writeTokenProblem(c, err)
		return 0, false
	}
	return newVersion, true
}

func tokenSummary(row tokenRecord) map[string]any {
	return map[string]any{"chain": row.Chain, "address": row.Address, "symbol": row.Symbol, "decimals": row.Decimals, "displayDecimals": row.DisplayDecimals, "enabled": row.Enabled, "scope": row.scope()}
}

// ---- 接口 ----

// listTokens GET /v1/admin/tokens?chain=
func (s *server) listTokens(c *gin.Context) {
	chainID := strings.TrimSpace(c.Query("chain"))
	if chainID != "" {
		if _, ok := supportedNetwork(chainID); !ok {
			problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", fmt.Sprintf("不支持的链 %q：当前平台支持 %s", chainID, supportedNetworkIDs()))
			return
		}
	}
	rows, err := s.queryTokens(c.Request.Context(), tenantID(c), chainID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load tokens")
		return
	}
	version, err := tokenConfigVersion(c.Request.Context(), s.db, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load tokens")
		return
	}
	items := []any{}
	for _, row := range mergeTokenRecords(rows) {
		items = append(items, tokenView(row))
	}
	c.JSON(http.StatusOK, gin.H{"tokens": items, "metadata": gin.H{"databaseVersion": version}})
}

// previewToken POST /v1/admin/tokens/preview —— 只读链，不入库。
func (s *server) previewToken(c *gin.Context) {
	var body struct {
		Chain           string `json:"chain"`
		ContractAddress string `json:"contractAddress"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", "chain 与 contractAddress 是必填项")
		return
	}
	network, ok := s.tokenNetwork(body.Chain)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", fmt.Sprintf("不支持的链 %q：当前平台支持 %s", body.Chain, supportedNetworkIDs()))
		return
	}
	address, err := normalizeTokenAddress(body.ContractAddress)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", err.Error())
		return
	}
	meta, err := s.tokens.ReadToken(c.Request.Context(), network, address)
	if err != nil {
		slog.Warn("token preview could not read the chain", "chain", body.Chain, "address", address, "error", err)
		writeTokenProblem(c, tokenChainProblem(err))
		return
	}
	global, own, err := findTokenPair(c.Request.Context(), s.db, tenantID(c), body.Chain, address)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load tokens")
		return
	}
	var exists any
	if own != nil && !own.Deleted {
		exists = gin.H{"id": own.ID, "scope": own.scope()}
	} else if global != nil {
		exists = gin.H{"id": global.ID, "scope": global.scope()}
	}
	c.JSON(http.StatusOK, gin.H{"chain": body.Chain, "contractAddress": address, "symbol": meta.Symbol, "name": meta.Name, "decimals": meta.Decimals, "allowlisted": tokenAllowlisted(body.Chain, address), "exists": exists})
}

// createToken POST /v1/admin/tokens
func (s *server) createToken(c *gin.Context) {
	var body struct {
		Chain           string  `json:"chain"`
		ContractAddress string  `json:"contractAddress"`
		DisplayDecimals *int    `json:"displayDecimals"`
		Name            *string `json:"name"`
		LogoColor       *string `json:"logoColor"`
		SortWeight      *int    `json:"sortWeight"`
		Enabled         *bool   `json:"enabled"`
		Reason          string  `json:"reason"`
		ExpectedVersion int     `json:"expectedVersion"`
	}
	if decode(c, &body) != nil || body.DisplayDecimals == nil {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", "chain、contractAddress、displayDecimals、reason 与 expectedVersion 是必填项")
		return
	}
	if err := validateReasonAndVersion(body.Reason, body.ExpectedVersion); err != nil {
		writeTokenProblem(c, err)
		return
	}
	network, ok := s.tokenNetwork(body.Chain)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", fmt.Sprintf("不支持的链 %q：当前平台支持 %s", body.Chain, supportedNetworkIDs()))
		return
	}
	address, err := normalizeTokenAddress(body.ContractAddress)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", err.Error())
		return
	}
	ctx := c.Request.Context()
	global, own, err := findTokenPair(ctx, s.db, tenantID(c), body.Chain, address)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load tokens")
		return
	}
	if own != nil && !own.Deleted {
		problem(c, http.StatusConflict, "TOKEN_EXISTS", "这条链上已经有这个合约的记录")
		return
	}
	row := tokenRecord{Chain: body.Chain, Address: address, Enabled: true}
	if global != nil {
		// 已有全局行：建的是覆盖行。symbol/decimals 从全局行复制、不读链——覆盖行
		// 只改租户能改的那几项，链上事实必须与全局行一致
		row.Symbol, row.Name, row.Decimals = global.Symbol, global.Name, global.Decimals
		row.LogoColor, row.SortWeight, row.Enabled = global.LogoColor, global.SortWeight, global.Enabled
		row.MetadataSyncedAt = global.MetadataSyncedAt
	} else {
		// 重新读链，不信 preview 的结果：那是另一个请求，中间可以被改
		meta, err := s.tokens.ReadToken(ctx, network, address)
		if err != nil {
			slog.Warn("token create could not read the chain", "chain", body.Chain, "address", address, "error", err)
			writeTokenProblem(c, tokenChainProblem(err))
			return
		}
		row.Symbol, row.Name, row.Decimals = meta.Symbol, meta.Name, meta.Decimals
		// 声明默认（OpenAPI 与管理端提示都写明）：合约没有 name() 时名称用符号
		if row.Name == "" {
			row.Name = meta.Symbol
		}
		row.MetadataSyncedAt = time.Now().UTC()
	}
	row, err = applyTokenPatch(row, tokenPatch{Name: body.Name, DisplayDecimals: body.DisplayDecimals, LogoColor: body.LogoColor, SortWeight: body.SortWeight, Enabled: body.Enabled})
	if err != nil {
		writeTokenProblem(c, err)
		return
	}
	var id int64
	_, ok = s.tokenTransaction(c, body.ExpectedVersion, "token_create", body.Reason, func(ctx context.Context, tx *sql.Tx) (string, map[string]any, error) {
		var err error
		if own != nil {
			// 软删除过的行复活：唯一键把删除行也算在内，再插一条会撞键
			row.ID = own.ID
			err = updateToken(ctx, tx, tenantID(c), row)
		} else {
			row.ID, err = insertToken(ctx, tx, tenantID(c), row)
		}
		if isDuplicateEntry(err) {
			return "", nil, &tokenError{status: http.StatusConflict, code: "TOKEN_EXISTS", detail: "这条链上已经有这个合约的记录"}
		}
		if err != nil {
			return "", nil, err
		}
		id = row.ID
		summary := tokenSummary(row)
		summary["overridesGlobal"] = global != nil
		return strconv.FormatInt(id, 10), summary, nil
	})
	if !ok {
		return
	}
	s.respondToken(c, http.StatusCreated, id)
}

// respondToken 提交后重新读一遍再返回：mtime 与 id 都是数据库给的。
func (s *server) respondToken(c *gin.Context, status int, id int64) {
	row, found, err := findToken(c.Request.Context(), s.db, tenantID(c), id)
	version, versionErr := tokenConfigVersion(c.Request.Context(), s.db, tenantID(c))
	if err != nil || !found || versionErr != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Token was saved but could not be reloaded")
		return
	}
	c.JSON(status, gin.H{"token": tokenView(row), "metadata": gin.H{"databaseVersion": version}})
}

// patchToken PATCH /v1/admin/tokens/{id}
func (s *server) patchToken(c *gin.Context) {
	id, ok := tokenIDParam(c)
	if !ok {
		return
	}
	patch, err := decodeTokenPatch(c)
	if err != nil {
		writeTokenProblem(c, err)
		return
	}
	if err := validateReasonAndVersion(patch.Reason, patch.ExpectedVersion); err != nil {
		writeTokenProblem(c, err)
		return
	}
	ctx := c.Request.Context()
	row, found, err := findToken(ctx, s.db, tenantID(c), id)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load token")
		return
	}
	if !found {
		problem(c, http.StatusNotFound, "TOKEN_NOT_FOUND", "代币不存在")
		return
	}
	target := row
	if row.scope() == "global" && tenantID(c) != "0" {
		// 租户改全局行 → 落到自己的覆盖行上：已有覆盖行（含软删除的）就改它，
		// 没有就从全局行复制一份再改
		_, own, err := findTokenPair(ctx, s.db, tenantID(c), row.Chain, row.Address)
		if err != nil {
			problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load token")
			return
		}
		if own != nil && !own.Deleted {
			target = *own
		} else {
			target = row
			target.ID = 0
			target.TenantID = tenantID(c)
			if own != nil {
				target.ID = own.ID
			}
		}
	}
	updated, err := applyTokenPatch(target, patch)
	if err != nil {
		writeTokenProblem(c, err)
		return
	}
	var savedID int64
	_, ok = s.tokenTransaction(c, patch.ExpectedVersion, "token_update", patch.Reason, func(ctx context.Context, tx *sql.Tx) (string, map[string]any, error) {
		var err error
		if updated.ID == 0 {
			updated.ID, err = insertToken(ctx, tx, tenantID(c), updated)
		} else {
			err = updateToken(ctx, tx, tenantID(c), updated)
		}
		if err != nil {
			return "", nil, err
		}
		savedID = updated.ID
		summary := tokenSummary(updated)
		summary["sourceId"], summary["sourceScope"] = row.ID, row.scope()
		return strconv.FormatInt(savedID, 10), summary, nil
	})
	if !ok {
		return
	}
	s.respondToken(c, http.StatusOK, savedID)
}

// resyncToken POST /v1/admin/tokens/{id}/resync
func (s *server) resyncToken(c *gin.Context) {
	id, ok := tokenIDParam(c)
	if !ok {
		return
	}
	var body struct {
		Reason          string `json:"reason"`
		ExpectedVersion int    `json:"expectedVersion"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", "reason 与 expectedVersion 是必填项")
		return
	}
	if err := validateReasonAndVersion(body.Reason, body.ExpectedVersion); err != nil {
		writeTokenProblem(c, err)
		return
	}
	ctx := c.Request.Context()
	row, found, err := findToken(ctx, s.db, tenantID(c), id)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load token")
		return
	}
	if !found {
		problem(c, http.StatusNotFound, "TOKEN_NOT_FOUND", "代币不存在")
		return
	}
	if row.Address == nativeTokenAddress {
		problem(c, http.StatusBadRequest, "TOKEN_NATIVE_NO_RESYNC", "原生币没有合约，符号与精度来自平台链目录")
		return
	}
	// 平台全局行、以及覆盖它的租户行，symbol/decimals 都是平台事实：租户上下文不能
	// 改写，也没必要先读链再给一个必然失败的确认框。这一步放在读链之前
	if tenantID(c) != "0" {
		global, _, err := findTokenPair(ctx, s.db, tenantID(c), row.Chain, row.Address)
		if err != nil {
			problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load token")
			return
		}
		if global != nil {
			problem(c, http.StatusForbidden, "TOKEN_GLOBAL_METADATA_READONLY", "平台全局代币（及其租户覆盖行）的链上元数据由平台维护，租户不能重新读取")
			return
		}
	}
	current, err := tokenConfigVersion(ctx, s.db, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load token")
		return
	}
	if current != body.ExpectedVersion {
		writeTokenProblem(c, errTokenVersionConflict)
		return
	}
	network, ok := s.tokenNetwork(row.Chain)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", fmt.Sprintf("链 %q 已不在平台目录里", row.Chain))
		return
	}
	meta, err := s.tokens.ReadToken(ctx, network, row.Address)
	if err != nil {
		slog.Warn("token resync could not read the chain", "chain", row.Chain, "address", row.Address, "error", err)
		writeTokenProblem(c, tokenChainProblem(err))
		return
	}
	if meta.Symbol == row.Symbol && meta.Decimals == row.Decimals {
		// 与库中一致：只刷新"最近核对时间"，不算配置变更，不动版本也不写审计
		if _, err := s.db.ExecContext(ctx, `UPDATE chain_token_catalog SET metadata_synced_at=? WHERE id=? AND tenant_id=?`, time.Now().UTC(), row.ID, row.TenantID); err != nil {
			writeTokenProblem(c, err)
			return
		}
		row.MetadataSyncedAt = time.Now().UTC()
		c.JSON(http.StatusOK, gin.H{"changed": false, "token": tokenView(row)})
		return
	}
	if !body.Confirm {
		// 精度变了意味着合约升级或地址被换，不该静默接受：把差异交给运营确认
		c.JSON(http.StatusOK, gin.H{"changed": true, "current": gin.H{"symbol": row.Symbol, "decimals": row.Decimals}, "onchain": gin.H{"symbol": meta.Symbol, "decimals": meta.Decimals}})
		return
	}
	updated := row
	updated.Symbol, updated.Decimals, updated.MetadataSyncedAt = meta.Symbol, meta.Decimals, time.Now().UTC()
	if updated.DisplayDecimals > updated.Decimals {
		updated.DisplayDecimals = updated.Decimals
	}
	_, ok = s.tokenTransaction(c, body.ExpectedVersion, "token_resync", body.Reason, func(ctx context.Context, tx *sql.Tx) (string, map[string]any, error) {
		if err := updateToken(ctx, tx, row.TenantID, updated); err != nil {
			return "", nil, err
		}
		summary := tokenSummary(updated)
		summary["previousSymbol"], summary["previousDecimals"] = row.Symbol, row.Decimals
		return strconv.FormatInt(row.ID, 10), summary, nil
	})
	if !ok {
		return
	}
	reloaded, found, err := findToken(ctx, s.db, tenantID(c), row.ID)
	version, versionErr := tokenConfigVersion(ctx, s.db, tenantID(c))
	if err != nil || !found || versionErr != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Token was saved but could not be reloaded")
		return
	}
	c.JSON(http.StatusOK, gin.H{"changed": true, "token": tokenView(reloaded), "metadata": gin.H{"databaseVersion": version}})
}

// deleteToken DELETE /v1/admin/tokens/{id} —— 软删除。删租户覆盖行等于恢复全局行。
func (s *server) deleteToken(c *gin.Context) {
	id, ok := tokenIDParam(c)
	if !ok {
		return
	}
	var body struct {
		Reason          string `json:"reason"`
		ExpectedVersion int    `json:"expectedVersion"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_TOKEN_REQUEST", "reason 与 expectedVersion 是必填项")
		return
	}
	if err := validateReasonAndVersion(body.Reason, body.ExpectedVersion); err != nil {
		writeTokenProblem(c, err)
		return
	}
	row, found, err := findToken(c.Request.Context(), s.db, tenantID(c), id)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TOKEN_QUERY_FAILED", "Unable to load token")
		return
	}
	if !found {
		problem(c, http.StatusNotFound, "TOKEN_NOT_FOUND", "代币不存在")
		return
	}
	if row.Address == nativeTokenAddress && row.scope() == "global" {
		// 原生币行删了就再也建不回来（create 只接受合约地址），而启用的链必须有它
		problem(c, http.StatusBadRequest, "TOKEN_NATIVE_REQUIRED", "原生币不能删除：要停用它，请在钱包配置里关闭这条链")
		return
	}
	if row.scope() == "global" && tenantID(c) != "0" {
		problem(c, http.StatusForbidden, "TOKEN_GLOBAL_READONLY", "平台全局代币不能从租户删除；要停用它，把这一行的 enabled 改为 false")
		return
	}
	version, ok := s.tokenTransaction(c, body.ExpectedVersion, "token_delete", body.Reason, func(ctx context.Context, tx *sql.Tx) (string, map[string]any, error) {
		result, err := tx.ExecContext(ctx, `UPDATE chain_token_catalog SET deleted=1,mtime=? WHERE id=? AND tenant_id=?`, time.Now().UTC(), row.ID, row.TenantID)
		if err != nil {
			return "", nil, err
		}
		if err := requireOneRow(result); err != nil {
			return "", nil, err
		}
		return strconv.FormatInt(row.ID, 10), tokenSummary(row), nil
	})
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"metadata": gin.H{"databaseVersion": version}})
}
