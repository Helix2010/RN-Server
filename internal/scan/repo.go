package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/secretbox"
)

// Querier 是 *sql.DB 与 *sql.Tx 的公共子集，让同一段 SQL 能在事务内外复用。
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// LoadConfigs 读出全部 chain-scan.<chain> 配置行（tenant 0）。坏行不跳过：返回错误，
// 让 indexer 把这条链标成 unconfigured 并在日志里说明，而不是带病运行。
func LoadConfigs(ctx context.Context, db Querier, box *secretbox.Box) (map[string]ChainConfig, map[string]error, error) {
	rows, err := db.QueryContext(ctx, `SELECT config_key,config_value,version FROM app_configs WHERE tenant_id=0 AND config_key LIKE ?`, ConfigKeyPrefix+"%")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	configs := map[string]ChainConfig{}
	broken := map[string]error{}
	for rows.Next() {
		var key string
		var raw []byte
		var version int
		if err := rows.Scan(&key, &raw, &version); err != nil {
			return nil, nil, err
		}
		chain := strings.TrimPrefix(key, ConfigKeyPrefix)
		cfg, err := Decode(chain, raw, version, box)
		if err != nil {
			broken[chain] = err
			continue
		}
		configs[chain] = cfg
	}
	return configs, broken, rows.Err()
}

// LoadConfig 读一条链的配置；不存在返回 sql.ErrNoRows。
func LoadConfig(ctx context.Context, db Querier, chain string, box *secretbox.Box) (ChainConfig, error) {
	var raw []byte
	var version int
	err := db.QueryRowContext(ctx, `SELECT config_value,version FROM app_configs WHERE tenant_id=0 AND config_key=?`, ConfigKey(chain)).Scan(&raw, &version)
	if err != nil {
		return ChainConfig{}, err
	}
	return Decode(chain, raw, version, box)
}

// SaveConfig 写一条链的配置：expectedVersion 不符返回 ErrVersionConflict；不存在时
// expectedVersion 必须为 0。返回新版本号。
func SaveConfig(ctx context.Context, tx Querier, cfg ChainConfig, expectedVersion int, actor string, box *secretbox.Box) (int, error) {
	raw, err := Encode(cfg, box)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	var current int
	err = tx.QueryRowContext(ctx, `SELECT version FROM app_configs WHERE tenant_id=0 AND config_key=? FOR UPDATE`, ConfigKey(cfg.Chain)).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedVersion != 0 {
			return 0, ErrVersionConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(0,?,?,1,?,?)`, ConfigKey(cfg.Chain), raw, actor, now); err != nil {
			return 0, err
		}
		return 1, nil
	case err != nil:
		return 0, err
	}
	if current != expectedVersion {
		return 0, ErrVersionConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=0 AND config_key=?`, raw, actor, now, ConfigKey(cfg.Chain)); err != nil {
		return 0, err
	}
	return current + 1, nil
}

// ErrVersionConflict 乐观锁冲突：别人改过了，管理端要重新读再改。
var ErrVersionConflict = errors.New("chain scan config version conflict")

// LoadState 读一条链的运行状态；不存在返回 sql.ErrNoRows。
func LoadState(ctx context.Context, db Querier, chain string) (ChainState, error) {
	var state ChainState
	var leaseUntil, scannedToTime sql.NullTime
	var health, jobs, alerts []byte
	err := db.QueryRowContext(ctx, `SELECT chain,scanned_to_block,scanned_to_hash,scanned_to_time,head_block,state,lease_owner,lease_until,last_error,error_count,reorg_count,endpoint_health,jobs,open_alerts,updated_at FROM chain_scan_state WHERE chain=?`, chain).Scan(
		&state.Chain, &state.ScannedToBlock, &state.ScannedToHash, &scannedToTime, &state.HeadBlock, &state.State, &state.LeaseOwner, &leaseUntil,
		&state.LastError, &state.ErrorCount, &state.ReorgCount, &health, &jobs, &alerts, &state.UpdatedAt)
	if err != nil {
		return ChainState{}, err
	}
	if leaseUntil.Valid {
		t := leaseUntil.Time
		state.LeaseUntil = &t
	}
	if scannedToTime.Valid {
		t := scannedToTime.Time.UTC()
		state.ScannedToTime = &t
	}
	if err := decodeJSON(health, &state.EndpointHealth); err != nil {
		return ChainState{}, fmt.Errorf("chain_scan_state.%s endpoint_health: %w", chain, err)
	}
	if err := decodeJSON(jobs, &state.Jobs); err != nil {
		return ChainState{}, fmt.Errorf("chain_scan_state.%s jobs: %w", chain, err)
	}
	if err := decodeJSON(alerts, &state.OpenAlerts); err != nil {
		return ChainState{}, fmt.Errorf("chain_scan_state.%s open_alerts: %w", chain, err)
	}
	return state, nil
}

// LoadStates 读全部链的运行状态，供管理端一览。
func LoadStates(ctx context.Context, db Querier) (map[string]ChainState, error) {
	rows, err := db.QueryContext(ctx, `SELECT chain FROM chain_scan_state`)
	if err != nil {
		return nil, err
	}
	chains := []string{}
	for rows.Next() {
		var chain string
		if err := rows.Scan(&chain); err != nil {
			rows.Close()
			return nil, err
		}
		chains = append(chains, chain)
	}
	rows.Close()
	states := map[string]ChainState{}
	for _, chain := range chains {
		state, err := LoadState(ctx, db, chain)
		if err != nil {
			return nil, err
		}
		states[chain] = state
	}
	return states, nil
}

// InsertState 初始化一条链的状态行（游标 = 起扫块）。已存在返回 false。
func InsertState(ctx context.Context, db Querier, chain string, block uint64, hash string) (bool, error) {
	result, err := db.ExecContext(ctx, `INSERT IGNORE INTO chain_scan_state(chain,scanned_to_block,scanned_to_hash,head_block,state,lease_owner,lease_until,last_error,error_count,reorg_count,endpoint_health,jobs,open_alerts,updated_at) VALUES(?,?,?,0,'idle','',NULL,'',0,0,'[]','[]','[]',?)`, chain, block, hash, time.Now().UTC())
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	return affected == 1, nil
}

// SaveState 写回运行状态里除游标外的字段（游标只在 CommitSlice 的事务里动）。
func SaveState(ctx context.Context, db Querier, state ChainState) error {
	health, jobs, alerts := mustJSON(state.EndpointHealth), mustJSON(state.Jobs), mustJSON(state.OpenAlerts)
	_, err := db.ExecContext(ctx, `UPDATE chain_scan_state SET head_block=?,state=?,last_error=?,error_count=?,reorg_count=?,endpoint_health=?,jobs=?,open_alerts=?,updated_at=? WHERE chain=?`,
		state.HeadBlock, string(state.State), truncate(state.LastError, 512), state.ErrorCount, state.ReorgCount, health, jobs, alerts, time.Now().UTC(), state.Chain)
	return err
}

// AcquireLease 尝试拿到或续上一条链的租约：没人持有、自己持有或已过期时成功。
func AcquireLease(ctx context.Context, db Querier, chain, owner string, until time.Time) (bool, error) {
	now := time.Now().UTC()
	result, err := db.ExecContext(ctx, `UPDATE chain_scan_state SET lease_owner=?,lease_until=? WHERE chain=? AND (lease_owner='' OR lease_owner=? OR lease_until IS NULL OR lease_until<?)`, owner, until.UTC(), chain, owner, now)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	return affected == 1, nil
}

// ReleaseLease 主动放掉租约（worker 停止时）。
func ReleaseLease(ctx context.Context, db Querier, chain, owner string) error {
	_, err := db.ExecContext(ctx, `UPDATE chain_scan_state SET lease_owner='',lease_until=NULL WHERE chain=? AND lease_owner=?`, chain, owner)
	return err
}

func decodeJSON(raw []byte, target any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, target)
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil || string(raw) == "null" {
		return []byte("[]")
	}
	return raw
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
