package indexer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

// BalanceSnapshot 是 wallet_user.scan_state["<chain>"] 的形状。
type BalanceSnapshot struct {
	BalanceRaw string `json:"balanceRaw"`
	Block      uint64 `json:"block"`
}

// WatchKey 唯一标识一个（租户, 地址）。
type WatchKey struct {
	TenantID   uint64
	AddressKey string
}

// Watched 派生监听集合里的一个地址（同一地址在两个租户各算一个）。
type Watched struct {
	TenantID   uint64
	AddressKey string
	Balance    *BalanceSnapshot
}

// Key 取 (租户, 地址) 键。
func (w Watched) Key() WatchKey { return WatchKey{TenantID: w.TenantID, AddressKey: w.AddressKey} }

// Row 一条待写入的 wallet_transfer_index 记录。
type Row struct {
	TenantID     uint64
	Chain        string
	AddressKey   string
	Direction    string
	Asset        string
	Contract     string
	AmountRaw    string
	Counterparty string
	TxHash       string
	LogIndex     int
	BlockNumber  uint64
	BlockHash    string
	BlockTime    time.Time
	Attribution  string
	GapFromBlock *uint64
}

// Store 是 worker 需要的全部持久化操作；测试用内存实现，生产用 SQLStore。
type Store interface {
	LoadState(ctx context.Context, chain string) (scan.ChainState, error)
	InsertState(ctx context.Context, chain string, block uint64, hash string) (bool, error)
	SaveState(ctx context.Context, state scan.ChainState) error
	AcquireLease(ctx context.Context, chain, owner string, until time.Time) (bool, error)
	ReleaseLease(ctx context.Context, chain, owner string) error
	Watched(ctx context.Context, chain string, tenants []uint64) ([]Watched, error)
	Tokens(ctx context.Context, chain string) ([]string, error)
	// CommitSlice 同一事务写记录并推进游标（toBlock=0 表示只写记录不动游标）。
	CommitSlice(ctx context.Context, chain string, rows []Row, toBlock uint64, toHash string) error
	SaveBalances(ctx context.Context, chain string, updates map[WatchKey]BalanceSnapshot) error
	MarkOrphaned(ctx context.Context, chain string, afterBlock uint64) error
	InsertAudit(ctx context.Context, action, chain string, summary map[string]any) error
}

// SQLStore 是 MySQL 实现。
type SQLStore struct{ DB *sql.DB }

func (s *SQLStore) LoadState(ctx context.Context, chain string) (scan.ChainState, error) {
	return scan.LoadState(ctx, s.DB, chain)
}

func (s *SQLStore) InsertState(ctx context.Context, chain string, block uint64, hash string) (bool, error) {
	return scan.InsertState(ctx, s.DB, chain, block, hash)
}

func (s *SQLStore) SaveState(ctx context.Context, state scan.ChainState) error {
	return scan.SaveState(ctx, s.DB, state)
}

func (s *SQLStore) AcquireLease(ctx context.Context, chain, owner string, until time.Time) (bool, error) {
	return scan.AcquireLease(ctx, s.DB, chain, owner, until)
}

func (s *SQLStore) ReleaseLease(ctx context.Context, chain, owner string) error {
	return scan.ReleaseLease(ctx, s.DB, chain, owner)
}

// Watched 读派生监听集合：给定租户里 active 的钱包用户，带上该链的余额快照。
func (s *SQLStore) Watched(ctx context.Context, chain string, tenants []uint64) ([]Watched, error) {
	if len(tenants) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(tenants))
	args := []any{jsonPath(chain)}
	for _, tenant := range tenants {
		args = append(args, tenant)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT tenant_id,address_key,JSON_EXTRACT(scan_state,?) FROM wallet_user WHERE status='active' AND tenant_id IN (`+placeholders[:len(placeholders)-1]+`) ORDER BY tenant_id,address_key`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Watched
	for rows.Next() {
		var item Watched
		var snapshot []byte
		if err := rows.Scan(&item.TenantID, &item.AddressKey, &snapshot); err != nil {
			return nil, err
		}
		if len(snapshot) > 0 && string(snapshot) != "null" {
			var parsed BalanceSnapshot
			if err := json.Unmarshal(snapshot, &parsed); err != nil {
				return nil, fmt.Errorf("wallet_user %d/%s scan_state.%s: %w", item.TenantID, item.AddressKey, chain, err)
			}
			item.Balance = &parsed
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) Tokens(ctx context.Context, chain string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT contract_address FROM chain_token_catalog WHERE chain=? AND enabled=1 AND deleted=0 AND contract_address<>'native' ORDER BY contract_address`, chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, err
		}
		out = append(out, address)
	}
	return out, rows.Err()
}

const insertBatch = 200

func (s *SQLStore) CommitSlice(ctx context.Context, chain string, rows []Row, toBlock uint64, toHash string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for start := 0; start < len(rows); start += insertBatch {
		end := start + insertBatch
		if end > len(rows) {
			end = len(rows)
		}
		var b strings.Builder
		b.WriteString(`INSERT IGNORE INTO wallet_transfer_index(tenant_id,chain,address_key,direction,asset,contract_address,amount_raw,counterparty,tx_hash,log_index,block_number,block_hash,block_time,attribution,gap_from_block,status,created_at) VALUES `)
		args := make([]any, 0, (end-start)*17)
		for index, row := range rows[start:end] {
			if index > 0 {
				b.WriteString(",")
			}
			b.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'confirmed',?)")
			var gap any
			if row.GapFromBlock != nil {
				gap = *row.GapFromBlock
			}
			args = append(args, row.TenantID, row.Chain, row.AddressKey, row.Direction, row.Asset, row.Contract, row.AmountRaw, row.Counterparty, row.TxHash, row.LogIndex, row.BlockNumber, row.BlockHash, row.BlockTime.UTC(), row.Attribution, gap, now)
		}
		if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
			return err
		}
	}
	if toBlock > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE chain_scan_state SET scanned_to_block=?,scanned_to_hash=?,updated_at=? WHERE chain=?`, toBlock, toHash, now, chain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) SaveBalances(ctx context.Context, chain string, updates map[WatchKey]BalanceSnapshot) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	path := jsonPath(chain)
	for watched, snapshot := range updates {
		raw, _ := json.Marshal(snapshot)
		if _, err := tx.ExecContext(ctx, `UPDATE wallet_user SET scan_state=JSON_SET(COALESCE(scan_state,JSON_OBJECT()),?,CAST(? AS JSON)) WHERE tenant_id=? AND address_key=?`, path, string(raw), watched.TenantID, watched.AddressKey); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) MarkOrphaned(ctx context.Context, chain string, afterBlock uint64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE wallet_transfer_index SET status='orphaned' WHERE chain=? AND block_number>? AND status='confirmed'`, chain, afterBlock)
	return err
}

// InsertAudit 系统事件写审计（actor system-indexer，tenant 0）。
func (s *SQLStore) InsertAudit(ctx context.Context, action, chain string, summary map[string]any) error {
	raw, _ := json.Marshal(summary)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at) VALUES(?,0,'system-indexer',?,'chain',?,'',?,?,?)`,
		"audit_"+randomID(16), action, chain, "indexer_"+randomID(8), raw, time.Now().UTC())
	return err
}

func jsonPath(chain string) string { return `$."` + strings.ReplaceAll(chain, `"`, "") + `"` }
