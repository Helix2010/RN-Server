package indexer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
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
	// CommitSlice 同一事务写记录并推进游标（toBlock=0 表示只写记录不动游标）；
	// toTime 是 toBlock 的链上时间戳，移动端据它算"落后秒数"。notify 为真时，首次写入的
	// in 行给该地址会话所在的安装入队 wallet.transfer.received 推送（重扫任务不推）。
	CommitSlice(ctx context.Context, chain string, rows []Row, toBlock uint64, toHash string, toTime time.Time, notify bool) error
	SaveBalances(ctx context.Context, chain string, updates map[WatchKey]BalanceSnapshot) error
	MarkOrphaned(ctx context.Context, chain string, afterBlock uint64) error
	InsertAudit(ctx context.Context, action, chain string, summary map[string]any) error
	// MutateJobs 行锁下读改写 jobs（管理端取消与 worker 进度互不覆盖），返回改后的数组。
	MutateJobs(ctx context.Context, chain string, mutate func([]scan.Job) ([]scan.Job, error)) ([]scan.Job, error)
	// ResolveUnattributed 补归属：写入 [from,to] 内全区块扫到的原生币行，并把与该区间相交的
	// unattributed 行按"新定位到的金额"扣减，扣完即删；同一事务。
	ResolveUnattributed(ctx context.Context, chain string, from, to uint64, rows []Row) error
}

// SQLStore 是 MySQL 实现。
type SQLStore struct {
	DB *sql.DB
	// ChainName 链 id → 显示名（推送文案的 {chain}）；nil 时用 id。
	ChainName func(chain string) string
}

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

func (s *SQLStore) CommitSlice(ctx context.Context, chain string, rows []Row, toBlock uint64, toHash string, toTime time.Time, notify bool) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var fresh []Row
	if notify {
		// 写入前判断哪些入账是第一次见：ON DUPLICATE KEY UPDATE 之后就分不清了
		for _, row := range rows {
			if row.Direction != "in" {
				continue
			}
			var one int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM wallet_transfer_index WHERE tenant_id=? AND chain=? AND tx_hash=? AND log_index=? AND address_key=? AND direction='in' AND block_number=? LIMIT 1`,
				row.TenantID, row.Chain, row.TxHash, row.LogIndex, row.AddressKey, row.BlockNumber).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				fresh = append(fresh, row)
			} else if err != nil {
				return err
			}
		}
	}
	if err := insertRows(ctx, tx, rows, now); err != nil {
		return err
	}
	for _, row := range fresh {
		if err := s.enqueueReceipt(ctx, tx, row, now); err != nil {
			return err
		}
	}
	if toBlock > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE chain_scan_state SET scanned_to_block=?,scanned_to_hash=?,scanned_to_time=?,updated_at=? WHERE chain=?`, toBlock, toHash, toTime.UTC(), now, chain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// enqueueReceipt 给收款地址当前有效会话所在的安装入队推送（设计 §4.10）。没有关联安装的
// 会话（旧版本 App 登录的）收不到定向推送；代币不在目录时没有符号与精度可显示，不推。
func (s *SQLStore) enqueueReceipt(ctx context.Context, tx *sql.Tx, row Row, now time.Time) error {
	cursor, err := tx.QueryContext(ctx, `SELECT DISTINCT s.installation_id FROM wallet_session s JOIN wallet_user u ON u.id=s.user_id WHERE s.tenant_id=? AND u.address_key=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.installation_id IS NOT NULL AND s.installation_id<>''`,
		row.TenantID, row.AddressKey, now)
	if err != nil {
		return err
	}
	var installations []string
	for cursor.Next() {
		var id string
		if err := cursor.Scan(&id); err != nil {
			cursor.Close()
			return err
		}
		installations = append(installations, id)
	}
	cursor.Close()
	if len(installations) == 0 {
		return nil
	}
	var symbol string
	var decimals, display int
	err = tx.QueryRowContext(ctx, `SELECT symbol,decimals,display_decimals FROM chain_token_catalog WHERE chain=? AND contract_address=? AND tenant_id IN (0,?) AND deleted=0 ORDER BY tenant_id DESC LIMIT 1`,
		row.Chain, row.Contract, row.TenantID).Scan(&symbol, &decimals, &display)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	chainName := row.Chain
	if s.ChainName != nil {
		chainName = s.ChainName(row.Chain)
	}
	payload, _ := json.Marshal(map[string]any{
		"chain": row.Chain, "chainName": chainName, "addressKey": row.AddressKey, "symbol": symbol, "decimals": decimals, "displayDecimals": display,
		"amountRaw": row.AmountRaw, "txHash": row.TxHash, "attribution": row.Attribution, "targetInstallationIds": installations,
	})
	_, err = tx.ExecContext(ctx, `INSERT INTO app_push_outbox(id,tenant_id,event_type,payload,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,'wallet.transfer.received',?,'pending',0,?,?,?)`,
		"push_"+randomID(16), row.TenantID, payload, now, now, now)
	return err
}

// insertRows 批量写记录。撞唯一键时不是忽略而是刷新：重组后同一笔交易回到同一区块号
// （只有区块哈希变了）时，原来标 orphaned 的行要重新变回 confirmed，重扫任务也靠它幂等。
func insertRows(ctx context.Context, tx *sql.Tx, rows []Row, now time.Time) error {
	for start := 0; start < len(rows); start += insertBatch {
		end := start + insertBatch
		if end > len(rows) {
			end = len(rows)
		}
		var b strings.Builder
		b.WriteString(`INSERT INTO wallet_transfer_index(tenant_id,chain,address_key,direction,asset,contract_address,amount_raw,counterparty,tx_hash,log_index,block_number,block_hash,block_time,attribution,gap_from_block,status,created_at) VALUES `)
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
		b.WriteString(` ON DUPLICATE KEY UPDATE status='confirmed',block_hash=VALUES(block_hash),block_time=VALUES(block_time),amount_raw=VALUES(amount_raw),counterparty=VALUES(counterparty),contract_address=VALUES(contract_address),gap_from_block=VALUES(gap_from_block)`)
		if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) MutateJobs(ctx context.Context, chain string, mutate func([]scan.Job) ([]scan.Job, error)) ([]scan.Job, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	next, err := scan.MutateJobs(ctx, tx, chain, mutate)
	if err != nil {
		return nil, err
	}
	return next, tx.Commit()
}

// ResolveUnattributed 见 Store 接口。扣减按每条 unattributed 行自己的区间与地址算：
// 先记下区间内已有的 tx 入账合计，写入新行后再算一次，差值就是这次新定位到的金额。
func (s *SQLStore) ResolveUnattributed(ctx context.Context, chain string, from, to uint64, rows []Row) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	type pending struct {
		id        uint64
		tenant    uint64
		address   string
		amount    *big.Int
		lo, hi    uint64
		beforeSum *big.Int
	}
	var targets []pending
	cursor, err := tx.QueryContext(ctx, `SELECT id,tenant_id,address_key,CAST(amount_raw AS CHAR),gap_from_block,block_number FROM wallet_transfer_index WHERE chain=? AND attribution='unattributed' AND status='confirmed' AND gap_from_block<=? AND block_number>=? FOR UPDATE`, chain, to, from)
	if err != nil {
		return err
	}
	for cursor.Next() {
		var item pending
		var amount string
		var gapFrom, block uint64
		if err := cursor.Scan(&item.id, &item.tenant, &item.address, &amount, &gapFrom, &block); err != nil {
			cursor.Close()
			return err
		}
		item.amount, _ = new(big.Int).SetString(amount, 10)
		item.lo, item.hi = gapFrom, block
		if item.lo < from {
			item.lo = from
		}
		if item.hi > to {
			item.hi = to
		}
		targets = append(targets, item)
	}
	cursor.Close()
	locatedSum := func(item pending) (*big.Int, error) {
		var text string
		if err := tx.QueryRowContext(ctx, `SELECT CAST(COALESCE(SUM(amount_raw),0) AS CHAR) FROM wallet_transfer_index WHERE tenant_id=? AND chain=? AND address_key=? AND direction='in' AND asset='native' AND attribution='tx' AND status='confirmed' AND block_number BETWEEN ? AND ?`, item.tenant, chain, item.address, item.lo, item.hi).Scan(&text); err != nil {
			return nil, err
		}
		sum, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return nil, fmt.Errorf("located sum %q is not an integer", text)
		}
		return sum, nil
	}
	for index := range targets {
		sum, err := locatedSum(targets[index])
		if err != nil {
			return err
		}
		targets[index].beforeSum = sum
	}
	if err := insertRows(ctx, tx, rows, time.Now().UTC()); err != nil {
		return err
	}
	for _, item := range targets {
		after, err := locatedSum(item)
		if err != nil {
			return err
		}
		remaining := new(big.Int).Sub(item.amount, new(big.Int).Sub(after, item.beforeSum))
		if remaining.Sign() <= 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM wallet_transfer_index WHERE id=?`, item.id); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE wallet_transfer_index SET amount_raw=? WHERE id=?`, remaining.String(), item.id); err != nil {
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
