package indexer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

const (
	// cacheTTL 派生监听集合与代币目录的刷新间隔。
	cacheTTL = 60 * time.Second
	// balanceChunk 一次 Multicall3 读多少个地址的余额。
	balanceChunk = 500
	// lagAlertAfter 落后多久告警。
	lagAlertAfter = 30 * time.Minute
	// stalledAlertAfter 全部端点不可用多久告警。
	stalledAlertAfter = 5 * time.Minute
	// progressSaveEvery 追块时每多少片写一次状态（游标本身每片都写）。
	progressSaveEvery = 10
)

// TenantResolver 回答"哪些租户启用了这条链且 onchainSends=true"——规则在 api 包
// （normalizeWallet），indexer 不复制它。
type TenantResolver interface {
	TenantsForChain(ctx context.Context) (map[string][]uint64, error)
}

// header 区块头里 worker 用到的字段。
type header struct {
	Number     uint64
	Hash       string
	ParentHash string
	Time       time.Time
}

type rpcTx struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Index string `json:"transactionIndex"`
}

// rpcBlock 区块；transactions 在 full=false 时是哈希数组、full=true 时是对象数组，
// 所以先留原始 JSON，只有全区块才解成 rpcTx。
type rpcBlock struct {
	Number       string          `json:"number"`
	Hash         string          `json:"hash"`
	ParentHash   string          `json:"parentHash"`
	Timestamp    string          `json:"timestamp"`
	Transactions json.RawMessage `json:"transactions"`
}

// fullBlock 全区块：头 + 已解码的交易。
type fullBlock struct {
	header
	Transactions []rpcTx
}

type rpcLog struct {
	Address     string   `json:"address"`
	Topics      []string `json:"topics"`
	Data        string   `json:"data"`
	BlockNumber string   `json:"blockNumber"`
	BlockHash   string   `json:"blockHash"`
	TxHash      string   `json:"transactionHash"`
	LogIndex    string   `json:"logIndex"`
	Removed     bool     `json:"removed"`
}

// Worker 一条链的扫链循环。
type Worker struct {
	cfg     scan.ChainConfig
	store   Store
	pool    *Pool
	tenants TenantResolver
	owner   string
	now     func() time.Time
	log     *slog.Logger

	state     scan.ChainState
	watched   []Watched
	byAddress map[string][]Watched
	watchedAt time.Time
	tokens    map[string]string // 小写 → 目录里的 EIP-55 形式
	tokensAt  time.Time
	headers   map[uint64]header
	// stalledSince 全部端点不可用的起点，用于告警。
	stalledSince time.Time
}

// NewWorker 构造一条链的 worker；pool 已按配置建好。
func NewWorker(cfg scan.ChainConfig, pool *Pool, store Store, tenants TenantResolver, owner string, now func() time.Time, log *slog.Logger) *Worker {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Worker{cfg: cfg, pool: pool, store: store, tenants: tenants, owner: owner, now: now, log: log.With("chain", cfg.Chain)}
}

// Run 循环到 ctx 取消：每轮 Round，然后按状态休眠。
func (w *Worker) Run(ctx context.Context) {
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.store.ReleaseLease(releaseCtx, w.cfg.Chain, w.owner)
	}()
	backoff := time.Second
	for {
		err := w.Round(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := time.Duration(w.cfg.PollSeconds) * time.Second
		switch {
		case err == nil:
			backoff = time.Second
			if w.state.State == scan.StateCatchingUp {
				delay = 0
			}
		case errors.Is(err, errLeaseHeld):
			// 别的实例在跑：按轮询间隔再试
		default:
			w.log.Warn("round failed", "error", err, "state", w.state.State)
			if backoff < delay {
				delay = backoff
			}
			backoff *= 2
			if backoff > coolingMax {
				backoff = coolingMax
			}
		}
		if delay <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

var errLeaseHeld = errors.New("lease held by another indexer")

// Round 跑一轮：租约 → 选端点 → 重组核对 → 分片扫描 → 余额轮 → 写状态。
func (w *Worker) Round(ctx context.Context) error {
	w.headers = map[uint64]header{}
	if err := w.ensureState(ctx); err != nil {
		return w.fail(ctx, err)
	}
	leaseTTL := 3 * time.Duration(w.cfg.PollSeconds) * time.Second
	if leaseTTL < 90*time.Second {
		leaseTTL = 90 * time.Second
	}
	held, err := w.store.AcquireLease(ctx, w.cfg.Chain, w.owner, w.now().Add(leaseTTL))
	if err != nil {
		return w.fail(ctx, err)
	}
	if !held {
		return errLeaseHeld
	}
	if w.cfg.Paused {
		w.state.State = scan.StatePaused
		return w.save(ctx)
	}
	head, err := w.pool.BeginRound(ctx, w.state.ScannedToBlock)
	if err != nil {
		if w.stalledSince.IsZero() {
			w.stalledSince = w.now()
		}
		w.state.State = scan.StateStalled
		if w.now().Sub(w.stalledSince) >= stalledAlertAfter {
			w.raise(ctx, scan.AlertStalled, "all endpoints unavailable: "+err.Error())
		}
		return w.fail(ctx, err)
	}
	w.stalledSince = time.Time{}
	w.resolve(ctx, scan.AlertStalled)
	w.state.HeadBlock = head
	confirmed := uint64(0)
	if head > uint64(w.cfg.Confirmations) {
		confirmed = head - uint64(w.cfg.Confirmations)
	}
	if err := w.checkReorg(ctx); err != nil {
		return w.fail(ctx, err)
	}
	if confirmed <= w.state.ScannedToBlock {
		w.state.State = scan.StateIdle
		return w.finish(ctx)
	}
	if err := w.refreshCaches(ctx); err != nil {
		return w.fail(ctx, err)
	}
	span := w.pool.SpanFor(w.cfg.MaxLogSpan)
	if confirmed-w.state.ScannedToBlock > uint64(2*span) {
		w.state.State = scan.StateCatchingUp
	} else {
		w.state.State = scan.StateScanning
	}
	if err := w.save(ctx); err != nil {
		return err
	}
	slices := 0
	for from := w.state.ScannedToBlock + 1; from <= confirmed; {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		to, rows, used, err := w.scanSlice(ctx, from, confirmed, span)
		if err != nil {
			return w.fail(ctx, err)
		}
		// 节点拒绝过的跨度这一轮不再试：后面的片直接用减半后的值
		span = used
		tip, err := w.header(ctx, to)
		if err != nil {
			return w.fail(ctx, err)
		}
		if err := w.store.CommitSlice(ctx, w.cfg.Chain, rows, to, tip.Hash); err != nil {
			return w.fail(ctx, err)
		}
		w.state.ScannedToBlock, w.state.ScannedToHash = to, tip.Hash
		if len(rows) > 0 {
			w.log.Info("slice committed", "from", from, "to", to, "rows", len(rows), "endpoint", w.pool.Current())
		}
		from = to + 1
		slices++
		if slices%progressSaveEvery == 0 {
			if err := w.save(ctx); err != nil {
				return err
			}
		}
	}
	if w.cfg.NativeMode == scan.NativeModeBalance {
		if err := w.balanceRound(ctx, confirmed); err != nil {
			return w.fail(ctx, err)
		}
	}
	w.state.State = scan.StateIdle
	return w.finish(ctx)
}

// ensureState 读状态行；没有就用配置的 startBlock 初始化（要先拿到它的哈希）。
func (w *Worker) ensureState(ctx context.Context) error {
	state, err := w.store.LoadState(ctx, w.cfg.Chain)
	switch {
	case err == nil:
		w.state = state
		w.pool.RestoreHealth(state.EndpointHealth)
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := w.pool.BeginRound(ctx, 0); err != nil {
		return fmt.Errorf("initialise cursor: %w", err)
	}
	start, err := w.header(ctx, w.cfg.StartBlock)
	if err != nil {
		return fmt.Errorf("initialise cursor at block %d: %w", w.cfg.StartBlock, err)
	}
	if _, err := w.store.InsertState(ctx, w.cfg.Chain, start.Number, start.Hash); err != nil {
		return err
	}
	state, err = w.store.LoadState(ctx, w.cfg.Chain)
	if err != nil {
		return err
	}
	w.state = state
	return nil
}

// checkReorg 核对游标区块哈希；不一致回退 confirmations 块并把区间内记录标 orphaned。
func (w *Worker) checkReorg(ctx context.Context) error {
	if w.state.ScannedToHash == "" {
		return nil
	}
	current, err := w.header(ctx, w.state.ScannedToBlock)
	if err != nil {
		return err
	}
	if strings.EqualFold(current.Hash, w.state.ScannedToHash) {
		return nil
	}
	back := uint64(0)
	if w.state.ScannedToBlock > uint64(w.cfg.Confirmations) {
		back = w.state.ScannedToBlock - uint64(w.cfg.Confirmations)
	}
	if back < w.cfg.StartBlock {
		back = w.cfg.StartBlock
	}
	anchor, err := w.header(ctx, back)
	if err != nil {
		return err
	}
	if err := w.store.MarkOrphaned(ctx, w.cfg.Chain, back); err != nil {
		return err
	}
	if err := w.store.CommitSlice(ctx, w.cfg.Chain, nil, back, anchor.Hash); err != nil {
		return err
	}
	w.log.Warn("reorg detected", "cursor", w.state.ScannedToBlock, "expected", w.state.ScannedToHash, "got", current.Hash, "rolledBackTo", back)
	w.state.ScannedToBlock, w.state.ScannedToHash = back, anchor.Hash
	w.state.ReorgCount++
	w.raise(ctx, scan.AlertReorg, fmt.Sprintf("reorg at block %d, rolled back to %d", current.Number, back))
	_ = w.store.InsertAudit(ctx, "chain_scan.reorg", w.cfg.Chain, map[string]any{"at": current.Number, "rolledBackTo": back})
	return nil
}

func (w *Worker) refreshCaches(ctx context.Context) error {
	if w.watched == nil || w.now().Sub(w.watchedAt) >= cacheTTL {
		tenantsByChain, err := w.tenants.TenantsForChain(ctx)
		if err != nil {
			return fmt.Errorf("resolve tenants: %w", err)
		}
		watched, err := w.store.Watched(ctx, w.cfg.Chain, tenantsByChain[w.cfg.Chain])
		if err != nil {
			return fmt.Errorf("load watched addresses: %w", err)
		}
		if watched == nil {
			watched = []Watched{}
		}
		w.watched = watched
		w.byAddress = map[string][]Watched{}
		for _, item := range watched {
			key := strings.ToLower(item.AddressKey)
			w.byAddress[key] = append(w.byAddress[key], item)
		}
		w.watchedAt = w.now()
	}
	if w.tokens == nil || w.now().Sub(w.tokensAt) >= cacheTTL {
		tokens, err := w.store.Tokens(ctx, w.cfg.Chain)
		if err != nil {
			return fmt.Errorf("load token catalog: %w", err)
		}
		w.tokens = map[string]string{}
		for _, address := range tokens {
			w.tokens[strings.ToLower(address)] = address
		}
		w.tokensAt = w.now()
	}
	return nil
}

// scanSlice 扫 [from, min(from+span-1, limit)]；节点拒绝跨度就减半重试。返回实际扫到的 to
// 与最终生效的跨度（调用方沿用，免得每片都先撞一次）。
func (w *Worker) scanSlice(ctx context.Context, from, limit uint64, span int) (uint64, []Row, int, error) {
	if span < 1 {
		span = 1
	}
	for {
		to := from + uint64(span) - 1
		if to > limit {
			to = limit
		}
		rows, err := w.scanRange(ctx, from, to)
		if err == nil {
			return to, rows, span, nil
		}
		if !errors.Is(err, errSpanTooLarge) || span == 1 {
			return 0, nil, span, err
		}
		span /= 2
		w.log.Info("span rejected, halving", "span", span, "endpoint", w.pool.Current())
	}
}

// scanRange 一片区间的全部查询：ERC-20 双向日志 + 原生币（blocks 模式）。
func (w *Worker) scanRange(ctx context.Context, from, to uint64) ([]Row, error) {
	var rows []Row
	if len(w.tokens) > 0 && len(w.watched) > 0 {
		addresses := make([]string, 0, len(w.byAddress))
		for key := range w.byAddress {
			addresses = append(addresses, key)
		}
		tokenFilter := make([]string, 0, len(w.tokens))
		for lower := range w.tokens {
			tokenFilter = append(tokenFilter, lower)
		}
		for start := 0; start < len(addresses); start += w.cfg.AddrChunk {
			end := start + w.cfg.AddrChunk
			if end > len(addresses) {
				end = len(addresses)
			}
			topics := make([]string, 0, end-start)
			for _, address := range addresses[start:end] {
				topics = append(topics, topicAddress(address))
			}
			incoming, err := w.logs(ctx, from, to, tokenFilter, []any{transferTopic, nil, topics})
			if err != nil {
				return nil, err
			}
			outgoing, err := w.logs(ctx, from, to, tokenFilter, []any{transferTopic, topics, nil})
			if err != nil {
				return nil, err
			}
			for _, item := range append(incoming, outgoing...) {
				decoded, err := w.rowsFromLog(ctx, item)
				if err != nil {
					return nil, err
				}
				rows = append(rows, decoded...)
			}
		}
	}
	if w.cfg.NativeMode == scan.NativeModeBlocks && len(w.watched) > 0 {
		for number := from; number <= to; number++ {
			block, err := w.fullBlock(ctx, number)
			if err != nil {
				return nil, err
			}
			rows = append(rows, w.rowsFromBlock(block, nil)...)
		}
	}
	return dedupe(rows), nil
}

// dedupe 同一笔转账会同时命中"入账"和"出账"两条查询（双方都被监听时），只留一份。
func dedupe(rows []Row) []Row {
	type key struct {
		tenant                       uint64
		tx, address, direction, hash string
		index                        int
		block                        uint64
	}
	seen := map[key]bool{}
	out := rows[:0]
	for _, row := range rows {
		k := key{row.TenantID, row.TxHash, row.AddressKey, row.Direction, row.BlockHash, row.LogIndex, row.BlockNumber}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, row)
	}
	return out
}

func (w *Worker) logs(ctx context.Context, from, to uint64, addresses []string, topics []any) ([]rpcLog, error) {
	filter := map[string]any{"fromBlock": hexBlock(from), "toBlock": hexBlock(to), "topics": topics}
	if len(addresses) > 0 {
		filter["address"] = addresses
	}
	raw, err := w.pool.Call(ctx, "eth_getLogs", []any{filter})
	if err != nil {
		return nil, err
	}
	var logs []rpcLog
	if err := json.Unmarshal(raw, &logs); err != nil {
		return nil, fmt.Errorf("eth_getLogs: malformed result")
	}
	return logs, nil
}

// rowsFromLog 一条 Transfer 日志 → 每个相关（租户, 地址）一行。
func (w *Worker) rowsFromLog(ctx context.Context, item rpcLog) ([]Row, error) {
	if item.Removed || len(item.Topics) != 3 || !strings.EqualFold(item.Topics[0], transferTopic) {
		return nil, nil
	}
	contract, known := w.tokens[strings.ToLower(item.Address)]
	if !known {
		return nil, nil
	}
	from, err := addressFromTopic(item.Topics[1])
	if err != nil {
		return nil, err
	}
	to, err := addressFromTopic(item.Topics[2])
	if err != nil {
		return nil, err
	}
	amount, err := uint256FromData(item.Data)
	if err != nil {
		return nil, err
	}
	number, err := parseHexUint64(item.BlockNumber)
	if err != nil {
		return nil, err
	}
	logIndex, err := parseHexUint64(item.LogIndex)
	if err != nil {
		return nil, err
	}
	head, err := w.header(ctx, number)
	if err != nil {
		return nil, err
	}
	var rows []Row
	build := func(watched Watched, direction, counterparty string) Row {
		return Row{TenantID: watched.TenantID, Chain: w.cfg.Chain, AddressKey: watched.AddressKey, Direction: direction, Asset: "erc20",
			Contract: contract, AmountRaw: amount.String(), Counterparty: counterparty, TxHash: strings.ToLower(item.TxHash), LogIndex: int(logIndex),
			BlockNumber: number, BlockHash: strings.ToLower(item.BlockHash), BlockTime: head.Time, Attribution: "tx"}
	}
	for _, watched := range w.byAddress[to] {
		rows = append(rows, build(watched, "in", from))
	}
	for _, watched := range w.byAddress[from] {
		rows = append(rows, build(watched, "out", to))
	}
	return rows, nil
}

// rowsFromBlock 全区块里 to/from 命中监听地址且 value>0 的交易。only 非空时只取这些收款地址的入账。
func (w *Worker) rowsFromBlock(block fullBlock, only map[string]bool) []Row {
	number, at := block.Number, block.Time
	var rows []Row
	for _, tx := range block.Transactions {
		value, err := parseHexQuantity(tx.Value)
		if err != nil || value.Sign() == 0 {
			continue
		}
		index, err := parseHexUint64(tx.Index)
		if err != nil {
			continue
		}
		to, from := strings.ToLower(tx.To), strings.ToLower(tx.From)
		build := func(watched Watched, direction, counterparty string) Row {
			return Row{TenantID: watched.TenantID, Chain: w.cfg.Chain, AddressKey: watched.AddressKey, Direction: direction, Asset: "native",
				Contract: "native", AmountRaw: value.String(), Counterparty: counterparty, TxHash: strings.ToLower(tx.Hash), LogIndex: int(index),
				BlockNumber: number, BlockHash: strings.ToLower(block.Hash), BlockTime: at, Attribution: "tx"}
		}
		if only == nil || only[to] {
			for _, watched := range w.byAddress[to] {
				rows = append(rows, build(watched, "in", from))
			}
		}
		if only == nil {
			for _, watched := range w.byAddress[from] {
				rows = append(rows, build(watched, "out", to))
			}
		}
	}
	return rows
}

// balanceRound balance 模式：读全部监听地址在 confirmed 块的余额，与快照比较，增加的才定位交易。
func (w *Worker) balanceRound(ctx context.Context, confirmed uint64) error {
	if len(w.watched) == 0 {
		return nil
	}
	type increase struct {
		watched Watched
		prev    BalanceSnapshot
		delta   *big.Int
	}
	updates := map[WatchKey]BalanceSnapshot{}
	var increased []increase
	for start := 0; start < len(w.watched); start += balanceChunk {
		end := start + balanceChunk
		if end > len(w.watched) {
			end = len(w.watched)
		}
		chunk := w.watched[start:end]
		addresses := make([]string, 0, len(chunk))
		for _, item := range chunk {
			addresses = append(addresses, item.AddressKey)
		}
		raw, err := w.pool.Call(ctx, "eth_call", []any{map[string]string{"to": multicall3, "data": encodeGetEthBalances(addresses)}, hexBlock(confirmed)})
		if err != nil {
			return fmt.Errorf("multicall balances: %w", err)
		}
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return errors.New("multicall balances: malformed result")
		}
		balances, err := decodeAggregate3Balances(encoded, len(addresses))
		if err != nil {
			return fmt.Errorf("multicall balances: %w", err)
		}
		for index, item := range chunk {
			current := balances[index]
			updates[item.Key()] = BalanceSnapshot{BalanceRaw: current.String(), Block: confirmed}
			if item.Balance == nil {
				continue
			}
			previous, ok := new(big.Int).SetString(item.Balance.BalanceRaw, 10)
			if !ok {
				return fmt.Errorf("wallet_user %d/%s scan_state balance %q is not an integer", item.TenantID, item.AddressKey, item.Balance.BalanceRaw)
			}
			if current.Cmp(previous) > 0 {
				increased = append(increased, increase{watched: item, prev: *item.Balance, delta: new(big.Int).Sub(current, previous)})
			}
		}
	}
	var rows []Row
	if len(increased) > 0 {
		// 小缺口一次扫过所有增加的地址；大缺口先记差额，交给后台归属任务
		scanFrom, scanTo := uint64(0), uint64(0)
		targets := map[string]bool{}
		var deferred []increase
		for _, item := range increased {
			from := item.prev.Block + 1
			if confirmed-item.prev.Block > w.cfg.NativeGapCap {
				deferred = append(deferred, item)
				continue
			}
			targets[strings.ToLower(item.watched.AddressKey)] = true
			if scanFrom == 0 || from < scanFrom {
				scanFrom = from
			}
			scanTo = confirmed
		}
		found := map[string]*big.Int{}
		if len(targets) > 0 {
			for number := scanFrom; number <= scanTo; number++ {
				block, err := w.fullBlock(ctx, number)
				if err != nil {
					return err
				}
				for _, row := range w.rowsFromBlock(block, targets) {
					key := fmt.Sprintf("%d/%s", row.TenantID, row.AddressKey)
					amount, _ := new(big.Int).SetString(row.AmountRaw, 10)
					if found[key] == nil {
						found[key] = new(big.Int)
					}
					found[key].Add(found[key], amount)
					rows = append(rows, row)
				}
			}
		}
		tip, err := w.header(ctx, confirmed)
		if err != nil {
			return err
		}
		for _, item := range increased {
			key := fmt.Sprintf("%d/%s", item.watched.TenantID, item.watched.AddressKey)
			remaining := new(big.Int).Set(item.delta)
			if located := found[key]; located != nil {
				remaining.Sub(remaining, located)
			}
			if remaining.Sign() <= 0 {
				continue
			}
			gapFrom := item.prev.Block + 1
			rows = append(rows, Row{TenantID: item.watched.TenantID, Chain: w.cfg.Chain, AddressKey: item.watched.AddressKey, Direction: "in", Asset: "native",
				Contract: "native", AmountRaw: remaining.String(), BlockNumber: confirmed, BlockHash: strings.ToLower(tip.Hash), BlockTime: tip.Time,
				Attribution: "unattributed", GapFromBlock: &gapFrom, LogIndex: -1})
		}
		for _, item := range deferred {
			w.enqueueAttribute(item.prev.Block+1, confirmed)
		}
	}
	if len(rows) > 0 {
		if err := w.store.CommitSlice(ctx, w.cfg.Chain, rows, 0, ""); err != nil {
			return err
		}
		w.log.Info("balance round committed", "rows", len(rows))
	}
	if err := w.store.SaveBalances(ctx, w.cfg.Chain, updates); err != nil {
		return err
	}
	// 缓存里的快照同步更新：监听集合 60 秒才重读一次，下一轮要拿本轮的余额做基线
	for index := range w.watched {
		if snapshot, ok := updates[w.watched[index].Key()]; ok {
			copied := snapshot
			w.watched[index].Balance = &copied
		}
	}
	w.byAddress = map[string][]Watched{}
	for _, item := range w.watched {
		key := strings.ToLower(item.AddressKey)
		w.byAddress[key] = append(w.byAddress[key], item)
	}
	return nil
}

// enqueueAttribute 给大缺口建一条归属任务（同区间已有任务则合并）。
func (w *Worker) enqueueAttribute(from, to uint64) {
	for index := range w.state.Jobs {
		job := &w.state.Jobs[index]
		if job.Kind == scan.JobAttribute && job.State == scan.JobPending && job.FromBlock <= from && job.ToBlock >= to {
			return
		}
	}
	w.state.Jobs = append(w.state.Jobs, scan.Job{ID: "job_" + randomID(12), Kind: scan.JobAttribute, FromBlock: from, ToBlock: to, ProgressBlock: from - 1,
		State: scan.JobPending, CreatedBy: "system", Reason: "native balance increased across a gap larger than nativeGapCap", CreatedAt: w.now()})
}

// header 读区块头（本轮缓存）。
func (w *Worker) header(ctx context.Context, number uint64) (header, error) {
	if cached, ok := w.headers[number]; ok {
		return cached, nil
	}
	raw, err := w.pool.Call(ctx, "eth_getBlockByNumber", []any{hexBlock(number), false})
	if err != nil {
		return header{}, err
	}
	var block rpcBlock
	if err := json.Unmarshal(raw, &block); err != nil || block.Hash == "" {
		return header{}, fmt.Errorf("eth_getBlockByNumber %d: malformed result", number)
	}
	parsed, err := headerOf(block)
	if err != nil {
		return header{}, err
	}
	w.headers[number] = parsed
	return parsed, nil
}

func (w *Worker) fullBlock(ctx context.Context, number uint64) (fullBlock, error) {
	raw, err := w.pool.Call(ctx, "eth_getBlockByNumber", []any{hexBlock(number), true})
	if err != nil {
		return fullBlock{}, err
	}
	var block rpcBlock
	if err := json.Unmarshal(raw, &block); err != nil || block.Hash == "" {
		return fullBlock{}, fmt.Errorf("eth_getBlockByNumber %d (full): malformed result", number)
	}
	parsed, err := headerOf(block)
	if err != nil {
		return fullBlock{}, fmt.Errorf("eth_getBlockByNumber %d (full): %w", number, err)
	}
	w.headers[number] = parsed
	var txs []rpcTx
	if len(block.Transactions) > 0 {
		if err := json.Unmarshal(block.Transactions, &txs); err != nil {
			return fullBlock{}, fmt.Errorf("eth_getBlockByNumber %d (full): transactions are not objects", number)
		}
	}
	return fullBlock{header: parsed, Transactions: txs}, nil
}

func headerOf(block rpcBlock) (header, error) {
	number, err := parseHexUint64(block.Number)
	if err != nil {
		return header{}, fmt.Errorf("block number: %w", err)
	}
	seconds, err := parseHexUint64(block.Timestamp)
	if err != nil {
		return header{}, fmt.Errorf("block timestamp: %w", err)
	}
	return header{Number: number, Hash: strings.ToLower(block.Hash), ParentHash: strings.ToLower(block.ParentHash), Time: time.Unix(int64(seconds), 0).UTC()}, nil
}

func hexBlock(number uint64) string { return fmt.Sprintf("0x%x", number) }

// ---- 状态、告警 ----

func (w *Worker) finish(ctx context.Context) error {
	w.state.ErrorCount = 0
	w.state.LastError = ""
	if w.state.HeadBlock > w.state.ScannedToBlock {
		lag := w.state.HeadBlock - w.state.ScannedToBlock
		if uint64(w.cfg.Confirmations) < lag && time.Duration(lag-uint64(w.cfg.Confirmations))*w.blockTime() >= lagAlertAfter {
			w.raise(ctx, scan.AlertLagging, fmt.Sprintf("cursor %d is %d blocks behind head %d", w.state.ScannedToBlock, lag, w.state.HeadBlock))
		} else {
			w.resolve(ctx, scan.AlertLagging)
		}
	}
	return w.save(ctx)
}

// blockTime 用轮询间隔和跨度粗估出块时间，只用于把"落后 N 块"换算成告警门槛。
func (w *Worker) blockTime() time.Duration {
	if w.cfg.MaxLogSpan <= 0 {
		return time.Second
	}
	estimate := time.Duration(w.cfg.PollSeconds) * time.Second / time.Duration(w.cfg.MaxLogSpan)
	if estimate < 100*time.Millisecond {
		estimate = 100 * time.Millisecond
	}
	return estimate
}

func (w *Worker) fail(ctx context.Context, err error) error {
	w.state.ErrorCount++
	w.state.LastError = truncate(err.Error(), 512)
	// 状态保留 stalled / scanning / catching_up / idle 原值：管理端能看出是"扫着扫着出错"还是"完全断了"
	if saveErr := w.save(ctx); saveErr != nil {
		w.log.Error("save state failed", "error", saveErr)
	}
	return err
}

func (w *Worker) save(ctx context.Context) error {
	w.state.EndpointHealth = w.pool.Health()
	return w.store.SaveState(ctx, w.state)
}

func (w *Worker) raise(ctx context.Context, kind scan.AlertKind, message string) {
	if existing := w.state.Alert(kind); existing != nil {
		existing.Message = truncate(message, 512)
		return
	}
	w.state.OpenAlerts = append(w.state.OpenAlerts, scan.Alert{Kind: kind, Message: truncate(message, 512), RaisedAt: w.now()})
	w.log.Warn("alert raised", "kind", kind, "message", message)
	_ = w.store.InsertAudit(ctx, "chain_scan.alert_raised", w.cfg.Chain, map[string]any{"kind": kind, "message": message})
}

func (w *Worker) resolve(ctx context.Context, kind scan.AlertKind) {
	kept := w.state.OpenAlerts[:0]
	resolved := false
	for _, alert := range w.state.OpenAlerts {
		if alert.Kind == kind {
			resolved = true
			continue
		}
		kept = append(kept, alert)
	}
	w.state.OpenAlerts = kept
	if resolved {
		w.log.Info("alert resolved", "kind", kind)
		_ = w.store.InsertAudit(ctx, "chain_scan.alert_resolved", w.cfg.Chain, map[string]any{"kind": kind})
	}
}
