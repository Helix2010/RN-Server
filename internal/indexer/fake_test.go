package indexer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

// fakeChain 是一个内存里的链：区块、交易、日志；用 httptest 暴露成 JSON-RPC 端点。
type fakeBlock struct {
	Number       string
	Hash         string
	ParentHash   string
	Timestamp    string
	Transactions []rpcTx
}

type fakeChain struct {
	mu       sync.Mutex
	chainID  int64
	head     uint64
	blocks   map[uint64]fakeBlock
	logs     []rpcLog
	balances map[string]map[uint64]string // address → block → balance(hex)
	maxSpan  int
	fail     bool
	calls    map[string]int
	// beforeHandle 每次请求前的钩子（模拟节点落后等）
	beforeHandle func(method string)
}

func newFakeChain(chainID int64) *fakeChain {
	return &fakeChain{chainID: chainID, blocks: map[uint64]fakeBlock{}, balances: map[string]map[uint64]string{}, maxSpan: 1000, calls: map[string]int{}}
}

func (f *fakeChain) mine(number uint64, txs ...rpcTx) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hash := fmt.Sprintf("0x%064x", number*7919)
	parent := fmt.Sprintf("0x%064x", (number-1)*7919)
	for index := range txs {
		txs[index].Index = fmt.Sprintf("0x%x", index)
		if txs[index].Hash == "" {
			txs[index].Hash = fmt.Sprintf("0x%064x", number*1000+uint64(index))
		}
	}
	f.blocks[number] = fakeBlock{Number: fmt.Sprintf("0x%x", number), Hash: hash, ParentHash: parent, Timestamp: fmt.Sprintf("0x%x", 1_700_000_000+number*2), Transactions: txs}
	if number > f.head {
		f.head = number
	}
}

// reorg 换掉某个区块的哈希（模拟分叉）。
func (f *fakeChain) reorg(number uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	block := f.blocks[number]
	block.Hash = fmt.Sprintf("0x%064x", number*7919+1)
	f.blocks[number] = block
}

func (f *fakeChain) transfer(number uint64, token, from, to string, amount uint64, logIndex int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	block := f.blocks[number]
	f.logs = append(f.logs, rpcLog{Address: strings.ToLower(token), Topics: []string{transferTopic, topicAddress(from), topicAddress(to)},
		Data: fmt.Sprintf("0x%064x", amount), BlockNumber: block.Number, BlockHash: block.Hash, TxHash: fmt.Sprintf("0x%064x", number*5000+uint64(logIndex)), LogIndex: fmt.Sprintf("0x%x", logIndex)})
}

func (f *fakeChain) setBalance(address string, block uint64, balance uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.ToLower(address)
	if f.balances[key] == nil {
		f.balances[key] = map[uint64]string{}
	}
	f.balances[key][block] = fmt.Sprintf("%064x", balance)
}

func (f *fakeChain) balanceAt(address string, block uint64) string {
	history := f.balances[strings.ToLower(address)]
	best := uint64(0)
	value := strings.Repeat("0", 64)
	for at, balance := range history {
		if at <= block && at >= best {
			best, value = at, balance
		}
	}
	return value
}

func (f *fakeChain) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		f.mu.Lock()
		f.calls[request.Method]++
		fail := f.fail
		f.mu.Unlock()
		if f.beforeHandle != nil {
			f.beforeHandle(request.Method)
		}
		if fail {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		reply := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		}
		replyError := func(code int, message string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": code, "message": message}})
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch request.Method {
		case "eth_chainId":
			reply(fmt.Sprintf("0x%x", f.chainID))
		case "eth_blockNumber":
			reply(fmt.Sprintf("0x%x", f.head))
		case "eth_getBlockByNumber":
			number, _ := parseHexUint64(request.Params[0].(string))
			block, ok := f.blocks[number]
			if !ok {
				reply(nil)
				return
			}
			// 真实节点：full=false 时 transactions 是哈希数组，full=true 是对象数组
			var txs any = block.Transactions
			if full, _ := request.Params[1].(bool); !full {
				hashes := []string{}
				for _, tx := range block.Transactions {
					hashes = append(hashes, tx.Hash)
				}
				txs = hashes
			}
			reply(map[string]any{"number": block.Number, "hash": block.Hash, "parentHash": block.ParentHash, "timestamp": block.Timestamp, "transactions": txs})
		case "eth_getLogs":
			filter := request.Params[0].(map[string]any)
			from, _ := parseHexUint64(filter["fromBlock"].(string))
			to, _ := parseHexUint64(filter["toBlock"].(string))
			if int(to-from+1) > f.maxSpan {
				replyError(-32614, fmt.Sprintf("eth_getLogs is limited to a %d block range", f.maxSpan))
				return
			}
			topics := filter["topics"].([]any)
			var addresses map[string]bool
			if raw, ok := filter["address"].([]any); ok {
				addresses = map[string]bool{}
				for _, item := range raw {
					addresses[strings.ToLower(item.(string))] = true
				}
			}
			matches := []rpcLog{}
			for _, item := range f.logs {
				number, _ := parseHexUint64(item.BlockNumber)
				if number < from || number > to {
					continue
				}
				if addresses != nil && !addresses[strings.ToLower(item.Address)] {
					continue
				}
				if !topicMatches(topics, item.Topics) {
					continue
				}
				matches = append(matches, item)
			}
			reply(matches)
		case "eth_call":
			call := request.Params[0].(map[string]any)
			data := call["data"].(string)
			block, _ := parseHexUint64(request.Params[1].(string))
			if !strings.HasPrefix(data, "0x"+selectorAggregate3) {
				replyError(-32000, "unexpected call")
				return
			}
			// 解出地址列表：每个元组的第 5 词起是 getEthBalance 的 calldata
			payload := data[10:]
			count, _ := parseHexUint64("0x" + strings.TrimLeft(payload[64:128], "0"))
			results := make([]string, 0, int(count))
			offset := 128 + int(count)*64
			for index := 0; index < int(count); index++ {
				tuple := payload[offset+index*6*64:]
				address := "0x" + tuple[4*64+8+24:4*64+8+64]
				results = append(results, f.balanceAt(address, block))
			}
			reply(encodeAggregate3Result(results))
		default:
			replyError(-32601, "method not found")
		}
	}))
}

func topicMatches(filter []any, topics []string) bool {
	for index, want := range filter {
		if want == nil || index >= len(topics) {
			continue
		}
		switch value := want.(type) {
		case string:
			if !strings.EqualFold(value, topics[index]) {
				return false
			}
		case []any:
			found := false
			for _, candidate := range value {
				if strings.EqualFold(candidate.(string), topics[index]) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// encodeAggregate3Result 按 ABI 编 Result[]（success=true，returnData 一个词）。
func encodeAggregate3Result(balances []string) string {
	var b strings.Builder
	b.WriteString("0x")
	b.WriteString(word(0x20))
	b.WriteString(word(uint64(len(balances))))
	for index := range balances {
		b.WriteString(word(uint64(len(balances)*32 + index*4*32)))
	}
	for _, balance := range balances {
		b.WriteString(word(1))
		b.WriteString(word(0x40))
		b.WriteString(word(32))
		b.WriteString(balance)
	}
	return b.String()
}

// memStore 内存 Store。
type memStore struct {
	mu       sync.Mutex
	states   map[string]scan.ChainState
	watched  []Watched
	tokens   []string
	rows     []Row
	orphaned []uint64
	balances map[WatchKey]BalanceSnapshot
	audits   []string
	leaseOwn string
	// receipts 通知过的入账（首次写入且 notify=true 的 in 行）
	receipts []Row
}

func newMemStore() *memStore {
	return &memStore{states: map[string]scan.ChainState{}, balances: map[WatchKey]BalanceSnapshot{}}
}

func (m *memStore) LoadState(_ context.Context, chain string) (scan.ChainState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[chain]
	if !ok {
		return scan.ChainState{}, sql.ErrNoRows
	}
	return state, nil
}

func (m *memStore) InsertState(_ context.Context, chain string, block uint64, hash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.states[chain]; ok {
		return false, nil
	}
	m.states[chain] = scan.ChainState{Chain: chain, ScannedToBlock: block, ScannedToHash: hash, State: scan.StateIdle}
	return true, nil
}

func (m *memStore) SaveState(_ context.Context, state scan.ChainState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.states[state.Chain]
	state.ScannedToBlock, state.ScannedToHash = current.ScannedToBlock, current.ScannedToHash
	state.LeaseOwner = current.LeaseOwner
	// 同 SQL 版：jobs 只在 MutateJobs 里动
	state.Jobs = current.Jobs
	m.states[state.Chain] = state
	return nil
}

func (m *memStore) MutateJobs(_ context.Context, chain string, mutate func([]scan.Job) ([]scan.Job, error)) ([]scan.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[chain]
	if !ok {
		return nil, scan.ErrStateNotFound
	}
	next, err := mutate(append([]scan.Job(nil), state.Jobs...))
	if err != nil {
		return nil, err
	}
	if next == nil {
		next = []scan.Job{}
	}
	state.Jobs = next
	m.states[chain] = state
	return append([]scan.Job(nil), next...), nil
}

func (m *memStore) ResolveUnattributed(_ context.Context, chain string, from, to uint64, rows []Row) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	located := func(tenant uint64, address string, lo, hi uint64) *big.Int {
		sum := new(big.Int)
		for _, row := range m.rows {
			if row.TenantID == tenant && row.Chain == chain && row.AddressKey == address && row.Direction == "in" && row.Asset == "native" && row.Attribution == "tx" && row.BlockNumber >= lo && row.BlockNumber <= hi {
				amount, _ := new(big.Int).SetString(row.AmountRaw, 10)
				sum.Add(sum, amount)
			}
		}
		return sum
	}
	type target struct {
		index  int
		lo, hi uint64
		before *big.Int
	}
	var targets []target
	for index, row := range m.rows {
		if row.Attribution != "unattributed" || row.Chain != chain || row.GapFromBlock == nil || *row.GapFromBlock > to || row.BlockNumber < from {
			continue
		}
		lo, hi := *row.GapFromBlock, row.BlockNumber
		if lo < from {
			lo = from
		}
		if hi > to {
			hi = to
		}
		targets = append(targets, target{index: index, lo: lo, hi: hi, before: located(row.TenantID, row.AddressKey, lo, hi)})
	}
	m.insertLocked(rows)
	remove := map[int]bool{}
	for _, item := range targets {
		row := m.rows[item.index]
		after := located(row.TenantID, row.AddressKey, item.lo, item.hi)
		amount, _ := new(big.Int).SetString(row.AmountRaw, 10)
		remaining := new(big.Int).Sub(amount, new(big.Int).Sub(after, item.before))
		if remaining.Sign() <= 0 {
			remove[item.index] = true
			continue
		}
		m.rows[item.index].AmountRaw = remaining.String()
	}
	if len(remove) > 0 {
		kept := m.rows[:0]
		for index, row := range m.rows {
			if !remove[index] {
				kept = append(kept, row)
			}
		}
		m.rows = kept
	}
	return nil
}

func (m *memStore) hasLocked(row Row) bool {
	for _, existing := range m.rows {
		if existing.TenantID == row.TenantID && existing.TxHash == row.TxHash && existing.LogIndex == row.LogIndex && existing.AddressKey == row.AddressKey && existing.Direction == row.Direction && existing.BlockNumber == row.BlockNumber {
			return true
		}
	}
	return false
}

// insertLocked 同 SQL 的 INSERT … ON DUPLICATE KEY UPDATE：撞唯一键就刷新那一行。
func (m *memStore) insertLocked(rows []Row) {
	for _, row := range rows {
		replaced := false
		for index, existing := range m.rows {
			if existing.TenantID == row.TenantID && existing.TxHash == row.TxHash && existing.LogIndex == row.LogIndex && existing.AddressKey == row.AddressKey && existing.Direction == row.Direction && existing.BlockNumber == row.BlockNumber {
				m.rows[index] = row
				replaced = true
			}
		}
		if !replaced {
			m.rows = append(m.rows, row)
		}
	}
}

func (m *memStore) AcquireLease(_ context.Context, chain, owner string, _ time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leaseOwn != "" && m.leaseOwn != owner {
		return false, nil
	}
	m.leaseOwn = owner
	state := m.states[chain]
	state.LeaseOwner = owner
	m.states[chain] = state
	return true, nil
}

func (m *memStore) ReleaseLease(_ context.Context, chain, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leaseOwn == owner {
		m.leaseOwn = ""
	}
	return nil
}

func (m *memStore) Watched(_ context.Context, _ string, _ []uint64) ([]Watched, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Watched, 0, len(m.watched))
	for _, item := range m.watched {
		if snapshot, ok := m.balances[item.Key()]; ok {
			copied := snapshot
			item.Balance = &copied
		}
		out = append(out, item)
	}
	return out, nil
}

func (m *memStore) Tokens(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), m.tokens...), nil
}

func (m *memStore) CommitSlice(_ context.Context, chain string, rows []Row, toBlock uint64, toHash string, toTime time.Time, notify bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if notify {
		for _, row := range rows {
			if row.Direction == "in" && !m.hasLocked(row) {
				m.receipts = append(m.receipts, row)
			}
		}
	}
	m.insertLocked(rows)
	if toBlock > 0 {
		state := m.states[chain]
		state.ScannedToBlock, state.ScannedToHash = toBlock, toHash
		at := toTime
		state.ScannedToTime = &at
		m.states[chain] = state
	}
	return nil
}

func (m *memStore) SaveBalances(_ context.Context, _ string, updates map[WatchKey]BalanceSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, snapshot := range updates {
		m.balances[key] = snapshot
	}
	return nil
}

func (m *memStore) MarkOrphaned(_ context.Context, _ string, afterBlock uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orphaned = append(m.orphaned, afterBlock)
	kept := m.rows[:0]
	for _, row := range m.rows {
		if row.BlockNumber <= afterBlock {
			kept = append(kept, row)
		}
	}
	m.rows = kept
	return nil
}

func (m *memStore) InsertAudit(_ context.Context, action, _ string, _ map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, action)
	return nil
}

type staticTenants map[string][]uint64

func (s staticTenants) TenantsForChain(context.Context) (map[string][]uint64, error) { return s, nil }
