package indexer

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

const (
	tokenUSDC = "0x2eA619C7CFFFF6C1F1f8800b066D4797E71Bc3AD"
	alice     = "0x1111111111111111111111111111111111111111"
	bob       = "0x2222222222222222222222222222222222222222"
	carol     = "0x3333333333333333333333333333333333333333"
)

func testConfig(mode scan.NativeMode) scan.ChainConfig {
	return scan.ChainConfig{Chain: "op-sepolia", Enabled: true, MaxLogSpan: 100, Confirmations: 2, PollSeconds: 30, AddrChunk: 1000,
		NativeMode: mode, NativeGapCap: 50, StartBlock: 10, Version: 1}
}

func setup(t *testing.T, mode scan.NativeMode) (*fakeChain, *memStore, *Worker) {
	t.Helper()
	chain := newFakeChain(11155420)
	server := chain.server()
	t.Cleanup(server.Close)
	store := newMemStore()
	store.tokens = []string{tokenUSDC}
	store.watched = []Watched{{TenantID: 100000001, AddressKey: alice}, {TenantID: 100000001, AddressKey: bob}, {TenantID: 100000002, AddressKey: bob}}
	cfg := testConfig(mode)
	cfg.Endpoints = []scan.Endpoint{{URL: server.URL, Label: "fake", RPS: 1000}}
	pool := NewPool(cfg.Chain, 11155420, cfg.Endpoints, http.DefaultClient, nil)
	worker := NewWorker(cfg, pool, store, staticTenants{"op-sepolia": {100000001, 100000002}}, "test/1", nil, nil)
	for number := uint64(1); number <= 10; number++ {
		chain.mine(number)
	}
	return chain, store, worker
}

func TestRoundInitialisesCursorAtStartBlockAndIndexesTransfers(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBlocks)
	for number := uint64(11); number <= 20; number++ {
		chain.mine(number)
	}
	chain.transfer(12, tokenUSDC, carol, alice, 1_500_000, 3)                            // in for alice
	chain.transfer(13, tokenUSDC, bob, carol, 700, 0)                                    // out for bob (two tenants)
	chain.transfer(14, "0x9999999999999999999999999999999999999999", carol, alice, 5, 0) // 目录外代币：忽略
	chain.mine(21, rpcTx{From: carol, To: alice, Value: "0x64"}, rpcTx{From: alice, To: carol, Value: "0x0"})
	chain.mine(22)
	chain.mine(23)

	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	state := store.states["op-sepolia"]
	if state.ScannedToBlock != 21 { // head 23 − confirmations 2
		t.Fatalf("cursor = %d, want 21", state.ScannedToBlock)
	}
	if state.ScannedToHash != chain.blocks[21].Hash {
		t.Fatalf("cursor hash mismatch")
	}
	if state.State != scan.StateIdle {
		t.Fatalf("state = %s, want idle", state.State)
	}
	if len(state.EndpointHealth) != 1 || state.EndpointHealth[0].Health != scan.HealthHealthy {
		t.Fatalf("endpoint health = %+v", state.EndpointHealth)
	}
	var in, out, native int
	for _, row := range store.rows {
		switch {
		case row.Asset == "native":
			native++
			if row.AddressKey != alice || row.Direction != "in" || row.AmountRaw != "100" || row.Counterparty != carol {
				t.Fatalf("native row = %+v", row)
			}
		case row.Direction == "in":
			in++
			if row.AddressKey != alice || row.AmountRaw != "1500000" || row.Contract != tokenUSDC || row.LogIndex != 3 || row.BlockNumber != 12 {
				t.Fatalf("erc20 in row = %+v", row)
			}
			if row.BlockTime.Unix() != 1_700_000_000+12*2 {
				t.Fatalf("block time = %v", row.BlockTime)
			}
		default:
			out++
			if row.AddressKey != bob || row.Counterparty != carol {
				t.Fatalf("erc20 out row = %+v", row)
			}
		}
	}
	if in != 1 || out != 2 || native != 1 {
		t.Fatalf("rows in=%d out=%d native=%d (total %d)", in, out, native, len(store.rows))
	}
	// 第二轮没有新块：游标不动，不重复写
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("second round: %v", err)
	}
	if len(store.rows) != 4 || store.states["op-sepolia"].ScannedToBlock != 21 {
		t.Fatalf("second round changed rows=%d cursor=%d", len(store.rows), store.states["op-sepolia"].ScannedToBlock)
	}
}

func TestRoundHalvesSpanWhenEndpointRejectsRange(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	chain.maxSpan = 10
	for number := uint64(11); number <= 60; number++ {
		chain.mine(number)
	}
	chain.transfer(55, tokenUSDC, carol, alice, 42, 1)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	if store.states["op-sepolia"].ScannedToBlock != 58 {
		t.Fatalf("cursor = %d, want 58", store.states["op-sepolia"].ScannedToBlock)
	}
	if len(store.rows) != 1 || store.rows[0].AmountRaw != "42" {
		t.Fatalf("rows = %+v", store.rows)
	}
	if health := store.states["op-sepolia"].EndpointHealth[0]; health.SpanRejected == 0 {
		t.Fatalf("span rejections not recorded: %+v", health)
	}
}

func TestReorgRollsBackCursorAndOrphansRows(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	for number := uint64(11); number <= 30; number++ {
		chain.mine(number)
	}
	chain.transfer(27, tokenUSDC, carol, alice, 1, 0)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	if store.states["op-sepolia"].ScannedToBlock != 28 || len(store.rows) != 1 {
		t.Fatalf("precondition cursor=%d rows=%d", store.states["op-sepolia"].ScannedToBlock, len(store.rows))
	}
	// 区块 28 被换掉；27 的转账在新分叉里也不存在了
	chain.reorg(28)
	chain.reorg(27)
	chain.mu.Lock()
	chain.logs = nil
	chain.mu.Unlock()
	chain.mine(31)
	chain.mine(32)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round after reorg: %v", err)
	}
	state := store.states["op-sepolia"]
	if len(store.orphaned) != 1 || store.orphaned[0] != 26 {
		t.Fatalf("orphaned after block = %v, want [26]", store.orphaned)
	}
	if len(store.rows) != 0 {
		t.Fatalf("rows after reorg = %+v", store.rows)
	}
	if state.ScannedToBlock != 30 || state.ReorgCount != 1 {
		t.Fatalf("cursor=%d reorgs=%d", state.ScannedToBlock, state.ReorgCount)
	}
	if state.Alert(scan.AlertReorg) == nil {
		t.Fatalf("reorg alert missing: %+v", state.OpenAlerts)
	}
	if len(store.audits) == 0 || store.audits[0] != "chain_scan.alert_raised" {
		t.Fatalf("audits = %v", store.audits)
	}
}

func TestBalanceModeAttributesIncreasesAndRecordsUnattributedRemainder(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	for number := uint64(11); number <= 20; number++ {
		chain.mine(number)
	}
	chain.setBalance(alice, 0, 1000)
	chain.setBalance(bob, 0, 0)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("first round: %v", err)
	}
	if snapshot := store.balances[WatchKey{TenantID: 100000001, AddressKey: alice}]; snapshot.BalanceRaw != "1000" || snapshot.Block != 18 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if len(store.rows) != 0 {
		t.Fatalf("first round must only snapshot, got rows %+v", store.rows)
	}
	// alice 收到 300（区块 21 有一笔 200 的普通转账，其余 100 是合约内部转账，扫不到）
	chain.mine(21, rpcTx{From: carol, To: alice, Value: "0xc8"})
	chain.setBalance(alice, 21, 1300)
	// bob 收到 50，但 bob 同时被两个租户监听：两个租户各一行
	chain.mine(22, rpcTx{From: carol, To: bob, Value: "0x32"})
	chain.setBalance(bob, 22, 50)
	chain.mine(23)
	chain.mine(24)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("second round: %v", err)
	}
	var attributed, unattributed, bobRows int
	for _, row := range store.rows {
		switch {
		case row.AddressKey == bob:
			bobRows++
			if row.Attribution != "tx" || row.AmountRaw != "50" {
				t.Fatalf("bob row = %+v", row)
			}
		case row.Attribution == "tx":
			attributed++
			if row.AmountRaw != "200" || row.BlockNumber != 21 {
				t.Fatalf("attributed row = %+v", row)
			}
		default:
			unattributed++
			if row.AmountRaw != "100" || row.GapFromBlock == nil || *row.GapFromBlock != 19 || row.BlockNumber != 22 || row.LogIndex != -1 {
				t.Fatalf("unattributed row = %+v", row)
			}
		}
	}
	if attributed != 1 || unattributed != 1 || bobRows != 2 {
		t.Fatalf("attributed=%d unattributed=%d bob=%d rows=%+v", attributed, unattributed, bobRows, store.rows)
	}
}

func TestBalanceModeDefersHugeGapsToAJob(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	for number := uint64(11); number <= 20; number++ {
		chain.mine(number)
	}
	chain.setBalance(alice, 0, 0)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("first round: %v", err)
	}
	for number := uint64(21); number <= 120; number++ {
		chain.mine(number)
	}
	chain.setBalance(alice, 60, 999)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("second round: %v", err)
	}
	if calls := chain.calls["eth_getBlockByNumber"]; calls > 30 {
		t.Fatalf("huge gap must not be scanned block by block, got %d block calls", calls)
	}
	if len(store.rows) != 1 || store.rows[0].Attribution != "unattributed" || store.rows[0].AmountRaw != "999" {
		t.Fatalf("rows = %+v", store.rows)
	}
	jobs := store.states["op-sepolia"].Jobs
	if len(jobs) != 1 || jobs[0].Kind != scan.JobAttribute || jobs[0].FromBlock != 19 || jobs[0].ToBlock != 118 || jobs[0].State != scan.JobPending {
		t.Fatalf("jobs = %+v", jobs)
	}
}

func TestRoundStallsWhenEveryEndpointFails(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	chain.mine(11)
	chain.mine(12)
	chain.mine(13)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	chain.mu.Lock()
	chain.fail = true
	chain.mu.Unlock()
	err := worker.Round(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	state := store.states["op-sepolia"]
	if state.State != scan.StateStalled || state.ErrorCount != 1 || state.LastError == "" {
		t.Fatalf("state = %+v", state)
	}
	if state.ScannedToBlock != 11 {
		t.Fatalf("cursor moved while stalled: %d", state.ScannedToBlock)
	}
}

func TestPausedWorkerKeepsCursorAndReportsPaused(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	chain.mine(11)
	chain.mine(12)
	chain.mine(13)
	worker.cfg.Paused = true
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	if state := store.states["op-sepolia"]; state.State != scan.StatePaused || state.ScannedToBlock != 10 {
		t.Fatalf("state = %+v", state)
	}
}

func TestRoundYieldsWhenAnotherIndexerHoldsTheLease(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	chain.mine(11)
	chain.mine(12)
	chain.mine(13)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	store.leaseOwn = "other/2"
	if err := worker.Round(context.Background()); err != errLeaseHeld {
		t.Fatalf("err = %v, want errLeaseHeld", err)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	chain, _, worker := setup(t, scan.NativeModeBalance)
	chain.mine(11)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
}
