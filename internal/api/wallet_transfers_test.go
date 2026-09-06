package api

import (
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

func TestTransferCursorRoundTrip(t *testing.T) {
	encoded := encodeTransferCursor(transferCursor{Block: 48434118, ID: 77})
	decoded, err := decodeTransferCursor(encoded)
	if err != nil || decoded == nil || decoded.Block != 48434118 || decoded.ID != 77 {
		t.Fatalf("decoded = %+v, err = %v", decoded, err)
	}
	if first, err := decodeTransferCursor("  "); err != nil || first != nil {
		t.Fatalf("blank cursor must mean first page: %+v %v", first, err)
	}
	for _, bad := range []string{"not-base64!", "MTIz", "MTow", "YTpi"} {
		if _, err := decodeTransferCursor(bad); err == nil {
			t.Fatalf("cursor %q must be rejected", bad)
		}
	}
}

func TestTransferIndexOfMarksUnconfiguredChains(t *testing.T) {
	now := time.Date(2026, 9, 6, 5, 0, 0, 0, time.UTC)
	scanned := now.Add(-90 * time.Second)
	states := map[string]scan.ChainState{
		"op-sepolia": {State: scan.StateIdle, ScannedToBlock: 100, HeadBlock: 110, ScannedToTime: &scanned},
		"monad":      {State: scan.StateUnconfigured, ScannedToBlock: 5},
		"base":       {State: scan.StateCatchingUp, ScannedToBlock: 7},
	}
	index := transferIndexOf([]string{"op-sepolia", "monad", "base", "eth"}, true, states, now)
	live := index["op-sepolia"]
	if live.State != "idle" || live.Block == nil || *live.Block != 100 || *live.HeadBlock != 110 || live.LagSeconds == nil || *live.LagSeconds != 90 || live.Time == nil || *live.Time != "2026-09-06T04:58:30.000Z" {
		t.Fatalf("live chain view = %+v", live)
	}
	if index["monad"].State != "unconfigured" || index["monad"].Block != nil {
		t.Fatalf("disabled config must read unconfigured: %+v", index["monad"])
	}
	if base := index["base"]; base.State != "catching_up" || base.LagSeconds != nil || base.Time != nil {
		t.Fatalf("state without a scanned block time must omit lag: %+v", base)
	}
	if index["eth"].State != "unconfigured" {
		t.Fatalf("missing state row must read unconfigured: %+v", index["eth"])
	}
	// 租户没开链上转出：一律未开启，哪怕平台在扫这条链
	for chain, view := range transferIndexOf([]string{"op-sepolia"}, false, states, now) {
		if view.State != "unconfigured" {
			t.Fatalf("%s must be unconfigured when onchainSends is off: %+v", chain, view)
		}
	}
	// 时钟回拨也不显示负的落后
	future := now.Add(time.Minute)
	states["op-sepolia"] = scan.ChainState{State: scan.StateIdle, ScannedToTime: &future}
	if lag := transferIndexOf([]string{"op-sepolia"}, true, states, now)["op-sepolia"].LagSeconds; lag == nil || *lag != 0 {
		t.Fatalf("lag must clamp at zero: %v", lag)
	}
}

func TestTokenViewsByKeyMatchesCaseInsensitively(t *testing.T) {
	views := tokenViewsByKey([]tokenRecord{
		{Chain: "op-sepolia", Address: "native", Symbol: "ETH", Decimals: 18, DisplayDecimals: 6},
		{Chain: "op-sepolia", Address: "0x5fd84259d66Cd46123540766Be93DFE6D43130D7", Symbol: "USDC", Decimals: 6, DisplayDecimals: 2},
	})
	if token, ok := views["op-sepolia|0x5fd84259d66cd46123540766be93dfe6d43130d7"]; !ok || token.Symbol != "USDC" || token.Address != "0x5fd84259d66Cd46123540766Be93DFE6D43130D7" {
		t.Fatalf("lower-cased lookup must find the EIP-55 row: %+v %v", token, ok)
	}
	if token, ok := views["op-sepolia|native"]; !ok || token.Symbol != "ETH" {
		t.Fatalf("native lookup = %+v %v", token, ok)
	}
}
