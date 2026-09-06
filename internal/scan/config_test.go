package scan

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/secretbox"
)

func testBox(t *testing.T) *secretbox.Box {
	t.Helper()
	box, err := secretbox.New(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func valid() ChainConfig {
	return ChainConfig{Chain: "monad", Enabled: true, Endpoints: []Endpoint{{URL: "https://rpc.example/v1/abcdef0123456789abcdef", Label: "primary", RPS: 5}},
		MaxLogSpan: 100, Confirmations: 5, PollSeconds: 30, AddrChunk: 1000, NativeMode: NativeModeBalance, NativeGapCap: 20000, StartBlock: 100}
}

func TestValidateRejectsBadShapes(t *testing.T) {
	cases := map[string]func(*ChainConfig){
		"no endpoints when enabled": func(c *ChainConfig) { c.Endpoints = nil },
		"plain http":                func(c *ChainConfig) { c.Endpoints[0].URL = "http://10.0.0.1:8545" },
		"zero rps":                  func(c *ChainConfig) { c.Endpoints[0].RPS = 0 },
		"empty label":               func(c *ChainConfig) { c.Endpoints[0].Label = " " },
		"span zero":                 func(c *ChainConfig) { c.MaxLogSpan = 0 },
		"confirmations zero":        func(c *ChainConfig) { c.Confirmations = 0 },
		"bad native mode":           func(c *ChainConfig) { c.NativeMode = "logs" },
		"gap cap zero in balance":   func(c *ChainConfig) { c.NativeGapCap = 0 },
		"duplicate endpoint":        func(c *ChainConfig) { c.Endpoints = append(c.Endpoints, c.Endpoints[0]) },
	}
	for name, mutate := range cases {
		cfg := valid()
		mutate(&cfg)
		if err := Validate(cfg, false); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	if err := Validate(valid(), false); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	plain := valid()
	plain.Endpoints[0].URL = "http://10.0.0.1:8545"
	if err := Validate(plain, true); err != nil {
		t.Fatalf("plain http must pass when allowed: %v", err)
	}
	disabled := valid()
	disabled.Enabled = false
	disabled.Endpoints = nil
	if err := Validate(disabled, false); err != nil {
		t.Fatalf("disabled config without endpoints must pass: %v", err)
	}
}

func TestEncodeDecodeEncryptsEndpointURLs(t *testing.T) {
	box := testBox(t)
	cfg := valid()
	raw, err := Encode(cfg, box)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "rpc.example") {
		t.Fatalf("plaintext url leaked into stored json: %s", raw)
	}
	decoded, err := Decode("monad", raw, 7, box)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Endpoints[0].URL != cfg.Endpoints[0].URL || decoded.Version != 7 || decoded.NativeMode != NativeModeBalance || decoded.StartBlock != 100 {
		t.Fatalf("decoded = %+v", decoded)
	}
	// 换链解不开：关联数据绑定了链 id
	if _, err := Decode("base", raw, 7, box); err == nil {
		t.Fatal("decoding under another chain must fail")
	}
}

func TestMaskURLAndHasSecret(t *testing.T) {
	if got := MaskURL("https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"); got != "https://mainnet.infura.io/v3/…" {
		t.Fatalf("mask = %s", got)
	}
	if !HasSecret("https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef") || HasSecret("https://rpc.monad.xyz") || !HasSecret("https://x.io/?key=1") {
		t.Fatal("secret detection wrong")
	}
}
