package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// 哨兵值：只要任何一种打印方式把它们带出来，测试就失败。测试输出会进 CI 日志，所以断言失败时
// 也不把整段输出打出来，只说是哪种打印方式。
const (
	sentinelToken  = "rnm_SENTINELtokenMUSTneverBEprintedAnywhere0"
	sentinelSecret = "sentinel-secret-value-in-the-environment"
)

func TestSecretHoldingStructsNeverPrintTheirSecrets(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	key := newMachineKey(private)
	cfg := config{
		Server: "https://user:" + sentinelSecret + "@api.example.com/path?token=" + sentinelToken, MachineToken: sentinelToken,
		Repo: "/var/lib/rn-build-agent/repos/rn-app.git", Workspace: "/var/lib/rn-build-jobs", StateDir: "/var/lib/rn-build-agent/state",
		Platforms: []string{"android"}, Timeout: time.Minute, Runner: "/opt/rn-build-agent/build-runner", RunnerUser: "builder",
		MachineEnv: map[string]string{"PATH": "/usr/bin"},
	}
	ring := &keyring{dir: cfg.StateDir, current: key, next: &key}
	red := &redactor{values: []string{sentinelToken, sentinelSecret}}
	a := &agent{cfg: cfg, api: newClient(cfg), keys: ring, red: red}
	buf := newLogBuffer(red)

	forbidden := []string{
		sentinelToken, sentinelSecret,
		base64.StdEncoding.EncodeToString(seed), hex.EncodeToString(seed), hex.EncodeToString(private),
		fmt.Sprint([]byte(private)), fmt.Sprint(seed[:8]),
	}
	values := map[string]any{
		"config": cfg, "*config": &cfg, "client": a.api, "machineKey": key, "*machineKey": &key,
		"keyring": ring, "redactor": red, "agent": a, "logBuffer": buf,
		"enrollment": enrollment{MachineID: testMachineID, Token: sentinelToken, Status: "pending_key"},
		"wrapper with exported fields": struct {
			Cfg  config
			Keys *keyring
		}{cfg, ring},
	}
	for name, value := range values {
		outputs := map[string]string{}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%T"} {
			outputs[verb] = fmt.Sprintf(verb, value)
		}
		var text, jsonOut bytes.Buffer
		slog.New(slog.NewTextHandler(&text, nil)).Info("dump", "value", value)
		slog.New(slog.NewJSONHandler(&jsonOut, nil)).Info("dump", "value", value)
		outputs["slog text"] = text.String()
		outputs["slog json"] = jsonOut.String()
		if raw, err := json.Marshal(value); err == nil {
			outputs["json.Marshal"] = string(raw)
		}
		for how, out := range outputs {
			for _, secret := range forbidden {
				if strings.Contains(out, secret) {
					t.Errorf("%s printed with %s leaks a secret", name, how)
				}
			}
		}
	}
	// 白名单里的东西照常可见，否则上面的断言可能只是因为什么都没打印
	if summary := fmt.Sprintf("%#v", cfg); !strings.Contains(summary, "api.example.com") || !strings.Contains(summary, "machineToken=set") {
		t.Errorf("the config summary lost its allowed fields")
	}
	if summary := fmt.Sprint(ring); !strings.Contains(summary, key.sha256) {
		t.Errorf("the keyring summary lost the public key fingerprint")
	}
}
