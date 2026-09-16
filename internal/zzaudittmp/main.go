// 临时审计工具，用完即删。
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

type fileSink struct {
	dir   string
	paths map[string]string
}

func (s *fileSink) Writer(pair string) (io.WriteCloser, error) {
	p := filepath.Join(s.dir, "backup-"+fmt.Sprintf("%08d", seq)+"-"+pair+".rnbk")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.paths[pair] = p
	return f, nil
}

var seq = uint64(42)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func writeKey(dir, slot string, key *rsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	// 明文私钥，纯测试用：口令交互会卡住自动化
	must(os.WriteFile(filepath.Join(dir, slot+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
}

func tarOf(files map[string][]byte) []byte {
	// 复用 bundle 内部同样的思路：这里只要一个合法 tar
	var buf bytes.Buffer
	tw := newTar(&buf)
	names := []string{}
	for n := range files {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		must(tw.WriteHeader(tarHeader(n, int64(len(files[n])))))
		_, err := tw.Write(files[n])
		must(err)
	}
	must(tw.Close())
	return buf.Bytes()
}

func main() {
	out := os.Args[1]
	must(os.MkdirAll(out, 0o700))
	if v := os.Getenv("BACKUP_SEQ"); v != "" {
		fmt.Sscanf(v, "%d", &seq)
	}
	keydir := os.Getenv("REUSE_KEYS")

	// 三把恢复密钥
	keys := map[string]*rsa.PrivateKey{}
	recipients := []backupbundle.Recipient{}
	for _, slot := range backupcontainer.SlotNames {
		var k *rsa.PrivateKey
		if keydir != "" {
			raw, err := os.ReadFile(filepath.Join(keydir, slot+".key"))
			must(err)
			blk, _ := pem.Decode(raw)
			parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			must(err)
			k = parsed.(*rsa.PrivateKey)
		} else {
			var err error
			k, err = rsa.GenerateKey(rand.Reader, 3072)
			must(err)
		}
		keys[slot] = k
		writeKey(out, slot, k)
		fp, err := backupcontainer.Fingerprint(&k.PublicKey)
		must(err)
		recipients = append(recipients, backupbundle.Recipient{
			Slot: slot, Fingerprint: fp, Key: &k.PublicKey,
			Holder: "运维-" + slot,
		})
	}

	// 打包机的备份签名密钥
	var signPub ed25519.PublicKey
	var signPriv ed25519.PrivateKey
	if keydir != "" {
		seed, err := os.ReadFile(filepath.Join(keydir, "signing.seed"))
		must(err)
		signPriv = ed25519.NewKeyFromSeed(seed)
		signPub = signPriv.Public().(ed25519.PublicKey)
	} else {
		var err error
		signPub, signPriv, err = ed25519.GenerateKey(rand.Reader)
		must(err)
	}
	signFP, err := backupcontainer.SigningFingerprint(signPub)
	must(err)
	spkiDER, err := x509.MarshalPKIXPublicKey(signPub)
	must(err)
	must(os.WriteFile(filepath.Join(out, "signing.der"), spkiDER, 0o644))
	must(os.WriteFile(filepath.Join(out, "signing.seed"), signPriv.Seed(), 0o600))

	createdAt := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)

	// 打包机那一侧：内层明文（含机密），封给 A 和 B
	agentPlain := map[string][]byte{
		"agent-key":                         []byte(os.Getenv("AGENTKEY") + "AGENT-KEY-32-BYTES-XXXXXXXXXXXX")[:32],
		"backup-signing.key":                signPriv.Seed(),
		"build-agent.env":                   []byte("BUILD_AGENT_STATE_DIR=/var/lib/rn-build-agent\n"),
		"bin/build-agent":                   bytes.Repeat([]byte("B"), 4096),
		"systemd/rn-build-agent.service":    []byte("[Unit]\n"),
		"ssh/id_deploy":                     []byte("SSH-DEPLOY-KEY\n"),
		"ssh/config":                        []byte("Host rnapp\n"),
		"source-remote.txt":                 []byte("git@github.com:example/RN-App.git\n"),
		"keystores/acme/keystore.p12":       bytes.Repeat([]byte("P"), 2048),
		"keystores/acme/store-password.txt": []byte("weakpass"),
		"keystores/acme/key-alias.txt":      []byte("acme"),
		"keystores/acme/fingerprint.txt":    []byte("AA:BB:CC\n"),
	}
	agentManifest := []backupbundle.FileEntry{
		{Path: "agent-key", Size: int64(len(agentPlain["agent-key"])), SHA256: sha(agentPlain["agent-key"]),
			Target: "/var/lib/rn-build-agent/agent-key", Mode: "0600", Owner: "builder:builder"},
		{Path: "build-agent.env", Size: int64(len(agentPlain["build-agent.env"])), SHA256: sha(agentPlain["build-agent.env"]),
			Target: "/etc/rn-build-agent.env", Mode: "0600", Owner: "root:root"},
		{Path: "bin/build-agent", Size: int64(len(agentPlain["bin/build-agent"])), SHA256: sha(agentPlain["bin/build-agent"]),
			Target: "/opt/rn-build-agent/bin/build-agent", Mode: "0755", Owner: "root:root"},
	}

	innerMeta := map[string][]byte{}
	for k, v := range agentPlain {
		innerMeta[k] = v
	}
	innerMeta["manifest.json"] = []byte(`{"format":1,"side":"agent","files":[]}`)
	plain := tarOf(innerMeta)

	agentInner := map[string]backupbundle.InnerPart{}
	for _, slot := range backupcontainer.InnerSlots() {
		var sealed bytes.Buffer
		must(backupcontainer.Seal(&sealed, &keys[slot].PublicKey, backupcontainer.Meta{
			Layer: backupcontainer.LayerInner, Seq: seq, InstanceID: "prod-1",
			CreatedAt: createdAt.Format(time.RFC3339),
		}, bytes.NewReader(plain), int64(len(plain))))
		sig := backupcontainer.SignPayload(signPriv, sealed.Bytes())
		agentInner[slot] = backupbundle.InnerPart{Slot: slot, Sealed: sealed.Bytes(), Signature: sig}
	}

	// 服务端那一侧（照 backup_complete.go 的 backupServerFiles / exportBackupDatabaseConfig）
	serverFiles := map[string][]byte{
		"rn-foundation.env":                    []byte("STORAGE_MASTER_KEY=<测试密钥>\nADMIN_API_KEY=<测试密钥>\n"),
		"bin/rn-server":                        bytes.Repeat([]byte("S"), 4096),
		"systemd/rn-foundation-server.service": []byte("[Unit]\n"),
		"nginx/rn-foundation.conf":             []byte("server {}\n"),
		"tls/origin.crt":                       []byte("-----BEGIN CERTIFICATE-----\n"),
		"tls/origin.key":                       []byte("-----BEGIN PRIVATE KEY-----\n"),
		"db/tenants.json":                      []byte("[]"),
		"db/tenant-domain.json":                []byte("[]"),
		"db/build-config.json":                 []byte("[]"),
	}
	serverManifest := []backupbundle.FileEntry{
		{Path: "rn-foundation.env", Size: 1, SHA256: sha(serverFiles["rn-foundation.env"]),
			Target: "/etc/rn-foundation.env", Mode: "0600", Owner: "root:root"},
		{Path: "bin/rn-server", Size: 1, SHA256: sha(serverFiles["bin/rn-server"]),
			Target: "/opt/rn-foundation/bin/rn-server", Mode: "0755", Owner: "root:root"},
		{Path: "systemd/rn-foundation-server.service", Size: 1, SHA256: sha(serverFiles["systemd/rn-foundation-server.service"]),
			Target: "/etc/systemd/system/rn-foundation-server.service", Mode: "0644", Owner: "root:root"},
		{Path: "nginx/rn-foundation.conf", Size: 1, SHA256: sha(serverFiles["nginx/rn-foundation.conf"]),
			Target: "/etc/nginx/conf.d/rn-foundation.conf", Mode: "0644", Owner: "root:root"},
		{Path: "tls/origin.crt", Size: 1, SHA256: sha(serverFiles["tls/origin.crt"]),
			Target: "/etc/ssl/rn-foundation/origin.crt", Mode: "0644", Owner: "root:root"},
		{Path: "tls/origin.key", Size: 1, SHA256: sha(serverFiles["tls/origin.key"]),
			Target: "/etc/ssl/rn-foundation/origin.key", Mode: "0600", Owner: "root:root"},
		// 这三行照抄 backup_complete.go:collectServerPart 里 db/* 的 Target 写法
		{Path: "db/tenants.json", Size: 2, SHA256: sha(serverFiles["db/tenants.json"]),
			Target: "（数据库也没了时才用，见 RECOVERY.md）", Mode: "0600", Owner: "root:root"},
		{Path: "db/tenant-domain.json", Size: 2, SHA256: sha(serverFiles["db/tenant-domain.json"]),
			Target: "（数据库也没了时才用，见 RECOVERY.md）", Mode: "0600", Owner: "root:root"},
		{Path: "db/build-config.json", Size: 2, SHA256: sha(serverFiles["db/build-config.json"]),
			Target: "（数据库也没了时才用，见 RECOVERY.md）", Mode: "0600", Owner: "root:root"},
	}

	in := backupbundle.Input{
		Seq: seq, InstanceID: "prod-1", CreatedAt: createdAt,
		Recipients: recipients, AgentInner: agentInner,
		ServerFiles: serverFiles, ServerManifest: serverManifest, AgentManifest: agentManifest,
		Tenants: []backupbundle.Tenant{{Slug: "acme", Domain: "api.acme.example", HasKeystore: true,
			SignerSHA256: "aa11bb22"}},
		ServerVersion: "srv-abc1234", AgentVersion: "agt-def5678", SchemaVersion: 37,
		AgentKeyFingerprint: "0123456789abcdef", BackupSigningFingerprint: signFP,
	}

	sink := &fileSink{dir: out, paths: map[string]string{}}
	pkgs, err := backupbundle.Assemble(in, sink)
	must(err)
	for _, p := range pkgs {
		must(os.WriteFile(filepath.Join(out, fmt.Sprintf("backup-%08d-%s.README.txt", seq, p.Pair)),
			[]byte(p.ReadmeFirst), 0o644))
		fmt.Printf("包 %s  sha256=%s  size=%d\n", p.Pair, p.SHA256, p.Size)
	}
	fmt.Println("备份签名公钥指纹:", signFP)
	for _, r := range recipients {
		fmt.Printf("槽位 %s 指纹 %s\n", r.Slot, r.Fingerprint)
	}
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
