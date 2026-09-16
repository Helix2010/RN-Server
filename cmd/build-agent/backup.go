package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

// 打包机侧的备份产出（设计 platform-backup-recovery-2026-09-15 §4.1、§4.5）。
//
// 这台机器是**唯一**能做这件事的：签名密钥在库里是加密的，能解开它们的只有本机的
// agent-key。服务端故意读不到那个文件——签名密钥能放进数据库，靠的就是这条。
//
// 产出两份内层密文（封给槽位 A 和 B），不是三份：三组配对里内层收件人只有这两种
// （AB 与 AC 共用封给 A 的那份），所以解密全部租户密钥、打 tar 这件重活只做两遍。

// backupTimeout 是一次备份的总预算。
//
// **小于服务端 30 分钟的产出超时**，让打包机来得及在服务端判死之前主动上报失败。
// 没有这个 ctx 的话，一次卡住的上传会让这个 goroutine 永远不返回——而 runBackup
// 跑在轮询循环里，症状是「构建队列无限堆积，日志里什么都没有」。
const backupTimeout = 25 * time.Minute

// backupStagingDirName 是明文暂存。
//
// 必须有归宿：rn-build-agent.service 的注释教运维「急着换就 SIGKILL」，而同一个
// 文件已经点名过这条路径会「留下孤儿 worktree 和一份解开的 keystore」。所以
// 0700、defer 清理、**而且启动时先清上一次的残留**。
const backupStagingDirName = "backup-staging"

type backupRequest struct {
	ID string `json:"id"`
	// InstanceID 由服务端下发。**不许从主机名推导**：两层 meta 的 instanceId
	// 必须是同一个值，而 BUILD_AGENT_NAME 默认就是主机名
	InstanceID string `json:"instanceId"`
	Seq        uint64 `json:"seq"`
	Recipients []struct {
		Slot        string `json:"slot"`
		Fingerprint string `json:"fingerprint"`
	} `json:"recipients"`
}

type sealedKeystoreItem struct {
	Tenant         string          `json:"tenant"`
	Version        int             `json:"version"`
	SealedKeystore json.RawMessage `json:"sealedKeystore"`
	KeyAlias       string          `json:"keyAlias"`
}

// resetBackupStaging 清掉上一次进程留下的明文暂存。启动时调一次。
func resetBackupStaging(stateDir string) {
	_ = os.RemoveAll(filepath.Join(stateDir, backupStagingDirName))
}

// runBackup 做完一次备份。任何一步失败都主动上报，不让服务端干等到超时。
func runBackup(ctx context.Context, cfg config, api *client, request backupRequest) {
	slog.Info("producing a platform backup", "backupId", request.ID, "seq", request.Seq)
	if err := produceBackup(ctx, cfg, api, request); err != nil {
		slog.Error("producing a platform backup failed", "backupId", request.ID, "error", err)
		// 主动上报，而不是让它 30 分钟后被判死——那期间闸一直占着，
		// 控制台上看到的是「进行中」而实际什么都没在跑
		failCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := api.failBackup(failCtx, request.ID, err.Error()); err != nil {
			slog.Error("could not report the backup failure", "backupId", request.ID, "error", err)
		}
		return
	}
	slog.Info("platform backup produced", "backupId", request.ID, "seq", request.Seq)
}

func produceBackup(ctx context.Context, cfg config, api *client, request backupRequest) error {
	if err := cfg.backupReady(); err != nil {
		return err
	}
	// **核对服务端下发的三个指纹和本机 env 里那三把一致。**
	// 不接受服务端下发的收件人本体：服务端被攻破之后，攻击者只要改一下收件人，
	// 就能让打包机把全部签名密钥封给他自己
	if err := checkBackupRecipients(cfg, request); err != nil {
		return err
	}

	staging := filepath.Join(cfg.StateDir, backupStagingDirName, request.ID)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return fmt.Errorf("cannot create the staging directory: %w", err)
	}
	// 明文签名密钥在这里面。做完必须清掉，失败也要清
	defer os.RemoveAll(staging)

	items, err := api.backupKeystores(ctx, request.ID)
	if err != nil {
		return fmt.Errorf("cannot fetch the sealed keystores: %w", err)
	}
	files, tenants, err := unsealKeystores(cfg, items)
	if err != nil {
		return err
	}
	local, err := collectAgentFiles(cfg)
	if err != nil {
		return err
	}
	for path, body := range local {
		files[path] = body
	}

	manifest := buildInnerManifest(cfg, files)
	encoded, err := json.MarshalIndent(map[string]any{
		"format": backupcontainer.Format, "side": "agent",
		"createdAt": time.Now().UTC().Format(time.RFC3339), "files": manifest,
	}, "", "  ")
	if err != nil {
		return err
	}
	files["manifest.json"] = encoded

	plain, err := backupbundle.TarFiles(files)
	if err != nil {
		return fmt.Errorf("cannot pack the agent part: %w", err)
	}

	// 两份内层：封给 A 和封给 B。同一份明文，两把不同的锁
	uploaded := map[string]bool{}
	for _, slot := range backupcontainer.InnerSlots() {
		index := slotIndex(slot)
		var sealed bytes.Buffer
		meta := backupcontainer.Meta{
			Layer: backupcontainer.LayerInner, Seq: request.Seq,
			InstanceID: request.InstanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := backupcontainer.Seal(&sealed, cfg.BackupRecipients[index], meta,
			bytes.NewReader(plain), int64(len(plain))); err != nil {
			return fmt.Errorf("cannot seal the agent part for slot %s: %w", slot, err)
		}
		signature := backupcontainer.SignPayload(cfg.BackupSigningKey, sealed.Bytes())
		meta2 := backupbundle.PayloadMeta{
			RecipientSlot:            slot,
			AgentVersion:             agentBuildVersion(),
			AgentKeyFingerprint:      cfg.AgentPublicKey.Fingerprint(),
			BackupSigningFingerprint: backupSigningFingerprint(cfg),
			Tenants:                  tenants,
			InnerFiles:               manifest,
		}
		result, err := api.uploadBackupPayload(ctx, request.ID, meta2, sealed.Bytes(), signature)
		if err != nil {
			return fmt.Errorf("cannot upload the agent part for slot %s: %w", slot, err)
		}
		uploaded[slot] = true
		// 服务端说还缺一份**我们已经传过**的槽位，说明它那边的暂存没了
		// （最常见的原因：两份之间服务端重启了，启动时会清掉上一次的暂存）。
		// 只判 >=400 的话这里是「成功」，打包机会打出「备份产出成功」然后走人，
		// 而记录停在 running 干等 30 分钟产出超时——没有人知道发生了什么
		for _, still := range result.StillExpecting {
			if uploaded[still] {
				return fmt.Errorf("the server lost the payload for slot %s (it still expects it after we uploaded it); "+
					"it probably restarted mid-backup", still)
			}
		}
	}
	return nil
}

func checkBackupRecipients(cfg config, request backupRequest) error {
	if len(request.Recipients) != backupcontainer.SlotCount {
		return fmt.Errorf("the server offered %d recovery keys but the threshold is 2-of-%d",
			len(request.Recipients), backupcontainer.SlotCount)
	}
	for _, offered := range request.Recipients {
		index := slotIndex(offered.Slot)
		if index < 0 {
			return fmt.Errorf("the server offered an unknown recovery slot %q", offered.Slot)
		}
		if cfg.BackupFingerprints[index] != offered.Fingerprint {
			// 这条要说得具体：运维看到它就知道是哪一台机器上的哪个槽位没同步
			return fmt.Errorf("slot %s does not match: this machine has %s, the server offered %s; "+
				"refusing to produce a backup until both sides agree",
				offered.Slot, shortFingerprint(cfg.BackupFingerprints[index]), shortFingerprint(offered.Fingerprint))
		}
	}
	return nil
}

func shortFingerprint(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16] + "…"
}

func slotIndex(slot string) int {
	for i, name := range backupcontainer.SlotNames {
		if name == slot {
			return i
		}
	}
	return -1
}

// unsealKeystores 把每个租户的密封盒子解成明文 .p12 和口令。
//
// 这是整条链路上唯一能做这件事的地方，也是**唯一**会让全平台签名密钥同时以明文
// 存在的地方。所以它只在内存里做，写出去的那一份立刻进 tar、tar 立刻被加密。
func unsealKeystores(cfg config, items []sealedKeystoreItem) (map[string][]byte, []backupbundle.Tenant, error) {
	files := map[string][]byte{}
	tenants := make([]backupbundle.Tenant, 0, len(items))
	for _, item := range items {
		var sealed buildkeystore.Sealed
		if err := json.Unmarshal(item.SealedKeystore, &sealed); err != nil {
			return nil, nil, fmt.Errorf("tenant %s: the sealed keystore is not readable: %w", item.Tenant, err)
		}
		bundle, err := buildkeystore.OpenWith(sealed, cfg.AgentPrivateKey)
		if err != nil {
			// 打不开一个租户的盒子是**严重**的：它的签名密钥就此没有离线副本。
			// 整次备份失败，而不是安静地少备一个
			return nil, nil, fmt.Errorf("tenant %s: cannot open the sealed keystore: %w", item.Tenant, err)
		}
		raw, err := base64.StdEncoding.DecodeString(bundle.KeystoreBase64)
		if err != nil {
			return nil, nil, fmt.Errorf("tenant %s: the keystore is not valid base64: %w", item.Tenant, err)
		}
		// 证书指纹现算。它进 manifest 和 RECOVERY.md，恢复时可以离线核对
		// 「包里这把确实是线上在用的那把」——几秒钟的事，而它能证明的东西很硬
		fingerprint, err := androidkeystore.CertificateSHA256(raw, bundle.StorePassword)
		if err != nil {
			return nil, nil, fmt.Errorf("tenant %s: cannot read the certificate fingerprint: %w", item.Tenant, err)
		}
		slug := item.Tenant
		prefix := "keystores/" + slug + "/"
		files[prefix+"keystore.p12"] = raw
		files[prefix+"store-password.txt"] = []byte(bundle.StorePassword)
		files[prefix+"key-password.txt"] = []byte(bundle.KeyPassword)
		files[prefix+"key-alias.txt"] = []byte(bundle.KeyAlias)
		files[prefix+"fingerprint.txt"] = []byte(fingerprint)
		tenants = append(tenants, backupbundle.Tenant{
			Slug: slug, HasKeystore: true, SignerSHA256: fingerprint,
		})
	}
	if len(tenants) == 0 {
		return nil, nil, fmt.Errorf("no tenant keystores could be prepared; a backup with none is not worth keeping")
	}
	return files, tenants, nil
}

// collectAgentFiles 收这台机器上那些**不在数据库里**的东西。
//
// 二进制读的是 /proc/self/exe：目标机器上没有 Go 工具链，deploy.sh 是在开发机上
// 交叉编译的。不装它，恢复第一步就得先找一台能编译的机器。
func collectAgentFiles(cfg config) (map[string][]byte, error) {
	files := map[string][]byte{}
	required := map[string]string{
		"agent-key":          filepath.Join(cfg.StateDir, agentKeyFileName),
		"backup-signing.key": filepath.Join(cfg.StateDir, backupSigningKeyFileName),
	}
	for name, path := range required {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", name, err)
		}
		files[name] = body
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot find this binary: %w", err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		return nil, fmt.Errorf("cannot read this binary: %w", err)
	}
	files["bin/build-agent"] = body

	// 下面这些缺了只记一条 warn：部署布局各不相同，硬失败会让备份在一个只是
	// 路径不一样的环境里永远跑不起来。但它们缺了恢复会更费劲，所以要吵一声
	optional := map[string]string{
		"build-agent.env":                envOr("BUILD_AGENT_ENV_PATH", "/etc/rn-build-agent.env"),
		"systemd/rn-build-agent.service": envOr("BUILD_AGENT_UNIT_PATH", "/etc/systemd/system/rn-build-agent.service"),
		"ssh/id_deploy":                  envOr("BUILD_AGENT_SSH_KEY_PATH", ""),
		"ssh/config":                     envOr("BUILD_AGENT_SSH_CONFIG_PATH", ""),
	}
	for name, path := range optional {
		if strings.TrimSpace(path) == "" {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("a file is missing from the backup package; recovery will be harder without it",
				"name", name, "path", path, "error", err)
			continue
		}
		files[name] = body
	}
	// 没有源码就不能构建。装的是地址不是仓库本体——GitHub 长时间不可用是另一个
	// 量级的问题，见设计 §15
	files["source-remote.txt"] = []byte(cfg.Repo + "\n")
	return files, nil
}

// buildInnerManifest 描述内层每个文件该放到哪。
//
// 服务端拿它渲染 RECOVERY.md 和 recover.sh——**那两份东西里「哪个文件放到哪」
// 就是这里生成的**，不是手写的散文。
func buildInnerManifest(cfg config, files map[string][]byte) []backupbundle.FileEntry {
	targets := map[string]struct{ target, mode, owner string }{
		"agent-key":                      {filepath.Join(cfg.StateDir, agentKeyFileName), "0600", "builder:builder"},
		"backup-signing.key":             {filepath.Join(cfg.StateDir, backupSigningKeyFileName), "0600", "builder:builder"},
		"bin/build-agent":                {"/usr/local/bin/build-agent", "0755", "root:root"},
		"build-agent.env":                {"/etc/rn-build-agent.env", "0600", "root:root"},
		"systemd/rn-build-agent.service": {"/etc/systemd/system/rn-build-agent.service", "0644", "root:root"},
		"ssh/id_deploy":                  {"/home/builder/.ssh/id_deploy", "0600", "builder:builder"},
		"ssh/config":                     {"/home/builder/.ssh/config", "0600", "builder:builder"},
		"source-remote.txt":              {filepath.Join(cfg.StateDir, "source-remote.txt"), "0644", "builder:builder"},
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]backupbundle.FileEntry, 0, len(names))
	for _, name := range names {
		entry := backupbundle.FileEntry{
			Path: name, Size: int64(len(files[name])), SHA256: sha256Hex(files[name]),
			Mode: "0600", Owner: "builder:builder",
		}
		if known, ok := targets[name]; ok {
			entry.Target, entry.Mode, entry.Owner = known.target, known.mode, known.owner
		} else {
			// keystores/<slug>/* 之类：解出来放哪由人决定，给一个明确的暂存位置
			entry.Target = filepath.Join(cfg.StateDir, "restored", name)
		}
		out = append(out, entry)
	}
	return out
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// agentBuildVersion 说明「恢复时该装哪一版打包机」。
//
// 这个仓库不用 ldflags 打版本号，所以取 go 自己嵌进二进制的 vcs.revision；
// 没有就回落到二进制自身的 sha256 前 12 位——不好看，但它唯一地标识了这个
// 二进制，而恢复的人要的正是「和产出备份时同一个」。
func agentBuildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				return setting.Value
			}
		}
	}
	self, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	body, err := os.ReadFile(self)
	if err != nil {
		return "unknown"
	}
	return "sha256:" + sha256Hex(body)[:12]
}

func backupSigningFingerprint(cfg config) string {
	pub, err := backupcontainer.ParseSigningPublicKey(cfg.BackupSigningPublicKey)
	if err != nil {
		return ""
	}
	fingerprint, err := backupcontainer.SigningFingerprint(pub)
	if err != nil {
		return ""
	}
	return fingerprint
}
