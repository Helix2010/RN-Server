package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"crypto/ed25519"
	"crypto/rsa"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

// 配置全部来自**构建机本地**。服务端下发的只有租户 slug、git ref、version、
// buildNumber 和 OTA 证书——它说不出仓库在哪、密钥在哪、用什么命令构建。
type config struct {
	Server    string
	Token     string
	Name      string
	Repo      string
	Workspace string
	Platforms []string
	Timeout   time.Duration
	PollEvery time.Duration
	// KeystorePassphrase 开**旧格式**（v1，口令封）的盒子。留着是为了让已经存在的
	// 密钥继续能用；新写的一律加密给本机公钥（见 agentkey.go），不需要它。
	KeystorePassphrase string
	// StateDir 放本机私钥等需要长期保留的东西。默认是 workspace 的上一级，和
	// unit 文件里的 /var/lib/rn-build-agent 对齐：缓存删了只是慢一点，这里删了
	// 要重新配。
	StateDir string
	// AgentPrivateKey 是本机 X25519 私钥，永不外发
	AgentPrivateKey []byte
	// AgentPublicKey 登记给服务端，签名密钥加密给它
	AgentPublicKey buildkeystore.Recipient

	// BackupRecipients 是三把恢复公钥（槽位 A / B / C）。
	//
	// **只封给这里的公钥，不接受服务端下发的收件人。** 否则服务端被攻破之后，
	// 攻击者只要改一下收件人，就能让打包机把全部租户的签名密钥封给他自己——
	// 那等于把「服务端读不到签名密钥」这条论证直接作废。
	//
	// 服务端认领时会下发三个**指纹**供核对，对不上就拒绝执行并上报。
	BackupRecipients [backupcontainer.SlotCount]*rsa.PublicKey
	// BackupFingerprints 和上面一一对应，用来和服务端下发的比对
	BackupFingerprints [backupcontainer.SlotCount]string
	// backupRecipientMisnamed 记下哪几个槽位没配、却配了服务端那一侧的键名
	// （BACKUP_RECOVERY_RECIPIENT_*）。两台机器的 env 长得几乎一样，照着服务端那段
	// 抄过来是最容易犯的错，而它的表现只是一句「没配」——人盯着文件里明明有值的三行
	// 找不出原因。报错时点破它
	backupRecipientMisnamed [backupcontainer.SlotCount]bool
	// BackupSigningKey 给内层密文签名；BackupSigningPublicKey 登记给服务端
	BackupSigningKey       ed25519.PrivateKey
	BackupSigningPublicKey string
}

// backupReady 说明这台机器能不能产出备份。
//
// **缺配置不 fail-closed 启动**：把备份做成构建的单点故障是负收益，而且第一次
// 配置往往正好发生在恢复当天。但它必须拒绝认领待办并上报原因，让控制台上看得见
// 「打包机没配恢复公钥」，而不是静默不备份。
func (c config) backupReady() error {
	for i, slot := range backupcontainer.SlotNames {
		if c.BackupRecipients[i] == nil && c.backupRecipientMisnamed[i] {
			return fmt.Errorf("BUILD_AGENT_RECOVERY_RECIPIENT_%s is not configured on this build machine: "+
				"its env has BACKUP_RECOVERY_RECIPIENT_%s instead, which is the server's name for the key. "+
				"Rename it to BUILD_AGENT_RECOVERY_RECIPIENT_%s and restart build-agent", slot, slot, slot)
		}
		if c.BackupRecipients[i] == nil {
			return fmt.Errorf("BUILD_AGENT_RECOVERY_RECIPIENT_%s is not configured on this build machine", slot)
		}
	}
	if len(c.BackupSigningKey) == 0 {
		return fmt.Errorf("this build machine has no backup signing key")
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func loadConfig() (config, error) {
	host, _ := os.Hostname()
	cfg := config{
		Server:             strings.TrimRight(envOr("BUILD_AGENT_SERVER", ""), "/"),
		Token:              envOr("BUILD_AGENT_TOKEN", ""),
		Name:               envOr("BUILD_AGENT_NAME", host),
		Repo:               envOr("BUILD_AGENT_REPO", ""),
		Workspace:          envOr("BUILD_AGENT_WORKSPACE", ""),
		PollEvery:          10 * time.Second,
		KeystorePassphrase: envOr("BUILD_KEYSTORE_PASSPHRASE", ""),
		StateDir:           envOr("BUILD_AGENT_STATE_DIR", ""),
	}
	// 服务端那一侧的键名只用来在报错时点破「抄错了键名」，**不当作公钥读**：打包机只认自己那组键
	for i, raw := range []string{
		envOr("BACKUP_RECOVERY_RECIPIENT_A", ""),
		envOr("BACKUP_RECOVERY_RECIPIENT_B", ""),
		envOr("BACKUP_RECOVERY_RECIPIENT_C", ""),
	} {
		cfg.backupRecipientMisnamed[i] = raw != ""
	}
	// 三把恢复公钥。值是 PEM 的 base64 单行——PEM 带换行，直接写进 systemd 的
	// EnvironmentFile 极易写坏，而这个键要用的那一天正好最不该出意外。
	//
	// 键名写成字面量而不是拼出来：拼出来之后 grep 找不到「槽位 A 对应哪个环境变量」，
	// 而灾难当天要看的正是这个。
	for i, raw := range []string{
		envOr("BUILD_AGENT_RECOVERY_RECIPIENT_A", ""),
		envOr("BUILD_AGENT_RECOVERY_RECIPIENT_B", ""),
		envOr("BUILD_AGENT_RECOVERY_RECIPIENT_C", ""),
	} {
		if raw == "" {
			continue
		}
		pub, err := backupcontainer.ParsePublicKey(raw)
		if err != nil {
			// 不 fail-closed：把备份做成构建的单点故障是负收益。但要吵一声，
			// 否则「配了就以为有」——而这正是这套东西最不能出的错
			slog.Error("a recovery public key is unusable; this build machine will refuse to produce backups",
				"slot", backupcontainer.SlotNames[i], "error", err)
			continue
		}
		fingerprint, err := backupcontainer.Fingerprint(pub)
		if err != nil {
			slog.Error("a recovery public key could not be fingerprinted",
				"slot", backupcontainer.SlotNames[i], "error", err)
			continue
		}
		cfg.BackupRecipients[i] = pub
		cfg.BackupFingerprints[i] = fingerprint
	}

	for _, p := range strings.Split(envOr("BUILD_AGENT_PLATFORMS", "android"), ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p == "android" || p == "ios" {
			cfg.Platforms = append(cfg.Platforms, p)
		}
	}
	minutes, err := strconv.Atoi(envOr("BUILD_AGENT_TIMEOUT_MINUTES", "45"))
	if err != nil || minutes < 1 || minutes > 480 {
		return cfg, errors.New("BUILD_AGENT_TIMEOUT_MINUTES must be between 1 and 480")
	}
	cfg.Timeout = time.Duration(minutes) * time.Minute

	for key, value := range map[string]string{
		"BUILD_AGENT_SERVER":    cfg.Server,
		"BUILD_AGENT_TOKEN":     cfg.Token,
		"BUILD_AGENT_REPO":      cfg.Repo,
		"BUILD_AGENT_WORKSPACE": cfg.Workspace,
	} {
		if value == "" {
			return cfg, fmt.Errorf("%s is required", key)
		}
	}
	if len(cfg.Platforms) == 0 {
		return cfg, errors.New("BUILD_AGENT_PLATFORMS must name android or ios")
	}
	// 生产里用 http 等于把 token 明文发出去，而这个 token 能领走构建任务
	if !strings.HasPrefix(cfg.Server, "https://") && !strings.HasPrefix(cfg.Server, "http://127.0.0.1") && !strings.HasPrefix(cfg.Server, "http://localhost") {
		return cfg, errors.New("BUILD_AGENT_SERVER must be https, except for a loopback address in development")
	}
	if !filepath.IsAbs(cfg.Workspace) {
		return cfg, errors.New("BUILD_AGENT_WORKSPACE must be an absolute path")
	}
	if cfg.StateDir == "" {
		// workspace 是 /var/lib/rn-build-agent/workspace，状态放它的上一级
		cfg.StateDir = filepath.Dir(strings.TrimRight(cfg.Workspace, "/"))
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return cfg, errors.New("BUILD_AGENT_STATE_DIR must be an absolute path")
	}
	// 私钥不在这里读：loadConfig 只该解析配置，不该在磁盘上留下东西。落盘那一步
	// 在 main 里做，那样这个函数也能在测试里随便调
	return cfg, nil
}
