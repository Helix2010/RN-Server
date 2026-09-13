package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
