package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	// KeystorePassphrase 开服务端下发的那个盒子。它只存在于这台机器上——
	// 服务端没有它，所以服务端打不开签名密钥。
	KeystorePassphrase string
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
	return cfg, nil
}
