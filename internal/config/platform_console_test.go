package config

import (
	"strings"
	"testing"
)

// 平台控制台的域名与装机命令里的服务端地址（设计 service-and-console-split-2026-09-27 §4.3）：
// 前者会拼进统一登录的回调地址，后者会写进机器的配置，写错的形状要在启动时就拦下。
func TestPlatformConsoleHostAndMachineOrigin(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("PLATFORM_CONSOLE_HOST", " Platform.Example.COM ")
	t.Setenv("MACHINE_API_ORIGIN", "https://api.example.com/")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.PlatformConsoleHost != "platform.example.com" || cfg.MachineAPIOrigin != "https://api.example.com" {
		t.Fatalf("got %q %q", cfg.PlatformConsoleHost, cfg.MachineAPIOrigin)
	}

	for _, tc := range []struct{ env, host, origin, want string }{
		{"development", "https://platform.example.com", "", "PLATFORM_CONSOLE_HOST"},
		{"development", "platform.example.com:8443", "", "PLATFORM_CONSOLE_HOST"},
		{"development", "platform.example.com/x", "", "PLATFORM_CONSOLE_HOST"},
		{"development", "", "api.example.com", "MACHINE_API_ORIGIN"},
		{"development", "", "https://api.example.com/v1", "MACHINE_API_ORIGIN"},
		{"development", "", "https://user@api.example.com", "MACHINE_API_ORIGIN"},
		{"production", "", "http://api.example.com", "MACHINE_API_ORIGIN"},
	} {
		t.Setenv("APP_ENV", tc.env)
		t.Setenv("PLATFORM_CONSOLE_HOST", tc.host)
		t.Setenv("MACHINE_API_ORIGIN", tc.origin)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s host=%q origin=%q: want an error about %s, got %v", tc.env, tc.host, tc.origin, tc.want, err)
		}
	}
}
