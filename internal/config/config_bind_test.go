package config

import (
	"os"
	"testing"
)

// 裸机部署（amos）没有 Docker 的端口映射兜底：应用监听地址必须能锁到回环，
// 否则 13080 会绕过 nginx 直接对外，TLS 和它上面的一切都白设。
func TestBindAddressDefaultsToEveryInterface(t *testing.T) {
	// 开发环境即可：这里验的是监听地址怎么取，不是生产必填项
	t.Setenv("APP_ENV", "development")
	os.Unsetenv("BIND_ADDRESS")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// 空 = 所有网卡，与改动前的行为一致，web4 那套不受影响
	if cfg.BindAddress != "" {
		t.Fatalf("default must stay empty, got %q", cfg.BindAddress)
	}

	t.Setenv("BIND_ADDRESS", "127.0.0.1")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.BindAddress != "127.0.0.1" {
		t.Fatalf("BIND_ADDRESS must be honoured, got %q", cfg.BindAddress)
	}
}
