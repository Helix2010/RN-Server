package store

import (
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
)

// 连接参数的断言搬到了 internal/config：它们现在由 MYSQL_DSN 解析而来，
// store 这边只负责连接池——那几项驱动不认，必须留在 database/sql 这一层。

func TestPoolSettingsUseConfiguredLimits(t *testing.T) {
	cfg := config.Config{
		MySQLConnectionLimit:       5,
		MySQLMaxIdleConnections:    1,
		MySQLConnectionMaxLifetime: 601,
		MySQLConnectionMaxIdleTime: 61,
	}

	settings := configuredPoolSettings(cfg)
	if settings.maxOpen != 5 || settings.maxIdle != 1 || settings.maxLifetime != 601*time.Second || settings.maxIdleTime != 61*time.Second {
		t.Fatalf("unexpected pool settings: %#v", settings)
	}
}

func TestOTAMigrationIsForwardOnly(t *testing.T) {
	found := false
	foundApplyStrategy := false
	for _, item := range migrations {
		if item.version == 10 && item.name == "ota_releases" {
			found = true
		}
		if item.version == 11 && item.name == "ota_apply_strategy" {
			foundApplyStrategy = true
		}
	}
	if !found {
		t.Fatal("OTA schema migration 10 is missing")
	}
	if !foundApplyStrategy {
		t.Fatal("OTA apply strategy migration 11 is missing")
	}
}

// 历史数据里出现过 release_notes 的值被写成字符串，管理端整份列表因此打不开、
// bootstrap 的整段升级信息（含 mandatory）会一起消失。迁移把它们改成行数组。
func TestReleaseNotesFromLooseShapeRepairsStoredValues(t *testing.T) {
	notes := releaseNotesFromLooseShape(map[string]any{
		"zh-CN":   "写成了字符串",
		"en-US":   []any{"first", "  second  ", "", 7},
		"  ja-JP": "  トリム  ",
		"ko-KR":   7,
		"de-DE":   map[string]any{"line": "x"},
		"fr-FR":   nil,
		" ":       "无语言码",
		"nb-NO":   []any{"  "},
	})
	if got := notes["zh-CN"]; len(got) != 1 || got[0] != "写成了字符串" {
		t.Fatalf("a string value becomes one line, got %v", got)
	}
	if got := notes["en-US"]; len(got) != 2 || got[1] != "second" {
		t.Fatalf("arrays keep trimmed non-empty strings only, got %v", got)
	}
	if got := notes["ja-JP"]; len(got) != 1 || got[0] != "トリム" {
		t.Fatalf("language codes and lines are trimmed, got %v", got)
	}
	for _, language := range []string{"ko-KR", "de-DE", "fr-FR", " ", "nb-NO", "  ja-JP"} {
		if _, present := notes[language]; present {
			t.Fatalf("%q carries no usable lines and must be dropped", language)
		}
	}
}
