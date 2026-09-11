package api

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestVerifyPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key, err := scrypt.Key([]byte("correct-horse-battery-staple"), salt, 32768, 8, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("scrypt$32768$8$1$%s$%s", base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key))
	if !verifyPassword("correct-horse-battery-staple", hash) {
		t.Fatal("expected password to verify")
	}
	if verifyPassword("wrong-password", hash) {
		t.Fatal("wrong password verified")
	}
}

func TestVersionComparison(t *testing.T) {
	if !validVersion("1.2.3") || compareVersion("1.0.0", "1.1.0") >= 0 {
		t.Fatal("semantic version behavior is invalid")
	}
}

func TestSafeDownloadName(t *testing.T) {
	if got := safeDownloadName(`../AnyFun.apk`); got != "AnyFun.apk" {
		t.Fatalf("safeDownloadName stripped path = %q", got)
	}
	if got := safeDownloadName("bad\"name\r\n.apk"); got != "badname.apk" {
		t.Fatalf("safeDownloadName removed unsafe header characters = %q", got)
	}
	if got := safeDownloadName("../"); got != "application.apk" {
		t.Fatalf("safeDownloadName fallback = %q", got)
	}
}

func TestReleaseTransitionsDoNotExposeRollback(t *testing.T) {
	if _, exists := transitions["rollback"]; exists {
		t.Fatal("full-package rollback must not be exposed without restoring a previous release")
	}
}

func TestNormalizeReleaseNotesKeepsOnlyLineArrays(t *testing.T) {
	notes, failure := normalizeReleaseNotes(map[string]any{
		"zh-CN": []any{"修复精选卡片闪动", "轮播不再首帧变宽"},
		"en-US": []any{"Fix featured card flash"},
	})
	if failure != "" {
		t.Fatalf("line arrays must be accepted, got %q", failure)
	}
	if len(notes["zh-CN"]) != 2 || notes["zh-CN"][1] != "轮播不再首帧变宽" {
		t.Fatalf("lines must survive normalization, got %v", notes["zh-CN"])
	}
	if len(notes["en-US"]) != 1 {
		t.Fatalf("every language keeps its own lines, got %v", notes["en-US"])
	}
}

func TestNormalizeReleaseNotesAllowsAbsentNotes(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"nil":   nil,
		"empty": {},
	} {
		notes, failure := normalizeReleaseNotes(raw)
		if failure != "" {
			t.Fatalf("%s notes must be accepted, got %q", name, failure)
		}
		if len(notes) != 0 {
			t.Fatalf("%s notes must normalize to an empty map, got %v", name, notes)
		}
	}
}

// 管理端读列表时要求"语言 -> 行数组"，写入侧必须挡住别的形状：
// 曾经有人用管理接口直接写进一个字符串，整份 OTA 列表因此校验失败。
func TestNormalizeReleaseNotesRejectsWrongShapes(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"string value":    {"zh-CN": "改用同形骨架"},
		"number value":    {"zh-CN": 1},
		"object value":    {"zh-CN": map[string]any{"line": "x"}},
		"non-string line": {"zh-CN": []any{"ok", 2}},
		"blank line":      {"zh-CN": []any{"  "}},
		"empty array":     {"zh-CN": []any{}},
		"blank language":  {" ": []any{"ok"}},
	} {
		notes, failure := normalizeReleaseNotes(raw)
		if failure == "" {
			t.Fatalf("%s must be rejected", name)
		}
		if notes != nil {
			t.Fatalf("%s must not yield notes, got %v", name, notes)
		}
	}
}
