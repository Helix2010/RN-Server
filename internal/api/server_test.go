package api

import (
	"testing"
)

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
	notes, code, detail := normalizeReleaseNotes(map[string]any{
		"zh-CN": []any{"修复精选卡片闪动", "轮播不再首帧变宽"},
		"en-US": []any{"Fix featured card flash"},
	})
	if code != "" {
		t.Fatalf("line arrays must be accepted, got %s %s", code, detail)
	}
	if len(notes["zh-CN"]) != 2 || notes["zh-CN"][1] != "轮播不再首帧变宽" {
		t.Fatalf("lines must survive normalization, got %v", notes["zh-CN"])
	}
	if len(notes["en-US"]) != 1 {
		t.Fatalf("every language keeps its own lines, got %v", notes["en-US"])
	}
}

// 校验按去空白后的值做，存库也必须存去空白后的值：否则 " zh-CN " 能通过校验，
// 却永远匹配不上按语言码精确查找的读取侧。
func TestNormalizeReleaseNotesStoresTrimmedKeysAndLines(t *testing.T) {
	notes, code, detail := normalizeReleaseNotes(map[string]any{
		"  zh-CN ": []any{"  修复闪动  "},
	})
	if code != "" {
		t.Fatalf("padded input must be accepted after trimming, got %s %s", code, detail)
	}
	if _, ok := notes["zh-CN"]; !ok {
		t.Fatalf("language code must be stored trimmed, got %v", notes)
	}
	if notes["zh-CN"][0] != "修复闪动" {
		t.Fatalf("lines must be stored trimmed, got %q", notes["zh-CN"][0])
	}
}

func TestNormalizeReleaseNotesAllowsAbsentNotes(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			notes, code, detail := normalizeReleaseNotes(raw)
			if code != "" {
				t.Errorf("absent notes must be accepted, got %s %s", code, detail)
			}
			if len(notes) != 0 {
				t.Errorf("absent notes must normalize to an empty map, got %v", notes)
			}
		})
	}
}

// 管理端读列表时要求"语言 -> 行数组"，写入侧必须挡住别的形状：
// 曾经有人用管理接口直接写进一个字符串，整份 OTA 列表因此校验失败。
func TestNormalizeReleaseNotesRejectsWrongShapes(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"string value":      {"zh-CN": "改用同形骨架"},
		"number value":      {"zh-CN": 1},
		"object value":      {"zh-CN": map[string]any{"line": "x"}},
		"null value":        {"zh-CN": nil},
		"non-string line":   {"zh-CN": []any{"ok", 2}},
		"blank line":        {"zh-CN": []any{"  "}},
		"empty array":       {"zh-CN": []any{}},
		"blank language":    {" ": []any{"ok"}},
		"trim-collided key": {"zh-CN": []any{"a"}, " zh-CN ": []any{"b"}},
	} {
		t.Run(name, func(t *testing.T) {
			notes, code, detail := normalizeReleaseNotes(raw)
			if code != "INVALID_RELEASE_NOTES" {
				t.Errorf("expected rejection, got code %q detail %q", code, detail)
			}
			if notes != nil {
				t.Errorf("rejected input must not yield notes, got %v", notes)
			}
		})
	}
}

// 请求的语言和 zh-CN 都没有时按语言码排序取第一个：map 迭代顺序是随机的，
// 同一份数据不能在不同请求里返回不同语言。
func TestReleaseNotesForLocaleFallsBackDeterministically(t *testing.T) {
	notes := map[string][]string{
		"ko-KR": {"ko"},
		"en-US": {"en"},
		"ja-JP": {"ja"},
	}
	for attempt := 0; attempt < 50; attempt++ {
		if got := releaseNotesForLocale(notes, "de-DE"); got[0] != "en" {
			t.Fatalf("fallback must take the first language code in sort order, got %v", got)
		}
	}
	if got := releaseNotesForLocale(notes, "ja-JP"); got[0] != "ja" {
		t.Fatalf("an exact locale match still wins, got %v", got)
	}
}
