package store

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestRNAppLocalizationSeedHasMatchingLanguageKeys(t *testing.T) {
	raw, err := os.ReadFile("migrations.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func resetRNAppLocalizationMigration")
	end := strings.Index(source[start:], "func (s *Store) Migrate")
	if start < 0 || end < 0 {
		t.Fatal("reset migration function not found")
	}
	source = source[start : start+end]
	pattern := regexp.MustCompile(`\{"(zh-CN|en-US)", "([^"]+)"`)
	byLanguage := map[string][]string{"zh-CN": {}, "en-US": {}}
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		byLanguage[match[1]] = append(byLanguage[match[1]], match[2])
	}
	for code := range byLanguage {
		sort.Strings(byLanguage[code])
	}
	if len(byLanguage["zh-CN"]) < 60 {
		t.Fatalf("expected full RN-App seed, got %d zh-CN keys", len(byLanguage["zh-CN"]))
	}
	if len(byLanguage["zh-CN"]) != len(byLanguage["en-US"]) {
		t.Fatalf("language key counts differ: zh-CN=%d en-US=%d", len(byLanguage["zh-CN"]), len(byLanguage["en-US"]))
	}
	for index := range byLanguage["zh-CN"] {
		if byLanguage["zh-CN"][index] != byLanguage["en-US"][index] {
			t.Fatalf("language keys differ at %d: %s != %s", index, byLanguage["zh-CN"][index], byLanguage["en-US"][index])
		}
	}
}
