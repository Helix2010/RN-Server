package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The generated files are copied from RN-App/i18n/seed by
// scripts/sync-rn-app-i18n-seed.mjs. They are the complete embedded UI copy,
// not a hand-maintained subset.
//
//go:embed i18n-seed/*.json
var rnAppLocalizationSeed embed.FS

type rnAppLocaleSeed struct {
	LanguageCode string            `json:"languageCode"`
	Version      string            `json:"version"`
	Messages     map[string]string `json:"messages"`
}

func readRNAppLocaleSeed(locale string) (rnAppLocaleSeed, error) {
	var seed rnAppLocaleSeed
	raw, err := rnAppLocalizationSeed.ReadFile("i18n-seed/" + locale + ".json")
	if err != nil {
		return seed, err
	}
	if err := json.Unmarshal(raw, &seed); err != nil {
		return seed, err
	}
	if seed.LanguageCode != locale || len(seed.Messages) == 0 {
		return seed, fmt.Errorf("invalid RN-App locale seed %s", locale)
	}
	return seed, nil
}

// currentRNAppLocalizationSeedMigration fills the global database catalogue
// with every UI key currently shipped by RN-App. Existing global copy and all
// tenant overrides are preserved; operations can continue editing them in
// RN-Admin without a migration overwriting their choices.
func currentRNAppLocalizationSeedMigration(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, locale := range []string{"zh-CN", "en-US"} {
		seed, err := readRNAppLocaleSeed(locale)
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(seed.Messages))
		for key := range seed.Messages {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			content := seed.Messages[key]
			if _, err := tx.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?,'RN-App UI seed',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE id=id`, locale, strings.ToLower(key), content); err != nil {
				return fmt.Errorf("seed RN-App localization %s/%s: %w", locale, key, err)
			}
		}
	}
	return tx.Commit()
}
