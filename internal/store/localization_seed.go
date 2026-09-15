package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
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

// currentRNAppLocalizationSeedMigration 让全局文案目录（tenant_id=0）跟 RN-App
// 当前发出去的种子保持一致：缺的键补上，改过的值跟着更新。
//
// 只碰全局行。租户覆盖（tenant_id>0）一律不动——管理端写文案时用的是
// tenantID(c)（internal/api/localization.go），租户 id 从 1 起，所以运营的改动
// 全都落在租户行里，全局行的唯一来源本来就是这份种子。以前这里只插不改，结果
// 代码里改过的值永远到不了库里：action.refresh 从「刷新配置」改成「刷新」之后，
// 全局行还是旧文案，没写租户覆盖的租户拿到的也还是旧文案。
//
// meta 保留原值不覆盖：早期的文案迁移给一批键写过人工描述（action.refresh 的
// meta 是「Refresh」），那是管理端列表里给人看的分类，种子里没有对应信息。
func currentRNAppLocalizationSeedMigration(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	inserted, updated := 0, 0
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
			// mtime 的赋值必须排在 content 前面：ON DUPLICATE KEY UPDATE 从左到右求值，
			// 放到后面读到的就是刚写进去的新值，条件永远不成立。
			result, err := tx.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?,'RN-App UI seed',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE mtime=IF(content<>VALUES(content),UTC_TIMESTAMP(3),mtime),content=VALUES(content)`, locale, strings.ToLower(key), content)
			if err != nil {
				return fmt.Errorf("seed RN-App localization %s/%s: %w", locale, key, err)
			}
			// 受影响行数：1=新插入，2=已有行的内容被改了，0=本来就一致
			switch affected, _ := result.RowsAffected(); affected {
			case 1:
				inserted++
			case 2:
				updated++
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if inserted > 0 || updated > 0 {
		slog.Info("RN-App localization seed applied", "insertedKeys", inserted, "updatedKeys", updated)
	}
	return nil
}
