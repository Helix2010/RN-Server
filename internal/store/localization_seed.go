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
//
// 先一次读出全局行、在这里比对，只把缺的和变了的成批写回去。原来逐键 upsert 2488 行，每行一个到
// 远端库的往返，每次部署的迁移要 11–16 秒，而且这段时间服务是停着的（rn-foundation-apply 先停服务
// 再跑迁移）；种子没变的时候现在只有一条查询。写回用的仍是原来那条语句，「内容变了才动 mtime」
// 由库按列的排序规则判断，与逐条写时一致——这里的比对只决定哪些行值得发过去。
func currentRNAppLocalizationSeedMigration(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	locales := []string{"zh-CN", "en-US"}
	existing, err := globalSeedRows(ctx, tx, locales)
	if err != nil {
		return err
	}
	var pending []seedRow
	inserted, updated := 0, 0
	for _, locale := range locales {
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
			row := seedRow{lang: locale, key: strings.ToLower(key), content: seed.Messages[key]}
			current, found := existing[seedRowID(row.lang, row.key)]
			if found && current == row.content {
				continue
			}
			if found {
				updated++
			} else {
				inserted++
			}
			pending = append(pending, row)
		}
	}
	for start := 0; start < len(pending); start += seedBatchSize {
		if err := upsertSeedRows(ctx, tx, pending[start:min(start+seedBatchSize, len(pending))]); err != nil {
			return err
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

// 一条语句带多少行：每行 3 个占位符，200 行远低于占位符与包大小的上限
const seedBatchSize = 200

type seedRow struct{ lang, key, content string }

// seedRowID 按唯一键（lang, key, type=14, tenant_id=0）里会变的两列认行。两列都转小写：列的排序规则
// 不分大小写，库里认成同一行的，这里也要认成同一行
func seedRowID(lang, key string) string {
	return strings.ToLower(lang) + "\x00" + strings.ToLower(key)
}

// globalSeedRows 读出种子管的全局行（含软删除的：upsert 本来就不看 deleted）
func globalSeedRows(ctx context.Context, tx *sql.Tx, locales []string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT lang,`key`,content FROM language_document WHERE tenant_id=0 AND type=14 AND lang IN (?,?)", locales[0], locales[1])
	if err != nil {
		return nil, fmt.Errorf("read global localization rows: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var lang, key, content string
		if err := rows.Scan(&lang, &key, &content); err != nil {
			return nil, err
		}
		out[seedRowID(lang, key)] = content
	}
	return out, rows.Err()
}

// upsertSeedRows 一条语句写一批。mtime 的赋值必须排在 content 前面：ON DUPLICATE KEY UPDATE 从左到右
// 求值，放到后面读到的就是刚写进去的新值，条件永远不成立
func upsertSeedRows(ctx context.Context, tx *sql.Tx, batch []seedRow) error {
	values := make([]string, len(batch))
	args := make([]any, 0, len(batch)*3)
	for i, row := range batch {
		values[i] = "(?,?,?,'RN-App UI seed',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0)"
		args = append(args, row.lang, row.key, row.content)
	}
	query := "INSERT INTO language_document(lang,`key`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES " +
		strings.Join(values, ",") +
		" ON DUPLICATE KEY UPDATE mtime=IF(content<>VALUES(content),UTC_TIMESTAMP(3),mtime),content=VALUES(content)"
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("seed RN-App localization (%d rows from %s/%s): %w", len(batch), batch[0].lang, batch[0].key, err)
	}
	return nil
}
