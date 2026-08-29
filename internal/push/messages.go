package push

import (
	"context"
	"database/sql"
	"strings"
)

func localizedMessage(ctx context.Context, db *sql.DB, item event, locale string) (string, string) {
	titleKey, bodyKey := "update.noticeTitle", "update.noticeDescription"
	switch item.Type {
	case "ota_updated":
		titleKey, bodyKey = "update.otaTitle", "update.otaAvailable"
	case "localization_updated":
		titleKey, bodyKey = "update.localizationTitle", "update.localizationDescription"
	case "branding_updated":
		titleKey, bodyKey = "update.brandingTitle", "update.brandingDescription"
	case "bootstrap_updated":
		titleKey, bodyKey = "update.configTitle", "update.configDescription"
	}
	if strings.TrimSpace(locale) == "" {
		locale = "en-US"
	}
	return lookupMessage(ctx, db, item.TenantID, locale, titleKey, "Update available"), lookupMessage(ctx, db, item.TenantID, locale, bodyKey, "Open the app to review the latest update.")
}

func lookupMessage(ctx context.Context, db *sql.DB, tenant, locale, key, fallback string) string {
	var content string
	err := db.QueryRowContext(ctx, "SELECT content FROM language_document WHERE tenant_id IN (?,0) AND lang=? AND `key`=? AND type=14 AND deleted=0 ORDER BY tenant_id DESC LIMIT 1", tenant, locale, strings.ToLower(key)).Scan(&content)
	if err == nil && strings.TrimSpace(content) != "" {
		return content
	}
	if locale != "en-US" {
		_ = db.QueryRowContext(ctx, "SELECT content FROM language_document WHERE tenant_id IN (?,0) AND lang='en-US' AND `key`=? AND type=14 AND deleted=0 ORDER BY tenant_id DESC LIMIT 1", tenant, strings.ToLower(key)).Scan(&content)
		if strings.TrimSpace(content) != "" {
			return content
		}
	}
	return fallback
}
