package push

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
)

// eventTransferReceived 钱包收到链上入账（扫链索引写入 in 行时入队，定向到该地址的会话所在安装）。
const eventTransferReceived = "wallet.transfer.received"

func localizedMessage(ctx context.Context, db *sql.DB, item event, locale string) (string, string) {
	if strings.TrimSpace(locale) == "" {
		locale = "en-US"
	}
	if item.Type == eventTransferReceived {
		bodyKey, fallback := "wallet.receivedBody", "Received {amount} {symbol} on {chain}."
		if fmt.Sprint(item.Payload["attribution"]) == "unattributed" {
			bodyKey, fallback = "wallet.receivedUnattributedBody", "Received {amount} {symbol} on {chain} (source pending)."
		}
		values := transferPlaceholders(item.Payload)
		return fillPlaceholders(lookupMessage(ctx, db, item.TenantID, locale, "wallet.receivedTitle", "Funds received"), values),
			fillPlaceholders(lookupMessage(ctx, db, item.TenantID, locale, bodyKey, fallback), values)
	}
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
	return lookupMessage(ctx, db, item.TenantID, locale, titleKey, "Update available"), lookupMessage(ctx, db, item.TenantID, locale, bodyKey, "Open the app to review the latest update.")
}

// transferPlaceholders 收款文案的占位符：amount 按目录 displayDecimals 截断显示（不四舍五入），
// symbol / chain 原样。
func transferPlaceholders(payload map[string]any) map[string]string {
	decimals, _ := toInt(payload["decimals"])
	display, ok := toInt(payload["displayDecimals"])
	if !ok {
		display = decimals
	}
	return map[string]string{
		"amount": formatAmount(fmt.Sprint(payload["amountRaw"]), decimals, display),
		"symbol": fmt.Sprint(payload["symbol"]),
		"chain":  fmt.Sprint(payload["chainName"]),
	}
}

func toInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	}
	return 0, false
}

// formatAmount 最小单位整数 → 十进制文本，保留 display 位小数（向下截断），去掉尾零。
func formatAmount(raw string, decimals, display int) string {
	value, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
	if !ok || decimals < 0 {
		return raw
	}
	if display > decimals {
		display = decimals
	}
	if display < 0 {
		display = 0
	}
	digits := value.String()
	if len(digits) <= decimals {
		digits = strings.Repeat("0", decimals-len(digits)+1) + digits
	}
	whole, frac := digits[:len(digits)-decimals], digits[len(digits)-decimals:]
	frac = strings.TrimRight(frac[:display], "0")
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

func fillPlaceholders(template string, values map[string]string) string {
	for key, value := range values {
		template = strings.ReplaceAll(template, "{"+key+"}", value)
	}
	return template
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
