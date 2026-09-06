package indexer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

// Notifier 告警通知：resolved=false 是新告警，true 是恢复。失败只记日志，不影响扫链。
type Notifier func(ctx context.Context, chain string, alert scan.Alert, resolved bool) error

// webhookTimeout 单次通知的上限；告警通道慢不能拖住扫链轮次。
const webhookTimeout = 5 * time.Second

// WebhookNotifier 把告警 POST 成 JSON：
//
//	{"text": "...", "chain": "...", "kind": "...", "message": "...", "raisedAt": "...", "resolved": false}
//
// 顶层 `text` 直接兼容 Slack / Discord 一类 incoming webhook；企业微信要求 msgtype 结构，
// 需要经一层中转（README 有说明）。
func WebhookNotifier(url string, client *http.Client) Notifier {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, chain string, alert scan.Alert, resolved bool) error {
		state := "ALERT"
		if resolved {
			state = "RESOLVED"
		}
		payload := map[string]any{
			"text":     fmt.Sprintf("[chain-scan][%s] %s %s: %s", state, chain, alert.Kind, alert.Message),
			"chain":    chain,
			"kind":     alert.Kind,
			"message":  alert.Message,
			"raisedAt": alert.RaisedAt.UTC().Format(time.RFC3339),
			"resolved": resolved,
		}
		body, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("webhook returned %d", response.StatusCode)
		}
		return nil
	}
}
