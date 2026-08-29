package push

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (d *Dispatcher) sendHMS(ctx context.Context, targetToken string, data map[string]string, title, messageBody string, visible bool) (string, error) {
	if d.cfg.HMSAppID == "" || d.cfg.HMSClientID == "" || d.cfg.HMSClientSecret == "" {
		return "", fmt.Errorf("HMS is not configured")
	}
	accessToken, err := d.hmsAccessToken(ctx)
	if err != nil {
		return "", err
	}
	body := map[string]any{"validate_only": false, "message": map[string]any{"data": mustJSON(data), "token": []string{targetToken}}}
	if visible {
		body["message"].(map[string]any)["notification"] = map[string]string{"title": title, "body": messageBody}
	}
	raw, _ := json.Marshal(body)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://push-api.cloud.huawei.com/v1/"+d.cfg.HMSAppID+"/messages:send", strings.NewReader(string(raw)))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("authorization", "Bearer "+accessToken)
	response, err := d.plainClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("HMS status %d", response.StatusCode)
	}
	return "hms", nil
}

func (d *Dispatcher) hmsAccessToken(ctx context.Context) (string, error) {
	d.hmsMu.Lock()
	defer d.hmsMu.Unlock()
	if d.hmsToken != "" && d.hmsExpiry.After(time.Now().UTC().Add(30*time.Second)) {
		return d.hmsToken, nil
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth-login.cloud.huawei.com/oauth2/v3/token", strings.NewReader("grant_type=client_credentials&client_id="+url.QueryEscape(d.cfg.HMSClientID)+"&client_secret="+url.QueryEscape(d.cfg.HMSClientSecret)))
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	response, err := d.plainClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("HMS OAuth status %d", response.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.AccessToken == "" {
		return "", fmt.Errorf("HMS OAuth response invalid")
	}
	d.hmsToken, d.hmsExpiry = body.AccessToken, time.Now().UTC().Add(time.Duration(body.ExpiresIn)*time.Second)
	return d.hmsToken, nil
}

func mustJSON(value map[string]string) string { raw, _ := json.Marshal(value); return string(raw) }
