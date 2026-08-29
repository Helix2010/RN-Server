package push

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Dispatcher struct {
	db         *sql.DB
	cfg        config.Config
	httpClient *http.Client
	apns       *apns2.Client
}

type event struct {
	ID, TenantID, Type string
	Payload            map[string]any
	Attempts           int
}

type target struct {
	InstallationID, Provider, Token, Environment string
}

func New(ctx context.Context, db *sql.DB, cfg config.Config) (*Dispatcher, error) {
	d := &Dispatcher{db: db, cfg: cfg, httpClient: &http.Client{Timeout: 15 * time.Second}}
	if cfg.FCMServiceAccountJSON != "" {
		raw := decodeSecret(cfg.FCMServiceAccountJSON)
		credentials, err := google.CredentialsFromJSON(ctx, raw, "https://www.googleapis.com/auth/firebase.messaging")
		if err != nil {
			return nil, fmt.Errorf("load FCM credentials: %w", err)
		}
		d.httpClient = &http.Client{Transport: &oauth2.Transport{Source: credentials.TokenSource}, Timeout: 15 * time.Second}
	}
	if cfg.APNsPrivateKey != "" {
		authKey, err := token.AuthKeyFromBytes(decodeSecret(cfg.APNsPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("load APNs key: %w", err)
		}
		client := apns2.NewTokenClient(&token.Token{AuthKey: authKey, KeyID: cfg.APNsKeyID, TeamID: cfg.APNsTeamID})
		if cfg.APNsEnvironment == "sandbox" {
			client = client.Development()
		} else {
			client = client.Production()
		}
		d.apns = client
	}
	return d, nil
}

func decodeSecret(value string) []byte {
	trimmed := strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded
	}
	return []byte(strings.ReplaceAll(trimmed, `\n`, "\n"))
}

func (d *Dispatcher) Run(ctx context.Context) {
	_, _ = d.db.ExecContext(ctx, `UPDATE app_push_outbox SET status='pending',locked_at=NULL,updated_at=? WHERE status='processing' AND locked_at<?`, time.Now().UTC(), time.Now().UTC().Add(-5*time.Minute))
	ticker := time.NewTicker(time.Duration(d.cfg.PushPollInterval) * time.Second)
	defer ticker.Stop()
	for {
		_ = d.dispatchNext(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Dispatcher) dispatchNext(ctx context.Context) error {
	var item event
	var raw []byte
	err := d.db.QueryRowContext(ctx, `SELECT id,CAST(tenant_id AS CHAR),event_type,payload,attempts FROM app_push_outbox WHERE status='pending' AND next_attempt_at<=? ORDER BY created_at LIMIT 1`, time.Now().UTC()).Scan(&item.ID, &item.TenantID, &item.Type, &raw, &item.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &item.Payload) != nil {
		return d.finish(ctx, item, 0, 1, "invalid payload")
	}
	result, err := d.db.ExecContext(ctx, `UPDATE app_push_outbox SET status='processing',locked_at=?,updated_at=? WHERE id=? AND status='pending'`, time.Now().UTC(), time.Now().UTC(), item.ID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil
	}
	targets, err := d.targets(ctx, item.TenantID)
	if err != nil {
		return d.retry(ctx, item, err.Error())
	}
	successes, failures := 0, 0
	for _, recipient := range targets {
		providerID, sendErr := d.send(ctx, item, recipient)
		status, failureCode := "sent", ""
		if sendErr != nil {
			failures++
			status, failureCode = "failed", sendErr.Error()
		} else {
			successes++
		}
		_, _ = d.db.ExecContext(ctx, `INSERT INTO app_push_deliveries(event_id,tenant_id,installation_id,provider,provider_message_id,status,failure_code,sent_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE provider_message_id=VALUES(provider_message_id),status=VALUES(status),failure_code=VALUES(failure_code),sent_at=VALUES(sent_at),updated_at=VALUES(updated_at)`, item.ID, item.TenantID, recipient.InstallationID, recipient.Provider, providerID, status, failureCode, time.Now().UTC(), time.Now().UTC(), time.Now().UTC())
	}
	if len(targets) == 0 {
		return d.finish(ctx, item, 0, 0, "")
	}
	if successes == 0 {
		return d.retry(ctx, item, "all provider deliveries failed")
	}
	return d.finish(ctx, item, successes, failures, "")
}

func (d *Dispatcher) targets(ctx context.Context, tenant string) ([]target, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT installation_id,provider,token,environment FROM app_push_tokens WHERE tenant_id=? AND invalid_at IS NULL AND permission_status IN ('granted','authorized','provisional')`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []target{}
	for rows.Next() {
		var item target
		if rows.Scan(&item.InstallationID, &item.Provider, &item.Token, &item.Environment) == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (d *Dispatcher) send(ctx context.Context, item event, recipient target) (string, error) {
	data := map[string]string{"eventId": item.ID, "type": item.Type, "requiresRefresh": "true"}
	for key, value := range item.Payload {
		data[key] = fmt.Sprint(value)
	}
	visible := item.Type == "app_update_available"
	data["requiresUserAction"] = fmt.Sprint(visible)
	if recipient.Provider == "fcm" {
		return d.sendFCM(ctx, recipient.Token, data, visible)
	}
	if recipient.Provider == "apns" {
		return d.sendAPNs(ctx, recipient.Token, data, visible)
	}
	return "", errors.New("push provider is not configured")
}

func (d *Dispatcher) sendFCM(ctx context.Context, targetToken string, data map[string]string, visible bool) (string, error) {
	if d.cfg.FCMProjectID == "" || d.cfg.FCMServiceAccountJSON == "" {
		return "", errors.New("FCM is not configured")
	}
	message := map[string]any{"token": targetToken, "data": data, "android": map[string]any{"priority": "high"}}
	if visible {
		message["notification"] = map[string]string{"title": "App update available", "body": "Open the app to review the latest version."}
	}
	body, _ := json.Marshal(map[string]any{"message": message})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://fcm.googleapis.com/v1/projects/"+d.cfg.FCMProjectID+"/messages:send", strings.NewReader(string(body)))
	request.Header.Set("content-type", "application/json")
	response, err := d.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("FCM status %d", response.StatusCode)
	}
	var result struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(response.Body).Decode(&result)
	return result.Name, nil
}

func (d *Dispatcher) sendAPNs(ctx context.Context, targetToken string, data map[string]string, visible bool) (string, error) {
	if d.apns == nil || d.cfg.APNsBundleID == "" {
		return "", errors.New("APNs is not configured")
	}
	aps := map[string]any{"content-available": 1}
	if visible {
		aps["alert"] = map[string]string{"title": "App update available", "body": "Open the app to review the latest version."}
		aps["sound"] = "default"
	}
	payload := map[string]any{"aps": aps}
	for key, value := range data {
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	response, err := d.apns.PushWithContext(ctx, &apns2.Notification{DeviceToken: targetToken, Topic: d.cfg.APNsBundleID, Payload: raw})
	if err != nil {
		return "", err
	}
	if !response.Sent() {
		return response.ApnsID, fmt.Errorf("APNs status %d %s", response.StatusCode, response.Reason)
	}
	return response.ApnsID, nil
}

func (d *Dispatcher) finish(ctx context.Context, item event, successes, failures int, reason string) error {
	_ = successes
	_ = reason
	status := "sent"
	if failures > 0 {
		status = "partial_failed"
	}
	_, err := d.db.ExecContext(ctx, `UPDATE app_push_outbox SET status=?,attempts=attempts+1,last_error=NULL,sent_at=?,updated_at=? WHERE id=?`, status, time.Now().UTC(), time.Now().UTC(), item.ID)
	return err
}

func (d *Dispatcher) retry(ctx context.Context, item event, reason string) error {
	attempts := item.Attempts + 1
	status := "pending"
	if attempts >= 5 {
		status = "failed"
	}
	next := time.Now().UTC().Add(time.Duration(attempts*attempts) * time.Minute)
	_, err := d.db.ExecContext(ctx, `UPDATE app_push_outbox SET status=?,attempts=?,last_error=?,next_attempt_at=?,locked_at=NULL,updated_at=? WHERE id=?`, status, attempts, reason[:minInt(len(reason), 500)], next, time.Now().UTC(), item.ID)
	return err
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
