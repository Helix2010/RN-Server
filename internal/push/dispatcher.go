package push

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

type Dispatcher struct {
	db          *sql.DB
	cfg         config.Config
	secrets     *secretbox.Box
	plainClient *http.Client
	// senders 按**生效行**的租户缓存 FCM 客户端。键是生效行的 tenant_id 而不是
	// 事件的：四个租户都继承平台那一行时只有一个客户端、一个令牌源，而不是四份
	// 相同的。version 跟着 app_configs.version 走，换了密钥下一条事件就会重建,
	// 不需要重启进程，多实例也不需要互相广播。
	sendersMu sync.Mutex
	senders   map[string]*tenantSender
	// apnsClients 与 senders 同构：键是**生效行**的租户，version 跟着
	// app_configs.version 走，换了密钥下一条事件自然重建。
	// 2026-09-18 从全局一份改成按租户（设计 push-apns-and-shared-app-identity-2026-09-18 §2.6）。
	apnsMu      sync.Mutex
	apnsClients map[string]*apnsSender
	// hms 仍是全局的一份：没有租户在用。谁把它改成按租户，照 apns 这一套来。
	hmsMu     sync.Mutex
	hmsToken  string
	hmsExpiry time.Time
}

// apnsSender 是一个租户生效的 APNs 凭据在进程里的样子。
type apnsSender struct {
	version int
	client  *apns2.Client
}

// tenantSender 是一个租户生效的 FCM 凭据在进程里的样子。
type tenantSender struct {
	version   int
	projectID string
	client    *http.Client
}

// credentialError 是"在有人去改配置之前不会自愈"的那一类失败：项目不匹配、
// 密钥被吊销、根本没配。
//
// 它和别的失败要分开处理：重试解决的是瞬时故障，凭据错误重试五次只是把发现
// 问题的时间推迟半小时。事件直接判 failed，last_error 写一句能看懂的话——
// 那比五条 "FCM status 403" 有用得多。
type credentialError struct {
	code   string
	detail string
}

func (e credentialError) Error() string { return e.code + ": " + e.detail }

func asCredentialError(err error) (credentialError, bool) {
	var target credentialError
	ok := errors.As(err, &target)
	return target, ok
}

type event struct {
	ID, TenantID, Type string
	Payload            map[string]any
	Attempts           int
}

type target struct {
	InstallationID, PackageID, Provider, Token, Locale string
}

type message struct{ title, body string }

var errNoPendingEvents = errors.New("no pending push events")

type invalidTokenError struct{ cause error }

func (e invalidTokenError) Error() string { return e.cause.Error() }
func (e invalidTokenError) Unwrap() error { return e.cause }

func New(ctx context.Context, db *sql.DB, cfg config.Config, secrets *secretbox.Box) (*Dispatcher, error) {
	d := &Dispatcher{db: db, cfg: cfg, secrets: secrets,
		plainClient: &http.Client{Timeout: 15 * time.Second}, senders: map[string]*tenantSender{},
		apnsClients: map[string]*apnsSender{}}
	// 过渡期：库里一行凭据都没有时还认 env 里那两个键，但每次启动都说一次。
	// 下一版删掉 env 读取，所以这个状态不会永久化。
	if cfg.FCMServiceAccountJSON != "" {
		if configured, err := pushcreds.AnyConfigured(ctx, db); err == nil && !configured {
			slog.Warn("FCM credentials are still in the env file; run `rn-server push-credentials import-env` to move them into the database, then delete FCM_PROJECT_ID and FCM_SERVICE_ACCOUNT_JSON")
		}
	}
	// APNs 的 env 那份和 FCM 一样只当过渡期兜底，懒建（legacyAPNsSender）。
	// 这里只在启动时验一次形状：坏掉的 .p8 早说比第一条推送时才说好。
	if cfg.APNsPrivateKey != "" {
		if _, err := token.AuthKeyFromBytes(decodeSecret(cfg.APNsPrivateKey)); err != nil {
			return nil, fmt.Errorf("load APNs key: %w", err)
		}
		if configured, err := pushcreds.AnyAPNsConfigured(ctx, db); err == nil && !configured {
			slog.Warn("APNs credentials are still in the env file; run `rn-server push-credentials import-env` to move them into the database, then delete APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY and APNS_BUNDLE_ID")
		}
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
		d.dispatchBatch(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Dispatcher) dispatchBatch(ctx context.Context) {
	workers := d.cfg.PushConcurrency
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := d.dispatchNext(ctx); errors.Is(err, errNoPendingEvents) || err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
}

func (d *Dispatcher) dispatchNext(ctx context.Context) error {
	var item event
	var raw []byte
	err := d.db.QueryRowContext(ctx, `SELECT id,CAST(tenant_id AS CHAR),event_type,payload,attempts FROM app_push_outbox WHERE status='pending' AND next_attempt_at<=? ORDER BY created_at LIMIT 1`, time.Now().UTC()).Scan(&item.ID, &item.TenantID, &item.Type, &raw, &item.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return errNoPendingEvents
	}
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &item.Payload) != nil {
		return d.finish(ctx, item, 1)
	}
	result, err := d.db.ExecContext(ctx, `UPDATE app_push_outbox SET status='processing',locked_at=?,updated_at=? WHERE id=? AND status='pending'`, time.Now().UTC(), time.Now().UTC(), item.ID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil
	}
	targets, err := d.targets(ctx, item.TenantID, targetInstallations(item.Payload))
	if err != nil {
		return d.retry(ctx, item, err.Error())
	}
	// 凭据按事件解析一次：同一租户的所有收件人用同一个客户端、同一个令牌源。
	// 解析失败不在这里就退出——APNs / HMS 的收件人不该被 FCM 的配置问题拖下水。
	var fcm *tenantSender
	var fcmErr error
	for _, recipient := range targets {
		if recipient.Provider == "fcm" {
			fcm, fcmErr = d.fcmSender(ctx, item.TenantID)
			break
		}
	}

	successes, failures := 0, 0
	credentialFailure := ""
	jobs := make(chan target)
	messages := make(map[string]message)
	for _, recipient := range targets {
		if _, ok := messages[recipient.Locale]; !ok {
			title, body := localizedMessage(ctx, d.db, item, recipient.Locale)
			messages[recipient.Locale] = message{title: title, body: body}
		}
	}
	var deliveryWG sync.WaitGroup
	var resultMu sync.Mutex
	deliveryWorkers := d.cfg.PushConcurrency
	if deliveryWorkers > len(targets) {
		deliveryWorkers = len(targets)
	}
	for index := 0; index < deliveryWorkers; index++ {
		deliveryWG.Add(1)
		go func() {
			defer deliveryWG.Done()
			for recipient := range jobs {
				copy := messages[recipient.Locale]
				providerID, sendErr := d.sendWithMessage(ctx, item, fcm, fcmErr, recipient, copy.title, copy.body)
				status, failureCode := "sent", ""
				resultMu.Lock()
				if sendErr != nil {
					failures++
					status, failureCode = "failed", sendErr.Error()
					if problem, isCredential := asCredentialError(sendErr); isCredential && credentialFailure == "" {
						credentialFailure = problem.Error()
					}
				} else {
					successes++
				}
				resultMu.Unlock()
				if _, invalid := sendErr.(invalidTokenError); invalid {
					_, _ = d.db.ExecContext(ctx, `UPDATE app_push_tokens SET invalid_at=?,updated_at=? WHERE tenant_id=? AND installation_id=? AND provider=? AND token=?`, time.Now().UTC(), time.Now().UTC(), item.TenantID, recipient.InstallationID, recipient.Provider, recipient.Token)
				}
				_, _ = d.db.ExecContext(ctx, `INSERT INTO app_push_deliveries(event_id,tenant_id,installation_id,provider,provider_message_id,status,failure_code,sent_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE provider_message_id=VALUES(provider_message_id),status=VALUES(status),failure_code=VALUES(failure_code),sent_at=VALUES(sent_at),updated_at=VALUES(updated_at)`, item.ID, item.TenantID, recipient.InstallationID, recipient.Provider, providerID, status, failureCode, time.Now().UTC(), time.Now().UTC(), time.Now().UTC())
			}
		}()
	}
	for _, recipient := range targets {
		jobs <- recipient
	}
	close(jobs)
	deliveryWG.Wait()
	if len(targets) == 0 {
		return d.finish(ctx, item, 0)
	}
	if successes == 0 {
		// 凭据错误在有人改配置之前不会自愈：判 failed 并写清原因，不要把
		// 三十分钟的退避花在它身上。
		if credentialFailure != "" {
			return d.failNow(ctx, item, credentialFailure)
		}
		return d.retry(ctx, item, "all provider deliveries failed")
	}
	return d.finish(ctx, item, failures)
}

// targetInstallations 载荷里的 targetInstallationIds：非空表示只发给这些安装（钱包收款等
// 用户级事件），空表示租户全体（配置 / 发布类事件）。
func targetInstallations(payload map[string]any) []string {
	raw, _ := payload["targetInstallationIds"].([]any)
	ids := make([]string, 0, len(raw))
	for _, item := range raw {
		if id, ok := item.(string); ok && strings.TrimSpace(id) != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (d *Dispatcher) targets(ctx context.Context, tenant string, only []string) ([]target, error) {
	query := `SELECT p.installation_id,i.package_id,p.provider,p.token,COALESCE(i.locale,'') FROM app_push_tokens p JOIN app_installations i ON i.tenant_id=p.tenant_id AND i.installation_id=p.installation_id WHERE p.tenant_id=? AND p.invalid_at IS NULL AND i.status='active' AND p.permission_status IN ('granted','authorized','provisional')`
	args := []any{tenant}
	if len(only) > 0 {
		query += ` AND p.installation_id IN (?` + strings.Repeat(",?", len(only)-1) + `)`
		for _, id := range only {
			args = append(args, id)
		}
	}
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []target{}
	for rows.Next() {
		var item target
		if rows.Scan(&item.InstallationID, &item.PackageID, &item.Provider, &item.Token, &item.Locale) == nil {
			items = append(items, item)
		}
	}
	return items, rows.Err()
}

func (d *Dispatcher) sendWithMessage(ctx context.Context, item event, fcm *tenantSender, fcmErr error, recipient target, title, body string) (string, error) {
	data := map[string]string{"eventId": item.ID, "type": item.Type, "requiresRefresh": "true"}
	for key, value := range item.Payload {
		if key == "targetInstallationIds" {
			// 投递范围是服务端的事，不下发到设备
			continue
		}
		data[key] = fmt.Sprint(value)
	}
	visible := item.Type == "app_update_available" || item.Type == eventTransferReceived
	data["requiresUserAction"] = fmt.Sprint(visible)
	if recipient.Provider == "fcm" {
		if fcmErr != nil {
			return "", fcmErr
		}
		return d.sendFCM(ctx, fcm, recipient.Token, data, title, body, visible)
	}
	if recipient.Provider == "apns" {
		return d.sendAPNs(ctx, item.TenantID, recipient.Token, recipient.PackageID, data, title, body, visible)
	}
	if recipient.Provider == "hms" {
		return d.sendHMS(ctx, recipient.Token, data, title, body, visible)
	}
	return "", errors.New("push provider is not configured")
}

// fcmSender 取这个租户生效的 FCM 客户端。
//
// 每条事件查一次 app_configs（走主键索引），拿生效行的身份和版本；命中缓存且
// 版本没变就直接用，否则解密重建。这一次查询换来的是：换密钥不用重启进程，
// 多实例部署下各实例最迟在下一条事件时看到新密钥。
func (d *Dispatcher) fcmSender(ctx context.Context, tenant string) (*tenantSender, error) {
	record, err := pushcreds.LoadFCM(ctx, d.db, tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return d.legacyEnvSender(ctx)
	}
	if err != nil {
		return nil, err
	}
	if record.Value.ServiceAccountEncrypted == "" {
		return nil, credentialError{"FCM_NOT_CONFIGURED",
			"租户 " + record.SourceTenant + " 的 push.fcm 里没有服务账号"}
	}
	d.sendersMu.Lock()
	cached, ok := d.senders[record.SourceTenant]
	d.sendersMu.Unlock()
	if ok && cached.version == record.Version {
		return cached, nil
	}
	account, err := record.ServiceAccount(d.secrets)
	if err != nil {
		return nil, credentialError{"FCM_CREDENTIAL_UNREADABLE", err.Error()}
	}
	client, err := pushcreds.NewHTTPClient(ctx, account)
	if err != nil {
		return nil, credentialError{"FCM_CREDENTIAL_UNREADABLE", err.Error()}
	}
	sender := &tenantSender{version: record.Version, projectID: account.ProjectID, client: client}
	d.sendersMu.Lock()
	d.senders[record.SourceTenant] = sender
	d.sendersMu.Unlock()
	return sender, nil
}

// legacyEnvSender 是过渡期的兜底：库里一行都没有、而 env 里还留着那两个键。
// 下一版删掉，见 New 里的那条警告。
func (d *Dispatcher) legacyEnvSender(ctx context.Context) (*tenantSender, error) {
	if d.cfg.FCMServiceAccountJSON == "" || d.cfg.FCMProjectID == "" {
		return nil, credentialError{"FCM_NOT_CONFIGURED",
			"这个租户没有 FCM 凭据，平台默认（tenant 0）也没有；到管理端配一份"}
	}
	const key = "env"
	d.sendersMu.Lock()
	cached, ok := d.senders[key]
	d.sendersMu.Unlock()
	if ok {
		return cached, nil
	}
	account, err := pushcreds.ParseServiceAccount(decodeSecret(d.cfg.FCMServiceAccountJSON))
	if err != nil {
		return nil, credentialError{"FCM_CREDENTIAL_UNREADABLE", "FCM_SERVICE_ACCOUNT_JSON 解析失败：" + err.Error()}
	}
	client, err := pushcreds.NewHTTPClient(ctx, account)
	if err != nil {
		return nil, credentialError{"FCM_CREDENTIAL_UNREADABLE", err.Error()}
	}
	sender := &tenantSender{version: 0, projectID: d.cfg.FCMProjectID, client: client}
	d.sendersMu.Lock()
	d.senders[key] = sender
	d.sendersMu.Unlock()
	return sender, nil
}

func (d *Dispatcher) sendFCM(ctx context.Context, sender *tenantSender, targetToken string, data map[string]string, title, messageBody string, visible bool) (string, error) {
	message := map[string]any{"token": targetToken, "data": data, "android": map[string]any{"priority": "high"}}
	if visible {
		message["notification"] = map[string]string{"title": title, "body": messageBody}
	}
	body, _ := json.Marshal(map[string]any{"message": message})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://fcm.googleapis.com/v1/projects/"+sender.projectID+"/messages:send", strings.NewReader(string(body)))
	request.Header.Set("content-type", "application/json")
	response, err := sender.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusNotFound || strings.Contains(string(responseBody), "UNREGISTERED") || strings.Contains(string(responseBody), "registration-token-not-registered") {
			return "", invalidTokenError{fmt.Errorf("FCM token is invalid")}
		}
		// SENDER_ID_MISMATCH：token 属于另一个 Firebase 项目。**绝不**把 token 标
		// 作废——token 是好的，错的是凭据；作废它等于让那台设备永久收不到推送，
		// 而且要等它重新注册才恢复。
		if strings.Contains(string(responseBody), "SENDER_ID_MISMATCH") {
			return "", credentialError{"FCM_PROJECT_MISMATCH",
				"这个 token 属于别的 Firebase 项目，服务端凭据是项目 " + sender.projectID +
					"；检查该租户的 google-services.json 与推送凭据是不是同一个项目"}
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return "", credentialError{"FCM_CREDENTIAL_REJECTED",
				fmt.Sprintf("Google 回 %d：密钥可能已被吊销或权限被收回（项目 %s）", response.StatusCode, sender.projectID)}
		}
		return "", fmt.Errorf("FCM status %d", response.StatusCode)
	}
	var result struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(responseBody, &result)
	return result.Name, nil
}

func (d *Dispatcher) sendAPNs(ctx context.Context, tenant, targetToken, packageID string, data map[string]string, title, messageBody string, visible bool) (string, error) {
	// topic 主取设备自报的 bundle id——它就是这台设备上装的那个 App。旧版本没
	// 上报时才回落到该租户 release.ios 的 bundleId（2026-09-18 之前这里是 env
	// 里全局的一份，多租户下必然发错 topic）。
	topic := packageID
	if topic == "" {
		topic = d.tenantBundleID(ctx, tenant)
	}
	if topic == "" {
		return "", credentialError{"IOS_BUNDLE_ID_REQUIRED",
			"这台设备没上报 bundle id，租户 " + tenant + " 的 release.ios 里也没有"}
	}
	client, err := d.apnsSender(ctx, tenant)
	if err != nil {
		return "", err
	}
	aps := map[string]any{"content-available": 1}
	if visible {
		aps["alert"] = map[string]string{"title": title, "body": messageBody}
		aps["sound"] = "default"
	}
	payload := map[string]any{"aps": aps}
	for key, value := range data {
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	response, err := client.PushWithContext(ctx, &apns2.Notification{DeviceToken: targetToken, Topic: topic, Payload: raw})
	if err != nil {
		return "", err
	}
	return response.ApnsID, apnsResponseError(response, topic)
}

// apnsResponseError 把 APNs 的一次回应分成三类，处理方式与 FCM 的三类一致（sendFCM）：
//
//   - token 失效：作废它；
//   - 凭据或配置错误（Key 无效或被吊销、Team ID / Key ID 填错、这把 Key 不能发这个 topic）：
//     在有人改配置之前不会自愈，事件直接判 failed、写清原因，不要把三十分钟花在五次重试上；
//   - 其它（限流、Apple 故障、令牌刚过期）：留给重试。
func apnsResponseError(response *apns2.Response, topic string) error {
	if response.Sent() {
		return nil
	}
	switch response.Reason {
	case apns2.ReasonBadDeviceToken, apns2.ReasonUnregistered, apns2.ReasonDeviceTokenNotForTopic:
		return invalidTokenError{fmt.Errorf("APNs token is invalid: %s", response.Reason)}
	case apns2.ReasonInvalidProviderToken, apns2.ReasonMissingProviderToken:
		return credentialError{"APNS_CREDENTIAL_REJECTED",
			fmt.Sprintf("Apple 回 %d %s：APNs Key 无效或已吊销，或者 Team ID / Key ID 填错", response.StatusCode, response.Reason)}
	case apns2.ReasonTopicDisallowed:
		return credentialError{"APNS_TOPIC_DISALLOWED",
			"Apple 不让这把 APNs Key 发 bundle id " + topic + "：Key 不属于这个 App 所在的 Team，或者被限定到了别的 App"}
	}
	return fmt.Errorf("APNs status %d %s", response.StatusCode, response.Reason)
}

func (d *Dispatcher) finish(ctx context.Context, item event, failures int) error {
	status := "sent"
	if failures > 0 {
		status = "partial_failed"
	}
	_, err := d.db.ExecContext(ctx, `UPDATE app_push_outbox SET status=?,attempts=attempts+1,last_error=NULL,sent_at=?,updated_at=? WHERE id=?`, status, time.Now().UTC(), time.Now().UTC(), item.ID)
	return err
}

// failNow 不重试，直接判 failed。给凭据类失败用。
func (d *Dispatcher) failNow(ctx context.Context, item event, reason string) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE app_push_outbox SET status='failed',attempts=attempts+1,last_error=?,locked_at=NULL,updated_at=? WHERE id=?`,
		reason[:minInt(len(reason), 500)], time.Now().UTC(), item.ID)
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
