package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

type claimedJob struct {
	ID         string `json:"id"`
	TenantSlug string `json:"tenantSlug"`
	// TenantDirectory 是仓库里 tenants/ 下的目录名。它与 TenantSlug 是两套命名，
	// 代理只用这一个去拼路径。
	TenantDirectory string `json:"tenantDirectory"`
	Platform        string `json:"platform"`
	// Kind 是 "apk" 或 "ota"。热更新任务不带签名密钥——它不需要，也就不该拿到。
	Kind          string `json:"kind"`
	BaseReleaseID string `json:"baseReleaseId"`
	Channel       string `json:"channel"`
	ApplyStrategy string `json:"applyStrategy"`
	// RuntimeVersion 是基线安装包的 runtime：热更新包必须对准它，否则一台设备都收不到。
	RuntimeVersion       string `json:"runtimeVersion"`
	GitRef               string `json:"gitRef"`
	Version              string `json:"version"`
	BuildNumber          int    `json:"buildNumber"`
	OTACertificatePEM    string `json:"otaCertificatePem"`
	OTACertificateSHA256 string `json:"otaCertificateSha256"`
	// SealedKeystore 是运维用自己的口令封的盒子，服务端只是转交，打不开它。
	SealedKeystore *buildkeystore.Sealed `json:"sealedKeystore"`
	KeyAlias       string                `json:"keyAlias"`
	// GoogleServicesJSON 不是机密（它原样编进每个 APK），但按租户不同，所以也随
	// 任务下发——这样新加一台打包机仍然只需要一个封装口令。
	GoogleServicesJSON string `json:"googleServicesJson"`
	// Icons 是这个租户要用的启动图标**文件名**。内容不在这里——一张 2048 见方的
	// PNG 将近 1MB，四张塞进这条响应会顶爆读取上限（见 downloadIcon）
	Icons []string `json:"icons"`
	// TenantFile 是服务端合成的 tenants/<目录>/tenant.json。它取代了仓库里那份
	// 提交上去的文件——开一个新租户不该需要改代码。代理仍然校验字段（tenantfile.go）。
	TenantFile json.RawMessage `json:"tenantFile"`
}

// APIBaseURL / ApplicationID 从服务端合成的身份文件里取。代理不自己拼这些值：
// 它们决定设备此后跟谁说话，唯一来源是服务端。
func (j claimedJob) APIBaseURL() string    { return j.tenantField("apiBaseUrl") }
func (j claimedJob) ApplicationID() string { return j.tenantField("applicationId") }

func (j claimedJob) tenantField(name string) string {
	var fields map[string]any
	if json.Unmarshal(j.TenantFile, &fields) != nil {
		return ""
	}
	value, _ := fields[name].(string)
	return value
}

type client struct {
	cfg  config
	http *http.Client
}

func newClient(cfg config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *client) post(ctx context.Context, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Server+path, reader)
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-build-agent-token", c.cfg.Token)
	response, err := c.http.Do(request)
	if err != nil {
		return 0, retryLater{err}
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		// 错误正文里不会有机密，但也不需要原样带出去——只留状态码和一小段
		return response.StatusCode, classify(response.StatusCode,
			fmt.Errorf("%s returned %d: %s", path, response.StatusCode, truncate(string(payload), 300)))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			// 半截正文多半是链路上出的事（反代截断、连接断在中途），下一次多半就好了
			return response.StatusCode, retryLater{fmt.Errorf("%s returned a body we cannot read: %w", path, err)}
		}
	}
	return response.StatusCode, nil
}

// classify 决定一个 HTTP 失败要不要再试：5xx 和 429 是"现在不行"，4xx 是"不行"。
func classify(status int, err error) error {
	if status >= 500 || status == http.StatusTooManyRequests {
		return retryLater{err}
	}
	return err
}

// get 和 post 走同一套鉴权与错误处理，只是没有请求体。
func (c *client) get(ctx context.Context, path string, out any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Server+path, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("x-build-agent-token", c.cfg.Token)
	response, err := c.http.Do(request)
	if err != nil {
		return 0, retryLater{err}
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return response.StatusCode, classify(response.StatusCode,
			fmt.Errorf("%s returned %d: %s", path, response.StatusCode, truncate(string(payload), 300)))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return response.StatusCode, retryLater{fmt.Errorf("%s returned a body we cannot read: %w", path, err)}
		}
	}
	return response.StatusCode, nil
}

// claim 返回 (任务, 有没有任务, 错误)。队列空时服务端给 204。
func (c *client) claim(ctx context.Context) (claimedJob, bool, error) {
	var job claimedJob
	status, err := c.post(ctx, "/v1/build-agent/claim", map[string]any{
		"agent": c.cfg.Name, "platforms": c.cfg.Platforms,
	}, &job)
	if err != nil {
		return job, false, err
	}
	if status == http.StatusNoContent || job.ID == "" {
		return job, false, nil
	}
	return job, true, nil
}

func (c *client) heartbeat(ctx context.Context, id string, logTail []string) error {
	_, err := c.post(ctx, "/v1/build-agent/jobs/"+id+"/heartbeat", map[string]any{"logTail": logTail}, nil)
	return err
}

func (c *client) complete(ctx context.Context, id, commit, digest, releaseID string, logTail []string) error {
	_, err := c.post(ctx, "/v1/build-agent/jobs/"+id+"/complete", map[string]any{
		"commitSha": commit, "artifactSha256": digest, "releaseId": releaseID, "logTail": logTail,
	}, nil)
	return err
}

func (c *client) fail(ctx context.Context, id, reason, commit string, logTail []string) error {
	_, err := c.post(ctx, "/v1/build-agent/jobs/"+id+"/fail", map[string]any{
		"failureReason": reason, "commitSha": commit, "logTail": logTail,
	}, nil)
	return err
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "…"
}

type uploadTicket struct {
	Artifact struct {
		Token string `json:"token"`
	} `json:"artifact"`
	Upload struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	} `json:"upload"`
}

// uploadArtifact 把产物和它的 SBOM 传回服务端，返回落成的发布记录 id。
//
// 走的是与人工上传**完全相同**的入库路径——APK 身份解析、ETag 固定、签名指纹
// 比对都在服务端那一侧，代理不复制其中任何一条。
//
// SBOM 必须在建发布记录**之前**传完：那条记录上要写它的对象键，不然产物入了库而
// 清单没有归属，等于回到"扫过但没人知道扫的是哪个包"。
// 三步各自重试，而不是整段重来：包已经传上去了却卡在建记录那一步时，重来一遍要把
// 几十兆再传一次，还会在对象存储里多留一份没人引用的副本。
//
// 仍然可能多留一份：PUT 落了地而响应丢在回来的路上，重试就是第二次上传。这一侧无
// 解——票据是一次性的，服务端也没法凭空知道那次传成没传成——只是把窗口收到最小。
func (c *client) uploadArtifact(ctx context.Context, jobID, path, sbomPath, fingerprint string, buf *logBuffer) (string, error) {
	artifactToken := ""
	err := withRetry(ctx, buf, "artifact upload", 6, func(ctx context.Context) error {
		token, err := c.putFile(ctx, jobID, path, "application/vnd.android.package-archive")
		artifactToken = token
		return err
	})
	if err != nil {
		return "", err
	}
	sbomToken := ""
	if sbomPath != "" {
		err := withRetry(ctx, buf, "SBOM upload", 6, func(ctx context.Context) error {
			token, err := c.putFile(ctx, jobID, sbomPath, "application/vnd.cyclonedx+json")
			sbomToken = token
			return err
		})
		if err != nil {
			return "", fmt.Errorf("the SBOM could not be uploaded: %w", err)
		}
	}
	// 只送 token：平台、版本、build 号和发布说明都取任务行上的值，代理没有理由
	// 知道该写什么
	var release struct {
		Release struct {
			ID string `json:"id"`
		} `json:"release"`
	}
	if err := withRetry(ctx, buf, "release creation", 6, func(ctx context.Context) error {
		_, err := c.post(ctx, "/v1/build-agent/jobs/"+jobID+"/release", map[string]any{
			"artifactToken":     artifactToken,
			"sbomToken":         sbomToken,
			"nativeFingerprint": fingerprint,
		}, &release)
		return err
	}); err != nil {
		return "", err
	}
	if release.Release.ID == "" {
		return "", errors.New("the server created a release but did not say which one")
	}
	return release.Release.ID, nil
}

// putFile 领一张上传票据把一个文件传上去，返回可以用来建发布记录的 artifact token。
func (c *client) putFile(ctx context.Context, jobID, path, contentType string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	var ticket uploadTicket
	if _, err := c.post(ctx, "/v1/build-agent/jobs/"+jobID+"/artifact-uploads", map[string]any{
		"fileName": filepath.Base(path), "contentType": contentType, "size": info.Size(),
	}, &ticket); err != nil {
		return "", err
	}
	if err := c.putTo(ctx, ticket, path); err != nil {
		return "", err
	}
	return ticket.Artifact.Token, nil
}

// putTo 按票据把一个文件 PUT 上去。内容类型跟着票据走（服务端在 headers 里给了），
// 这里不再自己拼。票据和 PUT 分开是因为热更新那条链路重试时要连票据一起重领——
// 票据是一次性的。
func (c *client) putTo(ctx context.Context, ticket uploadTicket, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, ticket.Upload.URL, file)
	if err != nil {
		return err
	}
	request.ContentLength = info.Size()
	// GetBody 让传输层在需要重试时能把请求体从头再读一遍。没有它，一次 h2 流错误
	// 就直接失败在 "cannot retry ... after Request.Body was written"——2026-09-11
	// 第一次真实回传就是这么挂的，包已经构建出来了却传不上去。
	request.GetBody = func() (io.ReadCloser, error) { return os.Open(path) }
	for key, value := range ticket.Upload.Headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("x-build-agent-token", c.cfg.Token)
	// 传一个几十上百兆的包，30 秒的默认超时肯定不够。
	// 强制 HTTP/1.1：几十兆的 PUT 经过反代链路时 h2 的流错误比 1.1 常见得多，
	// 而这条路径没有任何需要多路复用的理由。
	uploader := &http.Client{
		Timeout:   30 * time.Minute,
		Transport: &http.Transport{ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
	}
	response, err := uploader.Do(request)
	if err != nil {
		return retryLater{err}
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return classify(response.StatusCode,
			fmt.Errorf("upload of %s returned %d: %s", filepath.Base(path), response.StatusCode, truncate(string(payload), 300)))
	}
	return nil
}

type pendingKeystoreCheck struct {
	Tenant         string          `json:"tenant"`
	Version        int             `json:"version"`
	SealedKeystore json.RawMessage `json:"sealedKeystore"`
}

func (c *client) pendingKeystoreChecks(ctx context.Context) ([]pendingKeystoreCheck, error) {
	var out struct {
		Items []pendingKeystoreCheck `json:"items"`
	}
	if _, err := c.get(ctx, "/v1/build-agent/keystore-checks", &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *client) reportKeystoreCheck(ctx context.Context, tenant string, version int, ok bool, reason, agent string) error {
	_, err := c.post(ctx, "/v1/build-agent/keystore-checks", map[string]any{
		"tenant": tenant, "version": version, "ok": ok, "error": reason, "agent": agent,
	}, nil)
	return err
}

func (c *client) registerPublicKey(ctx context.Context, publicKey, agent string) (string, error) {
	var out struct {
		Status             string `json:"status"`
		Fingerprint        string `json:"fingerprint"`
		CurrentFingerprint string `json:"currentFingerprint"`
	}
	if _, err := c.post(ctx, "/v1/build-agent/public-key", map[string]any{
		"publicKey": publicKey, "agent": agent,
	}, &out); err != nil {
		return "", err
	}
	return out.Status, nil
}

// downloadIcon 取一张图标，直接写进 worktree，不经过内存里的字符串。
//
// 图标原来是 base64 塞在领取任务的响应里的，而那条响应有 1 MiB 的读取上限。
// 2026-09-13 真图标传上来之后响应被截断成半截 JSON，代理解不开就把整条任务丢了，
// 而服务端那边已经标成 claimed——任务从此卡死。
func (c *client) downloadIcon(ctx context.Context, jobID, name, target string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.cfg.Server+"/v1/build-agent/jobs/"+jobID+"/icons/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	request.Header.Set("x-build-agent-token", c.cfg.Token)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("icon %s returned %d: %s", name, response.StatusCode, truncate(string(payload), 200))
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	// 一张图上限 6MB（服务端那一侧的校验），留一倍余量挡住坏掉的响应
	if _, err := io.Copy(file, io.LimitReader(response.Body, 12<<20)); err != nil {
		return err
	}
	return nil
}

// uploadOTAPackage 把热更新包传回服务端，返回落成的修订 id。
//
// base、channel、生效方式和发布说明都取任务行上的值——代理只送它确实知道的东西
// （包本身和这次构建的提交）。和 APK 那条同一个原则。
func (c *client) uploadOTAPackage(ctx context.Context, jobID, path, commit string, buf *logBuffer) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	token := ""
	if err := withRetry(ctx, buf, "OTA upload ticket", 6, func(ctx context.Context) error {
		var ticket uploadTicket
		if _, err := c.post(ctx, "/v1/build-agent/jobs/"+jobID+"/ota-uploads", map[string]any{
			"fileName": filepath.Base(path), "size": info.Size(),
		}, &ticket); err != nil {
			return err
		}
		token = ticket.Artifact.Token
		return c.putTo(ctx, ticket, path)
	}); err != nil {
		return "", err
	}
	var created struct {
		Release struct {
			ID string `json:"id"`
		} `json:"release"`
	}
	if err := withRetry(ctx, buf, "OTA revision", 6, func(ctx context.Context) error {
		_, err := c.post(ctx, "/v1/build-agent/jobs/"+jobID+"/ota-release", map[string]any{
			"artifactToken": token, "sourceCommitSha": commit,
		}, &created)
		return err
	}); err != nil {
		return "", err
	}
	if created.Release.ID == "" {
		return "", errors.New("the server created an OTA revision but did not say which one")
	}
	return created.Release.ID, nil
}

// ---- 备份（设计 platform-backup-recovery-2026-09-15 §8.1）----

// pendingBackup 认领一条备份待办。没有待办返回 (_, false, nil)。
//
// 用 POST 不是 GET：它会改状态，而服务端把 GET 当安全方法——Origin 闸对它完全
// 不生效，何况任何 HTTP 客户端和代理都会对 GET 自动重试。
func (c *client) pendingBackup(ctx context.Context) (backupRequest, bool, error) {
	var out backupRequest
	status, err := c.post(ctx, "/v1/build-agent/backup-requests/claim",
		map[string]string{"agent": c.cfg.Name}, &out)
	if err != nil {
		return backupRequest{}, false, err
	}
	if status == http.StatusNoContent || out.ID == "" {
		return backupRequest{}, false, nil
	}
	return out, true, nil
}

func (c *client) backupKeystores(ctx context.Context, requestID string) ([]sealedKeystoreItem, error) {
	var out struct {
		Items []sealedKeystoreItem `json:"items"`
	}
	if _, err := c.get(ctx, "/v1/build-agent/backup-keystores?request="+url.QueryEscape(requestID), &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *client) failBackup(ctx context.Context, requestID, reason string) error {
	_, err := c.post(ctx, "/v1/build-agent/backup-requests/"+url.PathEscape(requestID)+"/fail",
		map[string]string{"reason": truncate(reason, 480)}, nil)
	return err
}

func (c *client) registerBackupSigningKey(ctx context.Context, publicKey string) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	_, err := c.post(ctx, "/v1/build-agent/backup-signing-key",
		map[string]string{"publicKey": publicKey, "agent": c.cfg.Name}, &out)
	return out.Status, err
}

// uploadBackupPayload 上报一份内层密文（multipart：meta / payload / sig，见 §4.7）。
//
// **meta 必须排在 payload 之前**：服务端靠这个顺序先解析元数据、校验通过再决定
// 要不要收那几十 MB。顺序反了服务端会直接拒。
func (c *client) uploadBackupPayload(ctx context.Context, requestID string,
	meta backupbundle.PayloadMeta, payload, signature []byte) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	encoded, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	metaPart, err := writer.CreateFormField("meta")
	if err != nil {
		return err
	}
	if _, err := metaPart.Write(encoded); err != nil {
		return err
	}
	payloadPart, err := writer.CreateFormFile("payload", "inner.rnbk")
	if err != nil {
		return err
	}
	if _, err := payloadPart.Write(payload); err != nil {
		return err
	}
	sigPart, err := writer.CreateFormFile("sig", "inner.rnbk.sig")
	if err != nil {
		return err
	}
	if _, err := sigPart.Write(signature); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.Server+"/v1/build-agent/backup-requests/"+url.PathEscape(requestID)+"/payload", &body)
	if err != nil {
		return err
	}
	request.Header.Set("content-type", writer.FormDataContentType())
	request.Header.Set("x-build-agent-token", c.cfg.Token)

	// 上传和收尾都可能要几分钟，而 client.http 的默认超时是 30 秒。
	// 用调用方的 ctx 兜底（runBackup 给了 25 分钟，小于服务端 30 分钟的产出超时）
	uploader := &http.Client{}
	response, err := uploader.Do(request)
	if err != nil {
		return retryLater{err}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return classify(response.StatusCode,
			fmt.Errorf("uploading the backup payload returned %d: %s",
				response.StatusCode, truncate(string(raw), 300)))
	}
	return nil
}
