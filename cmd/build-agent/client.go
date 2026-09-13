package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	TenantDirectory      string `json:"tenantDirectory"`
	Platform             string `json:"platform"`
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
	// TenantFile 是服务端合成的 tenants/<目录>/tenant.json。它取代了仓库里那份
	// 提交上去的文件——开一个新租户不该需要改代码。代理仍然校验字段（tenantfile.go）。
	TenantFile json.RawMessage `json:"tenantFile"`
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
		return 0, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		// 错误正文里不会有机密，但也不需要原样带出去——只留状态码和一小段
		return response.StatusCode, fmt.Errorf("%s returned %d: %s", path, response.StatusCode, truncate(string(payload), 300))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return response.StatusCode, fmt.Errorf("%s returned a body we cannot read: %w", path, err)
		}
	}
	return response.StatusCode, nil
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
		return 0, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return response.StatusCode, fmt.Errorf("%s returned %d: %s", path, response.StatusCode, truncate(string(payload), 300))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return response.StatusCode, fmt.Errorf("%s returned a body we cannot read: %w", path, err)
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
func (c *client) uploadArtifact(ctx context.Context, jobID, path, sbomPath string) (string, error) {
	artifactToken, err := c.putFile(ctx, jobID, path, "application/vnd.android.package-archive")
	if err != nil {
		return "", err
	}
	sbomToken := ""
	if sbomPath != "" {
		if sbomToken, err = c.putFile(ctx, jobID, sbomPath, "application/vnd.cyclonedx+json"); err != nil {
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
	if _, err := c.post(ctx, "/v1/build-agent/jobs/"+jobID+"/release", map[string]any{
		"artifactToken": artifactToken,
		"sbomToken":     sbomToken,
	}, &release); err != nil {
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
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, ticket.Upload.URL, file)
	if err != nil {
		return "", err
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
		return "", err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return "", fmt.Errorf("upload of %s returned %d: %s", filepath.Base(path), response.StatusCode, truncate(string(payload), 300))
	}
	return ticket.Artifact.Token, nil
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
