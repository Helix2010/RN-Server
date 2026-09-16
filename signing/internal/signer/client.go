package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// 服务端错误码（约定第 5 节）。
const (
	codeSignAttemptStale      = "SIGN_ATTEMPT_STALE"
	codeMachineKeyNotAccepted = "MACHINE_KEY_NOT_ACCEPTED"
	codeReleaseSequenceBusy   = "RELEASE_SEQUENCE_BUSY"
)

const (
	maxJSONResponse = 4 << 20
	jsonTimeout     = 30 * time.Second
	transferTimeout = 15 * time.Minute
)

// APIError 是服务端返回的 Problem Details。Detail 已经过清理，可以打印。
type APIError struct {
	Status int
	Code   string
	Detail string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Detail)
}

// Stale：服务端说这次签名认领已经过期（被回收或被强制判失败）。
func (e *APIError) Stale() bool {
	return e.Status == http.StatusConflict && e.Code == codeSignAttemptStale
}

// Transient：网络层以外的临时错误（5xx、429、发布序列忙）。
func (e *APIError) Transient() bool {
	return e.Status >= 500 || e.Status == http.StatusTooManyRequests || e.Code == codeReleaseSequenceBusy
}

// IsTransient 判断一个调用错误能不能原地重试：网络错误与 APIError.Transient。
func IsTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Transient()
	}
	var protocolErr *ProtocolError
	return !errors.As(err, &protocolErr)
}

// IsStale 判断错误是否为 409 SIGN_ATTEMPT_STALE。
func IsStale(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Stale()
}

// ProtocolError：服务端的响应不符合约定（形状不对、摘要不对）。不重试。
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "server response violates the contract: " + e.Msg }

// API 是签名闸用到的服务端接口（约定 5.3）。测试里用假服务端实现。
type API interface {
	RegisterKey(ctx context.Context, x25519Pub, ed25519Pub []byte) (KeyStatus, error)
	KeystoreChecks(ctx context.Context) (ChecksResponse, error)
	ReportChecks(ctx context.Context, items []CheckReport) error
	Claim(ctx context.Context, ready []ReadyItem) (*Claim, error)
	Heartbeat(ctx context.Context, jobID string, signAttempt int) error
	DownloadUnsigned(ctx context.Context, jobID string, signAttempt int, dst io.Writer, maxSize int64) (Download, error)
	UploadSigned(ctx context.Context, jobID string, signAttempt int, path string) (Upload, error)
	Complete(ctx context.Context, jobID string, signAttempt int, req CompleteRequest) (string, error)
	Release(ctx context.Context, jobID string, signAttempt int, code, detail string) error
	Reject(ctx context.Context, jobID string, signAttempt int, kind, code, detail string) error
}

// KeyStatus 是 POST /v1/signer/public-key 的响应。
type KeyStatus struct {
	Status                 string  `json:"status"`
	PublicKeySHA256        *string `json:"publicKeySha256"`
	Ed25519PublicKeySHA256 *string `json:"ed25519PublicKeySha256"`
	PendingPublicKeySHA256 *string `json:"pendingPublicKeySha256"`
}

// ChecksResponse 是 GET /v1/signer/keystore-checks 的响应。
type ChecksResponse struct {
	MachineID  string      `json:"machineId"`
	SignerRole *string     `json:"signerRole"`
	Items      []CheckItem `json:"items"`
}

// CheckItem 是发给本机的一份密钥。
type CheckItem struct {
	TenantSlug        string            `json:"tenantSlug"`
	KeystoreVersion   int64             `json:"keystoreVersion"`
	PackageName       string            `json:"packageName"`
	CertificateSHA256 string            `json:"certificateSha256"`
	KeyAlias          string            `json:"keyAlias"`
	Box               keystorebox.Box   `json:"box"`
	TrustRoots        *trustroots.Roots `json:"trustRoots"`
	TrustRootsDigest  *string           `json:"trustRootsDigest"`
}

// CheckReport 是 POST /v1/signer/keystore-checks 的一项。
type CheckReport struct {
	TenantSlug                string  `json:"tenantSlug"`
	KeystoreVersion           int64   `json:"keystoreVersion"`
	Decrypt                   string  `json:"decrypt"`
	Confirmed                 bool    `json:"confirmed"`
	ConfirmedTrustRootsDigest *string `json:"confirmedTrustRootsDigest"`
	TrialSign                 string  `json:"trialSign"`
	Error                     *string `json:"error"`
}

// ReadyItem 是 POST /v1/signer/claim 里本机就绪的租户。
type ReadyItem struct {
	TenantSlug        string `json:"tenantSlug"`
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	TrustRootsDigest  string `json:"trustRootsDigest"`
}

// Claim 是签名认领的 200 响应。
type Claim struct {
	Job struct {
		ID                string `json:"id"`
		TenantSlug        string `json:"tenantSlug"`
		Platform          string `json:"platform"`
		Version           string `json:"version"`
		BuildNumber       int64  `json:"buildNumber"`
		Attempt           int    `json:"attempt"`
		SignAttempt       int    `json:"signAttempt"`
		CommitSHA         string `json:"commitSha"`
		UnsignedSHA256    string `json:"unsignedSha256"`
		UnsignedSize      int64  `json:"unsignedSize"`
		SBOMSHA256        string `json:"sbomSha256"`
		NativeFingerprint string `json:"nativeFingerprint"`
	} `json:"job"`
	Provenance struct {
		Statement              string `json:"statement"`
		Signature              string `json:"signature"`
		BuilderID              string `json:"builderId"`
		BuilderPublicKey       string `json:"builderPublicKey"`
		BuilderPublicKeySHA256 string `json:"builderPublicKeySha256"`
	} `json:"provenance"`
	Keystore struct {
		KeystoreVersion   int64           `json:"keystoreVersion"`
		PackageName       string          `json:"packageName"`
		CertificateSHA256 string          `json:"certificateSha256"`
		KeyAlias          string          `json:"keyAlias"`
		Box               keystorebox.Box `json:"box"`
	} `json:"keystore"`
	TrustRoots       *trustroots.Roots `json:"trustRoots"`
	TrustRootsDigest string            `json:"trustRootsDigest"`
}

// Download 是下载结果。
type Download struct {
	Size          int64
	SHA256        string
	HeaderSHA256  string
	HeaderPresent bool
}

// Upload 是 PUT …/signed/upload 的响应。
type Upload struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// CompleteRequest 是 POST …/complete 的请求体。
type CompleteRequest struct {
	SignedSHA256      string `json:"signedSha256"`
	SignedSize        int64  `json:"signedSize"`
	CertificateSHA256 string `json:"certificateSha256"`
	UnsignedSHA256    string `json:"unsignedSha256"`
	NativeFingerprint string `json:"nativeFingerprint"`
}

// HTTPClient 是 API 的 HTTP 实现。
type HTTPClient struct {
	base  string
	token string
	http  *http.Client
}

// NewHTTPClient 创建客户端。不跟随重定向：令牌只发给配置的源。
func NewHTTPClient(baseURL, token string, transport http.RoundTripper) *HTTPClient {
	return &HTTPClient{
		base:  baseURL,
		token: token,
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// String 不含令牌。
func (c *HTTPClient) String() string { return "signer.HTTPClient{base=" + c.base + "}" }

func (c *HTTPClient) newRequest(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-machine-token", c.token)
	req.Header.Set("user-agent", "rn-signer/1")
	if contentType != "" {
		req.Header.Set("content-type", contentType)
	}
	return req, nil
}

func (c *HTTPClient) doJSON(ctx context.Context, method, path string, attempt int, in, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, jsonTimeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := c.newRequest(ctx, method, path, body, map[bool]string{true: "application/json", false: ""}[in != nil])
	if err != nil {
		return 0, err
	}
	if attempt > 0 {
		req.Header.Set("x-sign-attempt", strconv.Itoa(attempt))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONResponse+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if len(raw) > maxJSONResponse {
		return resp.StatusCode, &ProtocolError{Msg: path + ": response body is larger than 4 MiB"}
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, parseProblem(resp.StatusCode, raw)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, &ProtocolError{Msg: path + ": response is not the expected JSON"}
		}
	}
	return resp.StatusCode, nil
}

func parseProblem(status int, raw []byte) error {
	var p struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &p)
	return &APIError{Status: status, Code: cleanText(p.Code, 64), Detail: cleanText(p.Detail, 300)}
}

// cleanText 去掉控制字符并截断：服务端的文字会进日志与运维终端。
func cleanText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = '?'
		}
		if b.Len()+len(string(r)) > max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// RegisterKey 登记本机公钥（首次启动与每次启动都调用，同钥重复登记幂等）。
func (c *HTTPClient) RegisterKey(ctx context.Context, x25519Pub, ed25519Pub []byte) (KeyStatus, error) {
	var out KeyStatus
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/public-key", 0, map[string]any{
		"x25519PublicKey":   base64.StdEncoding.EncodeToString(x25519Pub),
		"ed25519PublicKey":  base64.StdEncoding.EncodeToString(ed25519Pub),
		"rotationSignature": nil,
	}, &out)
	return out, err
}

// KeystoreChecks 取回发给本机的全部密文。
func (c *HTTPClient) KeystoreChecks(ctx context.Context) (ChecksResponse, error) {
	var out ChecksResponse
	_, err := c.doJSON(ctx, http.MethodGet, "/v1/signer/keystore-checks", 0, nil, &out)
	return out, err
}

// ReportChecks 上报试解、确认、试签状态。
func (c *HTTPClient) ReportChecks(ctx context.Context, items []CheckReport) error {
	if items == nil {
		items = []CheckReport{}
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/keystore-checks", 0, map[string]any{"items": items}, nil)
	return err
}

// Claim 认领一条签名任务。没有活返回 nil。
func (c *HTTPClient) Claim(ctx context.Context, ready []ReadyItem) (*Claim, error) {
	if ready == nil {
		ready = []ReadyItem{}
	}
	var out Claim
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/claim", 0, map[string]any{"ready": ready}, &out)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &out, nil
}

// Heartbeat 续签名认领。
func (c *HTTPClient) Heartbeat(ctx context.Context, jobID string, signAttempt int) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/jobs/"+jobID+"/heartbeat", signAttempt, nil, nil)
	return err
}

// DownloadUnsigned 流式下载未签名包，边写边算 sha256，超过 maxSize 即中止。
func (c *HTTPClient) DownloadUnsigned(ctx context.Context, jobID string, signAttempt int, dst io.Writer, maxSize int64) (Download, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodGet, "/v1/signer/jobs/"+jobID+"/unsigned/download", nil, "")
	if err != nil {
		return Download{}, err
	}
	req.Header.Set("x-sign-attempt", strconv.Itoa(signAttempt))
	resp, err := c.http.Do(req)
	if err != nil {
		return Download{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxJSONResponse))
		return Download{}, parseProblem(resp.StatusCode, raw)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return Download{}, err
	}
	out := Download{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
	if v := resp.Header.Get("x-content-sha256"); v != "" {
		out.HeaderPresent, out.HeaderSHA256 = true, v
	}
	if resp.ContentLength >= 0 && resp.ContentLength != n && n <= maxSize {
		return out, fmt.Errorf("download ended after %d of %d bytes", n, resp.ContentLength)
	}
	return out, nil
}

// UploadSigned 流式上传已签名包。
func (c *HTTPClient) UploadSigned(ctx context.Context, jobID string, signAttempt int, path string) (Upload, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout)
	defer cancel()
	f, err := os.Open(path)
	if err != nil {
		return Upload{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Upload{}, err
	}
	req, err := c.newRequest(ctx, http.MethodPut, "/v1/signer/jobs/"+jobID+"/signed/upload", f, "application/octet-stream")
	if err != nil {
		return Upload{}, err
	}
	req.ContentLength = info.Size()
	req.Header.Set("x-sign-attempt", strconv.Itoa(signAttempt))
	resp, err := c.http.Do(req)
	if err != nil {
		return Upload{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONResponse))
	if err != nil {
		return Upload{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Upload{}, parseProblem(resp.StatusCode, raw)
	}
	var out Upload
	if err := json.Unmarshal(raw, &out); err != nil {
		return Upload{}, &ProtocolError{Msg: "signed upload response is not the expected JSON"}
	}
	return out, nil
}

// Complete 提交完成，返回发布 id。
func (c *HTTPClient) Complete(ctx context.Context, jobID string, signAttempt int, body CompleteRequest) (string, error) {
	var out struct {
		ReleaseID string `json:"releaseId"`
	}
	if _, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", signAttempt, body, &out); err != nil {
		return "", err
	}
	return out.ReleaseID, nil
}

// Release 暂不能签：任务退回待签名，不计次数。
func (c *HTTPClient) Release(ctx context.Context, jobID string, signAttempt int, code, detail string) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/jobs/"+jobID+"/release", signAttempt, map[string]string{"code": code, "detail": detail}, nil)
	return err
}

// Reject 违规（终态失败）或临时错误（计次）。
func (c *HTTPClient) Reject(ctx context.Context, jobID string, signAttempt int, kind, code, detail string) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/signer/jobs/"+jobID+"/reject", signAttempt, map[string]string{"kind": kind, "code": code, "detail": detail}, nil)
	return err
}
