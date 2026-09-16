package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/provenance"
)

// 服务端错误码（Problem Details 的 code）里构建机要分辨的几个。
const (
	codeAttemptStale        = "BUILD_ATTEMPT_STALE"
	codeBuilderHasActiveJob = "BUILDER_HAS_ACTIVE_JOB"
	codeKeyNotAccepted      = "MACHINE_KEY_NOT_ACCEPTED"
	codeKeyRotationUnproven = "MACHINE_KEY_ROTATION_UNPROVEN"
	codeClaimInProgress     = "BUILDER_CLAIM_IN_PROGRESS"

	headerMachineToken = "x-machine-token"
	headerBuildAttempt = "x-build-attempt"

	maxJSONResponseBytes      = 1 << 20
	uploadRequestTimeout      = 30 * time.Minute
	defaultHTTPRequestTimeout = 30 * time.Second
)

// apiError 是服务端给出的明确拒绝（或 5xx）。
type apiError struct {
	Path   string
	Status int
	Code   string
	Detail string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s returned %d %s: %s", e.Path, e.Status, e.Code, truncate(e.Detail, 300))
	}
	return fmt.Sprintf("%s returned %d: %s", e.Path, e.Status, truncate(e.Detail, 300))
}

func errorCode(err error) string {
	var api *apiError
	if errors.As(err, &api) {
		return api.Code
	}
	return ""
}

// isStale：服务端说这次认领已经不是这台机器的了（回收、取消、被重派）。立即中止，不再上报。
func isStale(err error) bool { return errorCode(err) == codeAttemptStale }

func newAPIError(path string, status int, payload []byte) error {
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(payload, &problem)
	detail := problem.Detail
	if detail == "" {
		detail = string(payload)
	}
	if status >= 300 && status < 400 {
		// 重定向不重试：同一个地址下一次多半还是同一个答案，而且这说明链路上有东西不对
		return &apiError{Path: path, Status: status,
			Detail: "the server answered with a redirect; build agents never follow redirects (they would carry the machine token elsewhere)"}
	}
	err := &apiError{Path: path, Status: status, Code: problem.Code, Detail: detail}
	if transientCodes[problem.Code] {
		return retryLater{err}
	}
	return classify(status, err)
}

// transientCodes 是状态码是 4xx、但服务端明说"现在不行、等会儿再来"的几种。其余 4xx 都是
// 明确的拒绝（UPLOAD_CONTENT_TYPE_INVALID、UPLOAD_TOO_LARGE、UPLOAD_EMPTY、INVALID_BUILD_ATTEMPT、
// BUILD_SBOM_INVALID、BUILD_PROVENANCE_INVALID、BUILD_KIND_MISMATCH……），重试一百次也是同一个答案。
var transientCodes = map[string]bool{
	// 同一台机器的另一次领取还在服务端手里（上一次请求超时后重发）
	codeClaimInProgress: true,
	// 上传的请求体没读完整：链路上断了，重传
	"UPLOAD_INTERRUPTED": true,
	// 服务端写对象存储失败（424）
	"UPLOAD_STORAGE_FAILED": true,
	// 机器登记表并发写冲突
	"MACHINES_VERSION_CONFLICT": true,
}

// refuseRedirects 让客户端从不跟随重定向，把 3xx 原样交回来按错误处理。
//
// Go 默认跟随重定向，并且会把自定义请求头（x-machine-token）和可重放的请求体（GetBody）
// 一起带到新地址——API 源或它前面的反代只要回一个 307/308，本机令牌和几十兆的包就发到了
// 任意一方（评审 R2 的 PoC 就是这样）。构建机要连的每个地址都是确定的，没有需要跟随的重定向。
func refuseRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// failedStatus：3xx（没有被跟随的重定向）与 4xx、5xx 都是失败。
func failedStatus(status int) bool { return status >= 300 }

// classify 决定一个 HTTP 失败要不要再试：5xx 和 429 是"现在不行"，4xx 是"不行"。
func classify(status int, err error) error {
	if status >= 500 || status == http.StatusTooManyRequests {
		return retryLater{err}
	}
	return err
}

// claimedJob 是领取结果里构建机要用的字段。领取结果还带着任务视图的其它字段，这里不建模；
// 但签名材料一类的字段出现就整条拒绝（见 forbiddenClaimField）。
type claimedJob struct {
	ID               string `json:"id"`
	Attempt          int    `json:"attempt"`
	ClaimedMachineID string `json:"claimedMachineId"`
	TenantSlug       string `json:"tenantSlug"`
	// TenantDirectory 是仓库里 tenants/ 下的目录名，与 TenantSlug 是两套命名，只用它拼路径。
	TenantDirectory    string          `json:"tenantDirectory"`
	Platform           string          `json:"platform"`
	Kind               string          `json:"kind"`
	BaseReleaseID      string          `json:"baseReleaseId"`
	Channel            string          `json:"channel"`
	ApplyStrategy      string          `json:"applyStrategy"`
	RuntimeVersion     string          `json:"runtimeVersion"`
	GitRef             string          `json:"gitRef"`
	Version            string          `json:"version"`
	BuildNumber        int             `json:"buildNumber"`
	OTACertificatePEM  string          `json:"otaCertificatePem"`
	GoogleServicesJSON string          `json:"googleServicesJson"`
	Icons              []string        `json:"icons"`
	TenantFile         json.RawMessage `json:"tenantFile"`
}

// APIBaseURL / ApplicationID / PackageName 从服务端合成的身份文件里取。
func (j claimedJob) APIBaseURL() string    { return j.tenantField("apiBaseUrl") }
func (j claimedJob) ApplicationID() string { return j.tenantField("applicationId") }
func (j claimedJob) PackageName() string   { return j.tenantField("androidPackage") }

func (j claimedJob) tenantField(name string) string {
	var fields map[string]any
	if json.Unmarshal(j.TenantFile, &fields) != nil {
		return ""
	}
	value, _ := fields[name].(string)
	return value
}

// claimResult 是一次领取的结果：领到任务、领到但拒收的任务、本机已有在途任务，或者都没有（无活）。
type claimResult struct {
	Job *claimedJob
	// Refused 是领到了、但领取结果本身不合规（带签名材料字段、字段类型不对）的任务
	Refused *refusedClaim
	// Active 是服务端说本机还有一条 claimed/running 的任务（409 BUILDER_HAS_ACTIVE_JOB）
	Active *activeJobRef
}

type refusedClaim struct {
	JobID   string
	Attempt int
	Reason  string
}

type activeJobRef struct {
	JobID   string `json:"jobId"`
	Attempt int    `json:"attempt"`
}

type client struct {
	server string
	token  string
	http   *http.Client
	upload *http.Client
}

func newClient(cfg config) *client {
	return &client{
		server: cfg.Server,
		token:  cfg.MachineToken,
		http:   &http.Client{Timeout: defaultHTTPRequestTimeout, CheckRedirect: refuseRedirects},
		// 几十上百兆的 PUT 经过反代链路时 h2 的流错误比 1.1 常见得多，这条路径也没有
		// 任何需要多路复用的理由，所以强制 HTTP/1.1。
		upload: &http.Client{
			Timeout:       uploadRequestTimeout,
			CheckRedirect: refuseRedirects,
			Transport:     &http.Transport{ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
		},
	}
}

// send 发一个带本机令牌（以及可选编号）的 JSON 请求，读回不超过 1 MiB 的正文。
func (c *client) send(ctx context.Context, method, path string, attempt int, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.server+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		request.Header.Set("content-type", "application/json")
	}
	c.authorize(request, attempt)
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, retryLater{err}
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxJSONResponseBytes+1))
	if err != nil {
		return response.StatusCode, nil, retryLater{fmt.Errorf("%s: reading the response failed: %w", path, err)}
	}
	if len(payload) > maxJSONResponseBytes {
		return response.StatusCode, nil, fmt.Errorf("%s returned more than %d bytes", path, maxJSONResponseBytes)
	}
	if failedStatus(response.StatusCode) {
		return response.StatusCode, payload, newAPIError(path, response.StatusCode, payload)
	}
	return response.StatusCode, payload, nil
}

func (c *client) authorize(request *http.Request, attempt int) {
	request.Header.Set(headerMachineToken, c.token)
	if attempt > 0 {
		request.Header.Set(headerBuildAttempt, strconv.Itoa(attempt))
	}
}

func decodeInto(path string, payload []byte, out any) error {
	if err := json.Unmarshal(payload, out); err != nil {
		// 半截正文多半是链路上出的事（反代截断、连接断在中途），下一次多半就好了
		return retryLater{fmt.Errorf("%s returned a body we cannot read: %w", path, err)}
	}
	return nil
}

func jobPath(jobID, suffix string) string {
	return "/v1/build-agent/jobs/" + url.PathEscape(jobID) + suffix
}

// keyRegistration 是 POST /v1/build-agent/public-key 的回答。MachineID 不在约定 5.2 的
// 响应里：服务端带了才能换钥（换钥签名要签机器 id），没带时换钥会明确拒绝执行。
type keyRegistration struct {
	Status                 string `json:"status"`
	PublicKeySHA256        string `json:"publicKeySha256"`
	PendingPublicKeySHA256 string `json:"pendingPublicKeySha256"`
	MachineID              string `json:"machineId"`
}

func (c *client) registerKey(ctx context.Context, publicKeyBase64 string, rotationSignature []byte) (keyRegistration, error) {
	body := map[string]any{"publicKey": publicKeyBase64, "rotationSignature": nil}
	if rotationSignature != nil {
		body["rotationSignature"] = base64.StdEncoding.EncodeToString(rotationSignature)
	}
	const path = "/v1/build-agent/public-key"
	var out keyRegistration
	_, payload, err := c.send(ctx, http.MethodPost, path, 0, body)
	if err != nil {
		return out, err
	}
	return out, decodeInto(path, payload, &out)
}

// claim 领一条任务。队列空时服务端给 204。
func (c *client) claim(ctx context.Context, platforms []string) (claimResult, error) {
	const path = "/v1/build-agent/claim"
	status, payload, err := c.send(ctx, http.MethodPost, path, 0, map[string]any{
		"platforms": platforms, "kinds": []string{"apk", "ota"},
	})
	if errorCode(err) == codeBuilderHasActiveJob {
		var active activeJobRef
		if json.Unmarshal(payload, &active) != nil || active.JobID == "" || active.Attempt < 1 {
			return claimResult{}, fmt.Errorf("%s said this machine has an active job but did not say which one", path)
		}
		return claimResult{Active: &active}, nil
	}
	if err != nil {
		return claimResult{}, err
	}
	if status == http.StatusNoContent || len(bytes.TrimSpace(payload)) == 0 {
		return claimResult{}, nil
	}
	return parseClaim(payload)
}

// parseClaim 解析领取结果。签名材料一类的字段出现，这条任务就不做——服务端按约定不会
// 下发它们，出现了就是服务端被改过或者版本不对，照做等于把签名材料写进构建目录。
func parseClaim(payload []byte) (claimResult, error) {
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return claimResult{}, retryLater{fmt.Errorf("the claim response is not JSON: %w", err)}
	}
	if _, ok := raw.(map[string]any); !ok {
		return claimResult{}, errors.New("the claim response is not a JSON object")
	}
	var ids struct {
		ID      string `json:"id"`
		Attempt int    `json:"attempt"`
	}
	_ = json.Unmarshal(payload, &ids)
	if field := forbiddenClaimField(raw, ""); field != "" {
		return claimResult{Refused: &refusedClaim{JobID: ids.ID, Attempt: ids.Attempt,
			Reason: "the claim response carries signing material (" + field + "); build machines never receive signing keys, so this job is refused"}}, nil
	}
	var job claimedJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return claimResult{Refused: &refusedClaim{JobID: ids.ID, Attempt: ids.Attempt,
			Reason: "the claim response has fields of the wrong type"}}, nil
	}
	return claimResult{Job: &job}, nil
}

// forbiddenClaimField 返回领取结果里第一个像签名材料的字段路径（递归）。
func forbiddenClaimField(value any, prefix string) string {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			for _, word := range []string{"keystore", "keyalias", "password", "passphrase", "secret", "privatekey", "p12"} {
				if strings.Contains(lower, word) {
					return prefix + key
				}
			}
			if found := forbiddenClaimField(child, prefix+key+"."); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range v {
			if found := forbiddenClaimField(child, prefix); found != "" {
				return found
			}
		}
	}
	return ""
}

func (c *client) heartbeat(ctx context.Context, job claimedJob, logTail []string) error {
	_, _, err := c.send(ctx, http.MethodPost, jobPath(job.ID, "/heartbeat"), job.Attempt, map[string]any{"logTail": nonNil(logTail)})
	return err
}

func (c *client) fail(ctx context.Context, jobID string, attempt int, reason, commit string, logTail []string) error {
	_, _, err := c.send(ctx, http.MethodPost, jobPath(jobID, "/fail"), attempt, map[string]any{
		"failureReason": truncate(reason, 1000), "commitSha": commit, "logTail": nonNil(logTail),
	})
	return err
}

// complete 只给热更新任务用：安装包任务以 /built 结束。
func (c *client) complete(ctx context.Context, job claimedJob, commit, digest, releaseID string, logTail []string) error {
	_, _, err := c.send(ctx, http.MethodPost, jobPath(job.ID, "/complete"), job.Attempt, map[string]any{
		"commitSha": commit, "artifactSha256": digest, "releaseId": releaseID, "logTail": nonNil(logTail),
	})
	return err
}

// built 交付出处声明，安装包任务转「待签名」。
func (c *client) built(ctx context.Context, job claimedJob, commit, nativeFingerprint string, envelope provenance.Envelope, logTail []string) error {
	_, _, err := c.send(ctx, http.MethodPost, jobPath(job.ID, "/built"), job.Attempt, map[string]any{
		"commitSha":         commit,
		"nativeFingerprint": nativeFingerprint,
		"provenance":        map[string]string{"statement": envelope.Statement, "signature": envelope.Signature},
		"logTail":           nonNil(logTail),
	})
	return err
}

func nonNil(lines []string) []string {
	if lines == nil {
		return []string{}
	}
	return lines
}

// uploadStream 把控制进程自己的副本以 octet-stream 流式 PUT 到服务端，核对服务端算出的 sha256 与大小。
func (c *client) uploadStream(ctx context.Context, job claimedJob, suffix, path, wantSHA256 string, wantSize int64) error {
	apiPath := jobPath(job.ID, suffix)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.server+apiPath, file)
	if err != nil {
		return err
	}
	request.ContentLength = wantSize
	// GetBody 让传输层需要重发时能从头再读一遍
	request.GetBody = func() (io.ReadCloser, error) { return os.Open(path) }
	request.Header.Set("content-type", "application/octet-stream")
	c.authorize(request, job.Attempt)
	response, err := c.upload.Do(request)
	if err != nil {
		return retryLater{err}
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, maxJSONResponseBytes))
	if failedStatus(response.StatusCode) {
		return newAPIError(apiPath, response.StatusCode, payload)
	}
	var stored struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	if err := decodeInto(apiPath, payload, &stored); err != nil {
		return err
	}
	if stored.SHA256 != wantSHA256 || stored.Size != wantSize {
		// 传的就是这份字节：对不上是链路或服务端的问题，重传一次
		return retryLater{fmt.Errorf("%s stored %d bytes with sha256 %s, but %d bytes with sha256 %s were sent",
			apiPath, stored.Size, truncate(stored.SHA256, 64), wantSize, wantSHA256)}
	}
	return nil
}

// downloadIcon 取一张图标写进 w（调用方给的是检出里以 O_EXCL 新建的文件），不经过内存里的字符串。
func (c *client) downloadIcon(ctx context.Context, job claimedJob, name string, w io.Writer) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+jobPath(job.ID, "/icons/"+url.PathEscape(name)), nil)
	if err != nil {
		return err
	}
	c.authorize(request, job.Attempt)
	response, err := c.http.Do(request)
	if err != nil {
		return retryLater{err}
	}
	defer response.Body.Close()
	if failedStatus(response.StatusCode) {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return newAPIError("icon "+name, response.StatusCode, payload)
	}
	// 一张图上限 6MB（服务端那一侧的校验），留一倍余量挡住坏掉的响应
	written, err := io.Copy(w, io.LimitReader(response.Body, 12<<20+1))
	if err != nil {
		return err
	}
	if written > 12<<20 {
		return fmt.Errorf("icon %s is larger than 12 MiB", name)
	}
	return nil
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

// uploadOTAPackage 把热更新包传回服务端，返回落成的修订 id。base、channel、生效方式都取
// 任务行上的值——构建机只送它确实知道的东西（包本身和这次检出的提交）。
func (c *client) uploadOTAPackage(ctx context.Context, job claimedJob, path string, size int64, commit string, buf *logBuffer) (string, error) {
	token := ""
	if err := withRetry(ctx, buf, "OTA upload", 6, func(ctx context.Context) error {
		var ticket uploadTicket
		ticketPath := jobPath(job.ID, "/ota-uploads")
		_, payload, err := c.send(ctx, http.MethodPost, ticketPath, job.Attempt, map[string]any{
			"fileName": filepath.Base(path), "size": size,
		})
		if err != nil {
			return err
		}
		if err := decodeInto(ticketPath, payload, &ticket); err != nil {
			return err
		}
		token = ticket.Artifact.Token
		return c.putTicket(ctx, job, ticket, path, size)
	}); err != nil {
		return "", err
	}
	var created struct {
		Release struct {
			ID string `json:"id"`
		} `json:"release"`
	}
	if err := withRetry(ctx, buf, "OTA revision", 6, func(ctx context.Context) error {
		releasePath := jobPath(job.ID, "/ota-release")
		_, payload, err := c.send(ctx, http.MethodPost, releasePath, job.Attempt, map[string]any{
			"artifactToken": token, "sourceCommitSha": commit,
		})
		if err != nil {
			return err
		}
		return decodeInto(releasePath, payload, &created)
	}); err != nil {
		return "", err
	}
	if created.Release.ID == "" {
		return "", errors.New("the server created an OTA revision but did not say which one")
	}
	return created.Release.ID, nil
}

// putTicket 按票据把文件 PUT 上去。本机令牌与编号只发给服务端自己：票据可以是对象存储的
// 预签名地址（ARTIFACT_UPLOAD_MODE=direct），把令牌发给第三方就是泄露。
func (c *client) putTicket(ctx context.Context, job claimedJob, ticket uploadTicket, path string, size int64) error {
	target, err := url.Parse(ticket.Upload.URL)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" {
		return errors.New("the upload ticket has no usable URL")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), file)
	if err != nil {
		return err
	}
	request.ContentLength = size
	request.GetBody = func() (io.ReadCloser, error) { return os.Open(path) }
	for key, value := range ticket.Upload.Headers {
		if strings.EqualFold(key, headerMachineToken) || strings.EqualFold(key, headerBuildAttempt) {
			continue
		}
		request.Header.Set(key, value)
	}
	if sameOrigin(c.server, target) {
		c.authorize(request, job.Attempt)
	}
	response, err := c.upload.Do(request)
	if err != nil {
		return retryLater{err}
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, maxJSONResponseBytes))
	if failedStatus(response.StatusCode) {
		return newAPIError("upload of "+filepath.Base(path), response.StatusCode, payload)
	}
	return nil
}

func sameOrigin(server string, target *url.URL) bool {
	base, err := url.Parse(server)
	return err == nil && strings.EqualFold(base.Scheme, target.Scheme) && strings.EqualFold(base.Host, target.Host)
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "…"
}
