package ascapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Build Uploads：把一个 .ipa 传进 App Store Connect（设计
// ios-mac-builders-home-network-2026-09-18 §4.3 第 3 步）。
//
// **这是这个包里唯一会改 Apple 侧状态的一组调用，而且只给打包机上的上传程序用。**
// 包注释里"服务端不写 Apple 侧任何状态"那条没有松动：服务端构造的是 Client，它只有 GET；
// 写的能力挂在 Uploader 上，只有 cmd/build-agent/ios-upload 构造它。一个类型的差别把
// "谁能传包"写进了类型系统，而不是写进注释里——TestServerSideNeverConstructsAnUploader
// 守着这条。
//
// 为什么不是 altool：Apple 的 TN3147 只弃用了它的公证功能，上传仍在支持列表里，但
// Xcode 26 的 `altool --upload-app` 有已知回归（打不开包、失败不返回非零），fastlane 靠
// `--use-old-altool` 绕。这套端点是纯 HTTPS，分块上传还顺带解决了家用上行"不可续传、
// 失败整个重传"的问题。

// uploadPartTimeout 是单个分块的上限。家用上行几百 MB 的包分成几十块，每块几十 MB。
const uploadPartTimeout = 15 * time.Minute

// writeRequestTimeout 是建上传、标记完成这类小请求的上限。
const writeRequestTimeout = 60 * time.Second

// Uploader 能创建 build 上传。它是 Client 的超集：读的那些方法照常可用。
type Uploader struct {
	Client
}

// UploadOperation 是 Apple 给出的一次分块上传指令。这套形状与 ASC 的截图、预览片上传
// 是同一套（uploadOperations），不是 Build Uploads 独有的。
type UploadOperation struct {
	Method  string
	URL     string
	Offset  int64
	Length  int64
	Headers []UploadHeader
}

type UploadHeader struct {
	Name  string
	Value string
}

// ErrBuildAlreadyExists 是"这个 build 号在 Apple 那边已经有了"。
//
// 它不是失败：任务被回收重排后 build 号不变，上一次尝试可能已经把包传上去、只是没报
// 回来（设计 §6.3）。调用方据此报 uploadedByEarlierAttempt，而不是让任务失败——失败会
// 烧掉一个 build 号，而 Apple 那边其实已经有这一版了。
var ErrBuildAlreadyExists = errors.New("App Store Connect 上已经有这个 build 号")

// ErrUploadForbidden 是"这把 Key 的角色不够用这套端点"。
// 上传 Key 用的是 Developer 角色（能上传 build 的最低角色）；真撞上这个错就把这台机器
// 这个 Team 的 Key 换成 App Manager 角色的团队密钥（§4.3a）。
var ErrUploadForbidden = errors.New("这把上传密钥不能使用 Build Uploads 端点")

// ProbeBuildUploads 只读地探一次这套端点：200 表示这把 Key 能用它。
//
// 启动时每个 Team 各探一次，结果随认领自报给服务端——好让"角色不够传不上去"在**第一次
// 构建之前**就看得见，而不是在一次构建跑了半小时之后的最后一步。
func (c Client) ProbeBuildUploads(ctx context.Context, appID string) error {
	var body struct {
		Data []json.RawMessage `json:"data"`
	}
	err := c.get(ctx, "/v1/apps/"+url.PathEscape(appID)+"/buildUploads", url.Values{"limit": {"1"}}, &body)
	if errors.Is(err, ErrKeyRejected) {
		return fmt.Errorf("%w：%s", ErrUploadForbidden, err.Error())
	}
	return err
}

// FindBuildByVersion 按 CFBundleVersion 查 build。第二个返回值是"找到了没有"。
//
// 上传前先查一次（§6.3 第 1 步）：同号的包传第二次会被 Apple 拒，而任务被回收重排后
// build 号不变。查到且不是 FAILED/INVALID 就不用再传几百 MB。
//
// **预查会漏**：刚传完的 build 在 Apple 处理期间几分钟内查不到。所以它只是省一次上传，
// 不是正确性依赖——真正兜住重复的是上传时的 ErrBuildAlreadyExists。
func (c Client) FindBuildByVersion(ctx context.Context, appID, version string) (Build, bool, error) {
	var body struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Version         string     `json:"version"`
				ProcessingState string     `json:"processingState"`
				Expired         bool       `json:"expired"`
				ExpirationDate  *time.Time `json:"expirationDate"`
				UploadedDate    *time.Time `json:"uploadedDate"`
			} `json:"attributes"`
		} `json:"data"`
	}
	query := url.Values{"filter[app]": {appID}, "filter[version]": {version}, "limit": {"10"}}
	if err := c.get(ctx, "/v1/builds", query, &body); err != nil {
		return Build{}, false, err
	}
	for _, item := range body.Data {
		if item.Attributes.Version != version {
			continue
		}
		// 处理失败或无效的那一版不算数：那个号可以重新用
		switch strings.ToUpper(item.Attributes.ProcessingState) {
		case "FAILED", "INVALID":
			continue
		}
		return Build{
			ID: item.ID, Version: item.Attributes.Version, ProcessingState: item.Attributes.ProcessingState,
			Expired: item.Attributes.Expired, ExpirationDate: item.Attributes.ExpirationDate,
			UploadedDate: item.Attributes.UploadedDate,
		}, true, nil
	}
	return Build{}, false, nil
}

// CreateBuildUpload 建一次上传，返回它的 id。
func (u Uploader) CreateBuildUpload(ctx context.Context, appID, shortVersion, buildVersion string) (string, error) {
	payload := map[string]any{"data": map[string]any{
		"type": "buildUploads",
		"attributes": map[string]any{
			"cfBundleShortVersionString": shortVersion,
			"cfBundleVersion":            buildVersion,
			"platform":                   "IOS",
		},
		"relationships": map[string]any{
			"app": map[string]any{"data": map[string]any{"type": "apps", "id": appID}},
		},
	}}
	var body struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := u.write(ctx, http.MethodPost, "/v1/buildUploads", payload, &body); err != nil {
		return "", err
	}
	if body.Data.ID == "" {
		return "", errors.New("App Store Connect 建了上传却没给 id")
	}
	return body.Data.ID, nil
}

// CreateBuildUploadFile 报文件，拿回分块上传指令。
func (u Uploader) CreateBuildUploadFile(ctx context.Context, uploadID, fileName string, size int64) (string, []UploadOperation, error) {
	payload := map[string]any{"data": map[string]any{
		"type": "buildUploadFiles",
		"attributes": map[string]any{
			"fileName":  fileName,
			"fileSize":  size,
			"assetType": "ASSET",
			"uti":       "com.apple.ipa",
		},
		"relationships": map[string]any{
			"buildUpload": map[string]any{"data": map[string]any{"type": "buildUploads", "id": uploadID}},
		},
	}}
	var body struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				UploadOperations []struct {
					Method         string `json:"method"`
					URL            string `json:"url"`
					Offset         int64  `json:"offset"`
					Length         int64  `json:"length"`
					RequestHeaders []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"requestHeaders"`
				} `json:"uploadOperations"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := u.write(ctx, http.MethodPost, "/v1/buildUploadFiles", payload, &body); err != nil {
		return "", nil, err
	}
	if body.Data.ID == "" || len(body.Data.Attributes.UploadOperations) == 0 {
		return "", nil, errors.New("App Store Connect 没有给出上传指令")
	}
	operations := make([]UploadOperation, 0, len(body.Data.Attributes.UploadOperations))
	for _, item := range body.Data.Attributes.UploadOperations {
		operation := UploadOperation{Method: item.Method, URL: item.URL, Offset: item.Offset, Length: item.Length}
		for _, header := range item.RequestHeaders {
			operation.Headers = append(operation.Headers, UploadHeader{Name: header.Name, Value: header.Value})
		}
		operations = append(operations, operation)
	}
	return body.Data.ID, operations, nil
}

// CompleteBuildUploadFile 把文件标成传完了。
func (u Uploader) CompleteBuildUploadFile(ctx context.Context, fileID string) error {
	payload := map[string]any{"data": map[string]any{
		"id":         fileID,
		"type":       "buildUploadFiles",
		"attributes": map[string]any{"uploaded": true},
	}}
	return u.write(ctx, http.MethodPatch, "/v1/buildUploadFiles/"+url.PathEscape(fileID), payload, nil)
}

// UploadPart 按一条指令传一块。body 只读这一块的字节。
//
// 这些 URL 是 Apple 给的短期地址，**不带我们的 JWT**：请求头由指令自己指定，多加一个
// Authorization 反而可能让对方拒。
func (u Uploader) UploadPart(ctx context.Context, operation UploadOperation, body io.Reader) error {
	ctx, cancel := context.WithTimeout(ctx, uploadPartTimeout)
	defer cancel()
	method := operation.Method
	if method == "" {
		method = http.MethodPut
	}
	request, err := http.NewRequestWithContext(ctx, method, operation.URL, body)
	if err != nil {
		return err
	}
	request.ContentLength = operation.Length
	for _, header := range operation.Headers {
		request.Header.Set(header.Name, header.Value)
	}
	response, err := u.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("上传分块失败（offset %d，%d 字节）：%w", operation.Offset, operation.Length, err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if response.StatusCode >= 300 {
		return fmt.Errorf("上传分块被拒（offset %d）：%d %s", operation.Offset, response.StatusCode,
			strings.TrimSpace(string(payload)))
	}
	return nil
}

// write 发一次 POST / PATCH。除了这个文件里的几个方法，这个包不写 Apple 侧任何状态。
func (u Uploader) write(ctx context.Context, method, path string, payload any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, writeRequestTimeout)
	defer cancel()
	token, err := u.Key.token(u.now())
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, u.baseURL()+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := u.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("连不上 App Store Connect：%w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读 App Store Connect 的响应失败：%w", err)
	}
	switch {
	case response.StatusCode == http.StatusConflict || duplicateBuildDetail(body):
		// 同号已经在那边了。预查会漏（刚传完的 build 几分钟内查不到），所以这条路必须
		// 当成"已经有了"而不是失败——失败会烧掉一个 build 号，而 Apple 那边其实有这一版
		return fmt.Errorf("%w：%s", ErrBuildAlreadyExists, appleErrorDetail(body))
	case response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w：%s", ErrUploadForbidden, appleErrorDetail(body))
	case response.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w：%s（401）", ErrKeyRejected, appleErrorDetail(body))
	case response.StatusCode >= 300:
		return fmt.Errorf("App Store Connect 返回 %d：%s", response.StatusCode, appleErrorDetail(body))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("App Store Connect 的响应不是预期的 JSON：%w", err)
	}
	return nil
}

// duplicateBuildDetail 判断这条错误是不是"同号已存在"。
//
// Apple 没有把这套端点的错误码写进文档（§4.3 第 3 条），所以这里按**说明文字**认，
// 并且只认几条明确的说法；认不出来的按普通失败处理。真机阶段把实际的 code 记进设计文档，
// 之后换成按 code 判。
func duplicateBuildDetail(body []byte) bool {
	var parsed struct {
		Errors []struct {
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return false
	}
	for _, item := range parsed.Errors {
		text := strings.ToLower(item.Code + " " + item.Title + " " + item.Detail)
		switch {
		case strings.Contains(text, "redundant binary upload"),
			strings.Contains(text, "already been used"),
			strings.Contains(text, "already exists"),
			strings.Contains(text, "duplicate"):
			return true
		}
	}
	return false
}
