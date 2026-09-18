package ascapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 服务端那一侧永远不构造 Uploader：写 Apple 侧状态的能力只在打包机上的上传程序里。
//
// 这条规则本来写在包注释里。注释挡不住一次"顺手复用一下"的改动，而这个包能做的事里
// 最不该被顺手复用的就是"把包传上去"——它对外可见、撤不回来。
func TestServerSideNeverConstructsAnUploader(t *testing.T) {
	root := filepath.Join("..", "api")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "ascapi.Uploader") {
			t.Errorf("internal/api/%s uses ascapi.Uploader: the server must not be able to upload builds", entry.Name())
		}
	}
}

// 上传的三步走通：建上传 → 报文件拿指令 → 按指令分块 PUT → 标记完成。
func TestBuildUploadWalksApplesThreeSteps(t *testing.T) {
	const payload = "this-stands-in-for-a-few-hundred-megabytes"
	var parts []string
	var completed bool
	var uploadBody, fileBody map[string]any
	var assets *httptest.Server
	assets = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apple-part") == "" {
			t.Errorf("the part upload did not carry the headers Apple asked for: %v", r.Header)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("the part upload must not carry our App Store Connect token")
		}
		body, _ := io.ReadAll(r.Body)
		parts = append(parts, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer assets.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("%s %s carried no token", r.Method, r.URL.Path)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/buildUploads":
			_ = json.NewDecoder(r.Body).Decode(&uploadBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"upload-1","type":"buildUploads"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/buildUploadFiles":
			_ = json.NewDecoder(r.Body).Decode(&fileBody)
			_, _ = w.Write([]byte(`{"data":{"id":"file-1","type":"buildUploadFiles","attributes":{"uploadOperations":[
				{"method":"PUT","url":"` + assets.URL + `/part0","offset":0,"length":10,"requestHeaders":[{"name":"x-apple-part","value":"0"}]},
				{"method":"PUT","url":"` + assets.URL + `/part1","offset":10,"length":` +
				strconv.Itoa(len(payload)-10) + `,"requestHeaders":[{"name":"x-apple-part","value":"1"}]}]}}}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/buildUploadFiles/file-1":
			var body struct {
				Data struct {
					Attributes struct {
						Uploaded bool `json:"uploaded"`
					} `json:"attributes"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			completed = body.Data.Attributes.Uploaded
			_, _ = w.Write([]byte(`{"data":{"id":"file-1","type":"buildUploadFiles"}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()

	uploader := Uploader{Client{Key: testKey(t), BaseURL: api.URL}}
	ctx := context.Background()
	uploadID, err := uploader.CreateBuildUpload(ctx, "app-1", "1.3.7", "33")
	if err != nil || uploadID != "upload-1" {
		t.Fatalf("create build upload: %q %v", uploadID, err)
	}
	fileID, operations, err := uploader.CreateBuildUploadFile(ctx, uploadID, "anyfun.ipa", int64(len(payload)))
	if err != nil || fileID != "file-1" || len(operations) != 2 {
		t.Fatalf("create build upload file: %q %+v %v", fileID, operations, err)
	}
	for _, operation := range operations {
		if err := uploader.UploadPart(ctx, operation, strings.NewReader(payload[operation.Offset:operation.Offset+operation.Length])); err != nil {
			t.Fatal(err)
		}
	}
	if err := uploader.CompleteBuildUploadFile(ctx, fileID); err != nil {
		t.Fatal(err)
	}
	if strings.Join(parts, "") != payload {
		t.Fatalf("the parts do not add up to the package: %q", strings.Join(parts, ""))
	}
	if !completed {
		t.Fatal("the file was never marked uploaded")
	}
	// Apple 要的是这几个字段名，写错一个整条链路在真机上才会发现
	data, _ := uploadBody["data"].(map[string]any)
	attributes, _ := data["attributes"].(map[string]any)
	if data["type"] != "buildUploads" || attributes["cfBundleShortVersionString"] != "1.3.7" ||
		attributes["cfBundleVersion"] != "33" || attributes["platform"] != "IOS" {
		t.Fatalf("build upload body: %v", uploadBody)
	}
	fileData, _ := fileBody["data"].(map[string]any)
	fileAttributes, _ := fileData["attributes"].(map[string]any)
	if fileAttributes["fileName"] != "anyfun.ipa" || fileAttributes["uti"] != "com.apple.ipa" ||
		fileAttributes["assetType"] != "ASSET" {
		t.Fatalf("build upload file body: %v", fileBody)
	}
}

// 同号已经在那边了不是失败：任务被回收重排后 build 号不变，上一次尝试可能已经传完
// 只是没报回来。当成失败会烧掉一个 build 号，而 Apple 那边其实有这一版。
func TestBuildUploadTellsApartADuplicateFromAFailure(t *testing.T) {
	for name, handler := range map[string]struct {
		status int
		body   string
		want   error
	}{
		"409":                  {http.StatusConflict, `{"errors":[{"code":"ENTITY_ERROR","detail":"whatever"}]}`, ErrBuildAlreadyExists},
		"redundant binary":     {http.StatusBadRequest, `{"errors":[{"code":"X","detail":"Redundant Binary Upload"}]}`, ErrBuildAlreadyExists},
		"already been used":    {http.StatusBadRequest, `{"errors":[{"code":"X","detail":"The build number has already been used"}]}`, ErrBuildAlreadyExists},
		"forbidden":            {http.StatusForbidden, `{"errors":[{"code":"FORBIDDEN","detail":"no"}]}`, ErrUploadForbidden},
		"unauthorized":         {http.StatusUnauthorized, `{"errors":[{"code":"NOT_AUTHORIZED","detail":"no"}]}`, ErrKeyRejected},
		"some other rejection": {http.StatusBadRequest, `{"errors":[{"code":"X","detail":"missing something"}]}`, nil},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(handler.status)
			_, _ = w.Write([]byte(handler.body))
		}))
		uploader := Uploader{Client{Key: testKey(t), BaseURL: server.URL}}
		_, err := uploader.CreateBuildUpload(context.Background(), "app-1", "1.3.7", "33")
		server.Close()
		if err == nil {
			t.Errorf("%s: the upload was reported as successful", name)
			continue
		}
		if handler.want != nil && !errors.Is(err, handler.want) {
			t.Errorf("%s: %v", name, err)
		}
		if handler.want == nil && (errors.Is(err, ErrBuildAlreadyExists) || errors.Is(err, ErrUploadForbidden)) {
			t.Errorf("%s was mistaken for a duplicate or a permission problem: %v", name, err)
		}
	}
}
