package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 上传程序的契约：一行 JSON 到标准输出，进度与错误到标准错误，退出码 0 才算这一步成功。
// 控制进程按严格 JSON 解析这一行——多一个字段、少一个字段都会让它把上传当成失败。

func writeKeyDir(t *testing.T, team string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, team)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"key.json":              []byte(`{"issuerId":"11111111-2222-3333-4444-555555555555","keyId":"ABCDE12345"}`),
		"AuthKey_ABCDE12345.p8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fakeASC 是一台假的 App Store Connect：应用查询、同号查询、三步上传。
type fakeASC struct {
	existingBuild string
	duplicate     bool
	parts         []string
	completed     bool
	assets        *httptest.Server
	server        *httptest.Server
}

func newFakeASC(t *testing.T) *fakeASC {
	t.Helper()
	asc := &fakeASC{}
	asc.assets = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		asc.parts = append(asc.parts, body.String())
		w.WriteHeader(http.StatusOK)
	}))
	asc.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/apps":
			_, _ = w.Write([]byte(`{"data":[{"id":"app-1","type":"apps","attributes":{"bundleId":"com.anyfun.foundation","name":"AnyFun","sku":"X"}}]}`))
		case r.URL.Path == "/v1/builds":
			if asc.existingBuild != "" && r.URL.Query().Get("filter[version]") == asc.existingBuild {
				_, _ = w.Write([]byte(`{"data":[{"id":"b1","attributes":{"version":"` + asc.existingBuild + `","processingState":"VALID"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.URL.Path == "/v1/apps/app-1/buildUploads":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/buildUploads":
			if asc.duplicate {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"code":"ENTITY_ERROR","detail":"Redundant Binary Upload"}]}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"upload-1","type":"buildUploads"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/buildUploadFiles":
			var body struct {
				Data struct {
					Attributes struct {
						FileSize int64 `json:"fileSize"`
					} `json:"attributes"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			size := strconv.FormatInt(body.Data.Attributes.FileSize, 10)
			_, _ = w.Write([]byte(`{"data":{"id":"file-1","type":"buildUploadFiles","attributes":{"uploadOperations":[
				{"method":"PUT","url":"` + asc.assets.URL + `/p0","offset":0,"length":` + size + `,"requestHeaders":[]}]}}}`))
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/buildUploadFiles/"):
			asc.completed = true
			_, _ = w.Write([]byte(`{"data":{"id":"file-1","type":"buildUploadFiles"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(func() {
		asc.server.Close()
		asc.assets.Close()
	})
	return asc
}

func uploadArgs(keys, baseURL string, extra ...string) []string {
	return append([]string{
		"--team", "AB12CD34EF", "--keys", keys, "--base-url", baseURL,
		"--expect-bundle-id", "com.anyfun.foundation", "--expect-version", "1.3.7", "--expect-build", "33",
	}, extra...)
}

func decodeOutcome(t *testing.T, stdout *bytes.Buffer) outcome {
	t.Helper()
	var result outcome
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("stdout is not one line of the agreed JSON: %v\n%s", err, stdout.String())
	}
	return result
}

func TestUploadWalksTheThreeStepsAndReportsSuccess(t *testing.T) {
	asc := newFakeASC(t)
	keys := writeKeyDir(t, "AB12CD34EF")
	var stdout, stderr bytes.Buffer
	const payload = "a-small-stand-in-for-a-few-hundred-megabytes"
	if code := run(uploadArgs(keys, asc.server.URL), strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	result := decodeOutcome(t, &stdout)
	if !result.Uploaded || result.UploadedByEarlierAttempt {
		t.Fatalf("outcome: %+v", result)
	}
	if strings.Join(asc.parts, "") != payload {
		t.Fatalf("what reached Apple is not the package: %q", strings.Join(asc.parts, ""))
	}
	if !asc.completed {
		t.Fatal("the upload was never marked complete")
	}
}

// 同号已经在那边了：**不是失败**。任务被回收重排后 build 号不变，上一次尝试可能已经
// 传完只是没报回来；当成失败会烧掉一个 build 号，而 Apple 那边其实有这一版。
func TestUploadTreatsAnAlreadyPresentBuildAsSuccess(t *testing.T) {
	for name, prepare := range map[string]func(*fakeASC){
		"found by the pre-check": func(asc *fakeASC) { asc.existingBuild = "33" },
		"rejected as duplicate":  func(asc *fakeASC) { asc.duplicate = true },
	} {
		asc := newFakeASC(t)
		prepare(asc)
		keys := writeKeyDir(t, "AB12CD34EF")
		var stdout, stderr bytes.Buffer
		if code := run(uploadArgs(keys, asc.server.URL), strings.NewReader("package"), &stdout, &stderr); code != 0 {
			t.Fatalf("%s: exit %d: %s", name, code, stderr.String())
		}
		result := decodeOutcome(t, &stdout)
		if !result.Uploaded || !result.UploadedByEarlierAttempt {
			t.Fatalf("%s: outcome %+v", name, result)
		}
	}
}

// 探测永远以 0 退出：探测本身失败不是这台机器的故障，结果要能报到控制台上让人看见。
func TestProbeAlwaysReportsAResultAndExitsZero(t *testing.T) {
	asc := newFakeASC(t)
	keys := writeKeyDir(t, "AB12CD34EF")
	var stdout, stderr bytes.Buffer
	args := []string{"--probe", "--team", "AB12CD34EF", "--keys", keys, "--base-url", asc.server.URL,
		"--expect-bundle-id", "com.anyfun.foundation"}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if result := decodeOutcome(t, &stdout); result.Probe != probeOK {
		t.Fatalf("probe: %+v", result)
	}
	// 没有这个 Team 的 Key：也要给出一行结果，而不是一个空的退出码
	stdout.Reset()
	missing := []string{"--probe", "--team", "ZZ99YY88XX", "--keys", keys, "--base-url", asc.server.URL,
		"--expect-bundle-id", "com.anyfun.foundation"}
	if code := run(missing, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if result := decodeOutcome(t, &stdout); result.Probe != probeError || result.Detail == "" {
		t.Fatalf("a missing key must be reported, not swallowed: %+v", result)
	}
}

// 角色不够（403）要报成 forbidden，不是 error：这两者的处理不同——forbidden 要去
// 把这台 Mac 这个 Team 的 Key 换成 App Manager 角色的团队密钥。
func TestProbeTellsForbiddenApartFromAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/apps" {
			_, _ = w.Write([]byte(`{"data":[{"id":"app-1","type":"apps","attributes":{"bundleId":"com.anyfun.foundation","name":"A","sku":"X"}}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"code":"FORBIDDEN","detail":"not allowed"}]}`))
	}))
	defer server.Close()
	keys := writeKeyDir(t, "AB12CD34EF")
	var stdout, stderr bytes.Buffer
	args := []string{"--probe", "--team", "AB12CD34EF", "--keys", keys, "--base-url", server.URL,
		"--expect-bundle-id", "com.anyfun.foundation"}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if result := decodeOutcome(t, &stdout); result.Probe != probeForbidden {
		t.Fatalf("probe: %+v", result)
	}
}

// 参数不合法在碰任何文件之前就拒：这个程序以持有上传密钥的账户运行。
func TestUploadRefusesMalformedArguments(t *testing.T) {
	keys := writeKeyDir(t, "AB12CD34EF")
	for name, args := range map[string][]string{
		"no team":     {"--keys", keys, "--expect-bundle-id", "com.a.b", "--expect-version", "1.0.0", "--expect-build", "1"},
		"short team":  {"--team", "SHORT", "--keys", keys, "--expect-bundle-id", "com.a.b", "--expect-version", "1.0.0", "--expect-build", "1"},
		"bad bundle":  {"--team", "AB12CD34EF", "--keys", keys, "--expect-bundle-id", "not a bundle", "--expect-version", "1.0.0", "--expect-build", "1"},
		"bad version": {"--team", "AB12CD34EF", "--keys", keys, "--expect-bundle-id", "com.a.b", "--expect-version", "latest", "--expect-build", "1"},
		"bad build":   {"--team", "AB12CD34EF", "--keys", keys, "--expect-bundle-id", "com.a.b", "--expect-version", "1.0.0", "--expect-build", "x"},
		"extra args":  {"--team", "AB12CD34EF", "--keys", keys, "--expect-bundle-id", "com.a.b", "--expect-version", "1.0.0", "--expect-build", "1", "rm -rf /"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d (stdout %q)", name, code, stdout.String())
		}
	}
}

// 空包不传：一个 0 字节的 .ipa 传上去只会在 Apple 那边变成一次失败的处理，
// 而这个 build 号就用掉了。
func TestUploadRefusesAnEmptyPackage(t *testing.T) {
	asc := newFakeASC(t)
	keys := writeKeyDir(t, "AB12CD34EF")
	var stdout, stderr bytes.Buffer
	if code := run(uploadArgs(keys, asc.server.URL), strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatalf("an empty package was uploaded: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "empty") {
		t.Fatalf("stderr does not say why: %s", stderr.String())
	}
}
