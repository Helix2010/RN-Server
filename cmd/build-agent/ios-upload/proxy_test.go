package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/ascapi"
)

// 代理走参数：sudoers 对这个程序是 NOSETENV，环境变量进不来。这里确认 --proxy 真的被用上——
// 目标写成一个不存在的主机名，只有经代理才可能拿到回答。
func TestRequestsGoThroughTheProxyGivenOnTheCommandLine(t *testing.T) {
	var sawHost atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost.Store(r.Host)
		switch r.URL.Path {
		case "/v1/apps":
			_, _ = w.Write([]byte(`{"data":[{"id":"app-1","type":"apps","attributes":{"bundleId":"com.anyfun.foundation","name":"AnyFun","sku":"X"}}]}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"code":"FORBIDDEN_ERROR","detail":"not allowed"}]}`))
		}
	}))
	defer proxy.Close()
	keys := writeKeyDir(t, "AB12CD34EF")
	args := []string{"--probe", "--team", "AB12CD34EF", "--keys", keys, "--base-url", "http://asc.invalid",
		"--expect-bundle-id", "com.anyfun.foundation", "--proxy", proxy.URL, "--no-proxy", "localhost"}
	var stdout, stderr bytes.Buffer
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if got, _ := sawHost.Load().(string); got != "asc.invalid" {
		t.Fatalf("the proxy saw host %q; the request did not go through it (stdout %s)", got, stdout.String())
	}
	if result := decodeOutcome(t, &stdout); result.Probe != probeForbidden {
		t.Fatalf("probe = %+v", result)
	}
}

func TestMalformedProxyArgumentsAreRefused(t *testing.T) {
	keys := writeKeyDir(t, "AB12CD34EF")
	for name, extra := range map[string][]string{
		"credentials":      {"--proxy", "http://user:pass@127.0.0.1:7897"},
		"no scheme":        {"--proxy", "127.0.0.1:7897"},
		"bad no-proxy":     {"--proxy", "http://127.0.0.1:7897", "--no-proxy", "a.example;touch /tmp/x"},
		"no-proxy spacing": {"--proxy", "http://127.0.0.1:7897", "--no-proxy", "a b"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(append(uploadArgs(keys, "http://asc.invalid"), extra...), strings.NewReader("x"), &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

// 找 App 记录是上传的第一个请求。2026-09-23 真机上它一次 TLS 握手超时就让整条任务失败，
// 前面已经编译了一个小时。连不上就再试；钥匙被拒不试，那不会自己好。
func TestFindingTheAppRetriesTransientFailuresButNotRejections(t *testing.T) {
	restore := retryPause
	retryPause = time.Millisecond
	defer func() { retryPause = restore }()
	key, err := readKey(filepath.Join(writeKeyDir(t, "AB12CD34EF"), "AB12CD34EF"))
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < findAppAttempts {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"app-1","type":"apps","attributes":{"bundleId":"com.anyfun.foundation"}}]}`))
	}))
	defer flaky.Close()
	var stderr bytes.Buffer
	app, err := findAppWithRetry(context.Background(), ascapi.Client{Key: key, BaseURL: flaky.URL}, &stderr, "com.anyfun.foundation")
	if err != nil || app.ID != "app-1" || calls.Load() != findAppAttempts {
		t.Fatalf("app %+v, err %v, calls %d", app, err, calls.Load())
	}
	if !strings.Contains(stderr.String(), "retrying") {
		t.Fatalf("retries are not logged: %q", stderr.String())
	}

	calls.Store(0)
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer rejecting.Close()
	if _, err := findAppWithRetry(context.Background(), ascapi.Client{Key: key, BaseURL: rejecting.URL}, &stderr, "com.anyfun.foundation"); err == nil || calls.Load() != 1 {
		t.Fatalf("a rejected key was retried: err %v, calls %d", err, calls.Load())
	}
}
