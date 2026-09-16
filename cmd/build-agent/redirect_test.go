package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// otherOrigin 记下它收到的一切：重定向被跟随时，令牌与包体会出现在这里
type otherOrigin struct {
	srv     *httptest.Server
	mu      sync.Mutex
	hits    int
	tokens  []string
	payload int
}

func newOtherOrigin(t *testing.T) *otherOrigin {
	o := &otherOrigin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		o.mu.Lock()
		defer o.mu.Unlock()
		o.hits++
		o.tokens = append(o.tokens, r.Header.Get(headerMachineToken))
		o.payload += len(body)
		_, _ = w.Write([]byte(`{"sha256":"x","size":1,"release":{"id":"rel_x"}}`))
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *otherOrigin) assertUntouched(t *testing.T, what string) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.hits != 0 {
		t.Fatalf("%s: the other origin received %d requests (tokens %d non-empty, %d body bytes)",
			what, o.hits, countNonEmpty(o.tokens), o.payload)
	}
}

func countNonEmpty(values []string) int {
	n := 0
	for _, v := range values {
		if v != "" {
			n++
		}
	}
	return n
}

// API 源（或它前面的反代）回 3xx：构建机不跟随，令牌与包体都不会到另一个源；3xx 按错误处理且不重试
func TestRedirectsAreNeverFollowed(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			other := newOtherOrigin(t)
			var apiHits atomic.Int64
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				apiHits.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				http.Redirect(w, r, other.srv.URL+r.URL.Path, status)
			}))
			defer api.Close()
			c := newClient(config{Server: api.URL, MachineToken: testToken})
			job := claimedJob{ID: "bld_redirect0001", Attempt: 1}
			payload := bytes.Repeat([]byte("A"), 4096)
			file := filepath.Join(t.TempDir(), "unsigned.apk")
			if err := os.WriteFile(file, payload, 0o600); err != nil {
				t.Fatal(err)
			}

			calls := map[string]func() error{
				"claim": func() error { _, err := c.claim(context.Background(), []string{"android"}); return err },
				"heartbeat": func() error {
					return c.heartbeat(context.Background(), job, []string{"line"})
				},
				"unsigned upload": func() error {
					return c.uploadStream(context.Background(), job, "/unsigned/upload", file, strings.Repeat("0", 64), int64(len(payload)))
				},
				"icon": func() error {
					var sink bytes.Buffer
					return c.downloadIcon(context.Background(), job, "icon.png", &sink)
				},
				"ota ticket PUT on the API origin": func() error {
					var ticket uploadTicket
					ticket.Upload.URL = api.URL + "/v1/build-agent/jobs/bld_redirect0001/ota-artifact"
					return c.putTicket(context.Background(), job, ticket, file, int64(len(payload)))
				},
				"key registration": func() error { _, err := c.registerKey(context.Background(), "AAAA", nil); return err },
			}
			for name, call := range calls {
				before := apiHits.Load()
				err := call()
				if err == nil {
					t.Fatalf("%s: a redirect was treated as success", name)
				}
				if worthRetrying(err) {
					t.Fatalf("%s: a redirect is retried: %v", name, err)
				}
				if strings.Contains(err.Error(), testToken) {
					t.Fatalf("%s: the error message carries the token", name)
				}
				if apiHits.Load() != before+1 {
					t.Fatalf("%s: the API origin was called %d times", name, apiHits.Load()-before)
				}
				other.assertUntouched(t, name)
			}

			// withRetry 包一层也只调一次
			before := apiHits.Load()
			buf := newLogBuffer(newRedactor())
			err := withRetry(context.Background(), buf, "upload", 6, func(context.Context) error { return calls["unsigned upload"]() })
			if err == nil || apiHits.Load() != before+1 {
				t.Fatalf("a redirected upload was retried (%d calls): %v", apiHits.Load()-before, err)
			}
			other.assertUntouched(t, "retried upload")
		})
	}
}

// 整条任务：交付上传被重定向，任务判失败，另一个源收不到令牌与包
func TestRedirectedDeliveryFailsTheJob(t *testing.T) {
	rig := newRig(t)
	other := newOtherOrigin(t)
	rig.server.mu.Lock()
	rig.server.redirects["/unsigned/upload"] = other.srv.URL
	rig.server.mu.Unlock()
	rig.server.queueClaim(claimBody("bld_redirectJOB1", "apk"))
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("no job")
	}
	other.assertUntouched(t, "job delivery")
	fails := rig.server.callsTo("/fail")
	if len(fails) != 1 || !strings.Contains(string(fails[0].Body), "redirect") {
		t.Fatalf("the redirect did not fail the job: %+v", fails)
	}
	if len(rig.server.callsTo("/built")) != 0 {
		t.Fatal("the job was delivered anyway")
	}
}
