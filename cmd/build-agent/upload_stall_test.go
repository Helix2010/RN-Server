package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 连接卡死时不能干等单次请求的总时限（30 分钟）：连续 uploadStallTimeout 一个字节都送不出去就
// 断开，交给重试（设计 ios-tenant-delivery-tiers-2026-09-24 §3.3）。家用上行连机房只有几十 KB/s，
// 一个 .ipa 要传十几分钟，总时限不能收紧，只能另看"有没有进展"。
func TestUploadStreamGivesUpOnAStalledConnection(t *testing.T) {
	previous := uploadStallTimeout
	uploadStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { uploadStallTimeout = previous })

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读一点就不读了：对端不收，发送缓冲写满之后客户端就再也读不出文件
		_, _ = io.CopyN(io.Discard, r.Body, 1024)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	file := filepath.Join(t.TempDir(), "app.ipa")
	// 比回环接口的收发缓冲大得多，保证读文件那一侧真的会停住
	if err := os.WriteFile(file, make([]byte, 64<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	api := newClient(config{Server: server.URL, MachineToken: testToken})
	started := time.Now()
	err := api.uploadStream(context.Background(), claimedJob{ID: "bld_stall00001", Attempt: 1}, "/ipa/upload", file, strings.Repeat("0", 64), 64<<20)
	if err == nil {
		t.Fatal("a stalled upload succeeded")
	}
	if !worthRetrying(err) || !strings.Contains(err.Error(), "no bytes went out") {
		t.Fatalf("a stall must be retried and say so: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the stall was noticed only after %s", elapsed)
	}
}

// 读完之后等服务端回话不算卡住：服务端要写存储、做核对，那一段可能比 uploadStallTimeout 长。
func TestUploadStreamWaitsForTheServerAfterSendingEverything(t *testing.T) {
	previous := uploadStallTimeout
	uploadStallTimeout = 200 * time.Millisecond
	t.Cleanup(func() { uploadStallTimeout = previous })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(time.Second)
		_, _ = w.Write([]byte(`{"sha256":"` + strings.Repeat("0", 64) + `","size":3}`))
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "small.ipa")
	if err := os.WriteFile(file, []byte("ipa"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := newClient(config{Server: server.URL, MachineToken: testToken})
	if err := api.uploadStream(context.Background(), claimedJob{ID: "bld_slowreply1", Attempt: 1}, "/ipa/upload", file, strings.Repeat("0", 64), 3); err != nil {
		t.Fatalf("a slow reply after the whole body was sent was treated as a stall: %v", err)
	}
}
