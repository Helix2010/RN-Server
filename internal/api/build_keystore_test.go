package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

// buildKeystoreServer 给签名密钥读写测试一个连着测试库、带主密钥的服务端，
// 并先登记一把打包机公钥：读接口的视图里带着它的登记状态。
func buildKeystoreServer(t *testing.T) *server {
	t.Helper()
	box, err := secretbox.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatalf("secretbox: %v", err)
	}
	s := &server{db: openTestDB(t), secrets: box}
	_, recipient, err := buildkeystore.NewAgentKey()
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	if err := s.saveBuildAgentKey(context.Background(), buildAgentKeyRecord{
		Current: recipient, Agent: "test-builder", RegisteredAt: iso(time.Now().UTC()),
	}, "tester"); err != nil {
		t.Fatalf("register agent key: %v", err)
	}
	return s
}

// 读和写回的是同一个资源，管理端两处用同一个 schema 解析。少两个键的表现是：
// 服务端明明存好了，界面却报"上传失败"，而错误说的是字段类型不对——上传这条路
// 就是因为这个从来没有成功过一次。
func TestDBBuildKeystoreReadAndWriteReturnTheSameShape(t *testing.T) {
	s := buildKeystoreServer(t)
	tenant := testTenant(4)

	c, recorder := testContext(t, tenant, http.MethodPut, "/v1/admin/build-keystore", map[string]any{
		"sealed": map[string]any{
			"v": 1, "kdf": "scrypt", "n": 65536, "r": 8, "p": 1,
			"salt": "c2FsdA==", "nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVy",
		},
		"keyAlias": "anyfun", "keystoreSha256": strings.Repeat("a", 64),
		"expectedVersion": 0, "reason": "upload sealed keystore", "confirm": true,
	})
	s.saveBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", recorder.Code, recorder.Body.String())
	}
	written := decodeBody(t, recorder)

	c, recorder = testContext(t, tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	s.getBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("read failed: %d %s", recorder.Code, recorder.Body.String())
	}
	read := decodeBody(t, recorder)

	for key := range read {
		if _, ok := written[key]; !ok {
			t.Fatalf("the write response is missing %q, which every reader of this resource expects", key)
		}
	}
	if written["keyAlias"] != read["keyAlias"] || written["version"] != read["version"] {
		t.Fatalf("write said %v, read says %v", written, read)
	}
}
