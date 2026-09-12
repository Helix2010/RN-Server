package api

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/siwe"
)

var sigField = regexp.MustCompile(`sig="([^"]*)"`)

// 客户端会做的事：从头里取出 sig，对**收到的原始字节**恢复签名者，与钉住的地址比。
func verifyAsClient(t *testing.T, header string, body []byte) string {
	t.Helper()
	match := sigField.FindStringSubmatch(header)
	if match == nil {
		t.Fatalf("header has no sig: %q", header)
	}
	raw, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		t.Fatalf("sig is not base64: %v", err)
	}
	address, err := siwe.RecoverAddress(string(body), raw)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	return address
}

func TestBootstrapSignatureVerifiesAgainstTheBytesSent(t *testing.T) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// 与 writeSignedBootstrap 同路：map 序列化一次，签的就是这串字节
	body, err := json.Marshal(gin.H{"schemaVersion": 1, "issuedAt": 1789178790393, "wallet": gin.H{"chains": []string{"eth"}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signature, err := siwe.SignPersonal(key, body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	header := bootstrapSignatureHeader(signature, "main")

	if got, want := verifyAsClient(t, header, body), siwe.AddressOf(key); !strings.EqualFold(got, want) {
		t.Fatalf("recovered %s, want %s", got, want)
	}
	if !strings.Contains(header, `keyid="main"`) || !strings.Contains(header, `alg="`+bootstrapSigningAlgorithm+`"`) {
		t.Fatalf("header is missing keyid or alg: %q", header)
	}
}

func TestBootstrapSignatureFailsOnASingleChangedByte(t *testing.T) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	body := []byte(`{"update":{"minSupportedVersion":"0.9.0"}}`)
	signature, err := siwe.SignPersonal(key, body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	header := bootstrapSignatureHeader(signature, "main")

	// 把 minSupportedVersion 改掉——这正是攻击者最想改的那一行
	tampered := []byte(`{"update":{"minSupportedVersion":"0.0.0"}}`)
	if got, want := verifyAsClient(t, header, tampered), siwe.AddressOf(key); strings.EqualFold(got, want) {
		t.Fatal("a tampered body still recovered the signer address")
	}
}

// sf-string 里 `"` 和 `\` 必须转义，否则一个 keyid 就能把这条头拆成两半
func TestBootstrapSignatureHeaderEscapesStringValues(t *testing.T) {
	header := bootstrapSignatureHeader([]byte{1, 2, 3}, `we"ird\id`)
	if !strings.Contains(header, `keyid="we\"ird\\id"`) {
		t.Fatalf("keyid was not escaped: %q", header)
	}
}

// 没配密钥时不签，也不报错：这条链路要能分两个版本上线（服务端先签、客户端后验）
func TestUnconfiguredTenantGetsNoSignatureHeader(t *testing.T) {
	s := &server{}
	if got := s.signBootstrapBody(t.Context(), "tenant-without-a-key", []byte("{}")); got != "" {
		t.Fatalf("expected no header, got %q", got)
	}
}

func TestParseBootstrapSigningKeyRejectsIncompleteRecords(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":       `{`,
		"missing keyId":  `{"privateKey":"abc"}`,
		"missing secret": `{"keyId":"main"}`,
		"blank keyId":    `{"keyId":"  ","privateKey":"abc"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBootstrapSigningKey([]byte(raw)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
