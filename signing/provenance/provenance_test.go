package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sampleStatement() Statement {
	return Statement{
		Version:           Version,
		Purpose:           Purpose,
		JobID:             "bld_AbCdEfGhIjKlMnOpQrStUv",
		Attempt:           1,
		TenantSlug:        "AnyFun",
		PackageName:       "com.anyfun.foundation",
		VersionCode:       47,
		VersionName:       "1.3.17",
		CommitSHA:         strings.Repeat("a1", 20),
		UnsignedSHA256:    strings.Repeat("0f", 32),
		UnsignedSize:      40513850,
		SBOMSHA256:        strings.Repeat("1e", 32),
		NativeFingerprint: strings.Repeat("c3", 20),
		BuilderID:         "mch_builderAAAAAAAAAAAAAAAA",
		BuiltAt:           "2026-09-16T08:00:00Z",
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	env, err := Sign(sampleStatement(), priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(env, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != sampleStatement() {
		t.Fatalf("round trip changed the statement: %+v", got)
	}
	// 字段顺序即序列化顺序：服务端与签名闸看到的原始字节以 {"v":1,"purpose": 开头
	raw, _ := base64.StdEncoding.DecodeString(env.Statement)
	if !strings.HasPrefix(string(raw), `{"v":1,"purpose":"rn-build-provenance","jobId":`) {
		t.Fatalf("unexpected field order: %s", raw)
	}
}

func TestVerifyRejectsWrongKeyAndTampering(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	env, err := Sign(sampleStatement(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, otherPub); !errors.Is(err, ErrSignature) {
		t.Fatalf("other key: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(env.Statement)
	changed := strings.Replace(string(raw), `"versionCode":47`, `"versionCode":48`, 1)
	tampered := Envelope{Statement: base64.StdEncoding.EncodeToString([]byte(changed)), Signature: env.Signature}
	if _, err := Verify(tampered, pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("changed statement: %v", err)
	}
	sig, _ := base64.StdEncoding.DecodeString(env.Signature)
	sig[0] ^= 1
	if _, err := Verify(Envelope{Statement: env.Statement, Signature: base64.StdEncoding.EncodeToString(sig)}, pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("changed signature: %v", err)
	}
	for name, e := range map[string]Envelope{
		"empty":         {},
		"short sig":     {Statement: env.Statement, Signature: base64.StdEncoding.EncodeToString(sig[:63])},
		"raw base64":    {Statement: strings.TrimRight(env.Statement, "="), Signature: env.Signature},
		"not base64":    {Statement: "***", Signature: env.Signature},
		"huge":          {Statement: strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxStatementSize)+4), Signature: env.Signature},
		"sig not b64":   {Statement: env.Statement, Signature: "@@"},
		"missing sig":   {Statement: env.Statement},
		"swapped roles": {Statement: env.Signature, Signature: env.Statement},
	} {
		if _, err := Verify(e, pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Verify(env, pub[:31]); err == nil {
		t.Fatal("accepted a short public key")
	}
}

// 签名对、内容不合法：必须报 ErrStatement，而不是照单全收。
func TestVerifyRejectsSignedButInvalidStatements(t *testing.T) {
	pub, priv := newKey(t)
	signRaw := func(raw string) Envelope {
		sig := ed25519.Sign(priv, signingInput([]byte(raw)))
		return Envelope{Statement: base64.StdEncoding.EncodeToString([]byte(raw)), Signature: base64.StdEncoding.EncodeToString(sig)}
	}
	good, _ := json.Marshal(sampleStatement())
	mutate := func(from, to string) string { return strings.Replace(string(good), from, to, 1) }
	for name, raw := range map[string]string{
		"unknown field":    strings.Replace(string(good), `{`, `{"extra":1,`, 1),
		"trailing data":    string(good) + `{}`,
		"wrong version":    mutate(`"v":1`, `"v":2`),
		"wrong purpose":    mutate(`"purpose":"rn-build-provenance"`, `"purpose":"rn-ota-provenance"`),
		"zero attempt":     mutate(`"attempt":1`, `"attempt":0`),
		"bad sha":          mutate(strings.Repeat("0f", 32), strings.Repeat("0F", 32)),
		"bad package":      mutate(`com.anyfun.foundation`, `com.anyfun.foundation;rm`),
		"negative size":    mutate(`"unsignedSize":40513850`, `"unsignedSize":-1`),
		"no fingerprint":   mutate(strings.Repeat("c3", 20), ``),
		"local time":       mutate(`2026-09-16T08:00:00Z`, `2026-09-16T16:00:00+08:00`),
		"control in name":  mutate(`"1.3.17"`, `"1.3.17[2J"`),
		"duplicate object": `[` + string(good) + `]`,
		"not json":         `hello`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(signRaw(raw), pub); !errors.Is(err, ErrStatement) {
				t.Fatalf("Verify = %v, want ErrStatement", err)
			}
		})
	}
}

// 域分隔：出处密钥对不带前缀的同一段字节签的名不能被当成出处签名。
func TestSignatureIsDomainSeparated(t *testing.T) {
	pub, priv := newKey(t)
	raw, _ := json.Marshal(sampleStatement())
	sig := ed25519.Sign(priv, raw)
	env := Envelope{Statement: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(sig)}
	if _, err := Verify(env, pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("an undomained signature verified: %v", err)
	}
}

func TestSignRejectsInvalidStatements(t *testing.T) {
	_, priv := newKey(t)
	for name, mutate := range map[string]func(*Statement){
		"job id":      func(s *Statement) { s.JobID = "../x" },
		"builder":     func(s *Statement) { s.BuilderID = "" },
		"commit":      func(s *Statement) { s.CommitSHA = "HEAD" },
		"versionCode": func(s *Statement) { s.VersionCode = 0 },
		"sbom":        func(s *Statement) { s.SBOMSHA256 = "" },
	} {
		s := sampleStatement()
		mutate(&s)
		if _, err := Sign(s, priv); err == nil {
			t.Errorf("%s: signed an invalid statement", name)
		}
	}
	if _, err := Sign(sampleStatement(), priv[:32]); err == nil {
		t.Fatal("accepted a short private key")
	}
	s := sampleStatement()
	s.CommitSHA = strings.Repeat("ab", 32) // SHA-256 仓库的对象 id
	if _, err := Sign(s, priv); err != nil {
		t.Fatalf("rejected a 64-char commit id: %v", err)
	}
}
