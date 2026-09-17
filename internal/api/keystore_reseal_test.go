package api

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
)

// 同证书重新封装的服务端把关（设计「同证书重新封装」）。签名闸侧的规则在 signing/internal/signer 里测。

func resealID(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return keystorebox.ResealIDPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// reseal 以 machine 身份交回一份重新封装，签名用 signer 的私钥。
func (f *gateFixture) reseal(machine gateMachine, id string, version int, upload keystorebox.Upload, signer ed25519.PrivateKey) *httptest.ResponseRecorder {
	f.t.Helper()
	signature, err := keystorebox.SignReseal(signer, id, upload)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.do(http.MethodPost, "/v1/signer/keystore-reseals", machine.Token, nil, map[string]any{
		"tenantSlug": f.slug, "keystoreVersion": version, "resealId": id, "upload": upload, "signature": signature,
	})
}

// currentKeystore 是库里这个租户的 build.keystore 记录与版本。
func (f *gateFixture) currentKeystore() (buildKeystoreRecord, int) {
	f.t.Helper()
	state, err := f.s.buildKeystoreStateFor(f.t.Context(), f.db, f.tenant)
	if err != nil || !state.configured() {
		f.t.Fatalf("build.keystore state: %+v %v", state, err)
	}
	return state.Record, state.Version
}

// TestDBKeystoreResealAddsRecipientsWithoutChangingTheCertificate：主签名闸把同一张证书重新封装给
// 多出来的收件人（新备签名闸），证书、包名、别名不变，发布身份不动，检查项带上新的收件人与 sealKind。
func TestDBKeystoreResealAddsRecipientsWithoutChangingTheCertificate(t *testing.T) {
	f := newGateFixture(t, 141)
	recoveryKey := f.registerRecoveryKey("recovery-2026")
	before, version := f.currentKeystore()
	_, identityBefore := f.keystoreVersions()

	upload := f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256,
		f.primary.X25519.PublicKey().Bytes(), f.standby.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes())
	id := resealID(t)
	if r := f.reseal(f.primary, id, version, upload, f.primary.Ed25519); r.Code != http.StatusOK {
		t.Fatalf("reseal: %d %s", r.Code, r.Body.String())
	}
	after, newVersion := f.currentKeystore()
	switch {
	case newVersion != version+1:
		t.Fatalf("keystore version: %d -> %d", version, newVersion)
	case after.CertificateSHA256 != before.CertificateSHA256 || after.PackageName != before.PackageName || after.KeyAlias != before.KeyAlias:
		t.Fatalf("a reseal must not change the identity: %+v", after)
	case after.SealKind != sealKindReseal || after.GenerationRequestID != id:
		t.Fatalf("sealKind/resealId: %+v", after)
	case len(after.Recipients) != 3:
		t.Fatalf("recipients: %v", after.Recipients)
	}
	if _, identityAfter := f.keystoreVersions(); identityAfter != identityBefore {
		t.Fatalf("a reseal must not touch the release identity: %d -> %d", identityBefore, identityAfter)
	}
	if f.auditCount(f.tenant, "build_keystore_resealed") != 1 {
		t.Fatal("the reseal was not audited")
	}
	item := f.checkItem(f.standby)
	if item == nil || item["sealKind"] != sealKindReseal || len(item["recipients"].([]any)) != 3 {
		t.Fatalf("check item after a reseal: %v", item)
	}
	// 重试（同一个 id 与签名）幂等
	if r := f.reseal(f.primary, id, version, upload, f.primary.Ed25519); r.Code != http.StatusOK {
		t.Fatalf("retrying the same reseal: %d %s", r.Code, r.Body.String())
	}
	if _, again := f.currentKeystore(); again != newVersion {
		t.Fatalf("a retried reseal wrote again: %d -> %d", newVersion, again)
	}
}

// TestDBKeystoreResealRefusesAnythingButNewRecipients：换证书、换包名、少主签名闸自己、少恢复公钥、
// 收件人不是登记过的、签名不对、版本旧、不是路由主、有待处理的生成请求——全部拒绝，库里不动。
func TestDBKeystoreResealRefusesAnythingButNewRecipients(t *testing.T) {
	f := newGateFixture(t, 142)
	recoveryKey := f.registerRecoveryKey("recovery-2026")
	before, version := f.currentKeystore()
	primaryKey, standbyKey, recovery := f.primary.X25519.PublicKey().Bytes(), f.standby.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes()
	stranger, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		upload       keystorebox.Upload
		machine      gateMachine
		signer       ed25519.PrivateKey
		staleVersion bool
		status       int
		code         string
		different    bool // 签名要用另一份 upload（签名与内容对不上）
	}{
		"another certificate": {
			upload: f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, newCertificateSHA256(), primaryKey, standbyKey, recovery),
			status: http.StatusUnprocessableEntity, code: "KEYSTORE_RESEAL_MISMATCH",
		},
		"another package": {
			upload: f.sealedUpload(f.slug, "com.gate.other", before.KeyAlias, before.CertificateSHA256, primaryKey, standbyKey, recovery),
			status: http.StatusUnprocessableEntity, code: "KEYSTORE_RESEAL_MISMATCH",
		},
		"another alias": {
			upload: f.sealedUpload(f.slug, before.PackageName, "other-release", before.CertificateSHA256, primaryKey, standbyKey, recovery),
			status: http.StatusUnprocessableEntity, code: "KEYSTORE_RESEAL_MISMATCH",
		},
		"without the primary's own box": {
			upload: f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, standbyKey, recovery),
			status: http.StatusUnprocessableEntity, code: "KEYSTORE_PRIMARY_RECIPIENT_MISSING",
		},
		"without a recovery key": {
			upload: f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, standbyKey),
			status: http.StatusUnprocessableEntity, code: "KEYSTORE_RECOVERY_RECIPIENT_MISSING",
		},
		"an unknown recipient": {
			upload: f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, stranger.PublicKey().Bytes(), recovery),
			status: http.StatusUnprocessableEntity, code: "BUILD_KEYSTORE_RECIPIENT_UNKNOWN",
		},
		"a stale version": {
			upload:       f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, standbyKey, recovery),
			staleVersion: true, status: http.StatusConflict, code: "KEYSTORE_RESEAL_STALE",
		},
		"the standby": {
			upload:  f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, standbyKey, recovery),
			machine: f.standby, signer: f.standby.Ed25519, status: http.StatusForbidden, code: "KEYSTORE_GENERATOR_NOT_PRIMARY",
		},
		"a signature over another upload": {
			upload: f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, standbyKey, recovery),
			status: http.StatusUnprocessableEntity, code: "KEYSTORE_RESEAL_SIGNATURE_INVALID", different: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			machine, signer, at := f.primary, f.primary.Ed25519, version
			if tc.machine.ID != "" {
				machine, signer = tc.machine, tc.signer
			}
			if tc.staleVersion {
				at = version + 7
			}
			id := resealID(t)
			signed := tc.upload
			if tc.different {
				signed = f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, recovery)
			}
			signature, err := keystorebox.SignReseal(signer, id, signed)
			if err != nil {
				t.Fatal(err)
			}
			r := f.do(http.MethodPost, "/v1/signer/keystore-reseals", machine.Token, nil, map[string]any{
				"tenantSlug": f.slug, "keystoreVersion": at, "resealId": id, "upload": tc.upload, "signature": signature,
			})
			if r.Code != tc.status || problemCode(t, r) != tc.code {
				t.Fatalf("%s: %d %s", name, r.Code, r.Body.String())
			}
			if _, now := f.currentKeystore(); now != version {
				t.Fatalf("%s: a refused reseal changed the keystore: %d -> %d", name, version, now)
			}
		})
	}

	// 有待处理的生成请求时不重新封装：生成本来就会换掉收件人
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusAccepted {
		t.Fatalf("generate: %d %s", r.Code, r.Body.String())
	}
	upload := f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256, primaryKey, standbyKey, recovery)
	r := f.reseal(f.primary, resealID(t), version, upload, f.primary.Ed25519)
	if r.Code != http.StatusConflict || problemCode(t, r) != "KEYSTORE_GENERATION_IN_PROGRESS" {
		t.Fatalf("reseal while a generation is pending: %d %s", r.Code, r.Body.String())
	}
}

// TestDBKeystoreResealCannotBorrowAGenerationSignature：生成签名与重新封装签名是两种消息，
// 互相冒充都不认。
func TestDBKeystoreResealCannotBorrowAGenerationSignature(t *testing.T) {
	f := newGateFixture(t, 143)
	recoveryKey := f.registerRecoveryKey("recovery-2026")
	before, version := f.currentKeystore()
	upload := f.sealedUpload(f.slug, before.PackageName, before.KeyAlias, before.CertificateSHA256,
		f.primary.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes())

	id := resealID(t)
	generationSignature, err := keystorebox.SignGeneration(f.primary.Ed25519, id, upload)
	if err != nil {
		t.Fatal(err)
	}
	r := f.do(http.MethodPost, "/v1/signer/keystore-reseals", f.primary.Token, nil, map[string]any{
		"tenantSlug": f.slug, "keystoreVersion": version, "resealId": id, "upload": upload, "signature": generationSignature,
	})
	if r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "KEYSTORE_RESEAL_SIGNATURE_INVALID" {
		t.Fatalf("a generation signature passed as a reseal: %d %s", r.Code, r.Body.String())
	}

	// 反过来也走不通：两种 id 的前缀不重叠，签名工具本身就不给用另一种 id 签
	if _, err := keystorebox.SignReseal(f.primary.Ed25519, "kgr_"+randomID(16), upload); err == nil {
		t.Fatal("a generation request id must not be signable as a reseal")
	}
	// 重新封装接口不收生成请求 id
	if r := f.do(http.MethodPost, "/v1/signer/keystore-reseals", f.primary.Token, nil, map[string]any{
		"tenantSlug": f.slug, "keystoreVersion": version, "resealId": "kgr_" + randomID(16), "upload": upload, "signature": generationSignature,
	}); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_KEYSTORE_RESEAL" {
		t.Fatalf("a generation request id on the reseal endpoint: %d %s", r.Code, r.Body.String())
	}
	// 交回生成的接口也不认重新封装的 id（没有这条请求）
	if r := f.deliverSigned(f.primary, id, upload, f.primary.ID, generationSignature); r.Code != http.StatusConflict ||
		problemCode(t, r) != generationStaleCode {
		t.Fatalf("a reseal id on the generation endpoint: %d %s", r.Code, r.Body.String())
	}
}

// TestDBResealedKeystoreStillValidatesItsShape：sealKind 与 resealId 的形状必须一致（备签名闸按
// sealKind 决定验哪种签名，对不上等于让它验错消息）。
func TestDBResealedKeystoreStillValidatesItsShape(t *testing.T) {
	generator := &keystoreGenerator{MachineID: machineIDPrefix + "_" + randomID(16), Name: "signer-a", Ed25519PublicKeySHA256: fingerprint.SHA256Hex([]byte("x"))}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	generator.Ed25519PublicKey = base64.StdEncoding.EncodeToString(public)
	generator.Ed25519PublicKeySHA256 = fingerprint.SHA256Hex(public)
	base := buildKeystoreRecord{
		Format: buildKeystoreRecordFormat, Sealed: "AA==", KeyAlias: "release", CertificateSHA256: newCertificateSHA256(),
		PackageName: "com.gate.shape", TenantSlug: "gate", Recipients: []string{newCertificateSHA256()},
		Generator: generator, GenerationSignature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	for name, tc := range map[string]struct {
		requestID string
		sealKind  string
		wantError bool
	}{
		"generation":                 {requestID: "kgr_" + randomID(16), sealKind: "", wantError: false},
		"reseal":                     {requestID: keystorebox.ResealIDPrefix + randomID(16), sealKind: sealKindReseal, wantError: false},
		"reseal id without the kind": {requestID: keystorebox.ResealIDPrefix + randomID(16), sealKind: "", wantError: true},
		"kind without a reseal id":   {requestID: "kgr_" + randomID(16), sealKind: sealKindReseal, wantError: true},
		"unknown kind":               {requestID: "kgr_" + randomID(16), sealKind: "whatever", wantError: true},
	} {
		record := base
		record.GenerationRequestID, record.SealKind = tc.requestID, tc.sealKind
		if err := record.validate(); (err != nil) != tc.wantError {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
