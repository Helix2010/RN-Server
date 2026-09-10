package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/gin-gonic/gin"
)

const productionSigner = "1111111111111111111111111111111111111111111111111111111111111111"

func TestParseAndroidReleaseIdentityNormalizesAndValidates(t *testing.T) {
	got, err := parseAndroidReleaseIdentity([]byte(`{"packageName":" com.anyfun.wallet ","signerSha256":"11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11"}`))
	if err != nil || got.PackageName != "com.anyfun.wallet" || got.SignerSHA256 != productionSigner {
		t.Fatalf("parse = %+v, %v", got, err)
	}
	for name, raw := range map[string]string{
		"bad package":   `{"packageName":"anyfun","signerSha256":"` + productionSigner + `"}`,
		"short signer":  `{"packageName":"com.anyfun.wallet","signerSha256":"abc"}`,
		"debug signer":  `{"packageName":"com.anyfun.wallet","signerSha256":"` + reactNativeDebugSignerSHA256 + `"}`,
		"not json":      `{`,
		"empty package": `{"packageName":"","signerSha256":"` + productionSigner + `"}`,
	} {
		if _, err := parseAndroidReleaseIdentity([]byte(raw)); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestCheckAndroidReleaseIdentityOrdersRejections(t *testing.T) {
	pin := &androidReleaseIdentity{PackageName: "com.anyfun.wallet", SignerSHA256: productionSigner}
	debugAPK := apkinspect.Metadata{PackageName: "com.anyfun.wallet", SignerSHA256: strings.ToUpper(reactNativeDebugSignerSHA256)}
	if code, _ := checkAndroidReleaseIdentity(debugAPK, pin, false); code != "RELEASE_DEBUG_SIGNER" {
		t.Fatalf("debug key with pin = %s", code)
	}
	if code, _ := checkAndroidReleaseIdentity(debugAPK, nil, false); code != "RELEASE_DEBUG_SIGNER" {
		t.Fatalf("debug key without pin in development = %s", code)
	}
	good := apkinspect.Metadata{PackageName: "com.anyfun.wallet", SignerSHA256: productionSigner}
	if code, _ := checkAndroidReleaseIdentity(good, nil, true); code != "RELEASE_SIGNER_UNPINNED" {
		t.Fatalf("production without pin = %s", code)
	}
	if code, _ := checkAndroidReleaseIdentity(good, nil, false); code != "" {
		t.Fatalf("development without pin must pass, got %s", code)
	}
	if code, _ := checkAndroidReleaseIdentity(apkinspect.Metadata{PackageName: "com.anyfun.foundation", SignerSHA256: productionSigner}, pin, true); code != "RELEASE_PACKAGE_MISMATCH" {
		t.Fatalf("package mismatch = %s", code)
	}
	if code, _ := checkAndroidReleaseIdentity(apkinspect.Metadata{PackageName: "com.anyfun.wallet", SignerSHA256: strings.Repeat("2", 64)}, pin, true); code != "RELEASE_SIGNER_MISMATCH" {
		t.Fatalf("signer mismatch = %s", code)
	}
	if code, _ := checkAndroidReleaseIdentity(good, pin, true); code != "" {
		t.Fatalf("matching APK must pass, got %s", code)
	}
}

func TestObjectIntegrityMismatch(t *testing.T) {
	info := func(size int64, etag string) objectstore.ObjectInfo {
		return objectstore.ObjectInfo{Size: size, ETag: etag}
	}
	if got := objectIntegrityMismatch(info(100, "abc"), 100, "abc"); got != "" {
		t.Fatalf("matching object reported %q", got)
	}
	if got := objectIntegrityMismatch(info(101, "abc"), 100, "abc"); got != "size" {
		t.Fatalf("size change reported %q", got)
	}
	if got := objectIntegrityMismatch(info(100, "zzz"), 100, "abc"); got != "etag" {
		t.Fatalf("etag change reported %q", got)
	}
	// 分段上传对象的 ETag 是 "<md5>-<分段数>"：同一对象再次 Stat 得到同样的值，按字串比对即可
	multipart := "9bb58f26192e4ba00f01e2e7b136bbd8-3"
	if got := objectIntegrityMismatch(info(100, multipart), 100, multipart); got != "" {
		t.Fatalf("stable multipart etag reported %q", got)
	}
	if got := objectIntegrityMismatch(info(100, "9bb58f26192e4ba00f01e2e7b136bbd8"), 100, multipart); got != "etag" {
		t.Fatalf("single-part rewrite of a multipart object reported %q", got)
	}
	// 旧记录里手工写入的带引号值也能比对
	if got := objectIntegrityMismatch(info(100, "abc"), 100, `"abc"`); got != "" {
		t.Fatalf("quoted stored etag reported %q", got)
	}
	// 改列前入库的记录没有 ETag：只能比大小，大小一致视为通过（下载路径会记 warning）
	if got := objectIntegrityMismatch(info(100, "zzz"), 100, ""); got != "" {
		t.Fatalf("legacy record without etag reported %q", got)
	}
	if got := objectIntegrityMismatch(info(99, "zzz"), 100, ""); got != "size" {
		t.Fatalf("legacy record with size change reported %q", got)
	}
}

func TestVerifyStoredObjectAgainstAFakeStore(t *testing.T) {
	store := newFakeObjectStore()
	store.put("tenants/t1/releases/rel_1.apk", []byte("verified-apk-bytes"), "etag-verified")
	ctx := context.Background()
	if _, mismatch, err := verifyStoredObject(ctx, store, "tenants/t1/releases/rel_1.apk", 18, "etag-verified"); err != nil || mismatch != "" {
		t.Fatalf("unchanged object = %q, %v", mismatch, err)
	}
	// 同大小替换：字节数不变、ETag 变 → 拒绝（这正是 N33 要抓的场景）
	store.put("tenants/t1/releases/rel_1.apk", []byte("tampered-apk-bytes"), "etag-tampered")
	if _, mismatch, err := verifyStoredObject(ctx, store, "tenants/t1/releases/rel_1.apk", 18, "etag-verified"); err != nil || mismatch != "etag" {
		t.Fatalf("same-size replacement = %q, %v", mismatch, err)
	}
	if _, _, err := verifyStoredObject(ctx, store, "tenants/t1/releases/missing.apk", 18, "etag-verified"); err == nil {
		t.Fatal("missing object must surface a Stat error, not a mismatch")
	}
	store.statErr = errors.New("storage down")
	if _, _, err := verifyStoredObject(ctx, store, "tenants/t1/releases/rel_1.apk", 18, "etag-verified"); err == nil {
		t.Fatal("storage failure must surface an error so the handler answers 502, never serves")
	}
}

func TestStoredMetadataStringDistinguishesMissingFromInvalid(t *testing.T) {
	if got, err := storedMetadataString(nil, "objectEtag"); err != nil || got != "" {
		t.Fatalf("NULL metadata = %q, %v", got, err)
	}
	if got, err := storedMetadataString([]byte(`{"objectEtag":" abc "}`), "objectEtag"); err != nil || got != "abc" {
		t.Fatalf("stored value = %q, %v", got, err)
	}
	if got, err := storedMetadataString([]byte(`{"size":1}`), "objectEtag"); err != nil || got != "" {
		t.Fatalf("legacy record without the key = %q, %v", got, err)
	}
	if _, err := storedMetadataString([]byte(`{not json`), "objectEtag"); err == nil {
		t.Fatal("invalid file_metadata must be an error, not a legacy record")
	}
}

func TestObjectChangeNoticesDedupeWithinTTL(t *testing.T) {
	notices := &objectChangeNotices{ttl: 10 * time.Minute}
	start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	if !notices.shouldNotify("release:t1:rel_1:etag", start) {
		t.Fatal("first notice must be written")
	}
	if notices.shouldNotify("release:t1:rel_1:etag", start.Add(9*time.Minute)) {
		t.Fatal("repeat within TTL must be suppressed")
	}
	if !notices.shouldNotify("release:t1:rel_1:size", start.Add(time.Minute)) {
		t.Fatal("a different mismatch dimension is a different notice")
	}
	if !notices.shouldNotify("release:t1:rel_1:etag", start.Add(11*time.Minute)) {
		t.Fatal("after the TTL the notice must be written again")
	}
	if notices.shouldNotify("release:t1:rel_1:etag", start.Add(12*time.Minute)) {
		t.Fatal("the renewed notice must start a new suppression window")
	}
}

func TestUpdateAndroidReleaseIdentityRejectsInvalidBodiesBeforeTouchingTheDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// db 为 nil：任何走到数据库的路径都会 panic，所以这些用例同时证明校验先于存储
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, body := range map[string]string{
		"not confirmed":    `{"packageName":"com.anyfun.wallet","signerSha256":"` + productionSigner + `","expectedVersion":0,"reason":"pin key","confirm":false}`,
		"short reason":     `{"packageName":"com.anyfun.wallet","signerSha256":"` + productionSigner + `","expectedVersion":0,"reason":"x","confirm":true}`,
		"debug signer":     `{"packageName":"com.anyfun.wallet","signerSha256":"` + reactNativeDebugSignerSHA256 + `","expectedVersion":0,"reason":"pin key","confirm":true}`,
		"bad package":      `{"packageName":"wallet","signerSha256":"` + productionSigner + `","expectedVersion":0,"reason":"pin key","confirm":true}`,
		"short signer":     `{"packageName":"com.anyfun.wallet","signerSha256":"abc","expectedVersion":0,"reason":"pin key","confirm":true}`,
		"negative version": `{"packageName":"com.anyfun.wallet","signerSha256":"` + productionSigner + `","expectedVersion":-1,"reason":"pin key","confirm":true}`,
		"not json":         `{`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("PUT", "/v1/admin/release-identity/android", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		s.updateAndroidReleaseIdentity(c)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_RELEASE_IDENTITY") {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func TestAbsoluteURLForcesHTTPSInProduction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	request := func(proto string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "http://api.anyfun.win/v1/mobile/bootstrap", nil)
		c.Request.Host = "api.anyfun.win"
		if proto != "" {
			c.Request.Header.Set("x-forwarded-proto", proto)
		}
		return c
	}
	production := &server{cfg: config.Config{Environment: "production"}}
	if got := production.absoluteURL(request(""), "/v1/public/releases/rel_1/download"); got != "https://api.anyfun.win/v1/public/releases/rel_1/download" {
		t.Fatalf("production without x-forwarded-proto = %q", got)
	}
	if got := production.absoluteURL(request("http"), ""); got != "https://api.anyfun.win" {
		t.Fatalf("production with plain proxy header = %q", got)
	}
	development := &server{cfg: config.Config{Environment: "development"}}
	if got := development.absoluteURL(request(""), "/x"); got != "http://api.anyfun.win/x" {
		t.Fatalf("development without proxy header = %q", got)
	}
	if got := development.absoluteURL(request("https"), "/x"); got != "https://api.anyfun.win/x" {
		t.Fatalf("development behind TLS proxy = %q", got)
	}
}

func TestStoredMetadataFieldTreatsPresentButEmptyAsInvalid(t *testing.T) {
	if value, present, err := storedMetadataField([]byte(`{"size":1}`), "objectEtag"); err != nil || present || value != "" {
		t.Fatalf("absent key = %q, %v, %v", value, present, err)
	}
	if value, present, err := storedMetadataField([]byte(`{"objectEtag":"abc-2"}`), "objectEtag"); err != nil || !present || value != "abc-2" {
		t.Fatalf("present value = %q, %v, %v", value, present, err)
	}
	// 入库路径从不写空 ETag：键存在却为空或不是字串只能是数据被改过，必须是错误而不是"旧记录"
	for name, raw := range map[string]string{"empty": `{"objectEtag":""}`, "blank": `{"objectEtag":"  "}`, "number": `{"objectEtag":5}`} {
		if _, present, err := storedMetadataField([]byte(raw), "objectEtag"); err == nil || !present {
			t.Fatalf("%s: must be present-but-invalid, got present=%v err=%v", name, present, err)
		}
	}
}

func TestBackfillRefusesABaseReleaseThatNoLongerMatchesItsRecord(t *testing.T) {
	store := newFakeObjectStore()
	verified := []byte("verified-base-apk-bytes")
	store.put("tenants/t1/releases/rel_1.apk", verified, "etag-1")
	sum := sha256.Sum256(verified)
	s := &server{cfg: config.Config{ArtifactMaxSizeBytes: 1 << 20}}
	ctx := context.Background()
	source := backfillSource{Tenant: "t1", ReleaseID: "rel_1", ObjectKey: "tenants/t1/releases/rel_1.apk", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(verified))}

	// 同大小替换：字节数不变、sha256 变 → 拒绝回填，不解析替换件的身份
	store.put("tenants/t1/releases/rel_1.apk", []byte("tampered-base-apk-bytes"), "etag-2")
	if _, err := s.backfillReleaseApplicationID(ctx, store, source, "req-1"); !errors.Is(err, errBaseReleaseChanged) {
		t.Fatalf("same-size replacement must be errBaseReleaseChanged, got %v", err)
	}
	// 大小也变了：同样拒绝
	store.put("tenants/t1/releases/rel_1.apk", []byte("short"), "etag-3")
	if _, err := s.backfillReleaseApplicationID(ctx, store, source, "req-2"); !errors.Is(err, errBaseReleaseChanged) {
		t.Fatalf("size change must be errBaseReleaseChanged, got %v", err)
	}
	// 记录里没有 sha256 / 大小：无法核对，拒绝（不是"变了"，是"没法验"）
	if _, err := s.backfillReleaseApplicationID(ctx, store, backfillSource{Tenant: "t1", ReleaseID: "rel_1", ObjectKey: source.ObjectKey, Size: -1}, "req-3"); err == nil || errors.Is(err, errBaseReleaseChanged) {
		t.Fatalf("unverifiable record must fail without claiming a change, got %v", err)
	}
	// 对象与记录一致但不是合法 APK：走到解析并以解析错误失败，说明完整性核对已通过
	store.put("tenants/t1/releases/rel_1.apk", verified, "etag-1")
	if _, err := s.backfillReleaseApplicationID(ctx, store, source, "req-4"); err == nil || errors.Is(err, errBaseReleaseChanged) || !strings.Contains(err.Error(), "inspect base release") {
		t.Fatalf("matching object must proceed to inspection, got %v", err)
	}
}
