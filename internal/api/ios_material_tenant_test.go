package api

// 租户自己的材料卡（设计 ios-tenant-owned-signing-material-2026-09-25 §3.3、§12.4）：按交付方式的要求清单、
// Mac 核对结果、平台的紧急删除记录。这一组钉住：
//
//   - 三类材料的要求随交付方式变：自助上传拒收上传 Key，存着就标「不该有」；
//   - 「装好了」只看按租户自报的 Mac，Mac 报的原因按种类归到对应那一格；
//   - 机器只给台数，不给 id 与名字；
//   - 按租户自报的 Mac 只按这个租户自己的材料派活，同 Team 的别的租户拿不走它的「能签」。
//
// 需要真实 MySQL（RN_TEST_MYSQL_DSN），否则整组跳过。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testCertificateSHA1 = "0123456789ABCDEF0123456789ABCDEF01234567"

func tenantMaterialView(t *testing.T, f *gateFixture) map[string]any {
	t.Helper()
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/ios/material", nil)
	f.s.getTenantIOSMaterial(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("tenant material: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(t, recorder)
}

// tenantClaim 以按租户落材料的 Mac 身份认领一次（appleTeams 照旧报，给控制台显示与过渡用）。
func tenantClaim(f *gateFixture, machine gateMachine, reports []tenantMaterialReport) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(http.MethodPost, "/v1/build-agent/claim", machine.Token, nil, map[string]any{
		"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK},
		"agentCommit": "1111111111111111111111111111111111111111", "os": machineOSDarwin,
		"appleTeams": teamReport(materialTeam, materialBundle), "tenantMaterial": reports, "freeGb": 120,
		"capabilities": []string{machineCapabilityTenantMaterial},
	})
}

func readyReport(tenant string) tenantMaterialReport {
	return tenantMaterialReport{TenantID: tenant, TeamID: materialTeam, BundleIDs: []string{materialBundle},
		CertificateSHA1: testCertificateSHA1, CertificateReady: true, ExpiresAt: "2027-03-01T00:00:00Z", UploadProbe: uploadProbeOK}
}

func requirement(t *testing.T, body map[string]any, kind string) map[string]any {
	t.Helper()
	for _, raw := range body["requirements"].([]any) {
		if row := raw.(map[string]any); row["kind"] == kind {
			return row
		}
	}
	t.Fatalf("no requirement for %s: %v", kind, body["requirements"])
	return nil
}

func TestDBTenantIOSMaterialRequirements(t *testing.T) {
	f, macs := newIOSPool(t, 91, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)

	body := tenantMaterialView(t, f)
	if body["tenantId"] != f.tenant || body["delivery"] != iosDeliveryTestFlight {
		t.Fatalf("view: %v", body)
	}
	if identity := body["identity"].(map[string]any); identity["teamId"] != materialTeam || identity["bundleId"] != materialBundle {
		t.Fatalf("identity: %v", identity)
	}
	if recipients := body["recipients"].(map[string]any); recipients["builder"].(map[string]any)["publicKey"] != builder.pubBase64 {
		t.Fatalf("the browser needs the builder public key: %v", recipients)
	}
	for _, kind := range []string{"certificate", "profile", "upload-key"} {
		if row := requirement(t, body, kind); row["need"] != iosMaterialNeedRequired || row["status"] != iosMaterialStatusMissing {
			t.Fatalf("%s before anything is uploaded: %v", kind, row)
		}
	}

	uploadOwn(t, f, certificateMaterial(), builder)
	uploadOwn(t, f, profileFor(materialBundle), builder)
	uploadOwn(t, f, uploadMaterial(), uploader)
	body = tenantMaterialView(t, f)
	for _, kind := range []string{"certificate", "profile", "upload-key"} {
		if row := requirement(t, body, kind); row["status"] != iosMaterialStatusPending || row["item"] == nil {
			t.Fatalf("%s uploaded but not installed anywhere: %v", kind, row)
		}
	}

	// Mac 核对通过：三类都就绪，这台算一台能打这个租户的包
	if r := tenantClaim(f, macs[0], []tenantMaterialReport{readyReport(f.tenant)}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}
	body = tenantMaterialView(t, f)
	for _, kind := range []string{"certificate", "profile", "upload-key"} {
		if row := requirement(t, body, kind); row["status"] != iosMaterialStatusOK {
			t.Fatalf("%s installed on the Mac: %v", kind, row)
		}
	}
	if machines := body["machines"].(map[string]any); machines["total"] != float64(1) || machines["ready"] != float64(1) {
		t.Fatalf("machines: %v", machines)
	}
	// 打包机是平台的基础设施：租户只看得到台数
	if raw := tenantMaterialRaw(t, f); strings.Contains(raw, macs[0].ID) || strings.Contains(raw, macs[0].Name) {
		t.Fatalf("the tenant view names a build machine: %s", raw)
	}

	// Mac 核对描述文件没通过：这一格标失败、带原话，前缀去掉；证书照样就绪
	rejected := readyReport(f.tenant)
	rejected.BundleIDs = []string{}
	rejected.Problems = []string{"profile: the profile does not include this tenant's certificate", "certificate: unrelated"}
	if r := tenantClaim(f, macs[0], []tenantMaterialReport{rejected}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}
	body = tenantMaterialView(t, f)
	profile := requirement(t, body, "profile")
	if profile["status"] != iosMaterialStatusFailed || len(profile["problems"].([]any)) != 1 ||
		profile["problems"].([]any)[0] != "the profile does not include this tenant's certificate" {
		t.Fatalf("a profile the Mac refused: %v", profile)
	}
	if certificate := requirement(t, body, "certificate"); certificate["status"] != iosMaterialStatusOK {
		t.Fatalf("the certificate is still installed: %v", certificate)
	}
	if machines := body["machines"].(map[string]any); machines["ready"] != float64(0) {
		t.Fatalf("a Mac without the profile cannot build this app: %v", machines)
	}

	// 自助上传：上传 Key 拒收，还存着就是「不该有」
	setIOSDelivery(t, f, f.tenant, iosDeliveryIPA)
	if row := requirement(t, tenantMaterialView(t, f), "upload-key"); row["need"] != iosMaterialNeedRejected || row["status"] != iosMaterialStatusUnexpected {
		t.Fatalf("a self-upload tenant still holding an upload key: %v", row)
	}

	// 换了平台公钥：旧密文 Mac 解不开，标出来要重传
	next := newSealedboxKey(t)
	if r := f.adminDo(http.MethodPut, "/v1/admin/platform/ios-material/recipients", map[string]any{
		"builderPublicKey": next.pubBase64, "uploaderPublicKey": uploader.pubBase64,
		"expectedVersion": iosMaterialVersion(t, f), "reason": "rotate the builder key", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", r.Code, r.Body.String())
	}
	if row := requirement(t, tenantMaterialView(t, f), "certificate"); row["status"] != iosMaterialStatusStale {
		t.Fatalf("a certificate sealed to the old key: %v", row)
	}
}

func tenantMaterialRaw(t *testing.T, f *gateFixture) string {
	t.Helper()
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/ios/material", nil)
	f.s.getTenantIOSMaterial(c)
	return recorder.Body.String()
}

// 按租户自报的 Mac 只按租户自己的材料派活：同一个 Team 的另一个租户排的任务，这台领不走——
// 它手上那张证书是这个租户交的，签别人的包就是拿 A 的材料打 B 的包（设计 §4.4）。
func TestDBIOSClaimFollowsTheTenantsOwnMaterial(t *testing.T) {
	f, macs := newIOSPool(t, 92, 1)
	other := readyReport(testTenant(93))
	// 旧自报说这台有这个 Team 的材料；按租户的自报说有的是另一个租户的——作数的是后者
	if r := tenantClaim(f, macs[0], []tenantMaterialReport{other}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}
	if r := queueIOS(f, "1.4.0", 40); r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "NO_BUILDER_FOR_TEAM") {
		t.Fatalf("no Mac holds this tenant's material, queueing must say so: %d %s", r.Code, r.Body.String())
	}
	// 证书在索引里、但不在钥匙串里：不算能签
	notReady := readyReport(f.tenant)
	notReady.CertificateReady = false
	if r := tenantClaim(f, macs[0], []tenantMaterialReport{other, notReady}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}
	if r := queueIOS(f, "1.4.0", 40); r.Code != http.StatusConflict {
		t.Fatalf("a certificate missing from the keychain signs nothing: %d %s", r.Code, r.Body.String())
	}
	if r := tenantClaim(f, macs[0], []tenantMaterialReport{other, readyReport(f.tenant)}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}
	if r := queueIOS(f, "1.4.0", 40); r.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", r.Code, r.Body.String())
	}
	r := tenantClaim(f, macs[0], []tenantMaterialReport{other, readyReport(f.tenant)})
	if r.Code != http.StatusOK {
		t.Fatalf("the Mac holding this tenant's material must get the job: %d %s", r.Code, r.Body.String())
	}
	// 领到的任务带租户 id：Mac 按它找本租户的描述文件与证书
	if job := decodeBody(t, r); job["tenantId"] != f.tenant {
		t.Fatalf("the claimed job must carry the tenant id: %v", job["tenantId"])
	}
}

func TestDBIOSClaimRejectsAMalformedTenantReport(t *testing.T) {
	f, macs := newIOSPool(t, 94, 1)
	for name, mutate := range map[string]func(*tenantMaterialReport){
		"a tenant id that is a path": func(r *tenantMaterialReport) { r.TenantID = "../1" },
		"a short certificate sha1":   func(r *tenantMaterialReport) { r.CertificateSHA1 = "ABCDEF" },
		"an unknown upload probe":    func(r *tenantMaterialReport) { r.UploadProbe = "maybe" },
		"a wildcard bundle id":       func(r *tenantMaterialReport) { r.BundleIDs = []string{"*"} },
		"too many problems": func(r *tenantMaterialReport) {
			r.Problems = strings.Split(strings.Repeat("profile: x,", maxTenantMaterialProblems+1), ",")
		},
	} {
		report := readyReport(f.tenant)
		mutate(&report)
		if r := tenantClaim(f, macs[0], []tenantMaterialReport{report}); r.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	duplicate := readyReport(f.tenant)
	if r := tenantClaim(f, macs[0], []tenantMaterialReport{duplicate, duplicate}); r.Code != http.StatusBadRequest {
		t.Errorf("the same tenant and team twice: %d %s", r.Code, r.Body.String())
	}
}
