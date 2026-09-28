package main

// 按租户落盘（设计 ios-tenant-owned-signing-material-2026-09-25 §4、§12）：控制进程这一侧。
//
// 这一组盯五件：取清单带能力、旧版服务端时一切照旧；收到按租户的清单就切过去且不回落；
// 核对不过的那一版不反复试；清单里没有了就撤（墓碑），旧布局在新布局装齐后清掉；认领里只在
// 按租户时报 tenantMaterial，领到任务后按 (租户, Team, bundle) 复核、把租户交给执行进程。

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

const (
	tenantA  = "1000000001"
	tenantB  = "1000000002"
	teamID   = "J4JDFC8LCC"
	bundleID = "com.anyfun.foundation"
)

// recorderScript 是假的角色程序：参数逐行记进 <名字>.calls，密文追加进 <名字>.stdin。
// dir 下出现 fail-<名字> 文件时，按它的内容失败（内容就是它要说的那句话）。
func recorderScript(dir, name string) string {
	return "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + dir + "/" + name + ".calls\n" +
		"if [ -f " + dir + "/fail-" + name + " ]; then cat >/dev/null; cat " + dir + "/fail-" + name + "; exit 1; fi\n" +
		"case \"$*\" in\n" +
		"  *remove*) printf '%s' '{\"removed\":true,\"existed\":true}';;\n" +
		"  *list-keys*) printf '%s' '{\"teams\":[],\"tenants\":{}}';;\n" +
		"  *) cat >> " + dir + "/" + name + ".stdin; printf '%s' '{\"installed\":true}';;\n" +
		"esac\n"
}

func tenantMaterialRig(t *testing.T) (*agent, *fakeServer, string) {
	t.Helper()
	a, server, dir := materialRig(t)
	for _, name := range []string{"build-runner", "ios-upload"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(recorderScript(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return a, server, dir
}

func tenantEntry(tenant, kind, scope, purpose string, version int64, legacy bool) map[string]any {
	entry := listEntry(kind, teamID, scope, purpose, version)
	entry["tenantId"], entry["legacy"] = tenant, legacy
	return entry
}

func recordedLines(t *testing.T, dir, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func failNext(t *testing.T, dir, name, message string) {
	t.Helper()
	path := filepath.Join(dir, "fail-"+name)
	if message == "" {
		_ = os.Remove(path)
		return
	}
	if err := os.WriteFile(path, []byte(message+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (a *agent) syncNow(ctx context.Context) {
	a.lastMaterialSync = time.Time{}
	a.syncIOSMaterial(ctx)
}

// 旧版服务端不认能力、回的清单没有 layout：取清单时照样带上能力，其余一切照旧——不带 --tenant、
// 本机记录还是旧格式、认领里不报 tenantMaterial。
func TestAnOldServerKeepsThePerTeamLayout(t *testing.T) {
	a, server, dir := tenantMaterialRig(t)
	server.material = []map[string]any{listEntry("certificate", teamID, "", iosmaterial.PurposeBuilder, 3)}
	server.materialBoxes = map[string][]byte{"certificate/J4JDFC8LCC/": []byte(`{"pretend":"certificate"}`)}

	a.syncIOSMaterial(context.Background())

	calls := server.callsTo("/v1/build-agent/ios-material")
	if len(calls) != 1 || calls[0].Query != "capability=tenant-signing-material" {
		t.Fatalf("the list must be asked for with the capability: %+v", calls)
	}
	for _, line := range recordedLines(t, dir, "build-runner.calls") {
		if strings.Contains(line, "--tenant") {
			t.Fatalf("a per-team material was installed as a tenant's: %s", line)
		}
	}
	raw, err := os.ReadFile(filepath.Join(a.cfg.StateDir, installedMaterialFile))
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]int64
	if err := json.Unmarshal(raw, &flat); err != nil || flat["certificate/J4JDFC8LCC/"] != 3 {
		t.Fatalf("the record must keep its old shape under an old server: %s", raw)
	}
	if a.tenantMode() {
		t.Fatal("an old server switched the machine to the per-tenant layout")
	}
	a.cfg.Platforms = []string{"ios"}
	a.iosScan = fakeIOSInventory
	if request := a.claimRequest(context.Background()); request.TenantMaterial != nil {
		t.Fatal("tenantMaterial was reported to a server that cannot parse it")
	}
}

// 收到按租户的清单：切过去并记下来，按证书、描述文件、上传 Key 的顺序装，带 --tenant（迁移来的 v1
// 再带 --legacy）；之后服务端回了按 Team 的清单也不回落，认领里什么 iOS 材料都不报。
func TestATenantListSwitchesTheMachineForGood(t *testing.T) {
	a, server, dir := tenantMaterialRig(t)
	server.materialLayout = materialLayoutTenant
	server.material = []map[string]any{
		tenantEntry(tenantA, "upload-key", "", iosmaterial.PurposeUploader, 7, true),
		tenantEntry(tenantA, "profile", bundleID, iosmaterial.PurposeBuilder, 6, false),
		tenantEntry(tenantA, "certificate", "", iosmaterial.PurposeBuilder, 5, false),
	}
	server.materialBoxes = map[string][]byte{
		tenantA + "/upload-key/J4JDFC8LCC/":                   []byte(`{"pretend":"upload key"}`),
		tenantA + "/profile/J4JDFC8LCC/com.anyfun.foundation": []byte(`{"pretend":"profile"}`),
		tenantA + "/certificate/J4JDFC8LCC/":                  []byte(`{"pretend":"certificate"}`),
	}

	a.syncIOSMaterial(context.Background())

	stdin := strings.Join(recordedLines(t, dir, "build-runner.stdin"), "")
	if strings.Index(stdin, "certificate") < 0 || strings.Index(stdin, "certificate") > strings.Index(stdin, "profile") {
		t.Fatalf("the certificate must be installed before the profile that is checked against it: %s", stdin)
	}
	for _, line := range recordedLines(t, dir, "build-runner.calls") {
		if !strings.Contains(line, "--tenant "+tenantA) || strings.Contains(line, "--legacy") {
			t.Fatalf("runner call: %s", line)
		}
	}
	if calls := recordedLines(t, dir, "ios-upload.calls"); len(calls) != 1 || !strings.Contains(calls[0], "--install-key") ||
		!strings.Contains(calls[0], "--tenant "+tenantA+" --legacy") {
		t.Fatalf("uploader calls: %v", calls)
	}
	for _, call := range server.callsTo("/ios-material/box") {
		if !strings.Contains(call.Query, "tenantId="+tenantA) {
			t.Fatalf("a tenant's box was fetched without the tenant: %s", call.Query)
		}
	}
	record := readMaterialRecord(a.cfg.StateDir)
	if record.Layout != materialLayoutTenant || record.Installed[tenantA+"/certificate/J4JDFC8LCC/"] != 5 ||
		record.Installed[tenantA+"/profile/J4JDFC8LCC/com.anyfun.foundation"] != 6 || record.Installed[tenantA+"/upload-key/J4JDFC8LCC/"] != 7 {
		t.Fatalf("record %+v", record)
	}

	// 服务端回滚到按 Team：不回落，也不装它给的东西
	server.materialLayout = ""
	server.material = []map[string]any{listEntry("certificate", teamID, "", iosmaterial.PurposeBuilder, 9)}
	server.materialBoxes["certificate/J4JDFC8LCC/"] = []byte(`{"pretend":"per-team certificate"}`)
	before := len(recordedLines(t, dir, "build-runner.calls"))
	a.syncNow(context.Background())
	if got := len(recordedLines(t, dir, "build-runner.calls")); got != before {
		t.Fatal("a per-team list was installed on a machine that already signs per tenant")
	}
	if !a.tenantMode() || readMaterialRecord(a.cfg.StateDir).Layout != materialLayoutTenant {
		t.Fatal("the machine fell back to the per-team layout")
	}
	a.cfg.Platforms = []string{"ios"}
	a.iosScan = func(context.Context) iosInventory { return readyTenantInventory() }
	request := a.claimRequest(context.Background())
	if request.TenantMaterial != nil || len(request.AppleTeams) != 0 {
		t.Fatalf("with the server back on the per-team list, no iOS material may be reported: %+v", request)
	}
	server.materialLayout = materialLayoutTenant
	a.syncNow(context.Background())
	if request := a.claimRequest(context.Background()); request.TenantMaterial == nil || len(*request.TenantMaterial) != 1 {
		t.Fatalf("tenantMaterial must come back once the server hands out material per tenant: %+v", request)
	}
}

// 核对不过的那一版记下来，不再反复试；清单上出现新版本才再试。一时的失败（不带 rejected:）下一轮照常再试。
// 证书换了，之前对着旧证书核不过的描述文件要重新核。
func TestARejectedVersionIsNotRetried(t *testing.T) {
	a, server, dir := tenantMaterialRig(t)
	server.materialLayout = materialLayoutTenant
	profileAt := func(version int64) {
		server.material = []map[string]any{tenantEntry(tenantA, "profile", bundleID, iosmaterial.PurposeBuilder, version, false)}
		server.materialBoxes[tenantA+"/profile/J4JDFC8LCC/com.anyfun.foundation"] = []byte(`{"pretend":"profile"}`)
	}
	runs := func() int { return len(recordedLines(t, dir, "build-runner.calls")) }

	failNext(t, dir, "build-runner", "build-runner: error: rejected: the profile does not include the tenant's certificate ABC")
	profileAt(6)
	a.syncNow(context.Background())
	a.syncNow(context.Background())
	if runs() != 1 {
		t.Fatalf("a rejected version was tried %d times", runs())
	}
	problems := a.tenantProblems()[tenantA+"/"+teamID]
	if len(problems) != 1 || problems[0] != "profile: the profile does not include the tenant's certificate ABC" {
		t.Fatalf("problems %v", problems)
	}
	profileAt(7)
	a.syncNow(context.Background())
	if runs() != 2 {
		t.Fatal("a new version was not tried")
	}

	failNext(t, dir, "build-runner", "build-runner: error: cannot unlock the signing keychain")
	profileAt(8)
	a.syncNow(context.Background())
	a.syncNow(context.Background())
	if runs() != 4 {
		t.Fatalf("a failure that is not a rejection must be retried every round: %d runs", runs())
	}

	// 证书到了：同一轮里描述文件重新核
	failNext(t, dir, "build-runner", "build-runner: error: rejected: the profile does not include the tenant's certificate ABC")
	profileAt(9)
	a.syncNow(context.Background())
	failNext(t, dir, "build-runner", "")
	server.material = append(server.material, tenantEntry(tenantA, "certificate", "", iosmaterial.PurposeBuilder, 10, false))
	server.materialBoxes[tenantA+"/certificate/J4JDFC8LCC/"] = []byte(`{"pretend":"certificate"}`)
	a.syncNow(context.Background())
	if record := readMaterialRecord(a.cfg.StateDir); record.Installed[tenantA+"/profile/J4JDFC8LCC/com.anyfun.foundation"] != 9 {
		t.Fatalf("the profile was not checked again after the certificate arrived: %+v", record)
	}
	if len(a.tenantProblems()) != 0 {
		t.Fatalf("problems of installed slots must be cleared: %v", a.tenantProblems())
	}
}

// 墓碑：清单完整时，本机装过、清单里没有的租户格一律撤；旧布局的格在新布局装齐之后清掉
// （旧证书只从记录里拿掉，钥匙串不动）。清单被截断时一概不动。
func TestTenantTombstonesAndThePerTeamCleanup(t *testing.T) {
	a, server, dir := tenantMaterialRig(t)
	server.materialLayout = materialLayoutTenant
	server.material = []map[string]any{
		tenantEntry(tenantA, "certificate", "", iosmaterial.PurposeBuilder, 5, false),
		tenantEntry(tenantA, "profile", bundleID, iosmaterial.PurposeBuilder, 6, false),
	}
	seed := func() {
		if err := writeMaterialRecord(a.cfg.StateDir, materialRecord{Layout: materialLayoutTenant, Installed: map[string]int64{
			tenantA + "/certificate/J4JDFC8LCC/":                  5,
			tenantA + "/profile/J4JDFC8LCC/com.anyfun.foundation": 6,
			tenantA + "/upload-key/J4JDFC8LCC/":                   7,
			tenantB + "/profile/J4JDFC8LCC/com.b.app":             3,
			"certificate/J4JDFC8LCC/":                             1,
			"profile/J4JDFC8LCC/com.anyfun.foundation":            1,
			"upload-key/J4JDFC8LCC/":                              1,
		}}); err != nil {
			t.Fatal(err)
		}
		a.layout = ""
	}

	seed()
	server.materialTruncated = true
	a.syncNow(context.Background())
	if calls := recordedLines(t, dir, "build-runner.calls"); len(calls) != 0 {
		t.Fatalf("a truncated list removed something: %v", calls)
	}

	server.materialTruncated = false
	a.syncNow(context.Background())
	runner := strings.Join(recordedLines(t, dir, "build-runner.calls"), "\n")
	uploader := strings.Join(recordedLines(t, dir, "ios-upload.calls"), "\n")
	for _, want := range []string{
		"remove-ios-material --signing-dir " + a.cfg.MachineEnv[jobspec.IOSSigningDirEnv] + " --tenant " + tenantB + " --kind profile --team J4JDFC8LCC --scope com.b.app",
		"remove-ios-material --signing-dir " + a.cfg.MachineEnv[jobspec.IOSSigningDirEnv] + " --kind profile --team J4JDFC8LCC --scope com.anyfun.foundation",
	} {
		if !strings.Contains(runner, want) {
			t.Errorf("runner was not asked to %q:\n%s", want, runner)
		}
	}
	for _, want := range []string{"--remove-key --tenant " + tenantA + " --team J4JDFC8LCC", "--remove-key --team J4JDFC8LCC"} {
		if !strings.Contains(uploader, want) {
			t.Errorf("uploader was not asked to %q:\n%s", want, uploader)
		}
	}
	if strings.Contains(runner, "--kind certificate") {
		t.Errorf("a per-team certificate must stay in the keychain: %s", runner)
	}
	record := readMaterialRecord(a.cfg.StateDir)
	if len(record.Installed) != 2 || record.Installed[tenantA+"/certificate/J4JDFC8LCC/"] != 5 {
		t.Fatalf("record %+v", record)
	}

	// 有一格还没装上：租户格照样撤，旧布局先留着
	seed()
	_ = os.Remove(filepath.Join(dir, "build-runner.calls"))
	_ = os.Remove(filepath.Join(dir, "ios-upload.calls"))
	server.material = append(server.material, tenantEntry(tenantA, "upload-key", "", iosmaterial.PurposeUploader, 8, false))
	server.materialBoxes[tenantA+"/upload-key/J4JDFC8LCC/"] = []byte(`{"pretend":"new key"}`)
	failNext(t, dir, "ios-upload", "cannot write the key")
	a.syncNow(context.Background())
	if record := readMaterialRecord(a.cfg.StateDir); record.Installed["profile/J4JDFC8LCC/com.anyfun.foundation"] != 1 ||
		record.Installed[tenantB+"/profile/J4JDFC8LCC/com.b.app"] != 0 {
		t.Fatalf("with one slot still pending, only the tenant tombstones may run: %+v", record)
	}
}

// profileWithCertificates 造一份描述文件，DeveloperCertificates 里放给定的「证书」字节。
func profileWithCertificates(team, bundle string, expires time.Time, certificates ...[]byte) []byte {
	var data strings.Builder
	for _, der := range certificates {
		data.WriteString("<data>" + base64.StdEncoding.EncodeToString(der) + "</data>")
	}
	return []byte("\x30\x82cms<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" +
		"<key>ExpirationDate</key><date>" + expires.UTC().Format(time.RFC3339) + "</date>" +
		"<key>TeamIdentifier</key><array><string>" + team + "</string></array>" +
		"<key>DeveloperCertificates</key><array>" + data.String() + "</array>" +
		"<key>Entitlements</key><dict><key>application-identifier</key><string>" + team + "." + bundle + "</string>" +
		"<key>aps-environment</key><string>production</string></dict></dict></plist>\x00sig")
}

func sha1Of(b []byte) string {
	digest := sha1.Sum(b)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

// 按租户盘点：证书就绪看钥匙串里有没有索引里那个 SHA-1；描述文件要包含租户当前那张证书；
// 问题都带种类前缀；按 Team 汇总的那份只算就绪的。
func TestTenantInventory(t *testing.T) {
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	certA, certB, other := []byte("certificate A"), []byte("certificate B"), []byte("some other certificate")
	certificateExpiry := now.AddDate(0, 3, 0)
	profileExpiry := now.AddDate(0, 6, 0)
	scanner := iosScanner{
		SigningDir: t.TempDir(), TenantLayout: true, RequireUploadKey: true, Now: func() time.Time { return now },
		IdentityHashes: func(context.Context, string) (map[string]bool, error) {
			return map[string]bool{sha1Of(certA): true}, nil
		},
		CertificateExpiry: func(context.Context, string) (map[string]time.Time, error) {
			return map[string]time.Time{sha1Of(certA): certificateExpiry}, nil
		},
		TenantCertificates: func() (map[string]string, error) {
			return map[string]string{tenantA + "/" + teamID: sha1Of(certA), tenantB + "/" + teamID: sha1Of(certB)}, nil
		},
		TenantProfiles: func() map[string][]byte {
			return map[string][]byte{
				tenantA + "/" + teamID + "/app.mobileprovision":   profileWithCertificates(teamID, bundleID, profileExpiry, other, certA),
				tenantA + "/" + teamID + "/stale.mobileprovision": profileWithCertificates(teamID, "com.anyfun.old", profileExpiry, other),
				tenantB + "/" + teamID + "/b.mobileprovision":     profileWithCertificates(teamID, "com.b.app", profileExpiry, certB),
			}
		},
		UploadKeyTenants: func(context.Context) (map[string]map[string]bool, error) {
			return map[string]map[string]bool{tenantA: {teamID: true}}, nil
		},
		ProbeTenant: func(_ context.Context, tenant, team string, bundles []string) string {
			if tenant != tenantA || team != teamID || len(bundles) == 0 {
				t.Errorf("probed %s/%s %v", tenant, team, bundles)
			}
			return "ok"
		},
		InstallProblems: map[string][]string{tenantB + "/" + teamID: {"certificate: macOS cannot import this .p12"}},
	}
	inv := scanner.scan(context.Background())
	if !inv.TenantLayout || len(inv.Tenants) != 2 {
		t.Fatalf("inventory %+v", inv)
	}
	a, b := inv.Tenants[0], inv.Tenants[1]
	if a.TenantID != tenantA || !a.CertificateReady || strings.Join(a.BundleIDs, ",") != bundleID || a.UploadProbe != "ok" ||
		!a.ExpiresAt.Equal(certificateExpiry) || a.APSEnvironment != "production" {
		t.Fatalf("tenant A %+v", a)
	}
	if len(a.Problems) != 1 || !strings.HasPrefix(a.Problems[0], "profile: com.anyfun.old does not include the tenant's current certificate") {
		t.Fatalf("tenant A problems %v", a.Problems)
	}
	// 描述文件本身合格（bundleIds 照报），但证书不在钥匙串里：服务端看 certificateReady 不派
	if b.CertificateReady || strings.Join(b.BundleIDs, ",") != "com.b.app" || b.UploadProbe != uploadProbeMissing {
		t.Fatalf("tenant B %+v", b)
	}
	if len(b.Problems) != 2 || b.Problems[0] != "certificate: macOS cannot import this .p12" || !strings.HasPrefix(b.Problems[1], "certificate: identity ") {
		t.Fatalf("tenant B problems %v", b.Problems)
	}
	if len(inv.Teams) != 1 || strings.Join(inv.Teams[0].BundleIDs, ",") != bundleID {
		t.Fatalf("the per-team summary may only count ready tenants: %+v", inv.Teams)
	}
	if !inv.coversTenant(tenantA, teamID, bundleID) || inv.coversTenant(tenantB, teamID, "com.b.app") || inv.coversTenant(tenantB, teamID, bundleID) {
		t.Fatal("coversTenant")
	}
}

func readyTenantInventory() iosInventory {
	return iosInventory{TenantLayout: true, Tenants: []tenantMaterial{{
		TenantID: tenantA, TeamID: "AB12CD34EF", BundleIDs: []string{bundleID}, CertificateSHA1: strings.Repeat("A", 40),
		CertificateReady: true, ExpiresAt: time.Now().Add(90 * 24 * time.Hour).UTC(), UploadProbe: "ok",
		Problems: []string{"profile: something"},
	}}, Teams: []appleTeamMaterial{{TeamID: "AB12CD34EF", BundleIDs: []string{bundleID}, UploadProbe: "ok"}}}
}

// 认领里的 tenantMaterial：按租户落盘、服务端也按租户时才有；一项都没有也要报成 []。
func TestClaimRequestCarriesTheTenantMaterial(t *testing.T) {
	rig := newRig(t)
	a := rig.agent
	a.cfg.Platforms = []string{"ios"}
	a.layout, a.serverLayout = materialLayoutTenant, materialLayoutTenant
	a.iosScan = func(context.Context) iosInventory { return readyTenantInventory() }
	raw, err := json.Marshal(a.claimRequest(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		TenantMaterial []map[string]any `json:"tenantMaterial"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || len(body.TenantMaterial) != 1 {
		t.Fatalf("claim body %s", raw)
	}
	got := body.TenantMaterial[0]
	for key, want := range map[string]any{"tenantId": tenantA, "teamId": "AB12CD34EF", "certificateReady": true,
		"certificateSha1": strings.Repeat("A", 40), "uploadProbe": "ok"} {
		if got[key] != want {
			t.Errorf("%s = %v, want %v (%s)", key, got[key], want, raw)
		}
	}
	a.iosScan = func(context.Context) iosInventory { return iosInventory{TenantLayout: true} }
	raw, _ = json.Marshal(a.claimRequest(context.Background()))
	if !strings.Contains(string(raw), `"tenantMaterial":[]`) {
		t.Fatalf("a per-tenant machine with nothing installed must still say so: %s", raw)
	}
}

// 端到端：按租户落盘的机器领到一条 iOS 任务，执行进程只拿这个租户的描述文件、按索引里的 SHA-1
// 钉签名身份；上传用这个租户的 Key。租户不明、这个租户没有材料时不开工。
func TestATenantIOSJobSignsWithThatTenantsMaterial(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	sha := strings.Repeat("C", 40)
	setup := func(t *testing.T) *testRig {
		rig := newRig(t)
		rig.agent.cfg.Platforms = []string{"ios"}
		rig.agent.cfg.IOSUpload = true
		rig.agent.cfg.IOSUploader = fakeUploader(t, rig, `{"uploaded":true,"uploadedByEarlierAttempt":false,"detail":"uploaded","probe":""}`)
		rig.agent.layout = materialLayoutTenant
		rig.agent.iosScan = func(context.Context) iosInventory { return readyTenantInventory() }
		signing := rig.agent.cfg.MachineEnv[jobspec.IOSSigningDirEnv]
		if err := os.WriteFile(filepath.Join(signing, jobspec.IOSTenantCertificatesFileName),
			[]byte(`{"`+tenantA+`/AB12CD34EF":"`+sha+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(signing, "profiles", "tenants", tenantA, "AB12CD34EF")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, bundleID+".mobileprovision"), []byte("tenant profile"), 0o600); err != nil {
			t.Fatal(err)
		}
		return rig
	}
	claim := func(rig *testRig, tenant string) {
		body := claimBody("bld_e2eIOStenant1", "apk")
		body["platform"] = "ios"
		if tenant != "" {
			body["tenantId"] = tenant
		}
		rig.server.queueClaim(body)
		if !rig.agent.pollOnce(context.Background()) {
			t.Fatal("the agent did not work on the claimed job")
		}
	}

	rig := setup(t)
	claim(rig, tenantA)
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("the job failed: %s", fails[0].Body)
	}
	signing := rig.agent.cfg.MachineEnv[jobspec.IOSSigningDirEnv]
	if got := readRecorded(t, rig, "ios-profiles-dir.txt"); got != filepath.Join(signing, "profiles", "tenants", tenantA) {
		t.Fatalf("the build script was not pointed at the tenant's profiles: %q", got)
	}
	if got := readRecorded(t, rig, "ios-signing-certificate.txt"); got != sha {
		t.Fatalf("the signing identity was not pinned to the tenant's certificate: %q", got)
	}
	if args := readRecorded(t, rig, "ios-upload.args"); !strings.Contains(args, "--tenant "+tenantA) {
		t.Fatalf("the upload must use the tenant's key: %s", args)
	}

	for name, c := range map[string]struct {
		tenant string
		want   string
		prep   func(*testRig)
	}{
		"no tenant":      {"", "did not say which tenant", nil},
		"another tenant": {tenantB, "no usable signing material of this tenant", nil},
		"no index on disk": {tenantA, "no certificate of tenant", func(rig *testRig) {
			_ = os.Remove(filepath.Join(rig.agent.cfg.MachineEnv[jobspec.IOSSigningDirEnv], jobspec.IOSTenantCertificatesFileName))
		}},
	} {
		rig := setup(t)
		if c.prep != nil {
			c.prep(rig)
		}
		claim(rig, c.tenant)
		fails := rig.server.callsTo("/fail")
		if len(fails) != 1 || !strings.Contains(string(fails[0].Body), c.want) {
			t.Errorf("%s: expected a failure saying %q, got %d: %v", name, c.want, len(fails), fails)
		}
		if calls := rig.server.callsTo("/ios-release"); len(calls) != 0 {
			t.Errorf("%s: the job was completed", name)
		}
	}
}
