package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

// 已登记机器的自升级（设计 ios-mac-builders-home-network-2026-09-18 §5.6）。
//
// 服务端在这条链路上只做两件事：批准一个版本（于是版本不对的机器在**空闲的时候**收到
// 409、自己去升），以及把清单、清单的离线签名与归档递过去。验签、核单调序号、核提交
// 都在机器那一侧——服务端手里没有那把发布私钥，这正是整条设计的要害。

const upgradeCommit = "1111111111111111111111111111111111111111"

// signStagedBundles 给夹具摆好的安装包目录补一份离线签名，返回发布公钥。
func signStagedBundles(t *testing.T, f *gateFixture, sequence int64) ed25519.PublicKey {
	t.Helper()
	dir := f.s.machineBundleDir
	manifestPath := filepath.Join(dir, machineBundleManifest)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Commit string `json:"commit"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// 夹具写的提交是一个短串，签名要求完整 sha：把它换成一个完整的再签
	rewritten := strings.Replace(string(raw), `"`+doc.Commit+`"`, `"`+upgradeCommit+`"`, 1)
	if rewritten == string(raw) {
		t.Fatal("cannot rewrite the staged manifest commit")
	}
	raw = []byte(rewritten)
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := bundlesig.Sign(private, raw, upgradeCommit, sequence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bundlesig.FileName), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	// 发布公钥与 manifest.json 并排放一份，与 build-bundles.sh 的产出一致：新 Mac 的
	// describe 要在下载归档之前拿到它验清单签名
	if err := os.WriteFile(filepath.Join(dir, machineReleaseKeyFile),
		[]byte(bundlesig.SSHPublicKeyLine(public, "rn-release-key")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return public
}

func TestDBAgentBundleIsOnlyHandedOutWhenItIsSigned(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	token := f.builder.Token

	// 还没签：一个字节都不给。没有签名的程序不该出现在任何一台 Mac 上
	if r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=darwin&arch=arm64", token, nil, nil); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unsigned bundle was handed out: %d %s", r.Code, r.Body.String())
	}
	public := signStagedBundles(t, f, 3)

	recorder := f.do(http.MethodGet, "/v1/build-agent/bundle?os=darwin&arch=arm64", token, nil, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("describe the darwin bundle: %d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	if body["bundle"] != machineBundleBuilderDarwin || body["commit"] != upgradeCommit {
		t.Fatalf("described: %v", body)
	}
	// 清单是 base64 的原始字节：签名签的是那些字节，重新编码一遍就对不上了
	manifest, err := base64.StdEncoding.DecodeString(body["manifestBase64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(body["signature"])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := bundlesig.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// 机器那一侧要做的就是这一步，这里替它做一遍，确认服务端递过来的东西自洽
	if err := bundlesig.Verify(public, manifest, signature); err != nil {
		t.Fatalf("what the server handed out does not verify: %v", err)
	}
	if signature.Sequence != 3 {
		t.Fatalf("sequence %d", signature.Sequence)
	}
	archive, _ := body["archive"].(map[string]any)
	if archive["name"] != machineBundleBuilderDarwin+".tar.gz" || archive["sha256"] == "" {
		t.Fatalf("archive: %v", archive)
	}
	download := f.do(http.MethodGet, "/v1/build-agent/bundle/archive?os=darwin&arch=arm64", token, nil, nil)
	if download.Code != http.StatusOK || download.Header().Get("x-content-sha256") != archive["sha256"] {
		t.Fatalf("download: %d %s", download.Code, download.Header().Get("x-content-sha256"))
	}
	// 不认识的 os/arch 不猜：Intel Mac 跑不了当前的 Xcode，给它一个 arm64 的包只会更难查
	if r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=darwin&arch=amd64", token, nil, nil); r.Code != http.StatusNotFound {
		t.Fatalf("darwin/amd64: %d", r.Code)
	}
	// 没有令牌就没有这条路
	if r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=linux&arch=amd64", "", nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("without a machine token: %d", r.Code)
	}
}

// 清单被改过、或者签名是给另一个提交签的：服务端自己就发现了，不让每台 Mac 各下一遍
// 几十 MB 才发现。
func TestDBAgentBundleRefusesAManifestThatDoesNotMatchItsSignature(t *testing.T) {
	f := newGateFixture(t, 72)
	f.installBundles()
	signStagedBundles(t, f, 1)
	token := f.builder.Token
	path := filepath.Join(f.s.machineBundleDir, machineBundleManifest)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=linux&arch=amd64", token, nil, nil); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("a manifest that no longer matches its signature was handed out: %d", r.Code)
	}
}

// 批准一个版本之后，版本不对的机器领不到任务——**在选任务之前**就 409，于是升级总是
// 发生在空闲的时候，正在跑的构建自然做完。
func TestDBApprovedAgentVersionStopsOutdatedMachinesFromClaiming(t *testing.T) {
	f, macs := newIOSPool(t, 73, 1)
	// 只有服务器上现在摆着的那一版才批得了（见 TestDBApproveAgentVersionOnlyTakesWhatIsDeployed），
	// 所以先把安装包摆成这个提交
	f.installBundles()
	clearStoredSignatures(t, f)
	stageUnsignedBundles(t, f, upgradeCommit)
	claim := func(commit string) *httptest.ResponseRecorder {
		body := map[string]any{
			"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK},
			"appleTeams": teamReport(poolTeamA, poolBundle),
		}
		if commit != "" {
			body["agentCommit"] = commit
		}
		return f.do(http.MethodPost, "/v1/build-agent/claim", macs[0].Token, nil, body)
	}
	if r := claim(upgradeCommit); r.Code != http.StatusNoContent {
		t.Fatalf("claim before any version was approved: %d %s", r.Code, r.Body.String())
	}
	approve := func(commit string, version int) *httptest.ResponseRecorder {
		return f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
			"commit": commit, "expectedVersion": version, "reason": "approve the new agent", "confirm": true,
		})
	}
	if r := approve(upgradeCommit, registryVersion(t, f)); r.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", r.Code, r.Body.String())
	}
	// 跟上了的机器照常认领
	if r := claim(upgradeCommit); r.Code != http.StatusNoContent {
		t.Fatalf("an up-to-date machine was refused: %d %s", r.Code, r.Body.String())
	}
	// 落后的、以及压根没报版本的旧代理都要被挡住，并被告知目标提交
	for name, commit := range map[string]string{"outdated": "2222222222222222222222222222222222222222", "silent": ""} {
		r := claim(commit)
		if r.Code != http.StatusConflict || problemCode(t, r) != "AGENT_UPGRADE_REQUIRED" {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body.String())
		}
		if body := decodeBody(t, r); body["agentCommit"] != upgradeCommit {
			t.Fatalf("%s: the machine was not told which commit to upgrade to: %v", name, body)
		}
	}
	// 撤销审批（空串）之后又回到"不管版本"
	if r := approve("", registryVersion(t, f)); r.Code != http.StatusOK {
		t.Fatalf("unpin: %d %s", r.Code, r.Body.String())
	}
	if r := claim("2222222222222222222222222222222222222222"); r.Code != http.StatusNoContent {
		t.Fatalf("after unpinning, any version may claim: %d %s", r.Code, r.Body.String())
	}
}

func TestDBApproveAgentVersionRefusesJunk(t *testing.T) {
	f := newGateFixture(t, 74)
	f.installBundles()
	clearStoredSignatures(t, f)
	stageUnsignedBundles(t, f, upgradeCommit)
	for name, commit := range map[string]any{
		"short":    "abc",
		"a branch": "main",
		"a number": 42,
	} {
		r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
			"commit": commit, "expectedVersion": registryVersion(t, f), "reason": "should be refused", "confirm": true,
		})
		if r.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	// 大写的 sha 归一成小写收下：git 打印的是小写，而人从别处复制过来的可能是大写；
	// 两种写法存进去会让"版本对不对"这条判断在字符串比较上失败
	upper := strings.ToUpper(upgradeCommit)
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": upper, "expectedVersion": registryVersion(t, f), "reason": "approve with an uppercase sha", "confirm": true,
	}); r.Code != http.StatusOK || decodeBody(t, r)["approvedAgentCommit"] != upgradeCommit {
		t.Fatalf("an uppercase sha was not normalised: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": "", "expectedVersion": registryVersion(t, f), "reason": "unpin", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("unpin: %d %s", r.Code, r.Body.String())
	}

	// 重复批准同一版当作冲突：控制台上那颗按钮不该在什么都没变的时候写一条审计
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": upgradeCommit, "expectedVersion": registryVersion(t, f), "reason": "approve", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("first approve: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": upgradeCommit, "expectedVersion": registryVersion(t, f), "reason": "approve again", "confirm": true,
	}); r.Code != http.StatusConflict {
		t.Fatalf("approving the same version twice: %d %s", r.Code, r.Body.String())
	}
}

// 控制台在批准之前要看见的那些事实（设计 C4）。
//
// 为什么这条读接口不能让整条请求失败：两组安装包的状态是独立的——darwin 那组可能还没
// 编出来，而这一页存在的理由正是"让人看见现在部署的是什么"。一组坏了就整页空白，等于
// 把要看的东西藏起来。
func TestDBBuildAgentVersionShowsWhatIsDeployedEvenWhenOneBundleIsBroken(t *testing.T) {
	f := newGateFixture(t, 76)
	f.installBundles()

	// 还没签：两组都各自带 error，但接口照常 200——不然控制台上什么都看不到
	body := decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil))
	if body["approvedAgentCommit"] != nil {
		t.Fatalf("nothing is approved yet: %v", body["approvedAgentCommit"])
	}
	bundles, ok := body["bundles"].([]any)
	if !ok || len(bundles) != 2 {
		t.Fatalf("want a view of both bundles, got %v", body["bundles"])
	}
	for _, entry := range bundles {
		bundle, _ := entry.(map[string]any)
		if bundle["error"] == nil {
			t.Fatalf("an unsigned bundle must say why it cannot be handed out: %v", bundle)
		}
		if bundle["commit"] != nil || bundle["sequence"] != nil {
			t.Fatalf("an unsigned bundle must not claim a commit: %v", bundle)
		}
	}

	public := signStagedBundles(t, f, 5)
	body = decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil))
	bundles, _ = body["bundles"].([]any)
	seen := map[string]map[string]any{}
	for _, entry := range bundles {
		bundle, _ := entry.(map[string]any)
		name, _ := bundle["bundle"].(string)
		seen[name] = bundle
	}
	darwin := seen[machineBundleBuilderDarwin]
	if darwin == nil {
		t.Fatalf("the darwin bundle is missing: %v", seen)
	}
	if darwin["error"] != nil {
		t.Fatalf("a signed bundle must not carry an error: %v", darwin)
	}
	if darwin["commit"] != upgradeCommit {
		t.Fatalf("commit = %v, want %s", darwin["commit"], upgradeCommit)
	}
	// 序号是防降级那道闸的全部依据，人在批准之前要能看见它
	if sequence, _ := darwin["sequence"].(float64); sequence != 5 {
		t.Fatalf("sequence = %v, want 5", darwin["sequence"])
	}
	// 发布公钥指纹是人拿来和密码管理器里记的那个比的
	if darwin["publicKeySha256"] != bundlesig.PublicKeySHA256(public) {
		t.Fatalf("publicKeySha256 = %v, want %s", darwin["publicKeySha256"], bundlesig.PublicKeySHA256(public))
	}
	if darwin["query"] != "darwin/arm64" {
		t.Fatalf("query = %v, want darwin/arm64", darwin["query"])
	}
	archive, _ := darwin["archive"].(map[string]any)
	if archive == nil || archive["sha256"] == nil || archive["name"] == nil {
		t.Fatalf("the archive digest is what the operator checks against the CI log: %v", darwin)
	}

	// 批准之后这里要能看到它，否则人没法确认刚才那一下生效了
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": upgradeCommit, "expectedVersion": registryVersion(t, f), "reason": "approve after checking", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", r.Code, r.Body.String())
	}
	body = decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil))
	if body["approvedAgentCommit"] != upgradeCommit {
		t.Fatalf("approvedAgentCommit = %v, want %s", body["approvedAgentCommit"], upgradeCommit)
	}
}

// 批准一个**不是服务器上现在摆着的那一版**，等于造一个谁都到不了的目标：被挡住的机器
// 去取安装包，而那个接口只下发当前这一版 → 503；就算取到了，升级程序也会以"签名里的
// 提交不是我被告知要装的那个"拒绝。
//
// 2026-09-19 真机停摆就是这么来的：批准了 A，CI 随后部署了 B，一台机器超前、一台落后，
// 两台都不等于 A，全都领不到活——而控制台上它们还都显示"在线"，因为版本闸在记完心跳之后
// 才拦。
func TestDBApproveAgentVersionOnlyTakesWhatIsDeployed(t *testing.T) {
	f := newGateFixture(t, 75)
	f.installBundles()
	clearStoredSignatures(t, f)
	deployed := strings.Repeat("c", 40)
	stageUnsignedBundles(t, f, deployed)

	stale := strings.Repeat("d", 40)
	r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": stale, "expectedVersion": registryVersion(t, f), "reason": "pin a commit that is no longer deployed", "confirm": true,
	})
	if r.Code != http.StatusConflict || problemCode(t, r) != "AGENT_VERSION_NOT_DEPLOYED" {
		t.Fatalf("a commit the server cannot hand out was approved: %d %s", r.Code, r.Body.String())
	}
	if detail, _ := decodeBody(t, r)["detail"].(string); !strings.Contains(detail, deployed) {
		t.Errorf("the refusal does not name the commit that can be approved: %q", detail)
	}

	// 当前部署的那一版照收
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": deployed, "expectedVersion": registryVersion(t, f), "reason": "approve what is deployed", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("the deployed commit was refused: %d %s", r.Code, r.Body.String())
	}
	// "不管版本"任何时候都能撤：它是出了事之后恢复服务的那一下，不该被任何检查挡住
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version", map[string]any{
		"commit": "", "expectedVersion": registryVersion(t, f), "reason": "unpin to recover", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("unpinning was refused: %d %s", r.Code, r.Body.String())
	}
}

// 安装包没签时那句 503 要说"还没签"，不能说成"去部署安装包"。机器把这句话原样打在装机
// 屏幕上、升级程序把它写进失败记录再报给控制台——说错方向的代价是运维去重新部署一遍毫无
// 问题的包，而真正要做的事（离线签一份清单交上来）没人提。
func TestDBUnsignedBundleSaysItIsUnsignedNotUndeployed(t *testing.T) {
	f := newGateFixture(t, 76)
	f.installBundles()
	clearStoredSignatures(t, f)
	stageUnsignedBundles(t, f, strings.Repeat("e", 40))

	r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=darwin&arch=arm64", f.builder.Token, nil, nil)
	if r.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unsigned bundle was handed out: %d %s", r.Code, r.Body.String())
	}
	detail, _ := decodeBody(t, r)["detail"].(string)
	if !strings.Contains(detail, "signature") {
		t.Errorf("the 503 does not say the bundles are unsigned: %q", detail)
	}
	if strings.Contains(detail, "deploy the machine bundles") {
		t.Errorf("the 503 still blames deployment for a signing problem: %q", detail)
	}
}
