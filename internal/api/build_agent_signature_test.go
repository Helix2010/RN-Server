package api

// 清单签名走管理端接口交（设计 ios-mac-builders-home-network-2026-09-18 §5.6，实现文档
// 「已知缺口」那一条）。
//
// 这条路存在的理由是角色分离：签名在离线机器上做，那台机器不该有服务器的 shell。只认
// machine-bundles/<提交>/manifest.sig 这个文件，等于要求持有发布私钥的人同时握着服务器
// shell——而"服务端被攻破也换不出能过验的清单"这个前提，要求私钥既不在服务端、也不在能碰
// 服务端的人手上。
//
// 接口本身不是安全边界：它做的检查全是"帮运维当场发现拿错了文件"。真正的判据在每台 Mac
// 上，按人手抄的指纹 pin 住的那把公钥。

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

// clearStoredSignatures 清空签名表。
//
// **整表清，不是只清一个提交**：序号的判据是历史最高值（跨提交），留下任何一行都会让这一次
// 的用例以「序号没往上走」失败。machine_bundle_signatures 是平台级的表，不按租户也不按夹具
// 隔离，而本地跑测试用的是一个长期存在的库——上一次 go test 留下的行同样会踩到。
//
// 放在每个用例的开头，不放进 stageUnsignedBundles：有的用例要在同一次里签两个提交。
func clearStoredSignatures(t *testing.T, f *gateFixture) {
	t.Helper()
	if _, err := f.s.db.Exec(`DELETE FROM machine_bundle_signatures`); err != nil {
		t.Fatal(err)
	}
}

// stageUnsignedBundles 摆好安装包但**不签**，并放好发布公钥。返回私钥与清单原始字节。
func stageUnsignedBundles(t *testing.T, f *gateFixture, commit string) (ed25519.PrivateKey, []byte) {
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
	raw = []byte(strings.Replace(string(raw), `"`+doc.Commit+`"`, `"`+commit+`"`, 1))
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, machineReleaseKeyFile),
		[]byte(bundlesig.SSHPublicKeyLine(public, "rn-release-key")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return private, raw
}

// uploadSignature 把一份签名交给接口，返回状态码与响应体。
func uploadSignature(t *testing.T, f *gateFixture, signature bundlesig.Signature) (int, map[string]any) {
	t.Helper()
	r := f.adminDo(http.MethodPost, "/v1/admin/platform/build-agent-version/signature", signature)
	var body map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &body)
	return r.Code, body
}

// 运维要能在**还没签**的时候拿到清单——那正是要签的东西。以前 build-agent-version 在未签名
// 时连 commit 都是 null，等于问不出"现在该签哪个提交"。
func TestDBDeployedManifestIsAvailableBeforeItIsSigned(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	clearStoredSignatures(t, f)
	commit := strings.Repeat("a", 40)
	_, raw := stageUnsignedBundles(t, f, commit)

	r := f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version/manifest", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("manifest must be downloadable before it is signed: %d %s", r.Code, r.Body.String())
	}
	// 逐字节相同：签名签的是这些字节的摘要，重新编码一遍就对不上了
	if !bytes.Equal(r.Body.Bytes(), raw) {
		t.Fatal("the manifest must be handed over byte for byte")
	}
	if got := r.Header().Get("X-Bundle-Commit"); got != commit {
		t.Fatalf("the response must name the deployed commit: %q", got)
	}

	// 卡片在**还没签**的时候也要答得出部署着哪一版：那正是要拿去签的那一版。答不出的话
	// 运维只能去服务器上 readlink current，而这两条接口本来就是为了不必登服务器才开的。
	//
	// 但它走的是 deployedCommit 而不是 commit：commit 是批准按钮的输入，给未签名的包填上
	// 它，就等于让人能批准一个下载不到的版本——机器因版本不符停止认领，又拿不到那一版的
	// 安装包，队列安静地死掉。
	card := decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil))
	bundles, _ := card["bundles"].([]any)
	if len(bundles) == 0 {
		t.Fatalf("want a view of the bundles: %v", card)
	}
	for _, entry := range bundles {
		view, _ := entry.(map[string]any)
		if view["deployedCommit"] != commit {
			t.Fatalf("an unsigned bundle must still report what is deployed: %v", view)
		}
		if view["commit"] != nil {
			t.Fatalf("an unsigned bundle must not offer a commit to approve: %v", view)
		}
	}
}

// 正路：交一份签名，机器那条下发口立刻可用，而且下发的签名与交上来的逐字节相同。
func TestDBUploadedSignatureIsServedToMachines(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	clearStoredSignatures(t, f)
	commit := strings.Repeat("b", 40)
	private, raw := stageUnsignedBundles(t, f, commit)
	token := f.builder.Token

	// 交之前：什么都不给
	if r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=linux&arch=amd64", token, nil, nil); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unsigned bundle must not be handed out: %d %s", r.Code, r.Body.String())
	}

	signature, err := bundlesig.Sign(private, raw, commit, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := uploadSignature(t, f, signature); code != http.StatusOK {
		t.Fatalf("a valid signature was refused: %d %v", code, body)
	}

	r := f.do(http.MethodGet, "/v1/build-agent/bundle?os=linux&arch=amd64", token, nil, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("the bundle must be available once the signature is stored: %d %s", r.Code, r.Body.String())
	}
	var served struct {
		Commit         string              `json:"commit"`
		ManifestBase64 string              `json:"manifestBase64"`
		Signature      bundlesig.Signature `json:"signature"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &served); err != nil {
		t.Fatal(err)
	}
	if served.Commit != commit || served.Signature.Sequence != 7 {
		t.Fatalf("served the wrong thing: %+v", served)
	}
	// 库里存一趟不能改动签名的任何一个字节：机器要用它验签
	if served.Signature.Signature != signature.Signature {
		t.Fatal("the stored signature was not handed back byte for byte")
	}
	decoded, err := base64.StdEncoding.DecodeString(served.ManifestBase64)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatal("the served manifest must be the bytes that were signed")
	}
}

// 下面三条都是"拿错文件"的当场反馈。它们不是安全检查——真正的判据在 Mac 上——但传错了
// 立刻说清楚，好过等一台机器下完几十 MB 才失败，或者等到装机时报"签名验不过"让人以为
// 遭到了攻击。
func TestDBUploadedSignatureMustMatchWhatIsDeployed(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	clearStoredSignatures(t, f)
	commit := strings.Repeat("c", 40)
	private, raw := stageUnsignedBundles(t, f, commit)

	other := strings.Repeat("2", 40)
	wrongCommit, err := bundlesig.Sign(private, raw, other, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := uploadSignature(t, f, wrongCommit); code != http.StatusConflict {
		t.Fatalf("a signature for another commit was accepted: %d %v", code, body)
	}

	wrongManifest, err := bundlesig.Sign(private, append(raw, ' '), commit, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := uploadSignature(t, f, wrongManifest); code != http.StatusConflict {
		t.Fatalf("a signature covering another manifest was accepted: %d %v", code, body)
	}

	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := bundlesig.Sign(attacker, raw, commit, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 拿安装包里那份 release-key.pub 验一遍。这**只**帮运维查错：那把公钥和服务端同源，
	// 攻破服务端的人两样都能换，所以它证明不了任何事
	if code, body := uploadSignature(t, f, wrongKey); code != http.StatusConflict {
		t.Fatalf("a signature made with another key was accepted: %d %v", code, body)
	}
}

// 序号只增不减，而且是**跨提交**的：水位线记在每台机器上，机器只认"比我见过的最高值更高"，
// 不管那份清单指向哪一个提交。按提交比的话，给一个新提交签一个用过的序号会被放行，然后在
// 装过机的机器上被当成降级拒掉——而那条报错说的是序号太低，不会提示"你重置了序号"。
func TestDBUploadedSignatureSequenceMustGoUp(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	clearStoredSignatures(t, f)
	commit := strings.Repeat("d", 40)
	private, raw := stageUnsignedBundles(t, f, commit)
	// 控制台拿 highestSequence 预填下一次签名的 --sequence：一份都没签过时是 null
	highestSequence := func() any {
		t.Helper()
		return decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil))["highestSequence"]
	}
	if got := highestSequence(); got != nil {
		t.Fatalf("nothing is signed yet, highestSequence must be null: %v", got)
	}

	first, err := bundlesig.Sign(private, raw, commit, 5, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := uploadSignature(t, f, first); code != http.StatusOK {
		t.Fatalf("the first signature was refused: %d %v", code, body)
	}
	lower, err := bundlesig.Sign(private, raw, commit, 4, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := uploadSignature(t, f, lower); code != http.StatusConflict {
		t.Fatalf("a lower sequence was accepted: %d", code)
	}
	if code, _ := uploadSignature(t, f, first); code != http.StatusConflict {
		t.Fatalf("the same sequence was accepted again: %d", code)
	}
	higher, err := bundlesig.Sign(private, raw, commit, 6, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := uploadSignature(t, f, higher); code != http.StatusOK {
		t.Fatalf("re-signing with a higher sequence was refused: %d %v", code, body)
	}
	// 被拒的那两次（4、重交的 5）不算：最高的是接受过的 6
	if got := highestSequence(); got != float64(6) {
		t.Fatalf("highestSequence must be the highest accepted one: %v", got)
	}

	// 换个提交也不能重用序号：机器只比数字，不管那份清单指向哪一个提交
	otherCommit := strings.Repeat("f", 40)
	otherPrivate, otherRaw := stageUnsignedBundles(t, f, otherCommit)
	reused, err := bundlesig.Sign(otherPrivate, otherRaw, otherCommit, 6, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := uploadSignature(t, f, reused); code != http.StatusConflict {
		t.Fatalf("a used sequence was accepted for another commit: %d", code)
	}
}

// 文件那条老路要继续管用：SIGNING_MATERIAL.md 一直这么写，能碰服务器文件系统的场景下
// 仍然有效，也是从旧部署升上来时的兜底。
func TestDBSignatureOnDiskStillWorks(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	clearStoredSignatures(t, f)
	signStagedBundles(t, f, 3)

	r := f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("build-agent-version: %d %s", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), `"sequence":3`) {
		t.Fatalf("a signature left on disk must still be picked up: %s", r.Body.String())
	}
}

// 清单里列着 ≠ 文件在服务器上。部署那一段按文件名逐个拷，漏掉一个不会有任何地方报错，
// 而清单是一次性生成的、照样列着那一组。
//
// 2026-09-19 装第一台 Mac 时正是这样：builder-darwin-arm64.tar.gz 与 release-key.pub 从来
// 没被传上去过（CI 与 rn-foundation-apply 都硬编码了三个文件名），于是控制台说 darwin 那组
// "没问题"，describe 却一直 503。控制台说假话比它报错更糟——人会去别处找原因。
func TestDBBundleIsUnavailableWhenItsArchiveIsMissing(t *testing.T) {
	f := newGateFixture(t, 71)
	f.installBundles()
	clearStoredSignatures(t, f)
	commit := strings.Repeat("e", 40)
	private, raw := stageUnsignedBundles(t, f, commit)
	signature, err := bundlesig.Sign(private, raw, commit, 3, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := uploadSignature(t, f, signature); code != http.StatusOK {
		t.Fatalf("a valid signature was refused: %d %v", code, body)
	}
	if err := os.Remove(filepath.Join(f.s.machineBundleDir, machineBundleBuilderDarwin+".tar.gz")); err != nil {
		t.Fatal(err)
	}

	card := decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/build-agent-version", nil))
	bundles, _ := card["bundles"].([]any)
	var darwin map[string]any
	for _, entry := range bundles {
		view, _ := entry.(map[string]any)
		if view["bundle"] == machineBundleBuilderDarwin {
			darwin = view
		}
	}
	if darwin == nil {
		t.Fatalf("the darwin bundle is missing from the card: %v", card)
	}
	detail, _ := darwin["error"].(string)
	if !strings.Contains(detail, "not on the server") {
		t.Fatalf("a bundle whose archive never shipped must not be reported as fine: %v", darwin)
	}
	// linux 那组还在，不能被连累
	for _, entry := range bundles {
		view, _ := entry.(map[string]any)
		if view["bundle"] == machineRoleBuilder && view["error"] != nil {
			t.Fatalf("the linux bundle must still be usable: %v", view)
		}
	}
}
