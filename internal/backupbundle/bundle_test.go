package backupbundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

type memorySink struct{ packages map[string]*bytes.Buffer }

func newSink() *memorySink { return &memorySink{packages: map[string]*bytes.Buffer{}} }

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }

func (s *memorySink) Writer(pair string) (io.WriteCloser, error) {
	buf := &bytes.Buffer{}
	s.packages[pair] = buf
	return nopCloser{buf}, nil
}

type holder struct {
	slot string
	key  *rsa.PrivateKey
}

func testHolders(t *testing.T) []holder {
	t.Helper()
	out := make([]holder, 0, backupcontainer.SlotCount)
	for _, slot := range backupcontainer.SlotNames {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, holder{slot: slot, key: key})
	}
	return out
}

func recipientsOf(t *testing.T, holders []holder) []Recipient {
	t.Helper()
	out := make([]Recipient, 0, len(holders))
	for _, h := range holders {
		fp, err := backupcontainer.Fingerprint(&h.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Recipient{Slot: h.slot, Fingerprint: fp, Key: &h.key.PublicKey, Holder: "holder-" + h.slot})
	}
	return out
}

// sealInnerFor 模拟打包机：把一份明文封给某个槽位并签名
func sealInnerFor(t *testing.T, pub *rsa.PublicKey, signer ed25519.PrivateKey, plain []byte) InnerPart {
	t.Helper()
	var sealed bytes.Buffer
	meta := backupcontainer.Meta{Layer: backupcontainer.LayerInner, Seq: 7, InstanceID: "test-1"}
	if err := backupcontainer.Seal(&sealed, pub, meta, bytes.NewReader(plain), int64(len(plain))); err != nil {
		t.Fatal(err)
	}
	return InnerPart{Sealed: sealed.Bytes(), Signature: backupcontainer.SignPayload(signer, sealed.Bytes())}
}

func testInput(t *testing.T, holders []holder) Input {
	t.Helper()
	in, _ := testInputWithSigner(t, holders)
	return in
}

// testInputWithSigner 额外返回签名公钥，给要跑验签的测试用
func testInputWithSigner(t *testing.T, holders []holder) (Input, ed25519.PublicKey) {
	t.Helper()
	signingPub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PublicKey{}
	for _, h := range holders {
		byslot[h.slot] = &h.key.PublicKey
	}
	// 内层明文必须是一个 tar——生产里 produceBackup 就是先打 tar 再封。
	// 封一个裸字符串的话，恢复脚本最后那步 `tar xf plain.tar` 会报
	// 「不是 tar」，而那是夹具不真实，不是代码的问题
	agentPlain, err := tarFiles(map[string][]byte{
		"agent-key":                         []byte("the build machine identity"),
		"keystores/acme/keystore.p12":       []byte("a signing key in the clear"),
		"keystores/acme/store-password.txt": []byte("the password for it"),
	})
	if err != nil {
		t.Fatal(err)
	}
	inner := map[string]InnerPart{}
	for _, slot := range backupcontainer.InnerSlots() {
		inner[slot] = sealInnerFor(t, byslot[slot], signer, agentPlain)
	}
	return Input{
		Seq:        7,
		InstanceID: "test-1",
		CreatedAt:  time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC),
		Recipients: recipientsOf(t, holders),
		AgentInner: inner,
		ServerFiles: map[string][]byte{
			"rn-foundation.env": []byte("STORAGE_MASTER_KEY=the-master-key\n"),
			"bin/rn-server":     []byte("ELF-ish bytes"),
		},
		ServerManifest: []FileEntry{
			{Path: "rn-foundation.env", Size: 34, SHA256: strings.Repeat("a", 64),
				Target: "/etc/rn-foundation.env", Mode: "0600", Owner: "root:root"},
			{Path: "bin/rn-server", Size: 13, SHA256: strings.Repeat("b", 64),
				Target: "/opt/rn/bin/rn-server", Mode: "0755", Owner: "root:root"},
		},
		AgentManifest: []FileEntry{
			{Path: "agent-key", Size: 32, SHA256: strings.Repeat("c", 64),
				Target: "/var/lib/rn-build-agent/agent-key", Mode: "0600", Owner: "builder:builder"},
		},
		Tenants: []Tenant{
			{Slug: "acme", Domain: "api.acme.example", HasKeystore: true, SignerSHA256: strings.Repeat("d", 64)},
		},
		ServerVersion:            "2026-09-15-server",
		AgentVersion:             "2026-09-15-agent",
		SchemaVersion:            53,
		AgentKeyFingerprint:      strings.Repeat("e", 16),
		BackupSigningFingerprint: strings.Repeat("f", 64),
	}, signingPub
}

func openOuter(t *testing.T, body []byte, key *rsa.PrivateKey) map[string][]byte {
	t.Helper()
	_, plain, err := backupcontainer.Open(bytes.NewReader(body), key)
	if err != nil {
		t.Fatalf("open outer: %v", err)
	}
	return readTar(t, plain)
}

func readTar(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(body))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[header.Name] = content
	}
}

// 2-of-3 的核心断言：三组配对各出一个包，**任意两个人能开自己那一组，
// 任何一个人单独谁都开不了**。九次断言，全部成立才算门限真的成立
func TestAnyTwoHoldersCanOpenTheirPackageAndNoOneAlone(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	packages, err := Assemble(testInput(t, holders), sink)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(packages) != 3 {
		t.Fatalf("2-of-3 应当产出三组包，得到 %d", len(packages))
	}
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}

	for _, pair := range backupcontainer.Pairs() {
		body := sink.packages[pair.Name].Bytes()

		// 这一组的两个人，按 外层→内层 的顺序能开到底
		outer := openOuter(t, body, byslot[pair.Outer])
		if _, _, err := backupcontainer.Open(bytes.NewReader(outer[nameInner]), byslot[pair.Inner]); err != nil {
			t.Fatalf("%s: 这一组的两个人应当能开内层: %v", pair.Name, err)
		}

		// 任何一个人单独都开不了：外层那个人剥开外层之后，内层不是给他的
		if _, _, err := backupcontainer.Open(bytes.NewReader(outer[nameInner]), byslot[pair.Outer]); err == nil {
			t.Fatalf("%s: 只有 %s 一个人就打开了内层——门限没有成立", pair.Name, pair.Outer)
		}
		// 内层那个人根本剥不开外层
		if _, _, err := backupcontainer.Open(bytes.NewReader(body), byslot[pair.Inner]); err == nil {
			t.Fatalf("%s: 只有 %s 一个人就剥开了外层", pair.Name, pair.Inner)
		}
		// 不在这一组的那个人，外层就开不了
		for _, h := range holders {
			if h.slot == pair.Inner || h.slot == pair.Outer {
				continue
			}
			if _, _, err := backupcontainer.Open(bytes.NewReader(body), h.key); err == nil {
				t.Fatalf("%s: 不在这一组的 %s 剥开了外层", pair.Name, h.slot)
			}
		}
	}
}

// 失去任意一个人，剩下两个人仍然有一个能开的包——这正是 2-of-3 买到的东西
func TestLosingAnyOneHolderStillLeavesAnOpenablePackage(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	if _, err := Assemble(testInput(t, holders), sink); err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}
	for _, lost := range backupcontainer.SlotNames {
		opened := false
		for _, pair := range backupcontainer.Pairs() {
			if pair.Inner == lost || pair.Outer == lost {
				continue
			}
			outer := openOuter(t, sink.packages[pair.Name].Bytes(), byslot[pair.Outer])
			if _, _, err := backupcontainer.Open(bytes.NewReader(outer[nameInner]), byslot[pair.Inner]); err == nil {
				opened = true
			}
		}
		if !opened {
			t.Fatalf("失去 %s 之后没有任何一组能开：这不是 2-of-3", lost)
		}
	}
}

// 服务端那部分也封给**内层**那个槽位。只封给开外层的人的话，一把私钥就能读到
// rn-foundation.env 里的 STORAGE_MASTER_KEY，这一组的两把锁就只剩一把
func TestTheServerPartIsSealedToTheInnerSlotNotTheOuterOne(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	if _, err := Assemble(testInput(t, holders), sink); err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}
	for _, pair := range backupcontainer.Pairs() {
		outer := openOuter(t, sink.packages[pair.Name].Bytes(), byslot[pair.Outer])
		if _, _, err := backupcontainer.Open(bytes.NewReader(outer[nameServer]), byslot[pair.Outer]); err == nil {
			t.Fatalf("%s: 只剥开外层的人就读到了服务端配置（里面有 STORAGE_MASTER_KEY）", pair.Name)
		}
		_, plain, err := backupcontainer.Open(bytes.NewReader(outer[nameServer]), byslot[pair.Inner])
		if err != nil {
			t.Fatalf("%s: 这一组的两个人应当能读到服务端那部分: %v", pair.Name, err)
		}
		files := readTar(t, plain)
		if !bytes.Contains(files["rn-foundation.env"], []byte("STORAGE_MASTER_KEY")) {
			t.Fatalf("%s: 服务端那部分的内容不对", pair.Name)
		}
	}
}

// manifest.files[] 必须覆盖三个密文成员。不覆盖的话，攻击者可以把一个**旧**备份的
// inner.rnbk 塞进新包、manifest 原样不动、重封外层——两层 MAC 全绿、两把私钥都用上了，
// 恢复出来的却是轮换前的旧密钥，而这正是本方案唯一要防的事
func TestOuterManifestCoversTheCiphertextMembersSoSplicingIsCaught(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	if _, err := Assemble(testInput(t, holders), sink); err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}
	pair := backupcontainer.Pairs()[0]
	outer := openOuter(t, sink.packages[pair.Name].Bytes(), byslot[pair.Outer])

	var manifest outerManifest
	if err := json.Unmarshal(outer[nameManifest], &manifest); err != nil {
		t.Fatal(err)
	}
	covered := map[string]string{}
	for _, f := range manifest.Files {
		covered[f.Path] = f.SHA256
	}
	for _, name := range []string{nameInner, nameInnerSig, nameServer, nameRecovery, nameRecoverSh} {
		if covered[name] == "" {
			t.Fatalf("manifest.files 没有覆盖 %s——拼接攻击就查不出来了", name)
		}
		if covered[name] != sha256Hex(outer[name]) {
			t.Fatalf("%s 的 sha256 和实际内容对不上", name)
		}
	}
	if covered[nameManifest] != "" {
		t.Fatal("manifest 不该覆盖它自己")
	}

	// 真的换一份进去：sha256 必须对不上
	another := testInput(t, holders)
	another.Seq = 8
	otherSink := newSink()
	if _, err := Assemble(another, otherSink); err != nil {
		t.Fatal(err)
	}
	otherOuter := openOuter(t, otherSink.packages[pair.Name].Bytes(), byslot[pair.Outer])
	if sha256Hex(otherOuter[nameInner]) == covered[nameInner] {
		t.Fatal("两次备份的内层密文竟然一样，这条测试没有意义")
	}
}

// 机密文件的哈希不得出现在外层：上传通道收的是管理员自带 .p12 的口令，
// 可以是人选的弱口令，它的 sha256 落在只需要一把钥匙就能读到的外层就是离线爆破
func TestSecretFileHashesDoNotLeakIntoTheOuterLayer(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	in := testInput(t, holders)
	if _, err := Assemble(in, sink); err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}
	pair := backupcontainer.Pairs()[0]
	outer := openOuter(t, sink.packages[pair.Name].Bytes(), byslot[pair.Outer])

	// AgentManifest 里那些 sha256 是内层机密文件的哈希，不该出现在外层任何地方
	for _, f := range in.AgentManifest {
		for name, body := range outer {
			if name == nameInner || name == nameServer || name == nameInnerSig {
				continue // 这些是密文，读不出来
			}
			if bytes.Contains(body, []byte(f.SHA256)) {
				t.Fatalf("内层文件 %s 的 sha256 出现在外层的 %s 里", f.Path, name)
			}
		}
	}
}

func TestAssembleRefusesAnIncompleteInput(t *testing.T) {
	holders := testHolders(t)
	cases := []struct {
		name string
		edit func(*Input)
		want string
	}{
		{"两把公钥", func(in *Input) { in.Recipients = in.Recipients[:2] }, "no reduced mode"},
		{"两把相同", func(in *Input) { in.Recipients[1].Fingerprint = in.Recipients[0].Fingerprint }, "open a package alone"},
		{"缺内层", func(in *Input) { delete(in.AgentInner, "B") }, "did not report an inner payload"},
		{"内层没签名", func(in *Input) {
			part := in.AgentInner["A"]
			part.Signature = nil
			in.AgentInner["A"] = part
		}, "no signature"},
		{"没有租户", func(in *Input) { in.Tenants = nil }, "no tenants"},
		{"没有 seq", func(in *Input) { in.Seq = 0 }, "seq is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput(t, holders)
			tc.edit(&in)
			_, err := Assemble(in, newSink())
			if err == nil {
				t.Fatal("应当被拒绝")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误应当提到 %q，得到: %v", tc.want, err)
			}
		})
	}
}

// recover.sh 恢复时以 root 跑。渲染进去的每一个值都必须被引号包住，
// 否则一个带空格或元字符的路径就变成了一条命令
func TestRecoverScriptQuotesEveryInterpolatedValue(t *testing.T) {
	holders := testHolders(t)
	in := testInput(t, holders)
	in.AgentManifest = append(in.AgentManifest, FileEntry{
		Path: "keystores/acme/keystore.p12", Size: 1, SHA256: strings.Repeat("0", 64),
		Target: "/var/lib/rn-build-agent/it's here", Mode: "0600", Owner: "builder:builder",
	})
	script := renderRecoverScript(in, backupcontainer.Pairs()[0])

	// 带单引号的路径必须被正确转义成 '\'' 形式
	if !strings.Contains(script, `'/var/lib/rn-build-agent/it'\''s here'`) {
		t.Fatalf("带单引号的路径没有被正确转义:\n%s", script)
	}
	// place 的每一次调用，后三个参数都必须以单引号开头
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "place \"$ROOT") {
			continue
		}
		fields := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(fields) < 3 || !strings.HasPrefix(fields[2], "'") {
			t.Fatalf("place 的参数没有被引号包住: %s", line)
		}
	}
}

// README-FIRST 要告诉人：本包要谁、另外两个包要谁、以及 sha256。
// 少了「另外两个包」那一句，拿到包的人不知道还有别的选择——而 2-of-3
// 的全部价值就在于换一组
func TestReadmeFirstTellsYouWhoIsNeededAndWhatElseExists(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	packages, err := Assemble(testInput(t, holders), sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		readme := pkg.ReadmeFirst
		if !strings.Contains(readme, pkg.SHA256) {
			t.Fatalf("%s: README 里没有印 sha256", pkg.Pair)
		}
		for _, other := range backupcontainer.Pairs() {
			if other.Name == pkg.Pair {
				continue
			}
			if !strings.Contains(readme, other.Name+".rnbk") {
				t.Fatalf("%s: README 没有提到另一个包 %s", pkg.Pair, other.Name)
			}
		}
		if !strings.Contains(readme, "holder-") {
			t.Fatalf("%s: README 没有写保管人", pkg.Pair)
		}
		if !strings.Contains(readme, "验签通过之前不要跑") {
			t.Fatalf("%s: README 没有警告先验签再跑脚本", pkg.Pair)
		}
	}
}

// 三组包装的是同一份内容
func TestAllThreePackagesCarryTheSameContent(t *testing.T) {
	holders := testHolders(t)
	sink := newSink()
	if _, err := Assemble(testInput(t, holders), sink); err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}
	var reference []byte
	for _, pair := range backupcontainer.Pairs() {
		outer := openOuter(t, sink.packages[pair.Name].Bytes(), byslot[pair.Outer])
		_, plain, err := backupcontainer.Open(bytes.NewReader(outer[nameInner]), byslot[pair.Inner])
		if err != nil {
			t.Fatal(err)
		}
		if reference == nil {
			reference = plain
			continue
		}
		if !bytes.Equal(reference, plain) {
			t.Fatalf("%s 里的内层内容和别的组不一样", pair.Name)
		}
	}
}
