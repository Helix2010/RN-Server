package checkwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
	"github.com/Helix2010/RN-Server/signing/policy"
)

func request(t *testing.T, in policy.Input, apk []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteRequest(&buf, in, bytes.NewReader(apk)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestServeProducesOneVerdictLine(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	build := testfixture.NewBuild(t, testfixture.NewBuilder(t), "bld_checkwireJOB0001", 46, nil)
	in := build.Input(t, testfixture.Hex64('c'))
	var out, errOut bytes.Buffer
	if code := Serve(bytes.NewReader(request(t, in, build.APK)), &out, &errOut); code != 0 {
		t.Fatalf("Serve = %d: %s", code, errOut.String())
	}
	v, err := ReadVerdict(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.CheckedSHA256 != build.SHA256 || v.Facts.VersionCode != 46 {
		t.Fatalf("verdict: %+v", v)
	}
	// 检查进程的临时文件在退出前删掉
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 0 {
		t.Fatalf("the checker left %d entries in its temporary directory", len(entries))
	}

	// 违规同样是一行结论、退出码 0
	in.Confirmed.TrustRoots.APIBaseURL = "https://api.other.example"
	out.Reset()
	if code := Serve(bytes.NewReader(request(t, in, build.APK)), &out, &errOut); code != 0 {
		t.Fatalf("Serve = %d", code)
	}
	v, err = ReadVerdict(bytes.NewReader(out.Bytes()))
	if err != nil || v.OK || v.Kind != policy.KindViolation || v.Code != "TRUST_ROOT_MISMATCH" {
		t.Fatalf("verdict: %+v %v", v, err)
	}
}

func TestServeRejectsBrokenRequests(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	build := testfixture.NewBuild(t, testfixture.NewBuilder(t), "bld_checkwireJOB0002", 46, nil)
	in := build.Input(t, testfixture.Hex64('c'))
	good := request(t, in, build.APK)
	line := good[:bytes.IndexByte(good, '\n')+1]
	huge := append(bytes.Repeat([]byte(" "), MaxInputLine+10), '\n')
	withSize := func(size int64) []byte {
		changed := in
		changed.APKSize = size
		return append(append(testfixture.MustJSON(t, changed), '\n'), build.APK...)
	}
	cases := map[string][]byte{
		"truncated apk":             good[:len(good)-10],
		"trailing data":             append(append([]byte{}, good...), 'x'),
		"no newline":                line[:len(line)-1],
		"unknown field":             append([]byte(`{"v":1,"extra":true}`), '\n'),
		"oversized line":            huge,
		"zero apk size":             withSize(0),
		"apk size above max":        withSize(1 << 40),
		"apk shorter than declared": withSize(int64(len(build.APK)) + 1),
		"two json values":           append([]byte(`{"v":1} {"v":1}`), '\n'),
		"empty":                     nil,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Serve(bytes.NewReader(raw), &out, &errOut); code == 0 {
				t.Fatalf("Serve accepted a broken request; stdout=%s", out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("a broken request produced a verdict: %s", out.String())
			}
		})
	}
}

func TestReadVerdictIsStrict(t *testing.T) {
	facts, _ := json.Marshal(policy.Verdict{OK: true, Facts: &policy.Facts{PackageName: "x"}})
	for name, raw := range map[string]string{
		"two lines":              string(facts) + "\n" + string(facts) + "\n",
		"no newline":             string(facts),
		"ok without facts":       `{"ok":true}` + "\n",
		"ok with a code":         `{"ok":true,"code":"X","facts":{}}` + "\n",
		"rejection without kind": `{"ok":false,"code":"X"}` + "\n",
		"unknown kind":           `{"ok":false,"kind":"maybe","code":"X"}` + "\n",
		"deferred":               `{"ok":false,"kind":"deferred","code":"X"}` + "\n",
		"rejection with facts":   `{"ok":false,"kind":"violation","code":"X","facts":{}}` + "\n",
		"rejection without code": `{"ok":false,"kind":"violation"}` + "\n",
		"unknown field":          `{"ok":false,"kind":"violation","code":"X","sneaky":1}` + "\n",
		"empty":                  "",
	} {
		if _, err := ReadVerdict(strings.NewReader(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ReadVerdict(strings.NewReader(string(facts) + "\n")); err != nil {
		t.Fatalf("valid verdict rejected: %v", err)
	}
	if v, err := ReadVerdict(strings.NewReader(`{"ok":false,"kind":"violation","code":"X","detail":"d"}` + "\n")); err != nil || v.Code != "X" {
		t.Fatalf("valid rejection: %+v, %v", v, err)
	}
}

func TestReadInputHandlesLongLines(t *testing.T) {
	build := testfixture.NewBuild(t, testfixture.NewBuilder(t), "bld_checkwireJOB0003", 46, nil)
	in := build.Input(t, testfixture.Hex64('c'))
	raw := request(t, in, build.APK)
	// 64 KiB 缓冲区装不下一整行时也要能读完（出处声明约 1 KiB，这里放大缓冲区外的情形）
	r := bufio.NewReaderSize(bytes.NewReader(raw), 16)
	got, err := ReadInput(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Job.ID != in.Job.ID || got.APKSize != in.APKSize {
		t.Fatalf("round trip: %+v", got.Job)
	}
}
