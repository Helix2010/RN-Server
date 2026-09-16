package releasekey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
)

func params() Params {
	return Params{Alias: "anyfun-release", CommonName: "AnyFun Android Release", Organization: "AnyFun", KeyBits: 2048, ValidityYears: 30}
}

func TestGenerate(t *testing.T) {
	r, err := Generate(params())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Password) != 64 || strings.Trim(r.Password, "0123456789abcdef") != "" {
		t.Fatal("password is not 64 lowercase hex characters")
	}
	entry, err := pkcs12.FindKey(r.PKCS12, r.Password, "anyfun-release")
	if err != nil {
		t.Fatal(err)
	}
	if pkcs12.CertificateSHA256(entry) != r.CertificateSHA256 || fingerprint.SHA256Hex(r.Certificate.Raw) != r.CertificateSHA256 {
		t.Fatal("certificate fingerprint mismatch")
	}
	if r.Certificate.Subject.CommonName != "AnyFun Android Release" || len(r.Certificate.Subject.Organization) != 1 {
		t.Fatalf("subject: %v", r.Certificate.Subject)
	}
	if years := r.NotAfter.Sub(time.Now()).Hours() / 24 / 365; years < 29.9 || years > 30.1 {
		t.Fatalf("validity %.2f years", years)
	}
	if r.Certificate.KeyUsage&0x1 == 0 {
		t.Fatal("digitalSignature key usage missing")
	}
	if r.Certificate.SerialNumber.Sign() <= 0 {
		t.Fatal("serial must be positive")
	}
	if _, err := pkcs12.FindKey(r.PKCS12, r.Password+"0", "anyfun-release"); err == nil {
		t.Fatal("wrong password opened the keystore")
	}
	other, err := Generate(params())
	if err != nil {
		t.Fatal(err)
	}
	if other.Password == r.Password || other.CertificateSHA256 == r.CertificateSHA256 || other.Certificate.SerialNumber.Cmp(r.Certificate.SerialNumber) == 0 {
		t.Fatal("two generations produced overlapping material")
	}
}

func TestGenerateRejectsParams(t *testing.T) {
	for name, mutate := range map[string]func(*Params){
		"alias":          func(p *Params) { p.Alias = "my alias" },
		"no common name": func(p *Params) { p.CommonName = "" },
		"padded name":    func(p *Params) { p.CommonName = " AnyFun" },
		"control in cn":  func(p *Params) { p.CommonName = "Any\x1bFun" },
		"long org":       func(p *Params) { p.Organization = strings.Repeat("o", 65) },
		"key bits":       func(p *Params) { p.KeyBits = 3072 },
		"short validity": func(p *Params) { p.ValidityYears = 10 },
		"long validity":  func(p *Params) { p.ValidityYears = 100 },
	} {
		p := params()
		mutate(&p)
		if _, err := Generate(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResultNeverFormatsSecrets(t *testing.T) {
	r, err := Generate(params())
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{r.Password, base64.StdEncoding.EncodeToString(r.PKCS12), fmt.Sprintf("%x", r.PKCS12[:32])}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, r), fmt.Sprintf(verb, &r), fmt.Sprintf(verb, []Result{r}),
			fmt.Sprintf(verb, struct{ R Result }{r}))
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("generated", "result", r)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("generated", "result", &r)
	outputs = append(outputs, buf.String(), fmt.Errorf("wrap: %v", r).Error())
	if raw, err := json.Marshal(r); err == nil {
		t.Fatalf("json.Marshal succeeded (%d bytes)", len(raw))
	}
	for _, out := range outputs {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Fatal("formatted output leaks the password or the keystore bytes")
			}
		}
	}
	if !strings.Contains(r.String(), r.CertificateSHA256) {
		t.Fatal("fingerprint missing from the formatted result")
	}
}
