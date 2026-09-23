package netproxy

import (
	"net/http"
	"slices"
	"testing"
)

func TestNoProxyConfiguredMeansDirectAndNothingToHandOut(t *testing.T) {
	cfg, err := New("", "ignored.example", "api.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled() || len(cfg.Env()) != 0 || cfg.Args() != nil || cfg.Func() != nil {
		t.Fatalf("an empty proxy must hand nothing out, got %+v", cfg)
	}
}

func TestOneKeyBecomesEveryVariableInBothCases(t *testing.T) {
	cfg, err := New("http://127.0.0.1:7897", "anyfun.win", "api.predict.kim")
	if err != nil {
		t.Fatal(err)
	}
	env := cfg.Env()
	if len(env) != len(EnvKeys) {
		t.Fatalf("want all %d keys, got %v", len(EnvKeys), env)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if env[key] != "http://127.0.0.1:7897" {
			t.Fatalf("%s = %q", key, env[key])
		}
	}
	want := "localhost,127.0.0.1,::1,api.predict.kim,anyfun.win"
	if env["NO_PROXY"] != want || env["no_proxy"] != want {
		t.Fatalf("no-proxy = %q / %q, want %q", env["NO_PROXY"], env["no_proxy"], want)
	}
	if !slices.Equal(cfg.Args(), []string{"--proxy", "http://127.0.0.1:7897", "--no-proxy", want}) {
		t.Fatalf("args = %v", cfg.Args())
	}
}

func TestNoProxyIsNormalised(t *testing.T) {
	cfg, err := New("http://proxy:3128/", " Anyfun.WIN ,,localhost, api.predict.kim ", "api.predict.kim")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "http://proxy:3128" {
		t.Fatalf("url = %q", cfg.URL)
	}
	if cfg.NoProxy != "localhost,127.0.0.1,::1,api.predict.kim,anyfun.win" {
		t.Fatalf("no-proxy = %q", cfg.NoProxy)
	}
}

func TestRejectsCredentialsAndMalformedValues(t *testing.T) {
	for _, bad := range []string{
		"http://user:pass@127.0.0.1:7897",
		"127.0.0.1:7897",
		"ftp://proxy:21",
		"http://proxy:7897/path",
		"http://proxy:7897 --evil",
	} {
		if _, err := New(bad, ""); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := New("http://proxy:7897", "a.example;rm -rf /"); err == nil {
		t.Fatal("accepted a malformed no-proxy list")
	}
	if _, err := New("http://proxy:7897", "", "bad host"); err == nil {
		t.Fatal("accepted a malformed direct host")
	}
}

func TestProxyFuncHonoursNoProxyAndSubdomains(t *testing.T) {
	cfg, err := New("http://127.0.0.1:7897", "anyfun.win", "api.predict.kim")
	if err != nil {
		t.Fatal(err)
	}
	proxy := cfg.Func()
	for target, wantProxy := range map[string]bool{
		"https://api.appstoreconnect.apple.com/v1/apps": true,
		"https://registry.npmjs.org/":                   true,
		"https://api.predict.kim/v1/build-agent/jobs":   false,
		"https://console.anyfun.win/":                   false,
		"https://anyfun.win/":                           false,
		"http://127.0.0.1:8080/":                        false,
	} {
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		got, err := proxy(request)
		if err != nil {
			t.Fatal(err)
		}
		if (got != nil) != wantProxy {
			t.Fatalf("%s: proxy %v, want proxied=%v", target, got, wantProxy)
		}
		if got != nil && got.String() != "http://127.0.0.1:7897" {
			t.Fatalf("%s went to %v", target, got)
		}
	}
}

func TestTransportIgnoresTheProcessEnvironmentWhenUnset(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://leftover:1")
	if (Config{}).Transport().Proxy != nil {
		t.Fatal("an unset proxy must mean direct, not whatever the process environment says")
	}
}
