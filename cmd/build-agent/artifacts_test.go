package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

func outLayout(t *testing.T) jobspec.Layout {
	t.Helper()
	layout, err := jobspec.NewLayout(t.TempDir(), "bld_artifact0001")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Out(), 0o770); err != nil {
		t.Fatal(err)
	}
	return layout
}

// 执行进程交回的产物是不可信数据：符号链接、硬链接、FIFO、超限一律拒收
func TestSpoolOutputRefusesAnythingButASmallRegularFile(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "provenance-ed25519.key")
	if err := os.WriteFile(secret, []byte("controller secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(layout jobspec.Layout, name string){
		"symlink": func(layout jobspec.Layout, name string) {
			if err := os.Symlink(secret, layout.OutFile(name)); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(layout jobspec.Layout, name string) {
			if err := os.Link(secret, layout.OutFile(name)); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(layout jobspec.Layout, name string) {
			if err := syscall.Mkfifo(layout.OutFile(name), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(layout jobspec.Layout, name string) {
			if err := os.Mkdir(layout.OutFile(name), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"oversize": func(layout jobspec.Layout, name string) {
			if err := os.WriteFile(layout.OutFile(name), []byte(strings.Repeat("x", 65)), 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"empty": func(layout jobspec.Layout, name string) {
			if err := os.WriteFile(layout.OutFile(name), nil, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"missing": func(jobspec.Layout, string) {},
	}
	for name, plant := range cases {
		layout := outLayout(t)
		plant(layout, jobspec.UnsignedFileName)
		spool := filepath.Join(t.TempDir(), "spool")
		if _, err := spoolOutput(layout, jobspec.UnsignedFileName, spool, 64); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	layout := outLayout(t)
	if err := os.WriteFile(layout.OutFile(jobspec.UnsignedFileName), []byte("unsigned apk bytes"), 0o640); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(t.TempDir(), "spool")
	got, err := spoolOutput(layout, jobspec.UnsignedFileName, spool, 64)
	if err != nil {
		t.Fatal(err)
	}
	// 之后执行进程改写原文件，不影响控制进程手里的副本
	if err := os.WriteFile(layout.OutFile(jobspec.UnsignedFileName), []byte("swapped after hashing"), 0o640); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(got.Path)
	if err != nil || string(copied) != "unsigned apk bytes" || got.Size != int64(len("unsigned apk bytes")) {
		t.Fatalf("spool copy = %q (%v)", copied, err)
	}
	if info, _ := os.Stat(got.Path); info.Mode().Perm() != 0o600 {
		t.Fatalf("spool copy mode %v", info.Mode())
	}
}

func TestSBOMMustBeBoundToTheUnsignedPackage(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	name := "anyfun-1.3.7-build33-release-unsigned.apk"
	write := func(doc string) string {
		path := filepath.Join(t.TempDir(), "sbom.json")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := `{"bomFormat":"CycloneDX","metadata":{"component":{"hashes":[{"alg":"SHA-256","content":"` + sha + `"}]},
		"properties":[{"name":"rn-app:artifact","value":"` + name + `"},{"name":"rn-app:artifact-signing","value":"unsigned"}]}}`
	if err := checkSBOMBinding(write(good), sha, name); err != nil {
		t.Fatalf("a bound SBOM was refused: %v", err)
	}
	for label, doc := range map[string]string{
		"other hash":      strings.Replace(good, sha, strings.Repeat("cd", 32), 1),
		"signed artifact": strings.Replace(good, `"unsigned"}`, `"signed"}`, 1),
		"other name":      strings.Replace(good, name, "anyfun-1.3.7-build33-release.apk", 1),
		"not cyclonedx":   strings.Replace(good, "CycloneDX", "SPDX", 1),
		"not json":        "{",
	} {
		if err := checkSBOMBinding(write(doc), sha, name); err == nil {
			t.Errorf("%s was accepted", label)
		}
	}
}
