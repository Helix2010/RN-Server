package signer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

// SignParams 是一次 apksigner sign 的输入。口令只以文件路径出现。
type SignParams struct {
	KeystorePath      string
	KeyAlias          string
	StorePasswordFile string
	KeyPasswordFile   string
	MinSDK            int64
	In, Out           string
	TmpDir            string
}

// VerifyResult 是 apksigner verify --print-certs 的解析结果。
type VerifyResult struct {
	Verified     bool
	V1, V2, V3   bool
	V31, V4      bool
	Signers      int
	Certificates []string // 每个签名者证书的 sha256
}

// APKSigner 签名与复核。测试里用假实现。
type APKSigner interface {
	Sign(ctx context.Context, p SignParams) error
	Verify(ctx context.Context, path string, minSDK int64, tmpDir string) (VerifyResult, error)
}

const apksignerTimeout = 10 * time.Minute

// JavaAPKSigner 直接调用 $JAVA_HOME/bin/java -jar <build-tools>/lib/apksigner.jar：
// 不走 build-tools 里那个会读 PATH、JDK_JAVA_OPTIONS 的 shell 包装脚本；子进程环境为空（env -i）。
type JavaAPKSigner struct {
	Java    string // 绝对路径
	Jar     string // 绝对路径
	Timeout time.Duration
}

// NewJavaAPKSigner 按配置定位 java 与 apksigner.jar，并检查它们存在。
func NewJavaAPKSigner(javaHome, buildToolsDir string) (JavaAPKSigner, error) {
	s := JavaAPKSigner{
		Java: filepath.Join(javaHome, "bin", "java"),
		Jar:  filepath.Join(buildToolsDir, "lib", "apksigner.jar"),
	}
	info, err := os.Stat(s.Java)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return s, fmt.Errorf("%s=%q: %s is not an executable file", EnvJavaHome, javaHome, s.Java)
	}
	info, err = os.Stat(s.Jar)
	if err != nil || !info.Mode().IsRegular() {
		return s, fmt.Errorf("%s=%q: %s does not exist", EnvBuildToolsDir, buildToolsDir, s.Jar)
	}
	return s, nil
}

// SignArgs 返回 sign 的完整参数（不含 java 本身）。导出给测试核对。
func (s JavaAPKSigner) SignArgs(p SignParams) []string {
	return append(s.jvmArgs(p.TmpDir),
		"sign",
		"--ks", p.KeystorePath,
		"--ks-type", "PKCS12",
		"--ks-key-alias", p.KeyAlias,
		"--ks-pass", "file:"+p.StorePasswordFile,
		"--key-pass", "file:"+p.KeyPasswordFile,
		"--v1-signing-enabled", "false",
		"--v2-signing-enabled", "true",
		"--v3-signing-enabled", "true",
		"--v4-signing-enabled", "false",
		"--min-sdk-version", strconv.FormatInt(p.MinSDK, 10),
		"--out", p.Out,
		p.In,
	)
}

func (s JavaAPKSigner) jvmArgs(tmpDir string) []string {
	args := []string{"-XX:-UsePerfData"}
	if tmpDir != "" {
		args = append(args, "-Djava.io.tmpdir="+tmpDir)
	}
	return append(args, "-jar", s.Jar)
}

func (s JavaAPKSigner) run(ctx context.Context, dir string, args []string) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = apksignerTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Java, args...)
	cmd.Env = []string{}
	if dir == "" {
		dir = "/"
	}
	cmd.Dir = dir
	var out limitedBuffer
	out.max = 256 << 10
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// Sign 实现 APKSigner。
func (s JavaAPKSigner) Sign(ctx context.Context, p SignParams) error {
	for _, path := range []string{p.KeystorePath, p.StorePasswordFile, p.KeyPasswordFile, p.In, p.Out} {
		if !filepath.IsAbs(path) {
			return errors.New("apksigner paths must be absolute")
		}
	}
	if p.MinSDK < 1 {
		return errors.New("apksigner min SDK must be positive")
	}
	output, err := s.run(ctx, p.TmpDir, s.SignArgs(p))
	if err != nil {
		return fmt.Errorf("apksigner sign failed (%v): %s", err, cleanText(output, 600))
	}
	return nil
}

// Verify 实现 APKSigner。
func (s JavaAPKSigner) Verify(ctx context.Context, path string, minSDK int64, tmpDir string) (VerifyResult, error) {
	args := append(s.jvmArgs(tmpDir), "verify", "--print-certs", "--verbose", "--min-sdk-version", strconv.FormatInt(minSDK, 10), path)
	output, err := s.run(ctx, tmpDir, args)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("apksigner verify failed (%v): %s", err, cleanText(output, 600))
	}
	return ParseVerifyOutput(output)
}

var (
	schemeLine = regexp.MustCompile(`^Verified using (v1|v2|v3|v3\.1|v4) scheme \([^)]*\): (true|false)$`)
	signersRe  = regexp.MustCompile(`^Number of signers: (\d+)$`)
	certRe     = regexp.MustCompile(`^Signer #(\d+) certificate SHA-256 digest: ([0-9a-fA-F]{64})$`)
)

// ParseVerifyOutput 严格解析 apksigner verify --print-certs --verbose 的输出。
func ParseVerifyOutput(output string) (VerifyResult, error) {
	var r VerifyResult
	seen := map[string]bool{}
	signersSeen := false
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		switch {
		case line == "Verifies":
			r.Verified = true
		case schemeLine.MatchString(line):
			m := schemeLine.FindStringSubmatch(line)
			if seen[m[1]] {
				return VerifyResult{}, fmt.Errorf("apksigner output repeats the %s line", m[1])
			}
			seen[m[1]] = true
			value := m[2] == "true"
			switch m[1] {
			case "v1":
				r.V1 = value
			case "v2":
				r.V2 = value
			case "v3":
				r.V3 = value
			case "v3.1":
				r.V31 = value
			case "v4":
				r.V4 = value
			}
		case signersRe.MatchString(line):
			if signersSeen {
				return VerifyResult{}, errors.New("apksigner output repeats the signer count")
			}
			signersSeen = true
			r.Signers, _ = strconv.Atoi(signersRe.FindStringSubmatch(line)[1])
		case certRe.MatchString(line):
			m := certRe.FindStringSubmatch(line)
			index, _ := strconv.Atoi(m[1])
			if index != len(r.Certificates)+1 {
				return VerifyResult{}, errors.New("apksigner output lists signer certificates out of order")
			}
			r.Certificates = append(r.Certificates, strings.ToLower(m[2]))
		}
	}
	if !r.Verified || !signersSeen || !seen["v2"] || !seen["v3"] {
		return VerifyResult{}, errors.New("apksigner output does not report a verified APK with v2 and v3 results")
	}
	if len(r.Certificates) != r.Signers {
		return VerifyResult{}, errors.New("apksigner output lists a different number of certificates than signers")
	}
	for _, c := range r.Certificates {
		if !fingerprint.Valid(c) {
			return VerifyResult{}, errors.New("apksigner output has a malformed certificate digest")
		}
	}
	return r, nil
}

// CheckSigned 是设计第 19 条：恰好 1 个签名者，v2、v3 通过，证书等于本机确认值。
func CheckSigned(r VerifyResult, certificateSHA256 string) error {
	switch {
	case !r.Verified:
		return errors.New("the signed APK does not verify")
	case r.Signers != 1 || len(r.Certificates) != 1:
		return fmt.Errorf("the signed APK has %d signers, expected exactly 1", r.Signers)
	case !r.V2 || !r.V3:
		return fmt.Errorf("the signed APK must verify with v2 and v3 (v2=%v v3=%v)", r.V2, r.V3)
	case r.Certificates[0] != certificateSHA256:
		return fmt.Errorf("the signed APK certificate %s is not the confirmed %s", r.Certificates[0], certificateSHA256)
	}
	return nil
}
