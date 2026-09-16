package signer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Helix2010/RN-Server/signing/ident"
)

// 配置键（/etc/rn-signer-a.env，只放启动项）。
const (
	EnvServerURL          = "SIGNER_SERVER_URL"
	EnvMachineToken       = "SIGNER_MACHINE_TOKEN"
	EnvName               = "SIGNER_NAME"
	EnvStateDir           = "SIGNER_STATE_DIR"
	EnvRuntimeDir         = "SIGNER_RUNTIME_DIR"
	EnvJavaHome           = "SIGNER_JAVA_HOME"
	EnvBuildToolsDir      = "SIGNER_BUILD_TOOLS_DIR"
	EnvCheckSocket        = "SIGNER_CHECK_SOCKET"
	EnvCheckExec          = "SIGNER_CHECK_EXEC"
	EnvMaxVersionCodeJump = "SIGNER_MAX_VERSION_CODE_JUMP"
	EnvMaxVersionCode     = "SIGNER_MAX_VERSION_CODE"

	DefaultMaxVersionCodeJump = 100
	DefaultMaxVersionCode     = 10_000_000
)

var knownKeys = map[string]bool{
	EnvServerURL: true, EnvMachineToken: true, EnvName: true, EnvStateDir: true, EnvRuntimeDir: true,
	EnvJavaHome: true, EnvBuildToolsDir: true, EnvCheckSocket: true, EnvCheckExec: true,
	EnvMaxVersionCodeJump: true, EnvMaxVersionCode: true,
}

var tokenPattern = regexp.MustCompile(`^rnm_[A-Za-z0-9_-]{43}$`)

// Config 是签名闸配置。MachineToken 是机密：格式化输出走白名单。
type Config struct {
	ServerURL          string
	MachineToken       string
	Name               string
	StateDir           string
	RuntimeDir         string
	JavaHome           string
	BuildToolsDir      string
	CheckSocket        string
	CheckExec          string
	MaxVersionCodeJump int64
	MaxVersionCode     int64
}

func (c Config) String() string {
	token := "(unset)"
	if c.MachineToken != "" {
		token = "[redacted]"
	}
	return fmt.Sprintf("signer.Config{serverURL=%q machineToken=%s name=%q stateDir=%q runtimeDir=%q javaHome=%q buildToolsDir=%q checkSocket=%q checkExec=%q maxVersionCodeJump=%d maxVersionCode=%d}",
		c.ServerURL, token, c.Name, c.StateDir, c.RuntimeDir, c.JavaHome, c.BuildToolsDir, c.CheckSocket, c.CheckExec, c.MaxVersionCodeJump, c.MaxVersionCode)
}

// GoString 覆盖 %#v。
func (c Config) GoString() string { return c.String() }

// Format 覆盖全部动词。
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue 覆盖 slog。
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("serverURL", c.ServerURL),
		slog.Bool("machineTokenSet", c.MachineToken != ""),
		slog.String("name", c.Name),
		slog.String("stateDir", c.StateDir),
		slog.String("runtimeDir", c.RuntimeDir),
		slog.String("javaHome", c.JavaHome),
		slog.String("buildToolsDir", c.BuildToolsDir),
		slog.String("checkSocket", c.CheckSocket),
		slog.String("checkExec", c.CheckExec),
		slog.Int64("maxVersionCodeJump", c.MaxVersionCodeJump),
		slog.Int64("maxVersionCode", c.MaxVersionCode),
	)
}

// MarshalJSON 拒绝序列化。
func (c Config) MarshalJSON() ([]byte, error) {
	return nil, errors.New("signer: refusing to JSON-encode the configuration")
}

// Need 说明一个子命令需要哪些配置。
type Need int

const (
	// NeedLocal：只用本机状态（show-key、list、abandon、trust-builder、promote）。
	NeedLocal Need = iota
	// NeedServer：还要连服务端（confirm）。
	NeedServer
	// NeedAll：签名闸主进程（run）。
	NeedAll
)

// LoadConfig 从 getenv 读配置并逐键校验。报错说明哪个键、写了什么（令牌除外）、期望什么。
func LoadConfig(getenv func(string) string, need Need) (Config, error) {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	c := Config{
		ServerURL:     getenv(EnvServerURL),
		MachineToken:  getenv(EnvMachineToken),
		Name:          getenv(EnvName),
		StateDir:      getenv(EnvStateDir),
		RuntimeDir:    getenv(EnvRuntimeDir),
		JavaHome:      getenv(EnvJavaHome),
		BuildToolsDir: getenv(EnvBuildToolsDir),
		CheckSocket:   getenv(EnvCheckSocket),
		CheckExec:     getenv(EnvCheckExec),
	}
	if !ident.ValidMachineName(c.Name) {
		add("%s=%q: expected the machine name registered in the console (^[a-z0-9][a-z0-9-]{1,39}$)", EnvName, c.Name)
	}
	checkDir := func(key, value string) {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
			add("%s=%q: expected an absolute, clean directory path", key, value)
		}
	}
	checkDir(EnvStateDir, c.StateDir)
	if need >= NeedServer {
		if err := validateServerURL(c.ServerURL); err != nil {
			add("%s=%q: %v", EnvServerURL, c.ServerURL, err)
		}
		if !tokenPattern.MatchString(c.MachineToken) {
			// 不回显令牌
			add("%s: expected the machine token shown once in the console (rnm_ followed by 43 base64url characters)", EnvMachineToken)
		}
	}
	if need >= NeedAll {
		checkDir(EnvRuntimeDir, c.RuntimeDir)
		checkDir(EnvJavaHome, c.JavaHome)
		checkDir(EnvBuildToolsDir, c.BuildToolsDir)
		if c.StateDir != "" && c.RuntimeDir != "" && (within(c.StateDir, c.RuntimeDir) || within(c.RuntimeDir, c.StateDir)) {
			add("%s=%q and %s=%q: the runtime directory (tmpfs) and the state directory must not contain each other", EnvStateDir, c.StateDir, EnvRuntimeDir, c.RuntimeDir)
		}
		switch {
		case c.CheckSocket == "" && c.CheckExec == "":
			add("%s or %s: exactly one is required (socket in production, exec only for local tests)", EnvCheckSocket, EnvCheckExec)
		case c.CheckSocket != "" && c.CheckExec != "":
			add("%s=%q and %s=%q: set exactly one of them", EnvCheckSocket, c.CheckSocket, EnvCheckExec, c.CheckExec)
		case c.CheckSocket != "" && (!filepath.IsAbs(c.CheckSocket) || filepath.Clean(c.CheckSocket) != c.CheckSocket):
			add("%s=%q: expected an absolute socket path", EnvCheckSocket, c.CheckSocket)
		case c.CheckExec != "" && (!filepath.IsAbs(c.CheckExec) || filepath.Clean(c.CheckExec) != c.CheckExec):
			add("%s=%q: expected an absolute path to the signer-check binary", EnvCheckExec, c.CheckExec)
		}
		c.MaxVersionCodeJump = parseLimit(getenv(EnvMaxVersionCodeJump), EnvMaxVersionCodeJump, DefaultMaxVersionCodeJump, 1, 100_000, add)
		c.MaxVersionCode = parseLimit(getenv(EnvMaxVersionCode), EnvMaxVersionCode, DefaultMaxVersionCode, 1, 2_100_000_000, add)
	}
	if len(problems) > 0 {
		return Config{}, fmt.Errorf("signer configuration is invalid:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return c, nil
}

func parseLimit(raw, key string, def, min, max int64, add func(string, ...any)) int64 {
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < min || n > max || strconv.FormatInt(n, 10) != raw {
		add("%s=%q: expected an integer between %d and %d (default %d)", key, raw, min, max, def)
		return def
	}
	return n
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)))
}

// validateServerURL：https 源；http 只允许回环地址（签名闸与服务端同机时走本机端口）。
// 不允许路径、查询、用户信息：令牌只发给这个源。
func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(raw, "/") {
		return errors.New("expected an origin such as https://api.example.com (no path, no trailing slash)")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); (ip != nil && ip.IsLoopback()) || host == "localhost" {
			return nil
		}
		return errors.New("plain http is only allowed for a loopback address")
	default:
		return errors.New("expected an https origin")
	}
}

// ReadEnvFile 读 systemd EnvironmentFile 风格的文件：KEY=VALUE，# 注释，值可以加单/双引号。
// 只接受 SIGNER_* 里已知的键（写错键名在这里就报出来）。
func ReadEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("%s: larger than 64 KiB", path)
	}
	out := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !ok || !knownKeys[key] {
			// 不回显整行：它可能是令牌
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE with a known SIGNER_* key", path, line)
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%s:%d: %s is set more than once", path, line, key)
		}
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
