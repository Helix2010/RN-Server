package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/internal/securefs"
	"github.com/Helix2010/RN-Server/signing/machinekey"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/recovery"
)

// enrollMarkerFile：signer enroll 生成了本机密钥与记录、但还没把令牌写进 env。有它时 signer run 与
// 运维命令都拒绝使用这个状态目录；再次执行 enroll 会清掉重来（那套密钥没有令牌，不会被服务端接受）。
const enrollMarkerFile = "enroll.incomplete"

// EnvEnrollmentCode 是 signer enroll 读注册码的环境变量（install.sh 用它，注册码不进进程参数）。
const EnvEnrollmentCode = "RN_ENROLLMENT_CODE"

// installedSignerPath 是 install.sh 安装 signer 的位置（打印下一步命令用）。
const installedSignerPath = "/opt/rn-signer/bin/signer"

// errEnrollPending：状态目录里的注册没完成。
var errEnrollPending = errors.New("this signing gate's enrollment did not finish (enroll.incomplete); run the install command (signer enroll) again")

// EnrollOptions 是 signer enroll 的参数。
type EnrollOptions struct {
	ServerURL      string
	Code           string // 一次性注册码：不打印
	EnvFile        string
	RecoverySHA256 string
	NameCheck      string
}

// DescribeResponse 是 POST /v1/machine-setup/describe 的响应（签名闸用到的部分）。SignerRole 与 PrimarySigner
// 只用来打印下一步提示：本机角色一律写备，签名闸之间的信任只由本机 trust-peer 写入。
type DescribeResponse struct {
	MachineID     string            `json:"machineId"`
	Name          string            `json:"name"`
	Role          string            `json:"role"`
	SignerRole    *string           `json:"signerRole"`
	RecoveryKeys  []PeerRecoveryKey `json:"recoveryKeys"`
	PrimarySigner *PrimarySigner    `json:"primarySigner"`
}

// PrimarySigner 是 describe 给备签名闸的当前主签名闸。只读机器名用于提示；服务端给的公钥与指纹不读、不上屏
// （运维要从主签名闸本机抄指纹）。
type PrimarySigner struct {
	MachineID string `json:"machineId"`
	Name      string `json:"name"`
}

// EnrollResponse 是 POST /v1/machine-setup/enroll 的响应。Token 是机密：格式化输出不含它。
type EnrollResponse struct {
	MachineID string `json:"machineId"`
	Token     string `json:"token"`
	Status    string `json:"status"`
}

func (e EnrollResponse) String() string {
	return fmt.Sprintf("signer.EnrollResponse{machineId=%q status=%q token=[redacted]}", e.MachineID, e.Status)
}

// GoString 覆盖 %#v。
func (e EnrollResponse) GoString() string { return e.String() }

// Format 覆盖全部动词。
func (e EnrollResponse) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.String()) }

// SetupAPI 是 machine-setup 接口（不带机器令牌，靠注册码）。
type SetupAPI interface {
	Describe(ctx context.Context, code string) (DescribeResponse, error)
	Enroll(ctx context.Context, code string, x25519Pub, ed25519Pub []byte) (EnrollResponse, error)
}

// Describe 查询注册码（不消耗）。
func (c *HTTPClient) Describe(ctx context.Context, code string) (DescribeResponse, error) {
	var out DescribeResponse
	_, err := c.doJSON(ctx, "POST", "/v1/machine-setup/describe", 0, map[string]string{"code": code}, &out)
	return out, err
}

// Enroll 用注册码登记本机公钥，换回长期机器令牌。
func (c *HTTPClient) Enroll(ctx context.Context, code string, x25519Pub, ed25519Pub []byte) (EnrollResponse, error) {
	var out EnrollResponse
	_, err := c.doJSON(ctx, "POST", "/v1/machine-setup/enroll", 0, map[string]string{
		"code":             code,
		"x25519PublicKey":  base64.StdEncoding.EncodeToString(x25519Pub),
		"ed25519PublicKey": base64.StdEncoding.EncodeToString(ed25519Pub),
	}, &out)
	return out, err
}

// ---- 以签名闸用户身份做的那一步（enroll-init）----

// enrollInitRequest 是 root 进程交给签名闸用户子进程的请求（stdin，一行 JSON）。没有角色与受信签名闸：
// 本机记录一律从备开始，不信任任何签名闸。
type enrollInitRequest struct {
	Probe    bool                   `json:"probe"`
	StateDir string                 `json:"stateDir"`
	Name     string                 `json:"name"`
	Recovery *records.RecoveryTrust `json:"recovery"`
}

// enrollInitResult 是子进程的回答（stdout，一行 JSON）。
type enrollInitResult struct {
	State            string `json:"state"` // empty | pending | initialized
	Name             string `json:"name"`
	X25519PublicKey  string `json:"x25519PublicKey"`
	Ed25519PublicKey string `json:"ed25519PublicKey"`
}

func (r enrollInitResult) keys() (x, ed []byte, err error) {
	x, err = recovery.DecodePublicKey(r.X25519PublicKey)
	if err != nil {
		return nil, nil, errors.New("the state initialization returned a malformed X25519 public key")
	}
	ed, err = base64.StdEncoding.Strict().DecodeString(r.Ed25519PublicKey)
	if err != nil || len(ed) != ed25519.PublicKeySize {
		return nil, nil, errors.New("the state initialization returned a malformed Ed25519 public key")
	}
	return x, ed, nil
}

// runEnrollInit 在签名闸用户身份下执行：探测状态目录，或生成本机密钥与初始记录（角色备、受信恢复公钥；
// 留下 enroll 标记）。
func runEnrollInit(req enrollInitRequest) (enrollInitResult, error) {
	if !filepath.IsAbs(req.StateDir) || filepath.Clean(req.StateDir) != req.StateDir {
		return enrollInitResult{}, errors.New("state directory must be an absolute clean path")
	}
	if err := securefs.CheckPrivateDir(req.StateDir); err != nil {
		return enrollInitResult{}, fmt.Errorf("state directory: %w", err)
	}
	marker := filepath.Join(req.StateDir, enrollMarkerFile)
	_, markerErr := os.Lstat(marker)
	pending := markerErr == nil
	parts := []string{x25519KeyFile, ed25519KeyFile, records.TrustFileName, records.SignedFileName, initMarkerFile}
	present := 0
	for _, name := range parts {
		if _, err := os.Lstat(filepath.Join(req.StateDir, name)); err == nil {
			present++
		} else if !errors.Is(err, fs.ErrNotExist) {
			return enrollInitResult{}, err
		}
	}
	state := "empty"
	switch {
	case pending:
		state = "pending"
	case present > 0:
		state = "initialized"
	}
	describe := func(state string) (enrollInitResult, error) {
		out := enrollInitResult{State: state}
		if state == "empty" {
			return out, nil
		}
		keys, err := loadKeys(req.StateDir, true)
		if err != nil && state == "pending" {
			// 上次注册在生成密钥之前就中断了：没有密钥可报
			return out, nil
		}
		if err != nil {
			return enrollInitResult{}, err
		}
		store, err := records.Open(req.StateDir, keys.Ed25519)
		if err != nil && state == "pending" {
			return out, nil
		}
		if err != nil {
			return enrollInitResult{}, err
		}
		defer store.Close()
		out.Name = store.Genesis().MachineName
		out.X25519PublicKey = base64.StdEncoding.EncodeToString(keys.X25519PublicKey())
		out.Ed25519PublicKey = base64.StdEncoding.EncodeToString(keys.Ed25519PublicKey())
		return out, nil
	}
	if req.Probe {
		return describe(state)
	}

	if state == "initialized" {
		return enrollInitResult{}, errors.New("the state directory already holds machine keys or local records; enroll only initializes a new signing gate")
	}
	if pending {
		// 上次注册没完成：那套密钥没有换到令牌，清掉重来
		for _, name := range parts {
			if err := os.Remove(filepath.Join(req.StateDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return enrollInitResult{}, err
			}
		}
	} else if err := securefs.WriteFileExclusive(marker, []byte("enrolling\n")); err != nil {
		return enrollInitResult{}, err
	}
	if _, _, err := initState(req.StateDir, req.Name); err != nil {
		return enrollInitResult{}, err
	}
	keys, err := loadKeys(req.StateDir, true)
	if err != nil {
		return enrollInitResult{}, err
	}
	store, err := records.Open(req.StateDir, keys.Ed25519)
	if err != nil {
		return enrollInitResult{}, err
	}
	defer store.Close()
	if err := store.SetRole(records.RoleChange{Role: records.RoleStandby, Mode: records.RoleModeEnroll, Operator: records.EnrollOperator,
		Reason: "new signing gate: standby until signer promote on this machine"}); err != nil {
		return enrollInitResult{}, err
	}
	if req.Recovery != nil {
		if err := store.TrustRecovery(*req.Recovery); err != nil {
			return enrollInitResult{}, err
		}
	}
	return describe("pending")
}

// EnrollInitMain 是隐藏子命令 enroll-init：root 的 signer enroll 以签名闸用户身份启动它，
// stdin 一行请求，stdout 一行结果。
func EnrollInitMain(stdin io.Reader, stdout, stderr io.Writer) int {
	if os.Geteuid() == 0 {
		// 状态目录必须属于签名闸用户：root 写出来的私钥与记录签名闸用户读不了
		fmt.Fprintln(stderr, "enroll-init must run as the signing gate user, not root (signer enroll starts it)")
		return 2
	}
	var req enrollInitRequest
	decoder := json.NewDecoder(io.LimitReader(stdin, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		fmt.Fprintln(stderr, "enroll-init: malformed request")
		return 2
	}
	result, err := runEnrollInit(req)
	if err != nil {
		fmt.Fprintln(stderr, cleanText(err.Error(), 1000))
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

// ---- 需要 root 的那几步 ----

// enrollAccount 是签名闸的系统用户。
type enrollAccount struct {
	Name string
	UID  int
	GID  int
}

// enrollHost 抽出需要 root 的操作，测试里用当前用户替代。
type enrollHost interface {
	// Account 核对 env 文件（root 所有、组是签名闸用户的组、组不可写、其它用户无权限），返回签名闸用户；
	// 状态目录不存在时以该用户身份建 0700。
	Account(envFile, stateDir string) (enrollAccount, error)
	// Init 以签名闸用户身份执行 enroll-init。
	Init(acct enrollAccount, req enrollInitRequest) (enrollInitResult, error)
	// WriteEnv 原子替换 env 文件（root:签名闸组 0640）。
	WriteEnv(acct enrollAccount, path string, content []byte) error
}

type rootHost struct {
	rootUID    int
	exe        string
	lookupUser func(gid int) (enrollAccount, error)
}

func newRootHost() *rootHost {
	return &rootHost{rootUID: 0, exe: "/proc/self/exe", lookupUser: lookupAccountByGroup}
}

// lookupAccountByGroup：env 文件的属组名就是签名闸用户名（useradd --user-group）。
func lookupAccountByGroup(gid int) (enrollAccount, error) {
	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		return enrollAccount{}, fmt.Errorf("the env file's group %d has no name: %w", gid, err)
	}
	u, err := user.Lookup(g.Name)
	if err != nil {
		return enrollAccount{}, fmt.Errorf("there is no user named after the env file's group %s (create the signing gate user with useradd --system --user-group): %w", g.Name, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	primary, _ := strconv.Atoi(u.Gid)
	if primary != gid {
		return enrollAccount{}, fmt.Errorf("user %s's primary group is not %s", u.Username, g.Name)
	}
	return enrollAccount{Name: u.Username, UID: uid, GID: gid}, nil
}

func (h *rootHost) Account(envFile, stateDir string) (enrollAccount, error) {
	if os.Geteuid() != h.rootUID {
		return enrollAccount{}, errors.New("signer enroll must run as root: it writes the env file and hands the state directory to the signing gate user")
	}
	info, err := os.Lstat(envFile)
	if err != nil {
		return enrollAccount{}, fmt.Errorf("env file: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return enrollAccount{}, fmt.Errorf("%s must be a regular file", envFile)
	case !ok || int(stat.Uid) != h.rootUID:
		return enrollAccount{}, fmt.Errorf("%s must be owned by root", envFile)
	case info.Mode().Perm()&0o027 != 0:
		return enrollAccount{}, fmt.Errorf("%s has permissions %04o; expected 0640 (root:<signing gate group>)", envFile, info.Mode().Perm())
	}
	acct, err := h.lookupUser(int(stat.Gid))
	if err != nil {
		return enrollAccount{}, err
	}
	if acct.UID == 0 || acct.GID == 0 {
		return enrollAccount{}, fmt.Errorf("%s must belong to the signing gate's group, not root's", envFile)
	}
	dirInfo, err := os.Lstat(stateDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(stateDir, 0o700); err != nil {
			return enrollAccount{}, fmt.Errorf("create the state directory: %w", err)
		}
		if err := os.Lchown(stateDir, acct.UID, acct.GID); err != nil {
			_ = os.Remove(stateDir)
			return enrollAccount{}, err
		}
		if err := os.Chmod(stateDir, 0o700); err != nil {
			return enrollAccount{}, err
		}
		return acct, securefs.SyncDir(filepath.Dir(stateDir))
	case err != nil:
		return enrollAccount{}, err
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if dirInfo.Mode()&fs.ModeSymlink != 0 || !dirInfo.IsDir() || !ok || int(dirStat.Uid) != acct.UID || dirInfo.Mode().Perm()&0o077 != 0 {
		return enrollAccount{}, fmt.Errorf("%s must be a 0700 directory owned by %s", stateDir, acct.Name)
	}
	return acct, nil
}

func (h *rootHost) Init(acct enrollAccount, req enrollInitRequest) (enrollInitResult, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return enrollInitResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.exe, "enroll-init")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stdin = bytes.NewReader(append(raw, '\n'))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cred := &syscall.Credential{Uid: uint32(acct.UID), Gid: uint32(acct.GID), Groups: []uint32{}}
	if os.Geteuid() != 0 {
		// 只在测试里（非 root、身份不变）走到：非 root 不能 setgroups
		cred.NoSetGroups = true
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	if err := cmd.Run(); err != nil {
		return enrollInitResult{}, fmt.Errorf("initialize the state directory as %s: %v: %s", acct.Name, err, cleanText(strings.TrimSpace(stderr.String()), 1000))
	}
	var out enrollInitResult
	decoder := json.NewDecoder(io.LimitReader(&stdout, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return enrollInitResult{}, errors.New("the state initialization returned malformed output")
	}
	return out, nil
}

func (h *rootHost) WriteEnv(acct enrollAccount, path string, content []byte) error {
	return writeEnvAtomic(path, content, h.rootUID, acct.GID)
}

// writeEnvAtomic 在同目录写临时文件（0600 起步，写完 fchown/fchmod 成 uid:gid 0640、fsync），再 rename 覆盖。
func writeEnvAtomic(path string, content []byte, uid, gid int) error {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(content); err != nil {
		return fail(err)
	}
	if err := f.Chown(uid, gid); err != nil {
		return fail(err)
	}
	if err := f.Chmod(0o640); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return securefs.SyncDir(filepath.Dir(path))
}

// updateEnvFile 替换或追加 SIGNER_SERVER_URL、SIGNER_NAME、SIGNER_MACHINE_TOKEN 三行，其余行原样保留。
func updateEnvFile(raw []byte, values map[string]string) []byte {
	var out bytes.Buffer
	written := map[string]bool{}
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if v, managed := values[key]; ok && managed && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			if !written[key] {
				out.WriteString(key + "=\"" + v + "\"\n")
				written[key] = true
			}
			continue
		}
		out.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			out.WriteString("\n")
		}
	}
	var missing []string
	for _, key := range []string{EnvServerURL, EnvName, EnvMachineToken} {
		if _, ok := values[key]; ok && !written[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		out.WriteString("\n# written by signer enroll\n")
		for _, key := range missing {
			out.WriteString(key + "=\"" + values[key] + "\"\n")
		}
	}
	return out.Bytes()
}

// ---- signer enroll ----

// enrollmentCode 取注册码：--code，或环境变量 RN_ENROLLMENT_CODE（install.sh 用后者，注册码不进进程参数、
// 不进 ps）。两者都给且不同就拒绝。环境变量读完就从本进程环境里删掉；以签名闸用户身份启动的 enroll-init
// 子进程本来就只拿到固定的 PATH、LANG。（/proc/<pid>/environ 仍是启动时的内容，只有 root 与同一用户读得到。）
func enrollmentCode(flagCode string, getenv func(string) string) (string, error) {
	envCode := getenv(EnvEnrollmentCode)
	_ = os.Unsetenv(EnvEnrollmentCode)
	switch {
	case envCode != "" && flagCode != "" && envCode != flagCode:
		// 不回显注册码
		return "", fmt.Errorf("--code and %s hold different enrollment codes; give the code only once", EnvEnrollmentCode)
	case envCode != "":
		return envCode, nil
	}
	return flagCode, nil
}

// Enroll 是 signer enroll（约定第 4 节，按「信任只在签名闸本机确认」收紧）：
//
//	核对 env 与状态目录 → 已注册就幂等退出 → describe → 核对恢复公钥 sha256 →
//	以签名闸用户身份生成本机密钥、写初始角色（一律是备）与恢复公钥（留 enroll 标记）→
//	enroll 换令牌 → 原子替换 env（令牌不经过屏幕）→ 清标记 → 打印机器名、完整指纹与下一步。
//
// 服务端给的主备与主签名闸只用于提示：服务端被攻破时不能让新机器本机为主（绕过 promote、与现有主各签
// 同一个 versionCode），也不能让备从此自动接受它指定的「主」生成的密钥。
func Enroll(ctx context.Context, opts EnrollOptions, api SetupAPI, host enrollHost, stdout io.Writer) error {
	if err := validateServerURL(opts.ServerURL); err != nil {
		return fmt.Errorf("--server %q: %v", opts.ServerURL, err)
	}
	if !machinekey.ValidEnrollmentCode(opts.Code) {
		// 不回显注册码
		return fmt.Errorf("the enrollment code (--code or %s) is not an enrollment code (rne_ followed by 43 base64url characters); copy the install command from the console again", EnvEnrollmentCode)
	}
	if !filepath.IsAbs(opts.EnvFile) || filepath.Clean(opts.EnvFile) != opts.EnvFile {
		return errors.New("--env-file must be an absolute clean path such as /etc/rn-signer-<instance>.env")
	}
	recoverySHA := ""
	if opts.RecoverySHA256 != "" {
		v, ok := fingerprint.Normalize(opts.RecoverySHA256)
		if !ok {
			return errors.New("--recovery-sha256 must be the full 64-character SHA-256 of the recovery public key (from the password manager)")
		}
		recoverySHA = v
	}
	if opts.NameCheck != "" && !ident.ValidMachineName(opts.NameCheck) {
		return errors.New("--name-check must be a machine name")
	}
	raw, err := os.ReadFile(opts.EnvFile)
	if err != nil {
		return fmt.Errorf("read the env file (install.sh renders it from the template first): %w", err)
	}
	values, err := ReadEnvFile(opts.EnvFile)
	if err != nil {
		return err
	}
	stateDir := values[EnvStateDir]
	if stateDir == "" || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || stateDir == "/" {
		return fmt.Errorf("%s in %s must be an absolute clean directory path", EnvStateDir, opts.EnvFile)
	}
	acct, err := host.Account(opts.EnvFile, stateDir)
	if err != nil {
		return err
	}
	probe, err := host.Init(acct, enrollInitRequest{Probe: true, StateDir: stateDir})
	if err != nil {
		return err
	}
	hasToken := tokenPattern.MatchString(values[EnvMachineToken])
	switch {
	case hasToken && probe.State == "empty":
		return fmt.Errorf("%s already has a machine token but %s has no machine keys; this machine was set up by hand or its state was lost — do not reuse the token, register it as a new machine", opts.EnvFile, stateDir)
	case hasToken:
		if probe.State == "pending" {
			if err := os.Remove(filepath.Join(stateDir, enrollMarkerFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := securefs.SyncDir(stateDir); err != nil {
				return err
			}
		}
		if values[EnvName] != "" && probe.Name != values[EnvName] {
			return fmt.Errorf("%s names machine %s, but the local records belong to %s", opts.EnvFile, values[EnvName], probe.Name)
		}
		fmt.Fprintf(stdout, "signing gate %s is already enrolled; nothing to do\n", probe.Name)
		return printEnrolled(stdout, probe, "")
	case probe.State == "initialized":
		return fmt.Errorf("%s already holds machine keys and local records but %s has no machine token; enroll only initializes a new signing gate", stateDir, opts.EnvFile)
	}

	desc, err := api.Describe(ctx, opts.Code)
	if err != nil {
		return fmt.Errorf("look up the enrollment code: %w (an expired or used code: reissue it in the console; if an earlier run of this command was interrupted after enrolling, the machine is already pending_key — delete it in the console and create it again)", err)
	}
	signerRole := ""
	if desc.SignerRole != nil {
		signerRole = *desc.SignerRole
	}
	switch {
	case desc.Role != "signer":
		return errors.New("this enrollment code is not for a signing gate (install the builder bundle instead)")
	case !ident.ValidServerID(desc.MachineID) || !ident.ValidMachineName(desc.Name):
		return &ProtocolError{Msg: "describe returned a malformed machine id or name"}
	case signerRole != string(records.RolePrimary) && signerRole != string(records.RoleStandby):
		return &ProtocolError{Msg: "describe returned no primary/standby role for a signing gate"}
	case opts.NameCheck != "" && desc.Name != opts.NameCheck:
		return fmt.Errorf("this enrollment code is for machine %s, not %s", desc.Name, opts.NameCheck)
	case values[EnvName] != "" && values[EnvName] != desc.Name:
		return fmt.Errorf("%s names machine %s, but this enrollment code is for %s", opts.EnvFile, values[EnvName], desc.Name)
	case recoverySHA == "":
		return errors.New("--recovery-sha256 is required for a signing gate: paste the recovery public key SHA-256 from the password manager")
	}
	var recoveryTrust *records.RecoveryTrust
	for _, k := range desc.RecoveryKeys {
		if k.X25519PublicKeySHA256 != recoverySHA {
			continue
		}
		if _, err := verifyPeerRecoveryKey(k); err != nil {
			return fmt.Errorf("the server's record for recovery key %s is malformed (%v)", recoverySHA, err)
		}
		recoveryTrust = &records.RecoveryTrust{Name: k.Name, X25519PublicKeySHA256: recoverySHA, Mode: records.TrustModeEnroll, Operator: records.EnrollOperator,
			Note: "--recovery-sha256 matched the server's recovery key at enrollment"}
	}
	if recoveryTrust == nil {
		return fmt.Errorf("the server has no recovery key with SHA-256 %s; check the value from the password manager, or register recovery-public.json in the console first", recoverySHA)
	}
	// 服务端说的当前主签名闸：只取机器名打印提示（不合格就当没有），不写记录
	primaryName := ""
	if p := desc.PrimarySigner; p != nil && ident.ValidMachineName(p.Name) && p.Name != desc.Name {
		primaryName = p.Name
	}

	initResult, err := host.Init(acct, enrollInitRequest{StateDir: stateDir, Name: desc.Name, Recovery: recoveryTrust})
	if err != nil {
		return err
	}
	if initResult.State != "pending" || initResult.Name != desc.Name {
		return errors.New("the state initialization did not produce this machine's records")
	}
	x, ed, err := initResult.keys()
	if err != nil {
		return err
	}
	enrolled, err := api.Enroll(ctx, opts.Code, x, ed)
	if err != nil {
		return fmt.Errorf("enroll this machine: %w (if the server accepted the enrollment before the connection failed, the code is used up: delete the machine in the console, create it again and rerun the new install command)", err)
	}
	if !tokenPattern.MatchString(enrolled.Token) {
		return &ProtocolError{Msg: "enroll returned a malformed machine token"}
	}
	if enrolled.MachineID != desc.MachineID {
		return &ProtocolError{Msg: "enroll returned a different machine id than describe"}
	}
	content := updateEnvFile(raw, map[string]string{EnvServerURL: opts.ServerURL, EnvName: desc.Name, EnvMachineToken: enrolled.Token})
	if err := host.WriteEnv(acct, opts.EnvFile, content); err != nil {
		return fmt.Errorf("the server issued a machine token but writing %s failed (%v); revoke this machine in the console and enroll a new one", opts.EnvFile, err)
	}
	if err := os.Remove(filepath.Join(stateDir, enrollMarkerFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := securefs.SyncDir(stateDir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "enrolled signing gate %s (machine id %s, %s, local role standby)\n", desc.Name, desc.MachineID, cleanText(enrolled.Status, 40))
	if err := printEnrolled(stdout, initResult, recoveryTrust.Name+" "+recoverySHA); err != nil {
		return err
	}
	printEnrollNextSteps(stdout, enrollNextSteps{name: desc.Name, consoleRole: signerRole, primaryName: primaryName, user: acct.Name, envFile: opts.EnvFile})
	return nil
}

func printEnrolled(w io.Writer, r enrollInitResult, recoveryLine string) error {
	x, ed, err := r.keys()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "  machine name:    %s\n  X25519 sha256:   %s\n  Ed25519 sha256:  %s\n", r.Name, fingerprint.SHA256Hex(x), fingerprint.SHA256Hex(ed))
	if recoveryLine != "" {
		fmt.Fprintf(w, "  recovery key:    %s\n", recoveryLine)
	}
	return nil
}

// enrollNextSteps 是注册后打印的下一步。consoleRole、primaryName 来自服务端，只决定提示的内容。
type enrollNextSteps struct {
	name, consoleRole, primaryName, user, envFile string
}

func printEnrollNextSteps(w io.Writer, n enrollNextSteps) {
	cmd := func(args string) string {
		return fmt.Sprintf("sudo -u %s %s %s --env-file %s", n.user, installedSignerPath, args, n.envFile)
	}
	fmt.Fprintf(w, "\nThis machine is a standby in its local records. The console's primary/standby only routes jobs;\n"+
		"only `signer promote` on this machine makes it primary, and it trusts signing gates only through `signer trust-peer` here.\n")
	fmt.Fprintf(w, "next:\n  1. Accept this machine in the console (compare both fingerprints above digit by digit).\n")
	if n.consoleRole == string(records.RolePrimary) {
		fmt.Fprintf(w, "  2. The console registered this machine as the primary. If it is the platform's first primary signing gate,\n"+
			"     stop its service and run on this machine:\n       %s\n"+
			"     If it replaces an existing primary, promote with --import or --manual instead (README section 9).\n", cmd("promote --first"))
		fmt.Fprintf(w, "  3. On this machine trust each builder and each standby:\n       %s\n       %s\n"+
			"     On every standby run `signer trust-peer --peer %s` and paste the fingerprints above.\n",
			cmd("trust-builder --builder <builder name>"), cmd("trust-peer --peer <standby name>"), n.name)
		return
	}
	if n.primaryName != "" {
		fmt.Fprintf(w, "  2. Trust the primary on this machine, pasting the fingerprints printed on the primary itself\n"+
			"     (its install output or `signer show-key` there), never the console's:\n       %s\n", cmd("trust-peer --peer "+n.primaryName))
	} else {
		fmt.Fprintf(w, "  2. The server reports no primary signing gate yet: install the primary first, then trust it on this machine:\n       %s\n",
			cmd("trust-peer --peer <primary name>"))
	}
	fmt.Fprintf(w, "  3. On the primary signing gate run `signer trust-peer --peer %s` and paste the fingerprints above,\n"+
		"     so that new keystores are also encrypted to this machine.\n  4. On this machine trust each builder:\n       %s\n",
		n.name, cmd("trust-builder --builder <builder name>"))
}
