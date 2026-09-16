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

// DescribeResponse 是 POST /v1/machine-setup/describe 的响应（签名闸用到的部分）。
type DescribeResponse struct {
	MachineID     string            `json:"machineId"`
	Name          string            `json:"name"`
	Role          string            `json:"role"`
	SignerRole    *string           `json:"signerRole"`
	RecoveryKeys  []PeerRecoveryKey `json:"recoveryKeys"`
	PrimarySigner *PrimarySigner    `json:"primarySigner"`
}

// PrimarySigner 是 describe 给备签名闸的当前主签名闸（首次信任）。
type PrimarySigner struct {
	MachineID              string `json:"machineId"`
	Name                   string `json:"name"`
	X25519PublicKey        string `json:"x25519PublicKey"`
	X25519PublicKeySHA256  string `json:"x25519PublicKeySha256"`
	Ed25519PublicKey       string `json:"ed25519PublicKey"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
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

// enrollInitRequest 是 root 进程交给签名闸用户子进程的请求（stdin，一行 JSON）。
type enrollInitRequest struct {
	Probe    bool                   `json:"probe"`
	StateDir string                 `json:"stateDir"`
	Name     string                 `json:"name"`
	Role     records.Role           `json:"role"`
	Recovery *records.RecoveryTrust `json:"recovery"`
	Primary  *records.PeerTrust     `json:"primary"`
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

// runEnrollInit 在签名闸用户身份下执行：探测状态目录，或生成本机密钥与初始记录（留下 enroll 标记）。
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
	if err := store.SetRole(records.RoleChange{Role: req.Role, Mode: records.RoleModeEnroll, Operator: records.EnrollOperator,
		Reason: "initial role from the server at enrollment"}); err != nil {
		return enrollInitResult{}, err
	}
	if req.Recovery != nil {
		if err := store.TrustRecovery(*req.Recovery); err != nil {
			return enrollInitResult{}, err
		}
	}
	if req.Primary != nil {
		if err := store.TrustPeer(*req.Primary); err != nil {
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

// Enroll 是 signer enroll（约定第 4 节）：
//
//	核对 env 与状态目录 → 已注册就幂等退出 → describe → 核对恢复公钥 sha256 与主备 →
//	以签名闸用户身份生成本机密钥、写初始角色、恢复公钥、首次信任的主签名闸（留 enroll 标记）→
//	enroll 换令牌 → 原子替换 env（令牌不经过屏幕）→ 清标记 → 打印机器名与完整指纹。
func Enroll(ctx context.Context, opts EnrollOptions, api SetupAPI, host enrollHost, stdout io.Writer) error {
	if err := validateServerURL(opts.ServerURL); err != nil {
		return fmt.Errorf("--server %q: %v", opts.ServerURL, err)
	}
	if !machinekey.ValidEnrollmentCode(opts.Code) {
		// 不回显注册码
		return errors.New("--code is not an enrollment code (rne_ followed by 43 base64url characters); copy the install command from the console again")
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
		return printEnrolled(stdout, probe, "", "", "")
	case probe.State == "initialized":
		return fmt.Errorf("%s already holds machine keys and local records but %s has no machine token; enroll only initializes a new signing gate", stateDir, opts.EnvFile)
	}

	desc, err := api.Describe(ctx, opts.Code)
	if err != nil {
		return fmt.Errorf("look up the enrollment code: %w", err)
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
	var primaryTrust *records.PeerTrust
	if signerRole == string(records.RoleStandby) && desc.PrimarySigner != nil {
		p := desc.PrimarySigner
		v, err := verifyPeerSigner(PeerSigner{MachineID: p.MachineID, Name: p.Name, Status: "active", X25519PublicKey: p.X25519PublicKey,
			X25519PublicKeySHA256: p.X25519PublicKeySHA256, Ed25519PublicKey: p.Ed25519PublicKey, Ed25519PublicKeySHA256: p.Ed25519PublicKeySHA256})
		if err != nil || p.Name == desc.Name {
			return &ProtocolError{Msg: "describe returned a malformed primary signing gate"}
		}
		primaryTrust = &records.PeerTrust{Name: v.Name, X25519PublicKeySHA256: v.X25519PublicKeySHA256, Ed25519PublicKeySHA256: v.Ed25519PublicKeySHA256,
			Mode: records.TrustModeEnrollFirstTrust, Operator: records.EnrollOperator, Note: "first trust: the server's primary signing gate at enrollment"}
	}

	initResult, err := host.Init(acct, enrollInitRequest{StateDir: stateDir, Name: desc.Name, Role: records.Role(signerRole), Recovery: recoveryTrust, Primary: primaryTrust})
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
		return fmt.Errorf("enroll this machine: %w", err)
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
	fmt.Fprintf(stdout, "enrolled signing gate %s (machine id %s, %s, local role %s)\n", desc.Name, desc.MachineID, cleanText(enrolled.Status, 40), signerRole)
	primaryLine := ""
	if primaryTrust != nil {
		primaryLine = fmt.Sprintf("%s (x25519 %s, ed25519 %s; first trust from the server — compare with that machine's fingerprints)", primaryTrust.Name, primaryTrust.X25519PublicKeySHA256, primaryTrust.Ed25519PublicKeySHA256)
	}
	return printEnrolled(stdout, initResult, signerRole, recoveryTrust.Name+" "+recoverySHA, primaryLine)
}

func printEnrolled(w io.Writer, r enrollInitResult, role, recoveryLine, primaryLine string) error {
	x, ed, err := r.keys()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "  machine name:    %s\n  X25519 sha256:   %s\n  Ed25519 sha256:  %s\n", r.Name, fingerprint.SHA256Hex(x), fingerprint.SHA256Hex(ed))
	if recoveryLine != "" {
		fmt.Fprintf(w, "  recovery key:    %s\n", recoveryLine)
	}
	if primaryLine != "" {
		fmt.Fprintf(w, "  trusts primary:  %s\n", primaryLine)
	}
	fmt.Fprintf(w, "next: accept this machine in the console (compare both fingerprints above).\n")
	switch role {
	case string(records.RoleStandby):
		fmt.Fprintf(w, "      On the primary signing gate run `signer trust-peer --peer %s` and paste these fingerprints,\n      so that new keystores are also encrypted to this machine.\n", r.Name)
	case string(records.RolePrimary):
		fmt.Fprintf(w, "      On every standby signing gate run `signer trust-peer --peer %s` and paste these fingerprints;\n      on this machine run `signer trust-peer` for each standby and `signer trust-builder --builder <name>` for each builder.\n", r.Name)
	}
	return nil
}
