package records

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/internal/securefs"
)

var (
	// ErrMissing：状态目录里缺记录文件。签名闸不会自己重建——记录丢了等于忘了签过什么。
	ErrMissing = errors.New("records: a local record file is missing")
	// ErrVersionCodeTaken：这个 (包名, 证书, versionCode) 已被别的任务或别的输入包预留。永久拒签。
	ErrVersionCodeTaken = errors.New("records: this versionCode is already reserved by another job or another unsigned package")
	// ErrVersionCodeNotIncreasing：versionCode 不大于本机记录里该 (包名, 证书) 已签过的最大值。
	ErrVersionCodeNotIncreasing = errors.New("records: versionCode is not greater than the highest one already signed for this package and certificate")
	// ErrJobConflict：同一个任务已经预留了另一个 versionCode 或另一个输入包。
	ErrJobConflict = errors.New("records: this job already holds a different reservation")
	// ErrNotReserved：没有这个任务的有效预留。
	ErrNotReserved = errors.New("records: this job has no matching reservation")
	// ErrAlreadyCompleted：预留已经完成，不能释放；或完成值与已记录的不同。
	ErrAlreadyCompleted = errors.New("records: this reservation has already been completed")
)

// GenesisParams 是初始化记录文件需要的本机信息。
type GenesisParams struct {
	MachineName           string
	Ed25519PrivateKey     ed25519.PrivateKey
	X25519PublicKeySHA256 string
}

// Init 在状态目录里创建两个记录文件，各写一行 genesis。任一文件已存在就报错。
func Init(dir string, p GenesisParams) error {
	if len(p.Ed25519PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("records: ed25519 private key must be 64 bytes")
	}
	pub := p.Ed25519PrivateKey.Public().(ed25519.PublicKey)
	g := Genesis{
		MachineName:            p.MachineName,
		Ed25519PublicKey:       base64.StdEncoding.EncodeToString(pub),
		Ed25519PublicKeySHA256: fingerprint.SHA256Hex(pub),
		X25519PublicKeySHA256:  p.X25519PublicKeySHA256,
	}
	if _, err := g.validate(); err != nil {
		return fmt.Errorf("records: %w", err)
	}
	if err := securefs.CheckPrivateDir(dir); err != nil {
		return fmt.Errorf("records: state directory: %w", err)
	}
	for _, kind := range []string{kindTrust, kindSigned} {
		raw, err := encodeLine(kind, 0, zeroHash, time.Now(), typeGenesis, g, p.Ed25519PrivateKey)
		if err != nil {
			return err
		}
		if err := securefs.WriteFileExclusive(filepath.Join(dir, fileName(kind)), append(raw, '\n')); err != nil {
			return fmt.Errorf("records: create %s: %w", fileName(kind), err)
		}
	}
	return nil
}

// Exists 报告状态目录里两个记录文件各自是否存在。
func Exists(dir string) (trust, signed bool, err error) {
	for _, kind := range []string{kindTrust, kindSigned} {
		_, statErr := os.Lstat(filepath.Join(dir, fileName(kind)))
		switch {
		case statErr == nil:
			if kind == kindTrust {
				trust = true
			} else {
				signed = true
			}
		case errors.Is(statErr, fs.ErrNotExist):
		default:
			return false, false, statErr
		}
	}
	return trust, signed, nil
}

func fileName(kind string) string {
	if kind == kindTrust {
		return TrustFileName
	}
	return SignedFileName
}

type logFile struct {
	kind   string
	path   string
	f      *os.File
	v      *verifier
	offset int64
}

type vcKey struct {
	pkg, cert string
	vc        int64
}

type pkgKey struct{ pkg, cert string }

type trustState struct {
	role          RoleChange
	builders      map[string]BuilderTrust
	confirmations map[pkgKey]Confirmation
}

type signedState struct {
	byVC      map[vcKey]*Reservation
	byJob     map[string]*Reservation
	all       []*Reservation
	baselines map[pkgKey]Baseline
}

func newTrustState() *trustState {
	return &trustState{
		role:          RoleChange{Role: RoleStandby},
		builders:      map[string]BuilderTrust{},
		confirmations: map[pkgKey]Confirmation{},
	}
}

func newSignedState() *signedState {
	return &signedState{byVC: map[vcKey]*Reservation{}, byJob: map[string]*Reservation{}, baselines: map[pkgKey]Baseline{}}
}

// Store 是打开并校验过的本机记录。方法可并发调用；多个进程（签名闸主进程与运维
// 命令）经 flock 协调，每次读写前先读入并校验别的进程追加的新行。
type Store struct {
	mu     sync.Mutex
	dir    string
	priv   ed25519.PrivateKey
	now    func() time.Time
	trust  *logFile
	signed *logFile
	ts     *trustState
	ss     *signedState
	broken error
}

// Open 打开状态目录里的记录，从头校验两条链；genesis 里的公钥必须是 priv 对应的公钥。
func Open(dir string, priv ed25519.PrivateKey) (*Store, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("records: ed25519 private key must be 64 bytes")
	}
	if err := securefs.CheckPrivateDir(dir); err != nil {
		return nil, fmt.Errorf("records: state directory: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	pinned := func(g Genesis) error {
		if g.Ed25519PublicKey != base64.StdEncoding.EncodeToString(pub) {
			return errors.New("genesis names a different machine key: these records were not written by this signing gate")
		}
		return nil
	}
	s := &Store{dir: dir, priv: priv, now: time.Now, ts: newTrustState(), ss: newSignedState()}
	var err error
	if s.trust, err = openLog(dir, kindTrust, pinned); err != nil {
		return nil, err
	}
	if s.signed, err = openLog(dir, kindSigned, pinned); err != nil {
		_ = s.trust.f.Close()
		return nil, err
	}
	if err := s.refresh(s.trust, false); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.refresh(s.signed, false); err != nil {
		s.Close()
		return nil, err
	}
	for _, lf := range []*logFile{s.trust, s.signed} {
		if lf.v.seq == 0 {
			s.Close()
			return nil, fmt.Errorf("%w: %s is empty", ErrCorrupt, lf.path)
		}
	}
	if s.trust.v.genesis != s.signed.v.genesis {
		s.Close()
		return nil, fmt.Errorf("%w: trust.jsonl and signed.jsonl have different genesis records", ErrCorrupt)
	}
	return s, nil
}

func openLog(dir, kind string, pinned func(Genesis) error) (*logFile, error) {
	path := filepath.Join(dir, fileName(kind))
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrMissing, path)
	}
	if err := securefs.CheckPrivateFile(path); err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return &logFile{kind: kind, path: path, f: f, v: newVerifier(kind, pinned)}, nil
}

// Close 关闭文件。
func (s *Store) Close() error {
	var first error
	for _, lf := range []*logFile{s.trust, s.signed} {
		if lf != nil && lf.f != nil {
			if err := lf.f.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// Genesis 返回本机记录的 genesis。
func (s *Store) Genesis() Genesis { return s.trust.v.genesis }

// SetClock 替换时间来源（测试用）。
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// refresh 读入并校验 offset 之后别的进程追加的行。调用方持有 s.mu；locked=true 表示
// 调用方已经持有该文件的 flock。
func (s *Store) refresh(lf *logFile, locked bool) error {
	if s.broken != nil {
		return s.broken
	}
	if !locked {
		if err := securefs.Lock(lf.f, false); err != nil {
			return err
		}
		defer securefs.Unlock(lf.f)
	}
	info, err := lf.f.Stat()
	if err != nil {
		return err
	}
	data, err := readRange(lf.f, lf.offset, info.Size())
	if err != nil {
		return s.fail(err)
	}
	if err := lf.v.feed(data, s.applier(lf.kind)); err != nil {
		return s.fail(err)
	}
	lf.offset = info.Size()
	return nil
}

func (s *Store) fail(err error) error {
	s.broken = err
	return err
}

func (s *Store) applier(kind string) func(entry) error {
	if kind == kindTrust {
		return func(e entry) error { return applyTrust(s.ts, e) }
	}
	return func(e entry) error { return applySigned(s.ss, e) }
}

// append 在独占锁下：读入新行 → check（基于最新状态）→ 写一行 → fsync → 经校验器回放。
func (s *Store) append(lf *logFile, typ string, data any, check func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := securefs.Lock(lf.f, true); err != nil {
		return err
	}
	defer securefs.Unlock(lf.f)
	if err := s.refresh(lf, true); err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	raw, err := encodeLine(lf.kind, lf.v.seq, lf.v.tail, s.now(), typ, data, s.priv)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	n, err := lf.f.Write(raw)
	if err == nil && n != len(raw) {
		err = errors.New("short write")
	}
	if err == nil {
		err = lf.f.Sync()
	}
	if err != nil {
		// 半行留在文件里：下次启动会报 ErrTornTail，由运维查看。本进程不再写。
		return s.fail(fmt.Errorf("records: append to %s failed: %w", lf.path, err))
	}
	if err := lf.v.feed(raw, s.applier(lf.kind)); err != nil {
		return s.fail(err)
	}
	lf.offset += int64(len(raw))
	return nil
}

// read 在共享锁下读入新行后执行 fn。
func (s *Store) read(lf *logFile, fn func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(lf, false); err != nil {
		return err
	}
	fn()
	return nil
}

// ---- trust.jsonl ----

// Role 返回本机当前角色。没有角色记录时是备（Mode 为空）。
func (s *Store) Role() (RoleChange, error) {
	var out RoleChange
	err := s.read(s.trust, func() { out = s.ts.role })
	return out, err
}

// SetRole 写入角色变化。
func (s *Store) SetRole(r RoleChange) error {
	if err := r.validate(); err != nil {
		return fmt.Errorf("records: role: %w", err)
	}
	return s.append(s.trust, typeRole, r, nil)
}

// TrustBuilder 写入（或更新）一台受信构建机。
func (s *Store) TrustBuilder(b BuilderTrust) error {
	if err := b.validate(); err != nil {
		return fmt.Errorf("records: builder: %w", err)
	}
	return s.append(s.trust, typeBuilder, b, nil)
}

// RevokeBuilder 撤销对一台构建机的信任。
func (s *Store) RevokeBuilder(builderID, operator, reason string) error {
	rec := builderRevoke{BuilderID: builderID, Operator: operator, Reason: reason}
	if err := rec.validate(); err != nil {
		return fmt.Errorf("records: builder revoke: %w", err)
	}
	return s.append(s.trust, typeBuilderRevoke, rec, func() error {
		if _, ok := s.ts.builders[builderID]; !ok {
			return fmt.Errorf("records: builder %s is not trusted on this signing gate", builderID)
		}
		return nil
	})
}

// TrustedBuilders 返回当前受信的构建机，按 id 排序。
func (s *Store) TrustedBuilders() ([]BuilderTrust, error) {
	var out []BuilderTrust
	err := s.read(s.trust, func() {
		for _, b := range s.ts.builders {
			out = append(out, b)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].BuilderID < out[j].BuilderID })
	return out, err
}

// Confirm 写入一条租户确认。
func (s *Store) Confirm(c Confirmation) error {
	if err := c.validate(); err != nil {
		return fmt.Errorf("records: confirmation: %w", err)
	}
	return s.append(s.trust, typeTenant, c, nil)
}

// Confirmation 返回 (包名, 证书) 的最新确认。
func (s *Store) Confirmation(packageName, certificateSHA256 string) (Confirmation, bool, error) {
	var out Confirmation
	var ok bool
	err := s.read(s.trust, func() { out, ok = s.ts.confirmations[pkgKey{packageName, certificateSHA256}] })
	return out, ok, err
}

// Confirmations 返回每个 (包名, 证书) 的最新确认，按租户、包名排序。
func (s *Store) Confirmations() ([]Confirmation, error) {
	var out []Confirmation
	err := s.read(s.trust, func() {
		for _, c := range s.ts.confirmations {
			out = append(out, c)
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantSlug != out[j].TenantSlug {
			return out[i].TenantSlug < out[j].TenantSlug
		}
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].CertificateSHA256 < out[j].CertificateSHA256
	})
	return out, err
}

// ---- signed.jsonl ----

// SignedView 是某个 (包名, 证书) 在本机记录里的版本号状态。
type SignedView struct {
	// Max 是已签（预留、完成、导入、人工基线）的最大 versionCode；HasMax=false 表示从未签过。
	// 不含 Existing 这条（同一任务同一输入包的幂等重签不和自己比）。
	Max    int64
	HasMax bool
	// Existing 是这个任务当前持有的有效预留（未释放），没有为 nil。
	Existing *Reservation
}

// SignedState 返回 (包名, 证书) 的版本号状态，供签名前检查使用。
func (s *Store) SignedState(packageName, certificateSHA256, jobID, unsignedSHA256 string) (SignedView, error) {
	var out SignedView
	err := s.read(s.signed, func() { out = s.ss.view(packageName, certificateSHA256, jobID, unsignedSHA256) })
	return out, err
}

func (ss *signedState) view(packageName, certificateSHA256, jobID, unsignedSHA256 string) SignedView {
	var out SignedView
	var exclude *Reservation
	if r := ss.byJob[jobID]; r != nil && r.Status != StatusAbandoned {
		copied := *r
		out.Existing = &copied
		if r.PackageName == packageName && r.CertificateSHA256 == certificateSHA256 && r.UnsignedSHA256 == unsignedSHA256 {
			exclude = r
		}
	}
	for k, r := range ss.byVC {
		if k.pkg != packageName || k.cert != certificateSHA256 || r == exclude {
			continue
		}
		if !out.HasMax || r.VersionCode > out.Max {
			out.Max, out.HasMax = r.VersionCode, true
		}
	}
	if b, ok := ss.baselines[pkgKey{packageName, certificateSHA256}]; ok && (!out.HasMax || b.MaxVersionCode > out.Max) {
		out.Max, out.HasMax = b.MaxVersionCode, true
	}
	return out
}

// Reserve 在解密前预留 (包名, 证书, versionCode)，写入并 fsync。
//
// 同一任务、同一输入包、同一 versionCode 已经预留（或已完成）时返回 idempotent=true，
// 不写新行：允许重签、重传。其余冲突一律报错，调用方按违规永久拒签。
func (s *Store) Reserve(r Reservation) (idempotent bool, err error) {
	if err := r.validateReserve(); err != nil {
		return false, fmt.Errorf("records: reservation: %w", err)
	}
	r.Status, r.SignedSHA256, r.ReleaseID, r.Source = "", "", "", ""
	err = s.append(s.signed, typeReserve, r, func() error {
		k := vcKey{r.PackageName, r.CertificateSHA256, r.VersionCode}
		if cur := s.ss.byVC[k]; cur != nil {
			if cur.JobID == r.JobID && cur.UnsignedSHA256 == r.UnsignedSHA256 && cur.TenantSlug == r.TenantSlug {
				idempotent = true
				return errIdempotent
			}
			return ErrVersionCodeTaken
		}
		if cur := s.ss.byJob[r.JobID]; cur != nil && cur.Status != StatusAbandoned {
			return ErrJobConflict
		}
		if view := s.ss.view(r.PackageName, r.CertificateSHA256, r.JobID, r.UnsignedSHA256); view.HasMax && r.VersionCode <= view.Max {
			return ErrVersionCodeNotIncreasing
		}
		return nil
	})
	if errors.Is(err, errIdempotent) {
		return true, nil
	}
	return false, err
}

var errIdempotent = errors.New("idempotent")

// Complete 记录签名完成：已签名包 sha256 与服务端返回的发布 id。已完成且值相同时幂等。
func (s *Store) Complete(jobID, unsignedSHA256, signedSHA256, releaseID string) error {
	var rec completeRecord
	err := s.append(s.signed, typeComplete, &rec, func() error {
		cur := s.ss.byJob[jobID]
		if cur == nil || cur.Status == StatusAbandoned || cur.UnsignedSHA256 != unsignedSHA256 {
			return ErrNotReserved
		}
		if cur.Status == StatusCompleted {
			if cur.SignedSHA256 == signedSHA256 && cur.ReleaseID == releaseID {
				return errIdempotent
			}
			return ErrAlreadyCompleted
		}
		rec = completeRecord{JobID: jobID, PackageName: cur.PackageName, CertificateSHA256: cur.CertificateSHA256,
			VersionCode: cur.VersionCode, UnsignedSHA256: unsignedSHA256, SignedSHA256: signedSHA256, ReleaseID: releaseID}
		return rec.validate()
	})
	if errors.Is(err, errIdempotent) {
		return nil
	}
	return err
}

// Abandon 释放一条从未交付出去的预留（运维确认服务端没有对应发布记录与下载记录后执行）。
func (s *Store) Abandon(jobID, operator, reason string) (Reservation, error) {
	if err := validateOperatorReason(operator, reason); err != nil {
		return Reservation{}, fmt.Errorf("records: abandon: %w", err)
	}
	var rec abandonRecord
	var out Reservation
	err := s.append(s.signed, typeAbandon, &rec, func() error {
		cur := s.ss.byJob[jobID]
		if cur == nil || cur.Status == StatusAbandoned {
			return ErrNotReserved
		}
		if cur.Status == StatusCompleted {
			return ErrAlreadyCompleted
		}
		out = *cur
		rec = abandonRecord{JobID: jobID, PackageName: cur.PackageName, CertificateSHA256: cur.CertificateSHA256,
			VersionCode: cur.VersionCode, UnsignedSHA256: cur.UnsignedSHA256, Operator: operator, Reason: reason}
		return rec.validate()
	})
	return out, err
}

// Reservations 按写入顺序返回全部预留（含已完成、已释放、导入）。
func (s *Store) Reservations() ([]Reservation, error) {
	var out []Reservation
	err := s.read(s.signed, func() {
		for _, r := range s.ss.all {
			out = append(out, *r)
		}
	})
	return out, err
}

// Baselines 返回人工基线，按包名排序。
func (s *Store) Baselines() ([]Baseline, error) {
	var out []Baseline
	err := s.read(s.signed, func() {
		for _, b := range s.ss.baselines {
			out = append(out, b)
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].CertificateSHA256 < out[j].CertificateSHA256
	})
	return out, err
}

// HasSigningHistory 报告 signed.jsonl 里是否有任何预留、导入或基线。
func (s *Store) HasSigningHistory() (bool, error) {
	var out bool
	err := s.read(s.signed, func() { out = len(s.ss.all) > 0 || len(s.ss.baselines) > 0 })
	return out, err
}

// Import 把旧主签名闸仍然有效的预留与完成记录写进本机（promote 用）。已经存在且完全相同的跳过；
// 任何冲突在写入第一行之前报错。返回写入的条数。
func (s *Store) Import(sourceEd25519SHA256 string, list []Reservation, operator string) (int, error) {
	if !fingerprint.Valid(sourceEd25519SHA256) || !operatorPattern.MatchString(operator) {
		return 0, errors.New("records: import: source fingerprint or operator is malformed")
	}
	var pending []importRecord
	s.mu.Lock()
	err := func() error {
		if err := s.refresh(s.signed, false); err != nil {
			return err
		}
		for _, r := range list {
			rec := importRecord{SourceEd25519SHA256: sourceEd25519SHA256, JobID: r.JobID, SignAttempt: r.SignAttempt,
				TenantSlug: r.TenantSlug, PackageName: r.PackageName, CertificateSHA256: r.CertificateSHA256,
				VersionCode: r.VersionCode, UnsignedSHA256: r.UnsignedSHA256, Status: r.Status,
				SignedSHA256: r.SignedSHA256, ReleaseID: r.ReleaseID, Operator: operator}
			if err := rec.validate(); err != nil {
				return fmt.Errorf("records: import %s: %w", r.JobID, err)
			}
			k := vcKey{r.PackageName, r.CertificateSHA256, r.VersionCode}
			if cur := s.ss.byVC[k]; cur != nil {
				if cur.JobID == r.JobID && cur.UnsignedSHA256 == r.UnsignedSHA256 &&
					(cur.Status == r.Status || cur.Status == StatusCompleted) {
					continue
				}
				return fmt.Errorf("%w: import of job %s conflicts with job %s on this machine", ErrVersionCodeTaken, r.JobID, cur.JobID)
			}
			if cur := s.ss.byJob[r.JobID]; cur != nil && cur.Status != StatusAbandoned {
				return fmt.Errorf("%w: job %s", ErrJobConflict, r.JobID)
			}
			pending = append(pending, rec)
		}
		return nil
	}()
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	written := 0
	for _, rec := range pending {
		rec := rec
		if err := s.append(s.signed, typeImport, rec, nil); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// SetBaseline 写入人工基线（promote --manual）。
func (s *Store) SetBaseline(b Baseline) error {
	if err := b.validate(); err != nil {
		return fmt.Errorf("records: baseline: %w", err)
	}
	return s.append(s.signed, typeBaseline, b, nil)
}

// ---- 回放 ----

func applyTrust(ts *trustState, e entry) error {
	switch e.Type {
	case typeGenesis:
		return nil
	case typeRole:
		var r RoleChange
		if err := strictUnmarshal(e.Data, &r); err != nil {
			return err
		}
		if err := r.validate(); err != nil {
			return err
		}
		r.At = e.At
		ts.role = r
	case typeBuilder:
		var b BuilderTrust
		if err := strictUnmarshal(e.Data, &b); err != nil {
			return err
		}
		if err := b.validate(); err != nil {
			return err
		}
		b.At = e.At
		ts.builders[b.BuilderID] = b
	case typeBuilderRevoke:
		var b builderRevoke
		if err := strictUnmarshal(e.Data, &b); err != nil {
			return err
		}
		if err := b.validate(); err != nil {
			return err
		}
		if _, ok := ts.builders[b.BuilderID]; !ok {
			return errors.New("revokes a builder that is not trusted")
		}
		delete(ts.builders, b.BuilderID)
	case typeTenant:
		var c Confirmation
		if err := strictUnmarshal(e.Data, &c); err != nil {
			return err
		}
		if err := c.validate(); err != nil {
			return err
		}
		c.ConfirmedAt = e.At
		ts.confirmations[pkgKey{c.PackageName, c.CertificateSHA256}] = c
	default:
		return fmt.Errorf("unknown trust record type %q", e.Type)
	}
	return nil
}

func applySigned(ss *signedState, e entry) error {
	switch e.Type {
	case typeGenesis:
		return nil
	case typeReserve:
		var r Reservation
		if err := strictUnmarshal(e.Data, &r); err != nil {
			return err
		}
		if err := r.validateReserve(); err != nil {
			return err
		}
		r.Status, r.Source, r.ReservedAt, r.UpdatedAt = StatusReserved, "local", e.At, e.At
		return ss.insert(&r)
	case typeImport:
		var i importRecord
		if err := strictUnmarshal(e.Data, &i); err != nil {
			return err
		}
		if err := i.validate(); err != nil {
			return err
		}
		r := Reservation{JobID: i.JobID, SignAttempt: i.SignAttempt, TenantSlug: i.TenantSlug, PackageName: i.PackageName,
			CertificateSHA256: i.CertificateSHA256, VersionCode: i.VersionCode, UnsignedSHA256: i.UnsignedSHA256,
			Status: i.Status, SignedSHA256: i.SignedSHA256, ReleaseID: i.ReleaseID, Source: "import", ReservedAt: e.At, UpdatedAt: e.At}
		return ss.insert(&r)
	case typeComplete:
		var c completeRecord
		if err := strictUnmarshal(e.Data, &c); err != nil {
			return err
		}
		if err := c.validate(); err != nil {
			return err
		}
		cur := ss.byJob[c.JobID]
		if cur == nil || cur.Status != StatusReserved || cur.PackageName != c.PackageName || cur.CertificateSHA256 != c.CertificateSHA256 ||
			cur.VersionCode != c.VersionCode || cur.UnsignedSHA256 != c.UnsignedSHA256 {
			return errors.New("completes a reservation that does not exist")
		}
		cur.Status, cur.SignedSHA256, cur.ReleaseID, cur.UpdatedAt = StatusCompleted, c.SignedSHA256, c.ReleaseID, e.At
	case typeAbandon:
		var a abandonRecord
		if err := strictUnmarshal(e.Data, &a); err != nil {
			return err
		}
		if err := a.validate(); err != nil {
			return err
		}
		cur := ss.byJob[a.JobID]
		if cur == nil || cur.Status != StatusReserved || cur.PackageName != a.PackageName || cur.CertificateSHA256 != a.CertificateSHA256 ||
			cur.VersionCode != a.VersionCode || cur.UnsignedSHA256 != a.UnsignedSHA256 {
			return errors.New("abandons a reservation that does not exist or is not open")
		}
		cur.Status, cur.UpdatedAt = StatusAbandoned, e.At
		delete(ss.byVC, vcKey{cur.PackageName, cur.CertificateSHA256, cur.VersionCode})
	case typeBaseline:
		var b Baseline
		if err := strictUnmarshal(e.Data, &b); err != nil {
			return err
		}
		if err := b.validate(); err != nil {
			return err
		}
		b.At = e.At
		k := pkgKey{b.PackageName, b.CertificateSHA256}
		if cur, ok := ss.baselines[k]; !ok || b.MaxVersionCode > cur.MaxVersionCode {
			ss.baselines[k] = b
		}
	default:
		return fmt.Errorf("unknown signed record type %q", e.Type)
	}
	return nil
}

func (ss *signedState) insert(r *Reservation) error {
	k := vcKey{r.PackageName, r.CertificateSHA256, r.VersionCode}
	if ss.byVC[k] != nil {
		return errors.New("reserves a versionCode that is already reserved")
	}
	if cur := ss.byJob[r.JobID]; cur != nil && cur.Status != StatusAbandoned {
		return errors.New("reserves for a job that already holds a reservation")
	}
	ss.byVC[k] = r
	ss.byJob[r.JobID] = r
	ss.all = append(ss.all, r)
	return nil
}

// ---- 导入旧主签名闸的记录（promote）----

// Foreign 是校验通过的另一台签名闸的 signed.jsonl。
type Foreign struct {
	Genesis      Genesis
	Lines        uint64
	Reservations []Reservation // 仍然有效的（预留或完成，未释放）
	Baselines    []Baseline
}

// VerifyForeignSigned 校验另一台签名闸的 signed.jsonl：genesis 里的 Ed25519 公钥指纹必须等于
// 运维从离线 pin 文件粘贴的 pinnedEd25519SHA256，每一行的链与签名都要对。
func VerifyForeignSigned(raw []byte, pinnedEd25519SHA256 string) (Foreign, error) {
	if !fingerprint.Valid(pinnedEd25519SHA256) {
		return Foreign{}, errors.New("records: pinned ed25519 fingerprint is malformed")
	}
	if len(raw) > MaxFileSize {
		return Foreign{}, fmt.Errorf("%w: the file is larger than %d bytes", ErrCorrupt, MaxFileSize)
	}
	if !bytes.HasPrefix(raw, []byte(`{"body":`)) {
		return Foreign{}, fmt.Errorf("%w: not a signed.jsonl file", ErrCorrupt)
	}
	v := newVerifier(kindSigned, func(g Genesis) error {
		if g.Ed25519PublicKeySHA256 != pinnedEd25519SHA256 {
			return errors.New("the file was written by a different signing gate than the pinned fingerprint")
		}
		return nil
	})
	ss := newSignedState()
	if err := v.feed(raw, func(e entry) error { return applySigned(ss, e) }); err != nil {
		return Foreign{}, err
	}
	if v.seq == 0 {
		return Foreign{}, fmt.Errorf("%w: empty file", ErrCorrupt)
	}
	out := Foreign{Genesis: v.genesis, Lines: v.seq}
	for _, r := range ss.all {
		if r.Status == StatusReserved || r.Status == StatusCompleted {
			out.Reservations = append(out.Reservations, *r)
		}
	}
	for _, b := range ss.baselines {
		out.Baselines = append(out.Baselines, b)
	}
	sort.Slice(out.Baselines, func(i, j int) bool { return out.Baselines[i].PackageName < out.Baselines[j].PackageName })
	return out, nil
}

// ValidJobID 判断任务 id。
func ValidJobID(s string) bool { return ident.ValidServerID(s) }
