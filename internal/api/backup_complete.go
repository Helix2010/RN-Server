package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/gin-gonic/gin"
)

// 两份内层密文都到齐之后的收尾：合并服务端那部分、封三个外层、上传、落库。

// backupFinishTimeout 给封装加上传。
//
// 它必须**另起一条 ctx**，不能用请求的：`…/payload` 不在 10 秒数据库超时的豁免
// 名单里（那份名单是 /upload、/finalize、/release-storage/test、/download），
// 于是封外层、上传 S3、写 succeeded 全都会 context deadline exceeded，记录停在
// running，30 分钟后判 failed——**每一次备份都是**。先例是
// simplified_releases.go 的 receiveAndStoreArtifact：同样另起 context.Background()。
//
// 不去改豁免名单是有意的：改名单会顺带把数据库超时也放开，那不是想要的。
const backupFinishTimeout = 20 * time.Minute

// 服务端那部分要收进包里的文件。路径可配，因为部署布局各不相同。
//
// **前两项缺失直接判这次备份失败。** 少了它们，恢复的人拿到包也立不起服务端，
// 而这正是「拿到东西却不知道怎么用」的那一半——安静地产出一个装不回去的包，
// 比没有备份更糟，因为你以为自己有。
type backupServerFile struct {
	Path     string
	Source   string
	Target   string
	Mode     string
	Owner    string
	Critical bool
}

func (s *server) backupServerFiles() []backupServerFile {
	env := func(key, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	// /proc/self/exe 是正在跑的那个二进制本身。收它而不是去仓库里找，是因为
	// 目标机器上**没有 Go 工具链**——deploy.sh 是在开发机上交叉编译的，
	// 不装它，恢复第一步就得先找一台能编译的机器
	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	return []backupServerFile{
		{Path: "rn-foundation.env", Source: env("BACKUP_SERVER_ENV_PATH", "/etc/rn-foundation.env"),
			Target: "/etc/rn-foundation.env", Mode: "0600", Owner: "root:root", Critical: true},
		{Path: "bin/rn-server", Source: self,
			Target: "/opt/rn-foundation/bin/rn-server", Mode: "0755", Owner: "root:root", Critical: true},
		{Path: "systemd/rn-foundation-server.service",
			Source: env("BACKUP_SERVER_UNIT_PATH", "/etc/systemd/system/rn-foundation-server.service"),
			Target: "/etc/systemd/system/rn-foundation-server.service", Mode: "0644", Owner: "root:root"},
		{Path: "nginx/rn-foundation.conf",
			Source: env("BACKUP_SERVER_NGINX_PATH", "/etc/nginx/conf.d/rn-foundation.conf"),
			Target: "/etc/nginx/conf.d/rn-foundation.conf", Mode: "0644", Owner: "root:root"},
		{Path: "tls/origin.crt", Source: env("BACKUP_SERVER_TLS_CERT_PATH", ""),
			Target: "/etc/ssl/rn-foundation/origin.crt", Mode: "0644", Owner: "root:root"},
		{Path: "tls/origin.key", Source: env("BACKUP_SERVER_TLS_KEY_PATH", ""),
			Target: "/etc/ssl/rn-foundation/origin.key", Mode: "0600", Owner: "root:root"},
	}
}

func (s *server) collectServerPart(ctx context.Context) (map[string][]byte, []backupbundle.FileEntry, error) {
	files := map[string][]byte{}
	manifest := []backupbundle.FileEntry{}

	for _, want := range s.backupServerFiles() {
		if strings.TrimSpace(want.Source) == "" {
			if want.Critical {
				return nil, nil, fmt.Errorf("%s has no source path configured", want.Path)
			}
			continue
		}
		body, err := os.ReadFile(want.Source)
		if err != nil {
			if want.Critical {
				return nil, nil, fmt.Errorf("cannot read %s (%s): %w", want.Path, want.Source, err)
			}
			// 非关键项缺失只记一条 warn：部署布局各不相同，硬失败会让备份
			// 在一个只是路径不一样的环境里永远跑不起来
			slog.Warn("a non-critical file is missing from the backup package",
				"path", want.Path, "source", want.Source, "error", err)
			continue
		}
		files[want.Path] = body
		manifest = append(manifest, backupbundle.FileEntry{
			Path: want.Path, Size: int64(len(body)), SHA256: sha256HexOf(body),
			Target: want.Target, Mode: want.Mode, Owner: want.Owner,
		})
	}

	// db/* 只在「数据库也没了」那个场景用得上。导出就是表里的列原样出，不做加工
	dumps, err := s.exportBackupDatabaseConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	for path, body := range dumps {
		files[path] = body
		manifest = append(manifest, backupbundle.FileEntry{
			Path: path, Size: int64(len(body)), SHA256: sha256HexOf(body),
			Target: "（数据库也没了时才用，见 RECOVERY.md）", Mode: "0600", Owner: "root:root",
		})
	}
	return files, manifest, nil
}

// exportBackupDatabaseConfig 导出打包相关的那部分库内配置。
//
// **tenants.id 必须逐字保留**：它是 AUTO_INCREMENT，而 app_configs 的 secretbox
// 密文把 tenant_id 绑进了 AAD——id 变了，那些密文全部解不开。恢复时要显式插入 id，
// 不能让数据库重新发号。
//
// 不导出任何密文列：签名密钥的明文已经在 inner.rnbk 里了，密文再导一份只是扩大
// 暴露面；其余 secretbox 密文没有 STORAGE_MASTER_KEY 也没用，而那把钥匙在
// rn-foundation.env 里。要恢复的是「打包服务」，不是整个库。
func (s *server) exportBackupDatabaseConfig(ctx context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	tenants, err := dumpQueryAsJSON(ctx, s.db,
		`SELECT id, slug, name, status, valid_from, valid_until, created_at, updated_at FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("export tenants: %w", err)
	}
	out["db/tenants.json"] = tenants

	domains, err := dumpQueryAsJSON(ctx, s.db,
		`SELECT tenant_id, domain, status, created_at, updated_at FROM tenant_domain ORDER BY tenant_id, domain`)
	if err != nil {
		return nil, fmt.Errorf("export tenant_domain: %w", err)
	}
	out["db/tenant-domain.json"] = domains

	// 打包必需的库内配置：应用身份、图标、Firebase、发布身份。
	// build.keystore 那一项**不导**——它是密文，明文已经在内层里了
	configs, err := dumpQueryAsJSON(ctx, s.db,
		`SELECT tenant_id, config_key, config_value, version, updated_by, updated_at
		   FROM app_configs
		  WHERE config_key IN ('build.android','build.icons','push.credentials.fcm',
		                       'release.identity.android','release.identity.ios')
		  ORDER BY tenant_id, config_key`)
	if err != nil {
		return nil, fmt.Errorf("export build configs: %w", err)
	}
	out["db/build-config.json"] = configs
	return out, nil
}

// dumpQueryAsJSON 把一条查询的结果导成 JSON 数组，键名用数据库列名。
//
// 表结构会变，而这份导出的用途是「在一台新机器上把打包配置补回去」——按列名原样
// 出比手写一堆 struct 更抗变化，少一列也不会静默丢数据。
func dumpQueryAsJSON(ctx context.Context, db *sql.DB, query string) ([]byte, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	records := []map[string]any{}
	for rows.Next() {
		cells := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range cells {
			pointers[i] = &cells[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		record := map[string]any{}
		for i, name := range columns {
			switch value := cells[i].(type) {
			case nil:
				record[name] = nil
			case []byte:
				record[name] = string(value)
			case time.Time:
				record[name] = value.UTC().Format(time.RFC3339Nano)
			default:
				record[name] = value
			}
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(records, "", "  ")
}

// fileSink 把每一组包写到暂存目录的一个文件里。
//
// 不在内存里攒：三个包各几十 MB，而且流式写下去正好对上「先算长度再开始写」
// 那条约束
type fileSink struct {
	dir   string
	paths map[string]string
}

func (s *fileSink) Writer(pair string) (io.WriteCloser, error) {
	path := filepath.Join(s.dir, "out-"+pair+".rnbk")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.paths[pair] = path
	return file, nil
}

func (s *server) completeBackup(c *gin.Context, run backupRun) {
	// 另起 ctx：请求那条已经被 10 秒数据库超时中间件套住了
	ctx, cancel := context.WithTimeout(context.Background(), backupFinishTimeout)
	defer cancel()

	objects, tenantCount, err := s.assembleAndUploadBackup(ctx, run)
	if err != nil {
		slog.Error("backup assembly failed", "backupId", run.ID, "seq", run.Seq, "error", err)
		if _, failErr := s.failBackupRun(ctx, run.ID, err.Error()); failErr != nil {
			slog.Error("unable to record a backup failure", "backupId", run.ID, "error", failErr)
		}
		cleanBackupStaging(run.ID)
		problem(c, http.StatusFailedDependency, "BACKUP_ASSEMBLY_FAILED", err.Error())
		return
	}

	// 带状态条件：0 行说明超时扫描抢先判死了，放弃并记日志，不要覆盖
	changed, err := s.finishBackupRun(ctx, run.ID, objects, tenantCount)
	cleanBackupStaging(run.ID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_FINISH_FAILED", "Unable to record the backup result")
		return
	}
	if !changed {
		slog.Warn("a backup finished after something else had already closed it out",
			"backupId", run.ID, "seq", run.Seq)
		c.JSON(http.StatusConflict, gin.H{"error": "BACKUP_ALREADY_FINISHED",
			"detail": "this backup was already closed out; the uploaded objects are orphans"})
		return
	}
	s.auditNow(newAudit(platformTenantID, "system-backup", "backup_succeeded", "platform-backup", run.ID,
		"a platform backup was produced and uploaded", requestID(c),
		map[string]any{"seq": run.Seq, "packages": len(objects), "tenants": tenantCount}))
	c.JSON(http.StatusOK, gin.H{"status": backupStatusSucceeded, "seq": run.Seq, "objects": objects})
}

func (s *server) assembleAndUploadBackup(ctx context.Context, run backupRun) ([]backupObject, int, error) {
	dir := backupStagingDir(run.ID)
	input, err := s.buildBundleInput(ctx, run, dir)
	if err != nil {
		return nil, 0, err
	}
	if _, err := s.markBackupPayloadComplete(ctx, run.ID); err != nil {
		return nil, 0, fmt.Errorf("record payload arrival: %w", err)
	}

	sink := &fileSink{dir: dir, paths: map[string]string{}}
	packages, err := backupbundle.Assemble(input, sink)
	if err != nil {
		return nil, 0, err
	}

	client, err := s.backupBucketClient()
	if err != nil {
		return nil, 0, err
	}
	prefix := s.cfg.Backup.Bucket.Prefix
	instance := s.cfg.Backup.InstanceID
	out := make([]backupObject, 0, len(packages))
	for _, pkg := range packages {
		path := sink.paths[pkg.Pair]
		key := backupObjectKey(prefix, instance, run.Seq, pkg.Pair, ".rnbk")
		if err := uploadFile(ctx, client, key, path, "application/octet-stream"); err != nil {
			return nil, 0, fmt.Errorf("upload %s: %w", pkg.Pair, err)
		}
		// 写入顺序固定：先 .rnbk 后 .README.txt。README 的存在就是
		// 「这一组上传完成了」的提交标记
		readmeKey := backupObjectKey(prefix, instance, run.Seq, pkg.Pair, ".README.txt")
		if err := client.Put(ctx, readmeKey, strings.NewReader(pkg.ReadmeFirst),
			int64(len(pkg.ReadmeFirst)), "text/plain; charset=utf-8"); err != nil {
			return nil, 0, fmt.Errorf("upload the readme for %s: %w", pkg.Pair, err)
		}
		out = append(out, backupObject{Pair: pkg.Pair, ObjectKey: key, SHA256: pkg.SHA256, SizeBytes: pkg.Size})
	}
	return out, len(input.Tenants), nil
}

func (s *server) buildBundleInput(ctx context.Context, run backupRun, dir string) (backupbundle.Input, error) {
	inner := map[string]backupbundle.InnerPart{}
	var anyMeta backupbundle.PayloadMeta
	for _, slot := range backupcontainer.InnerSlots() {
		sealed, err := os.ReadFile(filepath.Join(dir, slot+".enc"))
		if err != nil {
			return backupbundle.Input{}, fmt.Errorf("the staged payload for slot %s is gone: %w", slot, err)
		}
		signature, err := os.ReadFile(filepath.Join(dir, slot+".sig"))
		if err != nil {
			return backupbundle.Input{}, fmt.Errorf("the signature for slot %s is gone: %w", slot, err)
		}
		rawMeta, err := os.ReadFile(filepath.Join(dir, slot+".meta.json"))
		if err != nil {
			return backupbundle.Input{}, fmt.Errorf("the meta for slot %s is gone: %w", slot, err)
		}
		meta, err := backupbundle.ParsePayloadMeta(rawMeta)
		if err != nil {
			return backupbundle.Input{}, err
		}
		anyMeta = meta
		inner[slot] = backupbundle.InnerPart{Slot: slot, Sealed: sealed, Signature: signature}
	}

	serverFiles, serverManifest, err := s.collectServerPart(ctx)
	if err != nil {
		return backupbundle.Input{}, err
	}

	recipients := make([]backupbundle.Recipient, 0, backupcontainer.SlotCount)
	for i, slot := range backupcontainer.SlotNames {
		configured := s.cfg.Backup.Recipients[i]
		recipients = append(recipients, backupbundle.Recipient{
			Slot: slot, Fingerprint: configured.Fingerprint, Key: configured.Key,
			Holder: s.backupHolderName(ctx, slot),
		})
	}

	// 元数据现在就是 backupbundle 的类型，不用再转一遍——两份定义迟早会漂开，
	// 而漂开的表现是恢复说明里少一列，没人会发现
	tenants := anyMeta.Tenants
	agentManifest := anyMeta.InnerFiles

	return backupbundle.Input{
		Seq: run.Seq, InstanceID: s.cfg.Backup.InstanceID, CreatedAt: time.Now().UTC(),
		Recipients: recipients, AgentInner: inner,
		ServerFiles: serverFiles, ServerManifest: serverManifest, AgentManifest: agentManifest,
		Tenants: tenants, ServerVersion: serverBuildVersion(), AgentVersion: anyMeta.AgentVersion,
		SchemaVersion:            currentSchemaVersion(ctx, s.db),
		AgentKeyFingerprint:      anyMeta.AgentKeyFingerprint,
		BackupSigningFingerprint: anyMeta.BackupSigningFingerprint,
	}, nil
}

func uploadFile(ctx context.Context, client interface {
	Put(context.Context, string, io.Reader, int64, string) error
}, key, path, contentType string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return client.Put(ctx, key, file, info.Size(), contentType)
}

func currentSchemaVersion(ctx context.Context, db *sql.DB) int {
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0
	}
	return int(version.Int64)
}

func marshalIndentJSON(value any) ([]byte, error) { return json.MarshalIndent(value, "", "  ") }

func sha256HexOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// serverBuildVersion 说明「恢复时该装哪一版服务端」。
//
// 这个仓库不用 ldflags 打版本号，所以取 go 自己嵌进二进制的 vcs.revision。
// CI 构建带它；本地 go build 在 worktree 里可能没有（.git 是文件不是目录），
// 那就回落到二进制自身的 sha256 前 12 位——不好看，但它唯一地标识了这个二进制，
// 而恢复的人要的正是「和产出备份时同一个」。
func serverBuildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				return setting.Value
			}
		}
	}
	self, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	sum, _, err := sha256File(self)
	if err != nil || len(sum) < 12 {
		return "unknown"
	}
	return "sha256:" + sum[:12]
}

// backupRecoveryHoldersKey 存「哪个槽位由谁保管」。
//
// 这一行由运维在控制台上填，印进 README-FIRST.txt——拿到包的人得知道该去找谁。
// 它不是机密，但它是恢复流程里唯一能把「槽位 A」翻译成一个具体的人的东西。
const backupRecoveryHoldersKey = "backup.recovery.holders"

func (s *server) backupHolders(ctx context.Context) map[string]string {
	var raw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, backupRecoveryHoldersKey).Scan(&raw)
	if err != nil {
		return map[string]string{}
	}
	holders := map[string]string{}
	if json.Unmarshal(raw, &holders) != nil {
		return map[string]string{}
	}
	return holders
}

func (s *server) backupHolderName(ctx context.Context, slot string) string {
	return strings.TrimSpace(s.backupHolders(ctx)[slot])
}
