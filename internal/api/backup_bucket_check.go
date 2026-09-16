package api

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/Helix2010/RN-Server/internal/store"
)

// BackupBucketCheck 是备份桶一项权限的检查结果。
type BackupBucketCheck struct {
	// Action 是 S3 动作名；Permission 是这个提供商的 IAM 里它叫什么
	Action     string `json:"action"`
	Label      string `json:"label"`
	Permission string `json:"permission"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail,omitempty"`
}

// BackupBucketCheckResult 是一次完整的桶检查。
type BackupBucketCheckResult struct {
	OK         bool   `json:"ok"`
	Provider   string `json:"provider"`
	Endpoint   string `json:"endpoint"`
	Bucket     string `json:"bucket"`
	Prefix     string `json:"prefix"`
	InstanceID string `json:"instanceId"`
	ProbeKey   string `json:"probeKey"`
	// Checks 固定三项、固定顺序：写对象、读对象、读版本控制状态
	Checks           []BackupBucketCheck `json:"checks"`
	Versioning       bool                `json:"versioning"`
	VersioningDetail string              `json:"versioningDetail,omitempty"`
	CheckedAt        string              `json:"checkedAt"`
}

// backupProbeKey 放在单独的 _probe/ 下面：凭据故意不给删除权限，探针删不掉，
// 单独一个目录才好让桶上的生命周期规则把它们清掉，也不会和真包的名字混在一起。
func backupProbeKey(prefix, instance string) string {
	return joinObjectKey(prefix, instance, "_probe", "probe-"+randomID(8)+".txt")
}

// runBackupBucketChecks 分别测一次备份真正要用的三项权限。
//
// 三项都得测，一项都不能省：
//
//   - 写对象：上传三个包
//   - 读对象：**上传完要从桶里取回来重算 sha256**（verifyUploadedObject）。以前的
//     测试连接只测了写，于是会出现「测试通过、第一次真备份在回读那一步失败」
//   - 读版本控制状态：没开版本控制时覆盖写就是删除，拿到写权限的人覆盖掉真包之后
//     原件再也取不回来
//
// 三项互相独立地报：写失败时读自然跳过，但版本控制照样去问——人要一次看到全部缺口，
// 而不是补一条、再点一次、再发现下一条。
func runBackupBucketChecks(ctx context.Context, client objectstore.Client,
	bucket config.BackupBucket, instanceID string) BackupBucketCheckResult {
	now := iso(time.Now().UTC())
	provider := bucket.Provider
	result := BackupBucketCheckResult{
		Provider: provider, Endpoint: bucket.Endpoint, Bucket: bucket.Bucket, Prefix: bucket.Prefix,
		InstanceID: instanceID, CheckedAt: now, ProbeKey: backupProbeKey(bucket.Prefix, instanceID),
	}
	check := func(action, label string) BackupBucketCheck {
		return BackupBucketCheck{Action: action, Label: label,
			Permission: objectstore.Permission(provider, action)}
	}
	probe := "rn-foundation backup bucket probe " + now + "\n"

	put := check("PutObject", "写对象")
	if err := client.Put(ctx, result.ProbeKey, strings.NewReader(probe), int64(len(probe)), "text/plain"); err != nil {
		put.Detail = err.Error()
	} else {
		put.OK = true
	}

	get := check("GetObject", "读对象")
	if !put.OK {
		get.Detail = "探针没写进去，没东西可读——先解决写对象"
	} else if body, err := client.Get(ctx, result.ProbeKey); err != nil {
		get.Detail = err.Error()
	} else {
		got, readErr := io.ReadAll(io.LimitReader(body, int64(len(probe))+1))
		_ = body.Close()
		switch {
		case readErr != nil:
			get.Detail = readErr.Error()
		case string(got) != probe:
			// 能读但内容不对：代理截断、网关改写。真备份的回读校验会在这里失败
			get.Detail = fmt.Sprintf("读回来的内容和写进去的不一样（%d 字节，应为 %d 字节）", len(got), len(probe))
		default:
			get.OK = true
		}
	}

	versioning := check("GetBucketVersioning", "读版本控制状态")
	enabled, err := client.BucketVersioning(ctx)
	if err != nil {
		versioning.Detail = err.Error()
	} else {
		versioning.OK = true
	}

	result.Checks = []BackupBucketCheck{put, get, versioning}
	result.Versioning = versioning.OK && enabled
	switch {
	case !versioning.OK:
		result.VersioningDetail = "读不到桶的版本控制状态，这把凭据可能缺 " + versioning.Permission
	case !enabled:
		result.VersioningDetail = "这个桶没有开版本控制。备份桶必须开：没开的话覆盖写就是删除，" +
			"被覆盖掉的真包再也取不回来。"
	}
	result.OK = put.OK && get.OK && result.Versioning
	return result
}

// CheckBackupBucket 给 `rn-server backup-bucket-test` 用。
//
// 在持有凭据的那台机器上直接跑同一套检查：凭据不离开这台机器、不经过任何人的
// 终端，也不需要控制台活着——恢复场景 B 里控制台多半还没起来，而「这台新机器
// 连不连得上备份桶」恰恰是第一个要回答的问题。
func CheckBackupBucket(ctx context.Context, cfg config.Config, storage *store.Store) (BackupBucketCheckResult, error) {
	box, _ := secretbox.New(cfg.StorageMasterKey)
	s := &server{cfg: cfg, db: storage.DB, objects: objectstore.AWSFactory{}, secrets: box}
	bucket, _, err := s.resolveBackupBucket(ctx)
	if err != nil {
		return BackupBucketCheckResult{}, err
	}
	client, err := s.backupBucketClient()
	if err != nil {
		return BackupBucketCheckResult{}, err
	}
	return runBackupBucketChecks(ctx, client, bucket, cfg.Backup.InstanceID), nil
}
