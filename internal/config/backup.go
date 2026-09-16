package config

import (
	"crypto/rsa"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// Backup 是打包服务故障恢复备份的配置（设计 platform-backup-recovery-2026-09-15 §8.3）。
type Backup struct {
	// InstanceID 进对象键前缀，也进 manifest。**显式配，不从主机名推导**：
	// 主机改名、或者恰好在新机器上恢复之后，前缀就换了，历史备份全部 404
	InstanceID string
	// IntervalHours：0 = 关闭定时只留手动；否则 6–168
	IntervalHours int
	// RetentionDays 是桶上生命周期规则配的保留天数。**这里只是抄一份给控制台看**，
	// 服务端不删任何对象——删除由桶自己的生命周期规则做。
	//
	// 0 = 没配。控制台显示「未设置」而不是假装知道：真出事那天点到一条过期的，
	// 看到的是一句看不懂的 S3 NoSuchKey，那比没有这个字段更糟
	RetentionDays int
	Bucket        BackupBucket
	// Recipients 按槽位顺序 A / B / C。三把缺一不可（§2.1：没有降级模式）
	Recipients [backupcontainer.SlotCount]BackupRecipient
}

// BackupRecipient 是一个槽位上的恢复公钥。
type BackupRecipient struct {
	// Encoded 是 env 里那个值（PEM 的 base64，单行），原样留着给打包机下发核对用
	Encoded string
	Key     *rsa.PublicKey
	// Fingerprint 是 DER SPKI 的 SHA-256 小写 hex，64 字符。控制台显示它，
	// 三个持有人各自核对自己那一个
	Fingerprint string
}

// BackupBucket 是**独立**的备份桶。不要复用产物桶：产物桶凭据泄露不该等于
// 全平台签名密钥泄露。
type BackupBucket struct {
	Endpoint        string
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
}

// Enabled 说明备份功能是不是已经投用。
//
// 这个判据决定「三把公钥必须齐全」这道闸什么时候生效。**不能无条件强制**：
// 那等于把整个 wallet 后端的启动挂在一个还没投用的功能上，一旦有人写坏一行 PEM，
// 倒下的是全站。配了桶、或者开了定时，就是宣告「这套东西要跑了」，从那一刻起
// 三把钥匙是硬前置。
func (b Backup) Enabled() bool {
	return strings.TrimSpace(b.Bucket.Bucket) != "" || b.IntervalHours > 0
}

// Fingerprints 按槽位顺序返回三个指纹，没配的那个是空串。给 `rn-server config`
// 和控制台用
func (b Backup) Fingerprints() [backupcontainer.SlotCount]string {
	var out [backupcontainer.SlotCount]string
	for i, r := range b.Recipients {
		out[i] = r.Fingerprint
	}
	return out
}

var backupInstanceIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

const (
	backupIntervalMin = 6
	backupIntervalMax = 168
)

func (l *loader) backup(environment string) Backup {
	cfg := Backup{
		InstanceID:    strings.TrimSpace(os.Getenv("BACKUP_INSTANCE_ID")),
		IntervalHours: l.integer("BACKUP_INTERVAL_HOURS", 0),
		RetentionDays: l.integer("BACKUP_RETENTION_DAYS", 0),
		Bucket: BackupBucket{
			Endpoint:        strings.TrimSpace(os.Getenv("BACKUP_BUCKET_ENDPOINT")),
			Region:          strings.TrimSpace(os.Getenv("BACKUP_BUCKET_REGION")),
			Bucket:          strings.TrimSpace(os.Getenv("BACKUP_BUCKET_BUCKET")),
			Prefix:          strings.TrimSpace(os.Getenv("BACKUP_BUCKET_PREFIX")),
			AccessKeyID:     strings.TrimSpace(os.Getenv("BACKUP_BUCKET_ACCESS_KEY_ID")),
			SecretAccessKey: strings.TrimSpace(os.Getenv("BACKUP_BUCKET_SECRET_ACCESS_KEY")),
		},
	}
	// 三个键名写成字面量而不是 "…_" + slot 拼出来。拼出来的话，
	// documented_test 的正则看不见它们，这三个键会整组从「代码读了就必须写进
	// 配置参考和两份 .env.example」那道门禁底下溜过去——而它们正是灾难当天
	// 唯一要用的键。顺带也让 grep 找得到槽位和环境变量的对应关系。
	cfg.Recipients[0] = l.recoveryRecipient("BACKUP_RECOVERY_RECIPIENT_A", os.Getenv("BACKUP_RECOVERY_RECIPIENT_A"))
	cfg.Recipients[1] = l.recoveryRecipient("BACKUP_RECOVERY_RECIPIENT_B", os.Getenv("BACKUP_RECOVERY_RECIPIENT_B"))
	cfg.Recipients[2] = l.recoveryRecipient("BACKUP_RECOVERY_RECIPIENT_C", os.Getenv("BACKUP_RECOVERY_RECIPIENT_C"))

	// 间隔的下界是 6 而不是 1：1 小时 + 90 天保留 = 2160 次 × 3 份 = 6480 份
	// 全平台签名密钥副本躺在桶里；而且一条卡住的备份会连着吃掉好几次定时
	if cfg.IntervalHours != 0 && (cfg.IntervalHours < backupIntervalMin || cfg.IntervalHours > backupIntervalMax) {
		l.fail(fmt.Sprintf("BACKUP_INTERVAL_HOURS must be 0 (manual only) or between %d and %d, got %d",
			backupIntervalMin, backupIntervalMax, cfg.IntervalHours))
	}

	if !cfg.Enabled() {
		// 没投用就不查其余的。查了反而有害：它会在一个和备份毫无关系的部署里
		// 把整个后端拦在启动之外
		return cfg
	}

	if !backupInstanceIDPattern.MatchString(cfg.InstanceID) {
		l.fail("BACKUP_INSTANCE_ID is required when backups are enabled and must match ^[a-z0-9-]{1,32}$ " +
			"(it goes into the object key; deriving it from the hostname would break every historical download after a rename or a restore)")
	}
	if cfg.Bucket.Bucket == "" || cfg.Bucket.Region == "" {
		l.fail("BACKUP_BUCKET_BUCKET and BACKUP_BUCKET_REGION are required when backups are enabled")
	}
	if environment == "production" && cfg.Bucket.Endpoint != "" && !strings.HasPrefix(cfg.Bucket.Endpoint, "https://") {
		l.fail("BACKUP_BUCKET_ENDPOINT must be https in production")
	}

	// 三把必须全齐。少一把不会退回两把跑——没有降级模式（§2.1）
	missing := []string{}
	for i, slot := range backupcontainer.SlotNames {
		if cfg.Recipients[i].Fingerprint == "" {
			missing = append(missing, "BACKUP_RECOVERY_RECIPIENT_"+slot)
		}
	}
	if len(missing) > 0 {
		l.fail(strings.Join(missing, ", ") + " must be set when backups are enabled: the threshold is 2-of-3 and " +
			"there is no reduced mode. Configure all three, or turn backups off (leave BACKUP_BUCKET_BUCKET empty and BACKUP_INTERVAL_HOURS at 0)")
	}

	// 两把相同 = 某一组的两层封给同一个人 = 那一组一个人就能开。
	// 这是「填串了」最常见的表现，而它的后果安静得可怕
	for i := 0; i < len(cfg.Recipients); i++ {
		for j := i + 1; j < len(cfg.Recipients); j++ {
			a, b := cfg.Recipients[i], cfg.Recipients[j]
			if a.Fingerprint != "" && a.Fingerprint == b.Fingerprint {
				l.fail(fmt.Sprintf("BACKUP_RECOVERY_RECIPIENT_%s and BACKUP_RECOVERY_RECIPIENT_%s are the same key; "+
					"pair %s%s would then be sealed to one person twice and they could open it alone",
					backupcontainer.SlotNames[i], backupcontainer.SlotNames[j],
					backupcontainer.SlotNames[i], backupcontainer.SlotNames[j]))
			}
		}
	}
	return cfg
}

func (l *loader) recoveryRecipient(key, value string) BackupRecipient {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return BackupRecipient{}
	}
	pub, err := backupcontainer.ParsePublicKey(raw)
	if err != nil {
		l.fail(key + ": " + err.Error())
		return BackupRecipient{}
	}
	fingerprint, err := backupcontainer.Fingerprint(pub)
	if err != nil {
		l.fail(key + ": " + err.Error())
		return BackupRecipient{}
	}
	return BackupRecipient{Encoded: raw, Key: pub, Fingerprint: fingerprint}
}
