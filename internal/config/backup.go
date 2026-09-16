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
	// Fingerprint 是 DER SPKI 的 SHA-256 小写 hex，64 字符。**从公钥算出来的，
	// 不用配**——配置里只有公钥这一个事实源，指纹是它的函数。控制台显示它，
	// 三个持有人各自核对自己那一个
	Fingerprint string
	// Holder 是「这个槽位由谁保管」。印进 README-FIRST.txt：拿到包的人得知道
	// 该去找谁。和公钥一起放在配置文件里，而不是库里——它是恢复说明的一部分，
	// 只有数据库写权限的人不该能改掉「外层该找谁开」这句话
	Holder string
}

// BackupBucket 是**独立**的备份桶。不要复用产物桶：产物桶凭据泄露不该等于
// 全平台签名密钥泄露。
type BackupBucket struct {
	// Provider 只有三个值：s3 / r2 / minio，和发布存储那份同一套。空 = 老配置，
	// 按下面 ForcePathStyle 的注释走兼容路径
	Provider string
	Endpoint string
	Region   string
	Bucket   string
	Prefix   string
	// ForcePathStyle：MinIO 必须开，S3 / R2 不用。**以前是猜的**
	// （「填了 endpoint 就开」），猜错的表现是连不上桶——而备份是无人值守跑的，
	// 没人在现场看那条错误。现在显式配，只有老配置还走那条旧的推断
	ForcePathStyle  bool
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

// backupHolderName 收拾一下保管者姓名。
//
// 它会被渲染进 README-FIRST.txt。那份文件不是脚本，但灾难当天有人照着它读——
// 一段带控制字符的名字只会让人困惑，一段很长的名字会把那几行排版冲掉。
func backupHolderName(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, strings.TrimSpace(value))
	runes := []rune(cleaned)
	if len(runes) > 120 {
		return string(runes[:120])
	}
	return cleaned
}

var backupInstanceIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// ValidBackupInstanceID 说明 BACKUP_INSTANCE_ID 是不是一个能进对象键的值。
//
// 启动时的那道检查只在 Enabled()（env 里配了桶或开了定时）时生效；桶改到控制台上
// 配之后，env 里可以一个备份的键都没有，那道检查就不跑了。所以产出备份那一刻还要
// 再拦一次，用的是同一条规则。
func ValidBackupInstanceID(value string) bool {
	return backupInstanceIDPattern.MatchString(value)
}

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
			Provider:        strings.ToLower(strings.TrimSpace(os.Getenv("BACKUP_BUCKET_PROVIDER"))),
			ForcePathStyle:  l.boolean("BACKUP_BUCKET_FORCE_PATH_STYLE", false),
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
	cfg.Recipients[0].Holder = backupHolderName(os.Getenv("BACKUP_RECOVERY_HOLDER_A"))
	cfg.Recipients[1].Holder = backupHolderName(os.Getenv("BACKUP_RECOVERY_HOLDER_B"))
	cfg.Recipients[2].Holder = backupHolderName(os.Getenv("BACKUP_RECOVERY_HOLDER_C"))

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

	// 三把必须全齐，但这条**不在启动时拦**。
	//
	// 三把公钥是三个人各自生成的，收齐是一件跨人跨天的事；而桶是在控制台上配的，
	// 配了桶就让 Enabled() 成立。如果启动就要求全齐，管理员在控制台点一下保存桶，
	// 就给下一次重启埋了个起不来的雷——而那时候他不在现场。
	//
	// 真正的闸在产出备份那一刻：createBackupRun 会在不足三把时拒绝并说明差哪几把。
	// 那里拦既不会误伤启动，报错也更接近人当时在做的事。
	//
	// 这里只挡一种情况：填了一部分。那不是「还没配」，那是打字错误或者
	// 复制粘贴漏了一行，必须当场说出来。
	configured, missing := []string{}, []string{}
	for i, slot := range backupcontainer.SlotNames {
		if cfg.Recipients[i].Fingerprint != "" {
			configured = append(configured, slot)
		} else {
			missing = append(missing, "BACKUP_RECOVERY_RECIPIENT_"+slot)
		}
	}
	if len(configured) > 0 && len(missing) > 0 {
		l.fail(strings.Join(missing, ", ") + " is missing while " + strings.Join(configured, "/") +
			" is set: the threshold is 2-of-3 and there is no reduced mode. " +
			"Set all three, or leave all three empty until the holders have generated their keys.")
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

// ParseBackupRecipient 解析一把恢复公钥（PEM 的 base64），顺带算出指纹。
//
// 指纹不单独配：它是公钥的函数（DER SPKI 的 SHA-256），配两遍就会有对不上的
// 那一天，而那一天没人知道该信哪个。
func ParseBackupRecipient(value string) (BackupRecipient, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return BackupRecipient{}, nil
	}
	pub, err := backupcontainer.ParsePublicKey(raw)
	if err != nil {
		return BackupRecipient{}, err
	}
	fingerprint, err := backupcontainer.Fingerprint(pub)
	if err != nil {
		return BackupRecipient{}, err
	}
	return BackupRecipient{Encoded: raw, Key: pub, Fingerprint: fingerprint}, nil
}

func (l *loader) recoveryRecipient(key, value string) BackupRecipient {
	parsed, err := ParseBackupRecipient(value)
	if err != nil {
		l.fail(key + ": " + err.Error())
		return BackupRecipient{}
	}
	return parsed
}
