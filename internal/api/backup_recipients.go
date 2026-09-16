package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/Helix2010/RN-Server/internal/config"
)

// 三把恢复公钥只从配置文件读，控制台**只显示不编辑**（设计 §4.2）。
//
// 中间有一版把它们挪进了 app_configs，让管理员在控制台录入。那一版开了一条
// 不该有的路：只拿到**数据库写权限**的人（注入、库凭据泄露、一个被盗的管理员
// 会话）可以改掉外层收件人，而外层里装着 rn-foundation.env——STORAGE_MASTER_KEY、
// ADMIN_PASSWORD_HASH、TLS 私钥。等下一次备份，这些就封给他了，拿到主密钥之后
// 库里所有密文一起解开。公钥回到配置文件，改它需要 root 上机器，而能做到这个的人
// 已经不需要绕这一圈。
//
// 代价是换持有人要运维上两台机器改配置再重启。**这件事本来就应该需要一个人到场。**
//
// 打包机那一侧同样只认自己 env 里那三把（BUILD_AGENT_RECOVERY_RECIPIENT_*），
// 服务端下发的只是指纹、只用于比对：服务端被攻破也改不了签名密钥最终封给谁。
// 两边各管各的 env，是这个架构里两个安全域各自独立的形状。

// backupRecipients 返回按槽位顺序 A/B/C 的三把公钥。没配的那一项 Fingerprint 是
// 空串——调用方据此判断「配齐了没有」。
func (s *server) backupRecipients() [backupcontainer.SlotCount]config.BackupRecipient {
	return s.cfg.Backup.Recipients
}

// legacyBackupRecipientsKey 是上一版存在库里的那条记录。
//
// 现在**不再有任何东西读它来封包**，留着只为一件事：如果这套东西是在控制台上
// 配好的，升级之后那三把会安静地「不见了」，而表现是下一次备份报「槽位 A/B/C
// 还没有公钥」——人会以为配置丢了。控制台把这条遗留记录原样显示出来，让运维
// 照着抄进 env，抄完按面板里那条 SQL 删掉它，横幅自然消失。
const legacyBackupRecipientsKey = "backup.recipients"

type legacyBackupRecipient struct {
	Slot      string `json:"slot"`
	PublicKey string `json:"publicKey"`
	Holder    string `json:"holder,omitempty"`
}

type legacyBackupRecipientsRecord struct {
	Slots     []legacyBackupRecipient `json:"slots"`
	UpdatedBy string                  `json:"-"`
	UpdatedAt time.Time               `json:"-"`
}

func (s *server) legacyBackupRecipients(ctx context.Context) (*legacyBackupRecipientsRecord, error) {
	if s.db == nil {
		return nil, nil
	}
	var raw []byte
	var record legacyBackupRecipientsRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value, updated_by, updated_at FROM app_configs
		  WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, legacyBackupRecipientsKey).
		Scan(&raw, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// getBackupRecipients 是控制台那张只读卡片的数据源。
//
// 三个 env 键名一起回：控制台要照着它们生成「去哪台机器、改哪个键、怎么重启」
// 那段指令，而键名写在前端就会和后端漂开——漂开的表现是运维照着控制台改了一个
// 根本没人读的键，然后备份继续报「还没有公钥」。
func (s *server) getBackupRecipients(c *gin.Context) {
	recipients := s.backupRecipients()
	slots := make([]gin.H, 0, backupcontainer.SlotCount)
	for i, name := range backupcontainer.SlotNames {
		recipient := recipients[i]
		slots = append(slots, gin.H{
			"slot": name,
			// 公钥不是机密。回它是为了让控制台能把**服务端上真正生效的那个值**
			// 填进打包机那条指令里——两边不一致这类事故就是这么消掉的
			"publicKey":    nullableString(recipient.Encoded),
			"fingerprint":  nullableString(recipient.Fingerprint),
			"holder":       nullableString(recipient.Holder),
			"configured":   recipient.Fingerprint != "",
			"serverEnvKey": "BACKUP_RECOVERY_RECIPIENT_" + name,
			"holderEnvKey": "BACKUP_RECOVERY_HOLDER_" + name,
			"agentEnvKey":  "BUILD_AGENT_RECOVERY_RECIPIENT_" + name,
		})
	}

	view := gin.H{"slots": slots, "threshold": "2-of-3", "source": "env"}
	if record, err := s.legacyBackupRecipients(c.Request.Context()); err == nil && record != nil {
		legacy := make([]gin.H, 0, len(record.Slots))
		for _, item := range record.Slots {
			if strings.TrimSpace(item.PublicKey) == "" && strings.TrimSpace(item.Holder) == "" {
				continue
			}
			legacy = append(legacy, gin.H{
				"slot": item.Slot, "publicKey": nullableString(item.PublicKey),
				"holder": nullableString(item.Holder),
			})
		}
		if len(legacy) > 0 {
			view["legacy"] = gin.H{
				"configKey": legacyBackupRecipientsKey, "slots": legacy,
				"updatedBy": record.UpdatedBy, "updatedAt": iso(record.UpdatedAt),
			}
		}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, view)
}
