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

// 三把恢复公钥在控制台上录入（设计 §6）。
//
// 为什么不能只认 env：三把公钥是**三个人各自生成**的，生成和交付是一件跨人、
// 跨时间的事——A 今天给了，B 明天才给。只认 env 的话，每收到一把就要改一次
// env 重启一次整个 wallet 后端，而且在三把齐之前服务端**根本起不来**
// （config 里那条「三把必须全齐」的硬前置）。那等于这个功能没法从控制台启用。
//
// env 仍然是回退，也仍然是「库也没了」那天唯一还在的那份。
//
// 安全性不靠这里：打包机**不接受服务端下发的公钥**，它只认自己 env 里那三把，
// 拿服务端下发的指纹逐一比对，对不上就拒绝产出备份并上报原因（§4.2）。
// 所以就算有人写了库把公钥换掉，换来的也只是「备份失败并指名哪一把对不上」。
const backupRecipientsConfigKey = "backup.recipients"

type storedBackupRecipient struct {
	Slot string `json:"slot"`
	// PublicKey 是 PEM 公钥的 base64（单行），和 env 里那三个键同样的格式
	PublicKey string `json:"publicKey"`
	// Holder 是「由谁保管」。印进 README-FIRST：拿到包的人得知道该去找谁
	Holder string `json:"holder,omitempty"`
}

type backupRecipientsRecord struct {
	Slots     []storedBackupRecipient `json:"slots"`
	Version   int                     `json:"-"`
	UpdatedBy string                  `json:"-"`
	UpdatedAt time.Time               `json:"-"`
}

func (s *server) backupRecipientsRecord(ctx context.Context) (*backupRecipientsRecord, error) {
	var raw []byte
	var record backupRecipientsRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value, version, updated_by, updated_at FROM app_configs
		  WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, backupRecipientsConfigKey).
		Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
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

// resolveBackupRecipients 返回当前生效的三个槽位，按 A/B/C 顺序。
// 某个槽位没配时那一项的 Fingerprint 是空串——调用方据此判断「配齐了没有」。
func (s *server) resolveBackupRecipients(ctx context.Context) ([backupcontainer.SlotCount]config.BackupRecipient, []string, error) {
	out := s.cfg.Backup.Recipients
	holders := make([]string, backupcontainer.SlotCount)

	record, err := s.backupRecipientsRecord(ctx)
	if err != nil {
		return out, holders, err
	}
	if record == nil {
		return out, holders, nil
	}
	for _, stored := range record.Slots {
		index := slotIndex(stored.Slot)
		if index < 0 {
			continue
		}
		holders[index] = stored.Holder
		if strings.TrimSpace(stored.PublicKey) == "" {
			continue
		}
		parsed, err := config.ParseBackupRecipient(stored.PublicKey)
		if err != nil {
			// 存进去的时候校验过；这里还坏就说明有人直接写了库。
			// 不静默回落到 env——那会让人以为控制台上那把在生效
			return out, holders, err
		}
		out[index] = parsed
	}
	return out, holders, nil
}

func slotIndex(slot string) int {
	for i, name := range backupcontainer.SlotNames {
		if name == slot {
			return i
		}
	}
	return -1
}

// getBackupRecipients 是控制台那张公钥表单的数据源。
func (s *server) getBackupRecipients(c *gin.Context) {
	ctx := c.Request.Context()
	record, err := s.backupRecipientsRecord(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_RECIPIENTS_READ_FAILED", err.Error())
		return
	}
	resolved, holders, err := s.resolveBackupRecipients(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_RECIPIENTS_READ_FAILED", err.Error())
		return
	}
	stored := map[string]storedBackupRecipient{}
	if record != nil {
		for _, item := range record.Slots {
			stored[item.Slot] = item
		}
	}
	slots := []gin.H{}
	for i, name := range backupcontainer.SlotNames {
		item := stored[name]
		slots = append(slots, gin.H{
			"slot": name,
			// 公钥不是机密，可以回给前端——回了才能在控制台上核对和修改
			"publicKey":   nullableString(item.PublicKey),
			"fingerprint": nullableString(resolved[i].Fingerprint),
			"holder":      nullableString(holders[i]),
			"configured":  resolved[i].Fingerprint != "",
			"source":      recipientSource(item.PublicKey, resolved[i].Fingerprint),
		})
	}
	view := gin.H{"slots": slots, "threshold": "2-of-3", "version": 0}
	if record != nil {
		view["version"] = record.Version
		view["updatedBy"] = record.UpdatedBy
		view["updatedAt"] = iso(record.UpdatedAt)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, view)
}

func recipientSource(stored, fingerprint string) string {
	switch {
	case strings.TrimSpace(stored) != "":
		return "console"
	case fingerprint != "":
		return "env"
	default:
		return "none"
	}
}

type backupRecipientsWrite struct {
	Slots []struct {
		Slot      string `json:"slot"`
		PublicKey string `json:"publicKey"`
		Holder    string `json:"holder"`
	} `json:"slots"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

// updateBackupRecipients 录入/替换三把公钥和保管人。
//
// 允许只填其中一两把：三把是三个人各自生成的，收到一把就录一把，不必攒齐再一次性填。
// 「三把必须齐」那条在**真正要产出备份的时候**才拦（createBackupRun），
// 而不是在这里——那样会逼人把公钥攒在别处，反而更危险。
func (s *server) updateBackupRecipients(c *gin.Context) {
	var body backupRecipientsWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_RECIPIENTS", "reason and confirm=true are required")
		return
	}

	ctx := c.Request.Context()
	existing, err := s.backupRecipientsRecord(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_RECIPIENTS_READ_FAILED", err.Error())
		return
	}
	currentVersion := 0
	if existing != nil {
		currentVersion = existing.Version
	}
	if body.ExpectedVersion != 0 && body.ExpectedVersion != currentVersion {
		problem(c, http.StatusConflict, "BACKUP_RECIPIENTS_STALE",
			"someone else changed the recovery keys; reload and try again")
		return
	}

	next := make([]storedBackupRecipient, 0, backupcontainer.SlotCount)
	byFingerprint := map[string]string{}
	for _, name := range backupcontainer.SlotNames {
		item := storedBackupRecipient{Slot: name}
		for _, incoming := range body.Slots {
			if incoming.Slot != name {
				continue
			}
			item.PublicKey = strings.TrimSpace(incoming.PublicKey)
			item.Holder = strings.TrimSpace(incoming.Holder)
		}
		if item.PublicKey != "" {
			parsed, err := config.ParseBackupRecipient(item.PublicKey)
			if err != nil {
				problem(c, http.StatusBadRequest, "INVALID_BACKUP_RECIPIENTS",
					"槽位 "+name+" 的公钥读不了："+err.Error())
				return
			}
			// 两把相同 = 那一组的两层封给同一个人 = 他一个人就能开。
			// 这是「填串了」最常见的表现，而它的后果安静得可怕
			if other, seen := byFingerprint[parsed.Fingerprint]; seen {
				problem(c, http.StatusBadRequest, "INVALID_BACKUP_RECIPIENTS",
					"槽位 "+other+" 和 "+name+" 是同一把公钥："+
						other+name+" 那一组会被封给同一个人两次，他一个人就能打开")
				return
			}
			byFingerprint[parsed.Fingerprint] = name
		}
		next = append(next, item)
	}

	encoded, err := json.Marshal(backupRecipientsRecord{Slots: next})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_RECIPIENTS_SAVE_FAILED", err.Error())
		return
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		 VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=version+1,
		   updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		platformTenantID, backupRecipientsConfigKey, encoded, actor(c), now); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_RECIPIENTS_SAVE_FAILED", err.Error())
		return
	}

	configured := []string{}
	for _, item := range next {
		if item.PublicKey != "" {
			configured = append(configured, item.Slot)
		}
	}
	s.auditNow(newAudit(platformTenantID, actor(c), "backup_recipients_updated", "app-config",
		backupRecipientsConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"configured": configured}))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"status": "saved", "configured": configured})
}
