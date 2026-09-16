package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/Helix2010/RN-Server/internal/config"
)

type recipientsView struct {
	Slots []struct {
		Slot         string  `json:"slot"`
		PublicKey    *string `json:"publicKey"`
		Fingerprint  *string `json:"fingerprint"`
		Holder       *string `json:"holder"`
		Configured   bool    `json:"configured"`
		ServerEnvKey string  `json:"serverEnvKey"`
		HolderEnvKey string  `json:"holderEnvKey"`
		AgentEnvKey  string  `json:"agentEnvKey"`
	} `json:"slots"`
	Source string `json:"source"`
	Legacy *struct {
		ConfigKey string `json:"configKey"`
		Slots     []struct {
			Slot      string  `json:"slot"`
			PublicKey *string `json:"publicKey"`
			Holder    *string `json:"holder"`
		} `json:"slots"`
	} `json:"legacy"`
}

func readRecipients(t *testing.T, s *server) recipientsView {
	t.Helper()
	c, recorder := testContext(t, platformTenantID, "GET", "/x", nil)
	s.getBackupRecipients(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("读公钥应当成功: %d %s", recorder.Code, recorder.Body.String())
	}
	var view recipientsView
	if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// 控制台只显示不编辑：三把公钥的唯一事实源是配置文件。
//
// 指纹不单独配，是从公钥算出来的——控制台上那 64 个字符就是三个人各自核对
// 自己那一行的依据，配两遍就会有对不上的那一天。
func TestDBRecoveryKeysComeFromConfigAndShowTheirFingerprints(t *testing.T) {
	s := backupServer(t)

	view := readRecipients(t, s)
	if len(view.Slots) != backupcontainer.SlotCount {
		t.Fatalf("应当回三个槽位，得到 %d", len(view.Slots))
	}
	if view.Source != "env" {
		t.Errorf("来源应当是 env，得到 %q", view.Source)
	}
	for _, slot := range view.Slots {
		if !slot.Configured || slot.Fingerprint == nil || len(*slot.Fingerprint) != 64 {
			t.Errorf("槽位 %s 没有 64 位指纹: %+v", slot.Slot, slot)
		}
		if slot.Holder == nil || *slot.Holder == "" {
			t.Errorf("槽位 %s 没有保管人——拿到包的人不知道该去找谁", slot.Slot)
		}
		// 控制台照着这三个键名生成「改哪台机器的哪个键」那段指令。键名写死在
		// 前端的话，运维会照着控制台改一个根本没人读的键，而备份继续报没配
		if slot.ServerEnvKey != "BACKUP_RECOVERY_RECIPIENT_"+slot.Slot ||
			slot.HolderEnvKey != "BACKUP_RECOVERY_HOLDER_"+slot.Slot ||
			slot.AgentEnvKey != "BUILD_AGENT_RECOVERY_RECIPIENT_"+slot.Slot {
			t.Errorf("槽位 %s 的 env 键名不对: %+v", slot.Slot, slot)
		}
		// 公钥不是机密，而且控制台要拿**服务端上真正生效的那个值**填进打包机
		// 那条指令里——两边不一致这类事故就是这么消掉的
		if slot.PublicKey == nil || *slot.PublicKey == "" {
			t.Errorf("槽位 %s 没回公钥，控制台就没法生成打包机那条指令", slot.Slot)
		}
	}
}

// 少一把不能退回两把跑——没有降级模式（§2.1），而且要指名还差哪几把。
func TestDBRecoveryKeysRefuseToRunWhenASlotIsEmpty(t *testing.T) {
	s := backupServer(t)
	s.cfg.Backup.Recipients[1] = config.BackupRecipient{}
	s.cfg.Backup.Recipients[2] = config.BackupRecipient{}

	_, err := s.createBackupRun(context.Background(), "manual", "tester", "should refuse")
	if err == nil {
		t.Fatal("三把没齐却建出了一条备份待办——那会产出一个没人能开的包")
	}
	for _, want := range []string{"B", "C"} {
		if !contains(err.Error(), want) {
			t.Errorf("报错没指名还差哪几把（缺 %s）: %v", want, err)
		}
	}

	view := readRecipients(t, s)
	for _, slot := range view.Slots {
		want := slot.Slot == "A"
		if slot.Configured != want {
			t.Errorf("槽位 %s 的 configured 应当是 %v: %+v", slot.Slot, want, slot)
		}
	}
}

// 上一版把三把公钥存在库里。升级之后它们**不再参与封包**，但不能让它们安静地
// 消失：那时的表现是「备份报还没有公钥」，而运维以为配置丢了。
//
// 控制台把这条遗留记录原样显示出来，照着抄进 env 就行。
func TestDBRecoveryKeysSurfaceTheLegacyConsoleRecord(t *testing.T) {
	s := backupServer(t)
	keys := testRecoveryPublicKeys(t)
	encoded, err := json.Marshal(map[string]any{"slots": []map[string]string{
		{"slot": "A", "publicKey": keys[0], "holder": "库里那位"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		 VALUES(?,?,?,1,'上一版',UTC_TIMESTAMP(3))
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`,
		platformTenantID, legacyBackupRecipientsKey, encoded); err != nil {
		t.Fatalf("种一条遗留记录: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`,
			platformTenantID, legacyBackupRecipientsKey)
	})

	view := readRecipients(t, s)
	if view.Legacy == nil || len(view.Legacy.Slots) != 1 {
		t.Fatalf("遗留记录没有显示出来，升级之后运维会以为公钥丢了: %+v", view.Legacy)
	}
	if view.Legacy.ConfigKey != legacyBackupRecipientsKey {
		t.Errorf("没说清是哪条记录: %+v", view.Legacy)
	}
	if view.Legacy.Slots[0].PublicKey == nil || *view.Legacy.Slots[0].PublicKey != keys[0] {
		t.Error("遗留记录里的公钥要原样回，运维才能照着抄进 env")
	}

	// 但它绝不参与封包：库里有、配置里没有，照样不能产出
	s.cfg.Backup.Recipients[0] = config.BackupRecipient{}
	if _, err := s.createBackupRun(context.Background(), "manual", "tester", "legacy must not count"); err == nil {
		t.Fatal("库里那条记录被当成了生效的公钥——能写库的人就能改掉外层封给谁")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// 实例 ID 进对象键，必须显式配。启动时那道检查只在 env 里配了桶时才跑——桶改到
// 控制台上配之后，它就不跑了，于是产出备份那一刻要再拦一次。
func TestDBBackupRunRefusesWithoutAnInstanceID(t *testing.T) {
	s := backupServer(t)
	s.cfg.Backup.InstanceID = ""
	_, err := s.createBackupRun(context.Background(), "manual", "tester", "no instance id")
	if err == nil {
		t.Fatal("没有实例 ID 却建出了备份——包会落成没有实例段的键，和别的实例混在一起")
	}
	if !contains(err.Error(), "BACKUP_INSTANCE_ID") {
		t.Errorf("报错没说清缺的是哪个键: %v", err)
	}
}
