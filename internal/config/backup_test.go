package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 生成三把不同的恢复公钥。3072 位是下限，测试里够用且比 4096 快得多
func recoveryKeys(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := range out {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = base64.StdEncoding.EncodeToString(
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return out
}

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", "test")
	t.Setenv("MYSQL_DSN", "app:secret@tcp(db.internal:3306)/foundation")
}

func enableBucket(t *testing.T) {
	t.Helper()
	t.Setenv("BACKUP_INSTANCE_ID", "prod-1")
	t.Setenv("BACKUP_BUCKET_BUCKET", "rn-platform-backup")
	t.Setenv("BACKUP_BUCKET_REGION", "ap-southeast-1")
}

// 备份没投用时，少配公钥**不能**拦住启动。否则整个 wallet 后端被一个还没上线的
// 功能扣为人质——一行 PEM 写坏，倒下的是全站
func TestBackupDisabledDoesNotGateStartup(t *testing.T) {
	baseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("a deployment without backups configured must still start: %v", err)
	}
	if cfg.Backup.Enabled() {
		t.Fatal("backups should be off when neither a bucket nor an interval is configured")
	}
}

// 配了桶就是宣告「这套东西要跑了」，三把钥匙从那一刻起是硬前置。
//
// 缺 A、缺 B、缺 C 各测一条：只测一个的话，一个「只看槽位 A」的实现也能绿，
// 而那正是「以为配了三把其实只有两把」那种错的形状
func TestBackupEnabledRequiresAllThreeSlots(t *testing.T) {
	for _, missing := range backupcontainer.SlotNames {
		t.Run("缺"+missing, func(t *testing.T) {
			keys := recoveryKeys(t, backupcontainer.SlotCount)
			baseEnv(t)
			enableBucket(t)
			for i, slot := range backupcontainer.SlotNames {
				if slot == missing {
					continue
				}
				t.Setenv("BACKUP_RECOVERY_RECIPIENT_"+slot, keys[i])
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("缺了槽位 %s 还能启动：门限是 2-of-3，没有降级模式", missing)
			}
			if !strings.Contains(err.Error(), "BACKUP_RECOVERY_RECIPIENT_"+missing) {
				t.Fatalf("错误必须指名少的是哪个槽位，得到: %v", err)
			}
			if !strings.Contains(err.Error(), "no reduced mode") {
				t.Fatalf("错误必须说清没有降级模式，得到: %v", err)
			}
		})
	}
}

// 跳过中间那个槽位（只配 A+C）同样拒绝。它和「缺 B」是同一件事，单列是因为
// 它看起来像「我有意只用两个人」——而那个选项不存在
func TestBackupRefusesASkippedSlot(t *testing.T) {
	keys := recoveryKeys(t, 3)
	baseEnv(t)
	enableBucket(t)
	t.Setenv("BACKUP_RECOVERY_RECIPIENT_A", keys[0])
	t.Setenv("BACKUP_RECOVERY_RECIPIENT_C", keys[2])
	if _, err := Load(); err == nil {
		t.Fatal("A+C 跳过 B 应当被拒绝")
	}
}

func TestBackupEnabledAcceptsThreeDistinctKeys(t *testing.T) {
	keys := recoveryKeys(t, 3)
	baseEnv(t)
	enableBucket(t)
	for i, slot := range backupcontainer.SlotNames {
		t.Setenv("BACKUP_RECOVERY_RECIPIENT_"+slot, keys[i])
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("three distinct keys should be accepted: %v", err)
	}
	if !cfg.Backup.Enabled() {
		t.Fatal("backups should be on")
	}
	seen := map[string]bool{}
	for i, fp := range cfg.Backup.Fingerprints() {
		if len(fp) != 64 {
			t.Fatalf("slot %s: fingerprint is %d chars, the spec says 64", backupcontainer.SlotNames[i], len(fp))
		}
		if seen[fp] {
			t.Fatalf("slot %s: duplicate fingerprint", backupcontainer.SlotNames[i])
		}
		seen[fp] = true
	}
}

// 两把填成同一个 = 那一组的两层封给同一个人 = 他一个人就能开。
// 这是「填串了」最常见的表现，后果安静得可怕
func TestBackupRejectsDuplicateKeys(t *testing.T) {
	keys := recoveryKeys(t, 2)
	baseEnv(t)
	enableBucket(t)
	t.Setenv("BACKUP_RECOVERY_RECIPIENT_A", keys[0])
	t.Setenv("BACKUP_RECOVERY_RECIPIENT_B", keys[1])
	t.Setenv("BACKUP_RECOVERY_RECIPIENT_C", keys[0])

	_, err := Load()
	if err == nil {
		t.Fatal("the same key in two slots must be refused")
	}
	if !strings.Contains(err.Error(), "open it alone") {
		t.Fatalf("the error must explain the consequence, got: %v", err)
	}
}

func TestBackupIntervalBounds(t *testing.T) {
	keys := recoveryKeys(t, 3)
	for _, tc := range []struct {
		hours string
		ok    bool
	}{{"0", true}, {"1", false}, {"5", false}, {"6", true}, {"24", true}, {"168", true}, {"169", false}} {
		t.Run(tc.hours, func(t *testing.T) {
			baseEnv(t)
			enableBucket(t)
			for i, slot := range backupcontainer.SlotNames {
				t.Setenv("BACKUP_RECOVERY_RECIPIENT_"+slot, keys[i])
			}
			t.Setenv("BACKUP_INTERVAL_HOURS", tc.hours)
			_, err := Load()
			if tc.ok && err != nil {
				t.Fatalf("%s hours should be accepted: %v", tc.hours, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%s hours should be refused", tc.hours)
			}
		})
	}
}

// 只开定时、不配桶也算启用：那同样是「这套东西要跑了」的宣告
func TestBackupIntervalAloneEnablesTheGate(t *testing.T) {
	baseEnv(t)
	t.Setenv("BACKUP_INTERVAL_HOURS", "24")
	if _, err := Load(); err == nil {
		t.Fatal("an interval without recovery keys must be refused")
	}
}

func TestBackupInstanceIDMustBeExplicitAndSafe(t *testing.T) {
	keys := recoveryKeys(t, 3)
	for _, tc := range []struct {
		id string
		ok bool
	}{{"prod-1", true}, {"a", true}, {"", false}, {"Prod-1", false}, {"prod_1", false}, {"../etc", false},
		{strings.Repeat("a", 32), true}, {strings.Repeat("a", 33), false}} {
		t.Run(tc.id, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("BACKUP_BUCKET_BUCKET", "rn-platform-backup")
			t.Setenv("BACKUP_BUCKET_REGION", "ap-southeast-1")
			t.Setenv("BACKUP_INSTANCE_ID", tc.id)
			for i, slot := range backupcontainer.SlotNames {
				t.Setenv("BACKUP_RECOVERY_RECIPIENT_"+slot, keys[i])
			}
			_, err := Load()
			if tc.ok && err != nil {
				t.Fatalf("%q should be accepted: %v", tc.id, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%q should be refused", tc.id)
			}
		})
	}
}
