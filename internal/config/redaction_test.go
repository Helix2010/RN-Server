package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// 2026-09-13 一天泄了两次机密，都不是代码写错，而是输出跑到了不该去的地方。
// 这一组测试守的是"把配置打出来"这条路径。
//
// 它守得住的前提是 Config.String / GoString / LogValue 用**白名单**：只列可以打印的
// 字段，新加的字段默认不出现。反过来做（打印全部、减去机密）漏掉的那次没人会发现，
// 直到它出现在一条 CI 日志里。

// 每个机密键给一个独一无二的哨兵值，然后用四种方式把 Config 打出来，
// 一个哨兵都不许出现。
var secretEnv = map[string]string{
	"MYSQL_DSN":                "app:SENTINEL-dsn-password@tcp(db.internal:3306)/foundation",
	"STORAGE_MASTER_KEY":       "U0VOVElORUwtbWFzdGVyLWtleS0zMi1ieXRlcyEhISE=", // 32 字节的合法 base64，解出来是 SENTINEL-master-key-…
	"ADMIN_PASSWORD_HASH":      "SENTINEL-password-hash",
	"ADMIN_API_KEY":            "SENTINEL-admin-api-key",
	"DEVICE_IDENTITY_HMAC_KEY": "SENTINEL-device-hmac-key",
	"FCM_SERVICE_ACCOUNT_JSON": "SENTINEL-fcm-service-account",
	"APNS_PRIVATE_KEY":         "SENTINEL-apns-private-key",
	"HMS_CLIENT_SECRET":        "SENTINEL-hms-client-secret",
	"INDEXER_ALERT_WEBHOOK":    "https://hooks.example/SENTINEL-webhook-token",
}

func loadWithSecrets(t *testing.T) Config {
	t.Helper()
	t.Setenv("APP_ENV", "development")
	for key, value := range secretEnv {
		t.Setenv(key, value)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPrintingTheConfigNeverRevealsASecret(t *testing.T) {
	cfg := loadWithSecrets(t)

	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("startup", "cfg", cfg)

	outputs := map[string]string{
		`%v`:  fmt.Sprintf("%v", cfg),
		`%+v`: fmt.Sprintf("%+v", cfg),
		// %#v 是测试失败信息里最容易被写出来的那一种，而测试输出会进 CI 日志
		`%#v`:  fmt.Sprintf("%#v", cfg),
		`%s`:   fmt.Sprintf("%s", cfg),
		`slog`: logged.String(),
	}
	for how, out := range outputs {
		for key, secret := range secretEnv {
			needle := secret
			if key == "MYSQL_DSN" {
				needle = "SENTINEL-dsn-password" // DSN 本身要能打印，口令不行
			}
			if strings.Contains(out, needle) {
				t.Errorf("%s 打印出了 %s 的值：\n%s", how, key, out)
			}
		}
	}

	// 光是"什么都不打"也能通过上面那条，所以还要确认它仍然有用
	summary := fmt.Sprintf("%v", cfg)
	for _, want := range []string{"env=development", "db.internal:3306", "foundation", "mysqlSource="} {
		if !strings.Contains(summary, want) {
			t.Errorf("摘要里缺了 %q，那它就没有用了：%s", want, summary)
		}
	}
	// 机密只报"设了哪几个"，不报值
	if !strings.Contains(summary, "STORAGE_MASTER_KEY") || !strings.Contains(summary, "ADMIN_API_KEY") {
		t.Errorf("摘要要说清哪些机密已经设了：%s", summary)
	}
}

// 新加一个装机密的字段而忘了处理，这条会红。
//
// 白名单的实现让"忘了处理"默认是安全的（新字段根本不打印），这条测试守的是另一半：
// 别有人哪天把 String() 改回字段全量 dump。
func TestNoSecretLookingFieldEverReachesTheOutput(t *testing.T) {
	cfg := loadWithSecrets(t)
	out := fmt.Sprintf("%v|%+v|%#v", cfg, cfg, cfg)

	secretish := []string{"key", "token", "password", "hash", "secret", "credential", "passphrase", "private"}
	value := reflect.ValueOf(cfg)
	fields := reflect.TypeOf(cfg)
	checked := 0
	for i := 0; i < fields.NumField(); i++ {
		name := strings.ToLower(fields.Field(i).Name)
		looksSecret := false
		for _, mark := range secretish {
			if strings.Contains(name, mark) {
				looksSecret = true
				break
			}
		}
		if !looksSecret {
			continue
		}
		field := value.Field(i)
		if field.Kind() != reflect.String || field.String() == "" {
			continue
		}
		checked++
		if strings.Contains(out, field.String()) {
			t.Errorf("字段 %s 名字里带机密特征，而它的值出现在输出里了", fields.Field(i).Name)
		}
	}
	if checked < 5 {
		t.Fatalf("只检查了 %d 个机密字段，哨兵多半没设上——这条测试等于没跑", checked)
	}
}

// RedactedMySQLDSN 打码走结构体复制，不在字符串上做正则：口令里可以合法地含 '@'，
// 正则会打错位置，把口令的后半截留在输出里。
func TestRedactedDSNSurvivesAPasswordFullOfDelimiters(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_DSN", "app:p@ss:word/with(parens)@tcp(db.internal:3306)/foundation")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	redacted := cfg.RedactedMySQLDSN()
	for _, fragment := range []string{"p@ss", "word", "parens"} {
		if strings.Contains(redacted, fragment) {
			t.Fatalf("打码之后还剩口令的一部分 %q：%s", fragment, redacted)
		}
	}
	if !strings.Contains(redacted, "db.internal:3306") {
		t.Fatalf("打码把有用的部分也去掉了：%s", redacted)
	}
}
