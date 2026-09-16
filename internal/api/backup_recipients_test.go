package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// 三把公钥要能在控制台上录入（设计 §6）。
//
// 它们是三个人各自生成的，收齐是跨人跨天的事。只认 env 的话，每收到一把就要改
// env 重启一次整个 wallet 后端，而且在三把齐之前服务端**根本起不来**——
// 那等于这个功能没法从控制台启用。
func TestDBRecoveryKeysAreEnteredInTheConsole(t *testing.T) {
	s := backupServer(t)
	keys := testRecoveryPublicKeys(t)

	// 先只录一把：允许收到一把录一把，不必攒齐再一次性填
	c, recorder := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
		"slots": []map[string]string{
			{"slot": "A", "publicKey": keys[0], "holder": "运维负责人"},
		},
		"reason": "收到 A 的公钥", "confirm": true,
	})
	s.updateBackupRecipients(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("只录一把也应当能存: %d %s", recorder.Code, recorder.Body.String())
	}

	// 还没配齐就不能产出备份——没有降级模式（§2.1）
	_, err := s.createBackupRun(context.Background(), "manual", "tester", "should refuse")
	if err == nil {
		t.Fatal("三把没齐却建出了一条备份待办——那会产出一个只有一个人能开的包")
	}
	for _, want := range []string{"B", "C"} {
		if !contains(err.Error(), want) {
			t.Errorf("报错没指名还差哪几把（缺 %s）: %v", want, err)
		}
	}

	// 补齐另外两把
	c2, recorder2 := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
		"slots": []map[string]string{
			{"slot": "A", "publicKey": keys[0], "holder": "运维负责人"},
			{"slot": "B", "publicKey": keys[1], "holder": "技术负责人"},
			{"slot": "C", "publicKey": keys[2], "holder": "第三方托管"},
		},
		"reason": "三把齐了", "confirm": true,
	})
	s.updateBackupRecipients(c2)
	if recorder2.Code != http.StatusOK {
		t.Fatalf("补齐应当成功: %d %s", recorder2.Code, recorder2.Body.String())
	}
	if _, err := s.createBackupRun(context.Background(), "manual", "tester", "now it works"); err != nil {
		t.Fatalf("三把齐了就该能建: %v", err)
	}

	// 读回来要带指纹和保管人：指纹是三个人抄在纸上的那一行，保管人印进 README
	c3, recorder3 := testContext(t, platformTenantID, "GET", "/x", nil)
	s.getBackupRecipients(c3)
	var view struct {
		Slots []struct {
			Slot        string  `json:"slot"`
			Fingerprint *string `json:"fingerprint"`
			Holder      *string `json:"holder"`
			Configured  bool    `json:"configured"`
			Source      string  `json:"source"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(recorder3.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Slots) != 3 {
		t.Fatalf("应当回三个槽位，得到 %d", len(view.Slots))
	}
	for _, slot := range view.Slots {
		if !slot.Configured || slot.Fingerprint == nil || len(*slot.Fingerprint) != 64 {
			t.Errorf("槽位 %s 没有 64 位指纹: %+v", slot.Slot, slot)
		}
		if slot.Holder == nil || *slot.Holder == "" {
			t.Errorf("槽位 %s 没有保管人——拿到包的人不知道该去找谁", slot.Slot)
		}
		if slot.Source != "console" {
			t.Errorf("槽位 %s 的来源应当是 console，得到 %s", slot.Slot, slot.Source)
		}
	}
}

// 两把填成同一把 = 那一组的两层封给同一个人 = 他一个人就能开。
// 这是「填串了」最常见的表现，而它的后果安静得可怕：包照样产出、照样显示成功。
func TestDBRecoveryKeysRefuseTheSameKeyTwice(t *testing.T) {
	s := backupServer(t)
	keys := testRecoveryPublicKeys(t)

	c, recorder := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
		"slots": []map[string]string{
			{"slot": "A", "publicKey": keys[0]},
			{"slot": "B", "publicKey": keys[0]},
			{"slot": "C", "publicKey": keys[2]},
		},
		"reason": "手滑粘了两次", "confirm": true,
	})
	s.updateBackupRecipients(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("两把相同应当被拒，得到 %d", recorder.Code)
	}
	if !contains(recorder.Body.String(), "一个人就能打开") {
		t.Errorf("报错没说清后果: %s", recorder.Body.String())
	}
}

// 公钥读不了要当场说，而不是等到产出备份那一刻才炸。
func TestDBRecoveryKeysRejectAnUnreadableKey(t *testing.T) {
	s := backupServer(t)
	c, recorder := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
		"slots":  []map[string]string{{"slot": "A", "publicKey": "bm90LWEta2V5"}},
		"reason": "填错了", "confirm": true,
	})
	s.updateBackupRecipients(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("读不了的公钥应当被拒，得到 %d %s", recorder.Code, recorder.Body.String())
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
