package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

func storageServer(t *testing.T) *server {
	t.Helper()
	s := backupServer(t)
	// 32 字节的 base64 key
	box, err := secretbox.New(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	if err != nil {
		t.Fatal(err)
	}
	s.secrets = box
	s.cfg = config.Config{
		AdminPasswordHash: testAdminPasswordHash,
		Backup:            config.Backup{InstanceID: "inst"},
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`,
			platformTenantID, backupBucketConfigKey)
	})
	return s
}

// 桶要能在控制台上维护（设计 §6.1、§8.2）。
//
// 换一次桶、轮一次凭据是平台管理员的日常运维，不该需要改 env 再重启整个后端。
func TestDBBackupBucketIsMaintainedFromTheConsole(t *testing.T) {
	s := storageServer(t)

	c, recorder := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
		"bucket": "rn-backup", "region": "ap-southeast-1", "prefix": "prod/",
		"accessKeyId": "AKIAEXAMPLE", "secretAccessKey": "s3cr3t",
		"reason": "第一次配桶", "confirm": true,
	})
	s.updateBackupStorage(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("保存应当成功: %d %s", recorder.Code, recorder.Body.String())
	}

	// 存进去的凭据必须是密文——库里躺着明文 AK/SK 的话，一次库泄漏就等于桶被接管
	var raw string
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`,
		platformTenantID, backupBucketConfigKey).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AKIAEXAMPLE", "s3cr3t"} {
		if strings.Contains(raw, secret) {
			t.Errorf("凭据以明文存进了库里：%s", secret)
		}
	}

	// 读回来必须能用，而且接口不能把凭据吐出去
	c2, recorder2 := testContext(t, platformTenantID, "GET", "/x", nil)
	s.getBackupStorage(c2)
	if recorder2.Code != http.StatusOK {
		t.Fatalf("读取应当成功: %d", recorder2.Code)
	}
	body := recorder2.Body.String()
	for _, secret := range []string{"AKIAEXAMPLE", "s3cr3t"} {
		if strings.Contains(body, secret) {
			t.Errorf("接口把凭据回给了前端：%s", secret)
		}
	}
	var view map[string]any
	if err := json.Unmarshal(recorder2.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view["bucket"] != "rn-backup" || view["credentialsConfigured"] != true {
		t.Errorf("读回来的配置不对: %v", view)
	}
	if view["source"] != "console" {
		t.Errorf("配了之后来源应当是 console，得到 %v", view["source"])
	}

	// 真正生效的那条路径（backupBucketClient 用的）也要拿到解密后的凭据
	effective, source, err := s.resolveBackupBucket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if effective.AccessKeyID != "AKIAEXAMPLE" || effective.SecretAccessKey != "s3cr3t" {
		t.Error("解密回来的凭据不对——存得进去读不出来，等于桶配了个寂寞")
	}
	if source != "console" || effective.Bucket != "rn-backup" {
		t.Errorf("生效的配置不对: %s %+v", source, effective.Bucket)
	}
}

// 没配过的时候回落到 env：允许「先用 env 起来，之后再搬到控制台」这条路。
func TestDBBackupBucketFallsBackToEnv(t *testing.T) {
	s := storageServer(t)
	s.cfg.Backup.Bucket = config.BackupBucket{Bucket: "from-env", Region: "r"}

	effective, source, err := s.resolveBackupBucket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if source != "env" || effective.Bucket != "from-env" {
		t.Errorf("没配过时应当回落到 env，得到 %s / %s", source, effective.Bucket)
	}
}

// 改桶要填变更原因（和发布存储那页一致：原因进审计，不要口令）。
//
// 口令留给「跑一次备份」和「下载」——那两个动作直接经手全平台每个租户的签名密钥，
// 改桶不是。参考实现 release-storage 也只要原因。
func TestDBBackupBucketWriteNeedsAReason(t *testing.T) {
	s := storageServer(t)
	c, recorder := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
		"bucket": "x", "region": "r", "confirm": true,
	})
	s.updateBackupStorage(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("没有变更原因应当 400，得到 %d", recorder.Code)
	}
}

// 乐观锁：两个人同时改，后写的不该悄悄覆盖前一个。
func TestDBBackupBucketRejectsAStaleWrite(t *testing.T) {
	s := storageServer(t)
	save := func(version int, bucket string) int {
		c, recorder := testContext(t, platformTenantID, "PUT", "/x", map[string]any{
			"bucket": bucket, "region": "r", "expectedVersion": version,
			"reason": "并发写", "confirm": true,
		})
		s.updateBackupStorage(c)
		return recorder.Code
	}
	if code := save(0, "first"); code != http.StatusOK {
		t.Fatalf("第一次保存应当成功: %d", code)
	}
	// 现在库里是 version=1；有人拿着 version=1 之前读到的旧值再写
	if code := save(99, "second"); code != http.StatusConflict {
		t.Errorf("拿着过期版本号写应当 409，得到 %d", code)
	}
}
