package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/store"
)

// recordReleaseFingerprint 是 `rn-server release-fingerprint <releaseId> <hex> <reason>`：
// 给一个**在打包机开始记录原生指纹之前**构建的安装包补上那个值。
//
// 为什么需要它：热更新能不能发，判据是"更新包的原生指纹 == 基线安装包的原生指纹"。
// 指纹是打包机编 APK 时用 @expo/fingerprint 算出来、随发布记录存进 file_metadata 的。
// 这个功能 2026-09-13 09:00 才上线，在那之前构建的包一个都没有这个值，于是它们**永远**
// 不能作为热更新基线——不管改动本身多干净。anyfun 线上在分发的 1.3.14 就是这样一个包。
//
// 唯一正当的补法：在这个 APK 对应的那个提交上、用打包机构建热更新时的同一套环境，把
// @expo/fingerprint 再算一遍，把算出来的值补进去。这件事这个命令**不做**——它只负责写。
// 算错了就等于把闸关了，所以：
//
//   - 只在服务器上、由 root 通过 EnvironmentFile 运行，不开放成 HTTP 接口。管理端上
//     能改的指纹等于没有指纹：谁都可以把基线的值改成手里那个包的值，闸就只剩装饰。
//   - 已经有值的记录**拒绝**覆盖。补一个缺失的值是补数据，改一个已有的值是篡改证据。
//   - 必须给 reason，连同操作者一起写进 audit_events，和管理端上任何一次改动同等留痕。
func recordReleaseFingerprint(database *store.Store, releaseID, fingerprint, actor, reason string) error {
	releaseID = strings.TrimSpace(releaseID)
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if releaseID == "" || fingerprint == "" || actor == "" || len(reason) < 3 {
		return errors.New("用法：rn-server release-fingerprint <releaseId> <hex> <actor> <reason>")
	}
	if !isHexDigest(fingerprint) {
		return fmt.Errorf("%q 不像一个指纹：应该是 32 到 128 位十六进制", fingerprint)
	}

	ctx := context.Background()
	tx, err := database.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 行锁住再看：这个命令和打包机的入库路径写的是同一列
	var tenant, platform, version string
	var buildNumber int
	var metadata []byte
	err = tx.QueryRowContext(ctx,
		`SELECT tenant_id,platform,version,build_number,file_metadata FROM app_releases WHERE id=? FOR UPDATE`,
		releaseID).Scan(&tenant, &platform, &version, &buildNumber, &metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("没有这个发布记录：%s", releaseID)
	}
	if err != nil {
		return err
	}
	parsed := map[string]any{}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &parsed); err != nil {
			return fmt.Errorf("%s 的 file_metadata 不是 JSON：%w", releaseID, err)
		}
	}
	if existing, _ := parsed["nativeFingerprint"].(string); strings.TrimSpace(existing) != "" {
		if strings.EqualFold(strings.TrimSpace(existing), fingerprint) {
			fmt.Printf("%s (%s %d) 已经是这个指纹了，没有改动\n", releaseID, version, buildNumber)
			return nil
		}
		return fmt.Errorf("%s 已经记着一个原生指纹了，拒绝覆盖。"+
			"补一个缺失的值是补数据，改一个已有的值是篡改热更新闸的判据", releaseID)
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`UPDATE app_releases SET file_metadata=JSON_SET(COALESCE(file_metadata,JSON_OBJECT()),'$.nativeFingerprint',?),updated_at=? WHERE id=?`,
		fingerprint, now, releaseID); err != nil {
		return err
	}
	summary, _ := json.Marshal(map[string]any{
		"nativeFingerprint": fingerprint,
		"platform":          platform,
		"version":           version,
		"buildNumber":       buildNumber,
		"source":            "rn-server release-fingerprint",
	})
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events(id,tenant_id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"audit_"+randomToken(16), tenant, actor, "release_fingerprint_backfilled", "release", releaseID,
		reason, "cli", summary, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("%s (%s build %d, %s) 记下原生指纹 %s\n", releaseID, version, buildNumber, platform, fingerprint)
	return nil
}

func isHexDigest(v string) bool {
	if len(v) < 32 || len(v) > 128 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// 审计行的 id 只需要唯一；真的取不到随机数时退回时间戳，也好过不写审计
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}
