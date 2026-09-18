package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/Helix2010/RN-Server/internal/store"
)

// importPushCredentialsFromEnv 是 `rn-server push-credentials import-env`：
// 把 env 里那份全局推送凭据（FCM 与 APNs）搬进库，存成平台默认（tenant 0）。
//
// 这一步之后所有租户继承同一份凭据，发出去的请求和搬之前逐字节相同——迁移不
// 改变任何行为。之后哪个租户有自己的 Firebase 项目，就在管理端给它单独存一份
// 覆盖掉。
//
// 已经有平台行时**拒绝**，不静默覆盖：这个命令多半是在部署脚本里跑的，第二次
// 跑通常意味着有人搞错了，而覆盖掉一把正在用的钥匙没有回退路径。
func importPushCredentialsFromEnv(cfg config.Config, database *store.Store) error {
	if cfg.FCMServiceAccountJSON == "" && cfg.APNsPrivateKey == "" {
		return errors.New("FCM_SERVICE_ACCOUNT_JSON 和 APNS_PRIVATE_KEY 都是空的，没有东西可以导入")
	}
	if cfg.FCMServiceAccountJSON == "" {
		fmt.Println("FCM_SERVICE_ACCOUNT_JSON 是空的，跳过 FCM。")
		return importAPNsFromEnv(cfg, database)
	}
	box, err := secretbox.New(cfg.StorageMasterKey)
	if err != nil {
		return fmt.Errorf("需要 STORAGE_MASTER_KEY 才能封存凭据：%w", err)
	}
	// 沿用派发器一直在用的宽松解码：这个值历史上有 base64 和 \n 转义两种写法
	raw := decodeEnvSecret(cfg.FCMServiceAccountJSON)
	account, err := pushcreds.ParseServiceAccount(raw)
	if err != nil {
		return fmt.Errorf("FCM_SERVICE_ACCOUNT_JSON 不是一份可用的服务账号：%w", err)
	}
	if cfg.FCMProjectID != "" && cfg.FCMProjectID != account.ProjectID {
		// 这两个值不一致时，发送用的是 FCM_PROJECT_ID 而签名用的是服务账号里的
		// 项目——那样发出去必然 403。搬进库之后只有一个项目字段，正好把它治好，
		// 但要让人知道原来是歪的。
		return fmt.Errorf("FCM_PROJECT_ID 是 %q，而服务账号属于项目 %q；两者必须一致",
			cfg.FCMProjectID, account.ProjectID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var existing int
	if err := database.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_configs WHERE tenant_id=? AND config_key=?`,
		pushcreds.PlatformTenant, pushcreds.FCMConfigKey).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return errors.New("平台默认的推送凭据已经存在。要换钥匙请走管理端，那条路会先验证再替换")
	}

	// 先验证再写：搬一把已经失效的钥匙进来，只会把"推送为什么不通"这个问题
	// 从 env 挪到库里
	fmt.Printf("正在向 Google 换一次访问令牌，验证这把钥匙还有效……\n")
	if err := pushcreds.Verify(ctx, account); err != nil {
		return err
	}

	sealed, err := pushcreds.Encrypt(box, pushcreds.PlatformTenant, raw)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	value, _ := json.Marshal(pushcreds.FCM{
		ProjectID: account.ProjectID, ClientEmail: account.ClientEmail, PrivateKeyID: account.PrivateKeyID,
		ServiceAccountEncrypted: sealed, VerifiedAt: &now,
	})
	if _, err := database.DB.ExecContext(ctx,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)`,
		pushcreds.PlatformTenant, pushcreds.FCMConfigKey, value, "push-credentials-import-env", now); err != nil {
		return err
	}

	fmt.Printf("已存为平台默认（tenant %s）：\n", pushcreds.PlatformTenant)
	fmt.Printf("  项目      %s\n", account.ProjectID)
	fmt.Printf("  服务账号  %s\n", account.ClientEmail)
	fmt.Printf("  密钥 id   %s\n", pushcreds.KeyHint(account.PrivateKeyID))
	fmt.Println()
	fmt.Println("现在可以从 env 里删掉 FCM_PROJECT_ID 和 FCM_SERVICE_ACCOUNT_JSON 并重启。")
	fmt.Println("接着到管理端逐个租户看一眼「推送：服务端半边」——projectMatches 为 false 的")
	fmt.Println("那个租户，它的 google-services.json 和这把钥匙不是同一个 Firebase 项目，")
	fmt.Println("今天它的推送就是发不出去的。")
	fmt.Println()
	return importAPNsFromEnv(cfg, database)
}

// importAPNsFromEnv 把 env 里那份 APNs 凭据搬进库，同样存成平台默认。
//
// 与 FCM 的两点不同（设计 push-apns-and-shared-app-identity-2026-09-18 §2.5）：
//
//   - **APNS_BUNDLE_ID 不导**。库里那份的 topic 取自各租户 release.ios 的 bundleId；
//     env 里这一份是全局的，多租户下必然发错 topic，所以它到此为止。但它在这里
//     还有最后一个用处：拿它做这次导入的探活 topic。
//   - 探活是真发一条静默推送（APNs 没有换令牌那种廉价接口）。
func importAPNsFromEnv(cfg config.Config, database *store.Store) error {
	if cfg.APNsPrivateKey == "" {
		fmt.Println("APNS_PRIVATE_KEY 是空的，跳过 APNs。")
		return nil
	}
	if strings.TrimSpace(cfg.APNsTeamID) == "" || strings.TrimSpace(cfg.APNsKeyID) == "" {
		return errors.New("APNS_TEAM_ID 与 APNS_KEY_ID 都必须有，否则签不出 JWT")
	}
	box, err := secretbox.New(cfg.StorageMasterKey)
	if err != nil {
		return fmt.Errorf("需要 STORAGE_MASTER_KEY 才能封存凭据：%w", err)
	}
	raw := decodeEnvSecret(cfg.APNsPrivateKey)
	if err := pushcreds.ParseAPNsAuthKey(raw); err != nil {
		return fmt.Errorf("APNS_PRIVATE_KEY 不是一份可用的 .p8：%w", err)
	}
	environment, err := pushcreds.NormalizeAPNsEnvironment(cfg.APNsEnvironment)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var existing int
	if err := database.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_configs WHERE tenant_id=? AND config_key=?`,
		pushcreds.PlatformTenant, pushcreds.APNsConfigKey).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return errors.New("平台默认的 APNs 凭据已经存在。要换钥匙请走管理端，那条路会先探活再替换")
	}

	value := pushcreds.APNs{TeamID: strings.TrimSpace(cfg.APNsTeamID),
		KeyID: strings.TrimSpace(cfg.APNsKeyID), Environment: environment}

	// 探活要一个 topic。平台那一行没有自己的 bundle id，env 里这一份正好用在
	// 这里——它的最后一次出场。没配就跳过探活，并说清楚跳了。
	probeTopic := strings.TrimSpace(cfg.APNsBundleID)
	now := time.Now().UTC()
	if probeTopic == "" {
		fmt.Println("APNS_BUNDLE_ID 没配，跳过探活——这一份凭据存进去时没有验证过。")
	} else {
		fmt.Printf("正在用 %s 向 APNs 发一条静默推送，验证这把钥匙还有效……\n", probeTopic)
		if err := pushcreds.VerifyAPNs(ctx, value, raw, probeTopic); err != nil {
			return err
		}
		value.VerifiedAt = &now
	}

	sealed, err := pushcreds.EncryptAPNsAuthKey(box, pushcreds.PlatformTenant, raw)
	if err != nil {
		return err
	}
	value.AuthKeyEncrypted = sealed
	stored, _ := json.Marshal(value)
	if _, err := database.DB.ExecContext(ctx,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)`,
		pushcreds.PlatformTenant, pushcreds.APNsConfigKey, stored, "push-credentials-import-env", now); err != nil {
		return err
	}

	fmt.Printf("APNs 已存为平台默认（tenant %s）：\n", pushcreds.PlatformTenant)
	fmt.Printf("  Team ID   %s\n", value.TeamID)
	fmt.Printf("  Key ID    %s\n", pushcreds.KeyHint(value.KeyID))
	fmt.Printf("  环境      %s\n", value.Environment)
	fmt.Println()
	if err := warnBundleIDDrift(ctx, database, probeTopic); err != nil {
		return err
	}
	fmt.Println("现在可以从 env 里删掉 APNS_TEAM_ID、APNS_KEY_ID、APNS_PRIVATE_KEY 和")
	fmt.Println("APNS_BUNDLE_ID 并重启。topic 之后取自各租户 release.ios 的 bundleId，")
	fmt.Println("设备上报了 package_id 时以设备那一份为准。")
	return nil
}

// warnBundleIDDrift 列出 release.ios 的 bundleId 和 env 里那个全局值对不上的租户。
//
// 这正是今天可能已经错着的地方：env 只放得下一个 bundle id，而 topic 发错的表现
// 是 APNs 回 DeviceTokenNotForTopic——推送静默失效，没有任何一步会报错。
func warnBundleIDDrift(ctx context.Context, database *store.Store, envBundleID string) error {
	if envBundleID == "" {
		return nil
	}
	rows, err := database.DB.QueryContext(ctx,
		`SELECT CAST(tenant_id AS CHAR),config_value FROM app_configs WHERE config_key='release.ios' AND tenant_id<>0`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var drift []string
	for rows.Next() {
		var tenant string
		var raw []byte
		if rows.Scan(&tenant, &raw) != nil {
			continue
		}
		var identity struct {
			BundleID string `json:"bundleId"`
		}
		if json.Unmarshal(raw, &identity) != nil {
			continue
		}
		if bundleID := strings.TrimSpace(identity.BundleID); bundleID != "" && bundleID != envBundleID {
			drift = append(drift, tenant+" → "+bundleID)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(drift) > 0 {
		fmt.Printf("注意：这些租户的 release.ios bundleId 与 APNS_BUNDLE_ID(%s) 不同，\n", envBundleID)
		fmt.Println("也就是说在这次导入之前，它们的 iOS 推送 topic 一直是错的：")
		for _, item := range drift {
			fmt.Println("  租户 " + item)
		}
		fmt.Println("导入之后 topic 改按租户取，这几个会自动变对。")
		fmt.Println()
	}
	return nil
}

// decodeEnvSecret 和 push.decodeSecret 同一套：这个值历史上有 base64 和 \\n 转义
// 两种写法，导入时两种都要认，否则"搬过去推送就停了"。
func decodeEnvSecret(value string) []byte {
	trimmed := strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded
	}
	return []byte(strings.ReplaceAll(trimmed, `\n`, "\n"))
}
