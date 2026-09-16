package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// 主签名闸就绪判断（约定 4.4）。排队门禁（POST /builds 的 SIGNER_NOT_READY）、签名认领、
// 控制台签名密钥页用的是**同一个函数**：两边判据不一致时，排进去的任务会永远等不到签名闸，
// 或者签名闸领到一条它必然拒签的任务。

// build.keystore.check：每台签名闸对每个租户当前密钥的试解、本机确认、试签状态。
// 按机器 id 分键、用 JSON_SET 更新单个键——两台签名闸并发写整行会互相覆盖。
const buildKeystoreCheckConfigKey = "build.keystore.check"

const buildKeystoreCheckFormat = 2

type keystoreMachineCheck struct {
	KeystoreVersion           int       `json:"keystoreVersion"`
	Decrypt                   string    `json:"decrypt"`
	Confirmed                 bool      `json:"confirmed"`
	ConfirmedTrustRootsDigest optString `json:"confirmedTrustRootsDigest"`
	TrialSign                 string    `json:"trialSign"`
	CheckedAt                 string    `json:"checkedAt"`
	Error                     optString `json:"error"`
}

// keystoreChecksFor 读这个租户每台签名闸的检查记录。没有这一行、或者是旧格式（打包机时代的
// 单机记录）都当作空：旧记录说的是另一台机器、另一种密文，不能拿来给新密钥背书。
func (s *server) keystoreChecksFor(ctx context.Context, q rowQuerier, tenant string) (map[string]keystoreMachineCheck, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, tenant, buildKeystoreCheckConfigKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]keystoreMachineCheck{}, nil
	}
	if err != nil {
		return nil, err
	}
	var probe struct {
		Format int `json:"format"`
	}
	if json.Unmarshal(raw, &probe) != nil || probe.Format != buildKeystoreCheckFormat {
		return map[string]keystoreMachineCheck{}, nil
	}
	var doc struct {
		Format   int                             `json:"format"`
		Machines map[string]keystoreMachineCheck `json:"machines"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("build.keystore.check is malformed: %w", err)
	}
	if doc.Machines == nil {
		doc.Machines = map[string]keystoreMachineCheck{}
	}
	return doc.Machines, nil
}

// ---- 信任根 ----

// trustRootsFor 用服务端合成的 tenant manifest 与当前 OTA 证书算出包内信任根与摘要。
// 算不出来时返回原因（给控制台与排队门禁看），不是错误：租户配置没配全是正常状态。
func (s *server) trustRootsFor(ctx context.Context, tenant string) (*trustroots.Roots, string, []string, error) {
	slug, err := s.tenantSlug(ctx, tenant)
	if err != nil {
		return nil, "", nil, err
	}
	buildCfg, _, err := s.buildConfigFor(ctx, tenant, slug)
	if err != nil {
		return nil, "", nil, err
	}
	// 版本号与 build 号不进信任根，这里随便给一组合法值
	manifest, err := s.tenantManifestFor(ctx, tenant, buildCfg, "0.0.0", 1)
	if err != nil {
		var missing *missingIdentity
		if errors.As(err, &missing) {
			return nil, "", []string{"App 身份不完整，算不出包内信任根：" + strings.Join(missing.Fields, "、")}, nil
		}
		return nil, "", nil, err
	}
	record, err := s.otaSigningRecord(ctx, tenant)
	if err != nil {
		return nil, "", nil, err
	}
	if record == nil {
		return nil, "", []string{"没有配置 OTA 签名密钥：包里要编进 OTA 证书，签名闸按它核对信任根"}, nil
	}
	certificateSHA256, ok := certificateFingerprint(record.Value.Certificate)
	if !ok {
		return nil, "", nil, errors.New("stored OTA certificate is not PEM")
	}
	hosts, problem := appLinksHostsFor(manifest.APIBaseURL)
	if problem != "" {
		return nil, "", []string{problem}, nil
	}
	roots := trustroots.Roots{
		APIBaseURL:             manifest.APIBaseURL,
		OTACertificateSHA256:   certificateSHA256,
		BootstrapSignerAddress: manifest.BootstrapSignerAddress,
		AppLinksHosts:          hosts,
		Scheme:                 manifest.Scheme,
		DistributionChannel:    manifest.DistributionChannel,
		ApplicationID:          manifest.ApplicationID,
	}
	normalized, err := roots.Normalize()
	if err != nil {
		return nil, "", []string{"包内信任根不合法：" + err.Error()}, nil
	}
	digest, err := trustroots.Digest(normalized)
	if err != nil {
		return nil, "", []string{"包内信任根不合法：" + err.Error()}, nil
	}
	return &normalized, digest, nil, nil
}

// appLinksHostsFor 按 RN-App app.config.ts 的规则派生 App Links host：
// apiBaseUrl 是 https 时 host 为 new URL(apiBaseUrl).host（含非默认端口），否则没有 App Links。
//
// WHATWG URL 会去掉 https 的默认端口 443，而 trustroots.AppLinksHostFor 按原样保留。
// 两边对 ":443" 的说法不一致，所以显式写了 :443 的 apiBaseUrl 不就绪，要求去掉之后重新保存，
// 而不是在这里替签名闸猜它会怎么算。
func appLinksHostsFor(apiBaseURL string) ([]string, string) {
	host, err := trustroots.AppLinksHostFor(apiBaseURL)
	if err != nil {
		return nil, "apiBaseUrl 不是签名闸能确认的 https 源（小写域名、可选端口、不带路径与尾斜杠）"
	}
	if strings.HasSuffix(host, ":443") {
		return nil, "apiBaseUrl 写了默认端口 :443：App Links host 按 RN-App 的规则会去掉它，与签名闸确认的值对不上；去掉 :443 后重新保存"
	}
	return []string{host}, ""
}

// ---- 就绪 ----

type signerReadiness struct {
	Ready    bool
	Problems []string
	Keystore buildKeystoreState
	// 下面几项只在能算出来时有值
	Upload  *keystorebox.Upload
	Primary *buildMachine
	Box     *keystorebox.Box
	Check   *keystoreMachineCheck
	Roots   *trustroots.Roots
	Digest  string
}

// signerReadinessFor：该租户存在 v3 记录、与发布身份一致；主签名闸 active 且有发给它的密文；
// 信任根算得出来；主签名闸对当前密钥版本 decrypt=ok、confirmed、确认的信任根摘要等于当前摘要、
// trialSign=ok。任何一项不满足就不就绪，Problems 逐条说清缺什么。
func (s *server) signerReadinessFor(ctx context.Context, tenant string) (signerReadiness, error) {
	var r signerReadiness
	keystore, err := s.buildKeystoreStateFor(ctx, s.db, tenant)
	if err != nil {
		return r, err
	}
	r.Keystore = keystore
	switch {
	case !keystore.Exists:
		r.Problems = append(r.Problems, "还没有上传签名密钥（离线工具 build-keystore 产出的 v3 文件）")
	case keystore.Legacy:
		r.Problems = append(r.Problems, "库里是旧格式的签名密钥密文（签名闸上线前的口令封或打包机公钥封），需要按密钥重置流程离线生成并上传 v3 文件")
	}
	if keystore.configured() {
		identity, err := s.androidReleaseIdentityRecord(ctx, tenant)
		if err != nil {
			return r, err
		}
		if identity == nil || identity.Value.PackageName != keystore.Record.PackageName || identity.Value.SignerSHA256 != keystore.Record.CertificateSHA256 {
			r.Problems = append(r.Problems, "登记的 Android 发布身份（包名、签名证书指纹）与签名密钥不一致，重新上传签名密钥会一并写入")
		}
	}
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		return r, err
	}
	primary, hasPrimary := registry.activePrimary()
	if hasPrimary {
		r.Primary = &primary
	} else {
		r.Problems = append(r.Problems, "没有 active 的主签名闸（在「打包机与签名闸」登记主签名闸并接受它的公钥）")
	}
	if keystore.configured() {
		upload, err := s.keystoreUploadFor(tenant, keystore.Record)
		if err != nil {
			return r, err
		}
		r.Upload = &upload
		if hasPrimary {
			if box, ok := boxFor(upload, string(primary.PublicKeySHA256)); ok {
				r.Box = &box
			} else {
				r.Problems = append(r.Problems, "签名密钥没有加密给主签名闸 "+primary.Name+"：把它加进离线 pin 文件，用离线工具重新 seal 并上传")
			}
		}
	}
	roots, digest, rootProblems, err := s.trustRootsFor(ctx, tenant)
	if err != nil {
		return r, err
	}
	r.Roots, r.Digest = roots, digest
	r.Problems = append(r.Problems, rootProblems...)
	if keystore.configured() && hasPrimary {
		checks, err := s.keystoreChecksFor(ctx, s.db, tenant)
		if err != nil {
			return r, err
		}
		check, ok := checks[primary.ID]
		switch {
		case !ok || check.KeystoreVersion != keystore.Version:
			r.Problems = append(r.Problems, "主签名闸 "+primary.Name+" 还没有检查当前这一版签名密钥")
		default:
			r.Check = &check
			if check.Decrypt != "ok" {
				r.Problems = append(r.Problems, "主签名闸 "+primary.Name+" 解不开当前这一版签名密钥"+errorSuffix(string(check.Error)))
			}
			if !check.Confirmed {
				r.Problems = append(r.Problems, "主签名闸 "+primary.Name+" 还没有在本机确认这个租户（signer confirm）")
			} else if digest != "" && string(check.ConfirmedTrustRootsDigest) != digest {
				r.Problems = append(r.Problems, "包内信任根变了（apiBaseUrl、OTA 证书、bootstrap 签名地址、scheme 等），需要在主签名闸 "+primary.Name+" 上重新确认")
			}
			if check.TrialSign != "ok" {
				r.Problems = append(r.Problems, "主签名闸 "+primary.Name+" 还没有试签通过"+errorSuffix(string(check.Error)))
			}
		}
	}
	r.Ready = len(r.Problems) == 0
	return r, nil
}

func errorSuffix(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return "：" + detail
}
