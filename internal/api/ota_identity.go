package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// otaIdentityMismatch 拦住"身份和这个租户对不上"的热更新包。
//
// 这是这条链路上最重要的一道闸。App 应用 OTA 之后，`Constants.expoConfig` 读的是**更新
// 包 manifest 里的那一份**，不是 APK 内嵌的那一份（expo-constants 从 extra.expoClient
// 解析）。也就是说 manifest 里的这两个字段决定了设备此后：
//
//   - `apiBaseUrl`：所有请求发到哪台服务器（RN-App src/core/network/api-client.ts:10）
//   - `bootstrapSignerAddress`：用谁的公钥验配置签名（同文件 :59）
//
// 一个把它们改掉的热更新包，等于把全部设备迁移到另一台服务器上，并且把信任锚一起换掉，
// 而设备上没有任何可见迹象。在此之前这两个字段一个都没校验过——manifest 只被要求
// scopeKey 非空。租户管理员上传任意 zip 就能做到这件事，而现在管理端还能直接排一个
// 构建任务，所以这道闸必须先于那个功能存在。
//
// 比对的基准是服务端为这个租户合成的身份（tenantManifestFor），也就是打包机构建时用的
// 同一份。改域名这类事本来就必须重新出包（confirm + reason + 审计 + 身份漂移提示）。
func (s *server) otaIdentityMismatch(ctx context.Context, tenant string, manifest map[string]any, version string, buildNumber int) error {
	identity, err := s.tenantIdentityFor(ctx, tenant, version, buildNumber)
	if err != nil {
		return err
	}
	return otaIdentityMismatchAgainst(identity, manifest)
}

// tenantIdentityFor 取服务端为这个租户合成的身份，绑定到指定的版本与 build 号。
func (s *server) tenantIdentityFor(ctx context.Context, tenant, version string, buildNumber int) (tenantManifest, error) {
	slug, err := s.tenantSlug(ctx, tenant)
	if err != nil {
		return tenantManifest{}, fmt.Errorf("cannot resolve this tenant to check the OTA identity: %w", err)
	}
	buildCfg, _, err := s.buildConfigFor(ctx, tenant, slug)
	if err != nil {
		return tenantManifest{}, fmt.Errorf("cannot read this tenant's build configuration to check the OTA identity: %w", err)
	}
	identity, err := s.tenantManifestFor(ctx, tenant, buildCfg, version, buildNumber)
	if err != nil {
		return tenantManifest{}, fmt.Errorf("cannot compose this tenant's app identity to check the OTA package: %w", err)
	}
	return identity, nil
}

func otaIdentityMismatchAgainst(identity tenantManifest, manifest map[string]any) error {
	expected := map[string]string{
		"extra.apiBaseUrl":                              identity.APIBaseURL,
		"extra.expoClient.extra.apiBaseUrl":             identity.APIBaseURL,
		"extra.expoClient.extra.bootstrapSignerAddress": identity.BootstrapSignerAddress,
	}
	for path, want := range expected {
		got := manifestPathString(manifest, path)
		if want == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want)) {
			return fmt.Errorf("OTA 包里的 %s 是 %q，与这个租户的 %q 不一致。更新包不能改变应用身份——改了域名或签名地址就必须重新出安装包",
				path, got, want)
		}
	}
	// scopeKey 决定 expo-updates 的存储作用域，同样不能换：换掉等于让设备换一套缓存与
	// 更新身份。它的值是 API 地址的 origin（RN-App scripts/build-ota.mjs）。
	if parsed, err := url.Parse(identity.APIBaseURL); err == nil && parsed.Scheme != "" {
		scope := strings.TrimSpace(fmt.Sprint(manifestPathString(manifest, "extra.scopeKey")))
		if !strings.EqualFold(scope, parsed.Scheme+"://"+parsed.Host) {
			return fmt.Errorf("OTA 包里的 extra.scopeKey 是 %q，与这个租户的 %q 不一致",
				scope, parsed.Scheme+"://"+parsed.Host)
		}
	}
	return nil
}

// manifestPathString 按 a.b.c 取一个字符串；路径上任何一段不是对象就返回空串。
func manifestPathString(manifest map[string]any, path string) string {
	var current any = manifest
	for _, segment := range strings.Split(path, ".") {
		node, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = node[segment]
	}
	value, _ := current.(string)
	return value
}
