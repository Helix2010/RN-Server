package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

// 备份要能开两种格式的盒子，和构建一致。
//
// 以前备份只认 v2（加密给本机公钥），而迁移之前存下的租户还是 v1（口令封）。那些租户
// 构建一切正常，每一次备份却都失败在「unsupported sealed keystore format 1/」——
// 最该有离线副本的老租户，一份都产不出来
func TestUnsealKeystoresOpensBothFormats(t *testing.T) {
	generated, err := androidkeystore.Generate(androidkeystore.Params{
		CommonName: "Backup Test", KeyAlias: "upload", KeySize: 2048, ValidityYears: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildkeystore.Bundle{
		KeystoreBase64: base64.StdEncoding.EncodeToString(generated.PKCS12),
		StorePassword:  generated.StorePassword, KeyAlias: "upload", KeyPassword: generated.StorePassword,
	}
	const passphrase = "an-old-machine-wide-passphrase"
	v1, err := buildkeystore.Seal(bundle, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	private, recipient, err := buildkeystore.NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	v2, err := buildkeystore.SealTo(bundle, recipient)
	if err != nil {
		t.Fatal(err)
	}
	item := func(tenant, slug string, sealed buildkeystore.Sealed) sealedKeystoreItem {
		raw, err := json.Marshal(sealed)
		if err != nil {
			t.Fatal(err)
		}
		return sealedKeystoreItem{Tenant: tenant, Slug: slug, HasKeystore: true,
			Version: sealed.Version, SealedKeystore: raw}
	}
	// 线上真有带大写的 slug
	items := []sealedKeystoreItem{item("100000001", "AnyFun", v1), item("100000002", "new", v2)}

	files, tenants, err := unsealKeystores(config{AgentPrivateKey: private, KeystorePassphrase: passphrase}, items)
	if err != nil {
		t.Fatalf("v1 和 v2 都应当能进备份: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("两个租户都要进清单，得到 %d 个", len(tenants))
	}
	for _, slug := range []string{"AnyFun", "new"} {
		if got := string(files["keystores/"+slug+"/fingerprint.txt"]); got != generated.SignerSHA256 {
			t.Errorf("%s 的证书指纹 = %q，想要 %q", slug, got, generated.SignerSHA256)
		}
	}

	// 进不了目录名的 slug：一个盒子都不解就停
	bad := []sealedKeystoreItem{item("100000003", "../escape", v2)}
	if _, _, err := unsealKeystores(config{AgentPrivateKey: private}, bad); err == nil || !strings.Contains(err.Error(), "directory name") {
		t.Fatalf("slug 进不了目录名时要先拒绝: %v", err)
	}

	// 本机没有旧口令：整次失败，并且点名是哪个租户、差的是哪个键
	_, _, err = unsealKeystores(config{AgentPrivateKey: private}, items)
	if err == nil || !strings.Contains(err.Error(), "100000001") || !strings.Contains(err.Error(), "BUILD_KEYSTORE_PASSPHRASE") {
		t.Fatalf("缺旧口令时要点名租户和键: %v", err)
	}
}
