package iosmaterial

// 跨实现向量：这一份密文是**控制台在浏览器里封的**（RN-Admin src/core/ios-material-box.ts，
// 用固定的临时密钥与 nonce 产出）。Go 必须解得开它。
//
// 这条用例存在的理由：加密发生在浏览器里，而解密发生在 Mac 上的 Go 程序里。两边各写一遍
// 同一套构造，写歪一个字节的后果是"材料传上去了，机器永远解不开"——而那要等到真机取材料
// 时才发现，还会被当成密钥放错。有了这一份，任何一侧动了构造，这里立刻挂。
//
// 改 ios-material-box.ts 之后要重新生成这份向量（那边的 spec 用同样的固定输入产出它），
// 两处一起改才算数。

import (
	"encoding/base64"
	"testing"
)

const browserSealedBox = `{
  "v": 1,
  "alg": "x25519-hkdf-sha256-aes256gcm",
  "purpose": "ios-builder-material",
  "kind": "certificate",
  "teamId": "J4JDFC8LCC",
  "recipientSha256": "7538c5cdf61259c8e5f2a622a2e0dec8567baf6b3d898a3572036793375ae7b0",
  "epk": "iha45EIqzdIdQEURiJmE15a4+NtrUsZvGSGju5KX2CI=",
  "nonce": "AAECAwQFBgcICQoL",
  "ct": "7WasEvds8BnjWL6vHlVi6XJ+illBPfnaaIm7N9pHJWXxoAHnJIErWOwZyc3TWjEP9tBAvnAQNvfaBh1C3tC4x1n9XHBpckeW4ROpS0CZ3Nm2NVIbB4oIXaQjfrdvNBXXPKEBTkrtXCFin81ghzo/YenVfw5yWHBIyt97Mje3LrC+MnDsPsiCsym9gm90RBqiAEwKxuHe6/4jllQ38UuWRRidJKLVQuKp+Nxy2L0kUcTWgbvxA4giDkk7fsBaYf1KBF2CMCW+aIzeWdAc5bqXQ7DJQ0dl1i1mzwLVkV2ARqHJUbSP3SzvAPjK+y8SmCyGJGzr2xvw0Af+cKkYmOVU07TzT7TEX34UNDgGiEv19SXuu9/arw==",
  "createdAt": "2026-09-19T00:00:00Z"
}`

// browserSealedTenantBox 是控制台封的 v2（带租户）描述文件，与上面那份同一把收件人公钥、另一个 nonce
// （RN-Admin src/core/ios-material-box.spec.ts 的「v2」用例产出）。租户自己交材料只走这一版。
const browserSealedTenantBox = `{
  "v": 2,
  "alg": "x25519-hkdf-sha256-aes256gcm",
  "purpose": "ios-builder-material",
  "kind": "profile",
  "tenantId": "1000000001",
  "teamId": "J4JDFC8LCC",
  "bundleId": "win.anyfun.app",
  "recipientSha256": "7538c5cdf61259c8e5f2a622a2e0dec8567baf6b3d898a3572036793375ae7b0",
  "epk": "iha45EIqzdIdQEURiJmE15a4+NtrUsZvGSGju5KX2CI=",
  "nonce": "DA0ODxAREhMUFRYX",
  "ct": "cCc38EZEzSaZGZPu/4bx6ci4g97K+VSs/5WZkTi9BhSVsAumeHc4f4TwmZW/b0GFy9EkWL8OaaEpw6pnqv6E9B9WcDEnZZnpiUekyjneu2ixhlIai4LQv8p0LLeAFduMsPZxU7I9le7QJR9aAcitXub2I+XN3FKKZNlsR6wyCIVKttD9jArJXhccOgODlFBdQMptpcU4J+sv48PJSKlRth1+tSi3N/6+NGmoshLcvHcljPe4aAyCKNOSs+NU1nVRohZLAQm8L1vYt+6O9OX6tcodS7eZq/sj4XSM77NE8fjC7Ln1W318YBiI5pAIiYEFdl/jG8ARueG09EP95qRL7ekt3gGOE1jZYefeS4LZPORnHH0KSIU2+qTI2Pk5t07l",
  "createdAt": "2026-09-27T00:00:00Z"
}`

// 收件人私钥。它只为这条用例存在，不是任何一台机器上的密钥。
const browserVectorPrivateKey = "9QQKT1KEQKIn3tcW+032RRV20bmhaRlzxsif3HubmGk="

func TestOpensABoxSealedInTheBrowser(t *testing.T) {
	private, err := base64.StdEncoding.DecodeString(browserVectorPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	box, err := ParseBox([]byte(browserSealedBox))
	if err != nil {
		t.Fatalf("the browser's box does not even parse: %v", err)
	}
	material, err := Open(box, private)
	if err != nil {
		t.Fatalf("Go cannot open what the console sealed: %v\n"+
			"The two implementations of the same construction have drifted. "+
			"Check the KDF info, the additional data and the JSON field names in "+
			"RN-Admin src/core/ios-material-box.ts against signing/internal/sealedbox.", err)
	}
	if material.Kind != KindCertificate || material.TeamID != "J4JDFC8LCC" {
		t.Fatalf("decrypted the wrong thing: %s", material)
	}
	if material.P12Password != "浏览器封的这一份" {
		t.Errorf("the password came back changed: %q", material.P12Password)
	}
	p12, err := base64.StdEncoding.DecodeString(material.P12Base64)
	if err != nil || len(p12) != 5 || p12[0] != 1 || p12[4] != 5 {
		t.Errorf("the .p12 bytes came back changed: %v %v", p12, err)
	}
}

func TestOpensATenantBoxSealedInTheBrowser(t *testing.T) {
	private, err := base64.StdEncoding.DecodeString(browserVectorPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	box, err := ParseBox([]byte(browserSealedTenantBox))
	if err != nil {
		t.Fatalf("the browser's v2 box does not even parse: %v", err)
	}
	if box.Version != VersionTenant || box.TenantID != "1000000001" {
		t.Fatalf("the browser must seal a tenant's material as v2: v=%d tenant=%q", box.Version, box.TenantID)
	}
	material, err := Open(box, private)
	if err != nil {
		t.Fatalf("Go cannot open the v2 box the console sealed: %v\n"+
			"Check the tenantId field in both the box and the sealed record in RN-Admin src/core/ios-material-box.ts.", err)
	}
	if material.Kind != KindProfile || material.TenantID != "1000000001" || material.TeamID != "J4JDFC8LCC" ||
		material.BundleID != "win.anyfun.app" {
		t.Fatalf("decrypted the wrong thing: %s", material)
	}
	profile, err := base64.StdEncoding.DecodeString(material.ProfileBase64)
	if err != nil || len(profile) != 6 || profile[0] != 1 || profile[5] != 6 {
		t.Errorf("the profile bytes came back changed: %v %v", profile, err)
	}
}
