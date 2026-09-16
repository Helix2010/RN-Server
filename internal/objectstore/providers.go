package objectstore

// Providers 是控制台上能选的对象存储提供商。凡是要校验提供商的地方都认这一份——
// 各写一份的话，迟早一处加了华为云、另一处还在拒绝它。
var Providers = []string{"s3", "r2", "minio", "obs"}

// KnownProvider 说明这个值是不是上面那几个之一。
func KnownProvider(provider string) bool {
	for _, known := range Providers {
		if provider == known {
			return true
		}
	}
	return false
}

// ProviderNeedsEndpoint 说明这个提供商有没有默认地址。
//
// 华为云 OBS 没有：不填 endpoint 时 SDK 会去连 AWS 本家，拿到的是一次签名对不上的
// 403，报错里看不出其实是地址漏填了。R2 和 MinIO 同样没有默认地址，但发布存储那边
// 一直允许它们不填就保存（有测试钉着），这里不去改那条既有行为。
func ProviderNeedsEndpoint(provider string) bool {
	return provider == "obs"
}
