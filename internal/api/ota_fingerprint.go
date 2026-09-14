package api

import (
	"encoding/json"
	"errors"
	"strings"
)

// 热更新只能承载纯 JS / 样式 / 随包资源的改动。动了原生模块、权限、原生配置的改动
// 必须重新出安装包——把它塞进热更新，设备拉到之后会去调一个 APK 里根本不存在的原生
// 模块，表现是启动即崩，而且崩在所有装了那一版的设备上。
//
// 在此之前这条规则只写在文档里，靠发版的人记得。把"构建热更新"这件事交给管理端之后，
// 记得住的人就不再是同一批人了，所以它必须变成一道机器闸。
//
// 判据是 @expo/fingerprint 的哈希：它只看自动链接的原生模块、原生配置和 expo config，
// **不看 JS 源码**——这正是"要不要重新编译原生"这个问题的定义。打包机在编 APK 时算一
// 次，随发布记录存进 file_metadata；构建热更新包时在同一个 worktree 再算一次，写进
// manifest 的 extra。两者不等，这个热更新包就不该发给这个基线。
//
// runtimeVersion 不能替代它：app.config.ts 现在是 `runtimeVersion: appVersion`，也就是
// 版本号本身，同一个版本号下加一个原生模块它一个字都不会变。控制台把这个字段显示成
// "Expo Fingerprint"，名字是对的，东西不是。把 runtimeVersion 的策略换成 fingerprint
// 是更彻底的做法，但那会让现存设备的 runtime 全部改变（要先装新包才能再收热更新），
// 是一个产品决定，不该顺手做。
const otaFingerprintMetadataKey = "nativeFingerprint"

var errOTAFingerprintMissing = errors.New(
	"这个基线安装包没有记录原生指纹（它在该功能上线之前构建），无法判断热更新是否只含 JS 改动。" +
		"请先出一个新的安装包，再基于它发热更新")

// baseNativeFingerprint 从基线发布记录的 file_metadata 里读原生指纹，没有就返回空串。
//
// 排队时和上传时读的是同一个值，所以只留这一处解析：两边要是各写一遍，
// 早晚会一边改了另一边没改，于是控制台放行的任务在最后一步被拒——这次就是这样。
func baseNativeFingerprint(fileMetadata []byte) string {
	if len(fileMetadata) == 0 {
		return ""
	}
	var metadata map[string]any
	if json.Unmarshal(fileMetadata, &metadata) != nil {
		return ""
	}
	value, _ := metadata[otaFingerprintMetadataKey].(string)
	return strings.ToLower(strings.TrimSpace(value))
}

// otaFingerprintMismatch 比对更新包与基线的原生指纹。
func otaFingerprintMismatch(manifest map[string]any, baseFileMetadata []byte) error {
	base := baseNativeFingerprint(baseFileMetadata)
	if base == "" {
		return errOTAFingerprintMissing
	}
	packaged := strings.ToLower(strings.TrimSpace(manifestPathString(manifest, "extra."+otaFingerprintMetadataKey)))
	if packaged == "" {
		return errors.New("更新包没有带原生指纹（extra.nativeFingerprint），无法判断它是否只含 JS 改动。请用当前版本的构建脚本重新构建")
	}
	if packaged != base {
		return errors.New("这次改动动了原生部分（原生指纹与基线安装包不一致），不能走热更新。" +
			"新增或升级原生模块、改权限、改原生配置都属于这一类，必须重新出安装包发全量更新")
	}
	return nil
}
