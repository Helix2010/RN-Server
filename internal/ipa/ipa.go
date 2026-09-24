// Package ipa 读 iOS 安装包（.ipa）的身份并核对它是不是一个 App Store 包。
//
// 两处用它：Mac 上的控制进程在把包交给上传账户之前读一遍（设计
// ios-mac-builders-home-network-2026-09-18 §4.3 第 1 步）；服务端收下自助上传的 .ipa 时独立再读
// 一遍，并多做几项核对（设计 ios-tenant-delivery-tiers-2026-09-24 §3.5）——两侧分属不同的信任域，
// 各自按自己手里的记录把一次。
//
// 包是执行进程产出的，而执行进程跑的是第三方依赖，所以全程按不可信输入处理：用 Go 自己的
// zip 与 plist 解析器，不调 unzip / plutil；解压大小不采信压缩包的声明，按上限截断着读。
package ipa

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/plist"
)

const (
	// infoPlistLimit：Info.plist 是几 KB 的东西。给足余量，但不能让一个构造出来的
	// 压缩包把内存吃光
	infoPlistLimit = 1 << 20
	// profileLimit：描述文件几十 KB，带上设备列表的开发描述文件也就几百 KB
	profileLimit = 4 << 20
	// maxEntries：一个 React Native App 的 .ipa 是几千个条目，十万是构造出来的
	maxEntries = 100000
)

// Identity 是从 .ipa 里读出来的身份。
type Identity struct {
	BundleID     string
	ShortVersion string
	BuildNumber  string
}

// ReadIdentity 从 .ipa 里读 Payload/<App>.app/Info.plist。
//
// 只认恰好三段的路径：`Payload/x.app/Info.plist`。深一层的 Info.plist 属于 App 里的扩展
// （watch app、share extension），它们的 bundle id 是 `<主 id>.<后缀>`，认错了会让一个
// 身份不对的包通过核对。
func ReadIdentity(filePath string) (Identity, error) {
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return Identity{}, fmt.Errorf("cannot read the iOS package: %w", err)
	}
	defer reader.Close()
	return identityOf(&reader.Reader)
}

func identityOf(reader *zip.Reader) (Identity, error) {
	found, err := single(reader, IsAppInfoPlistPath, "Payload/<app>.app/Info.plist")
	if err != nil {
		return Identity{}, err
	}
	raw, err := readLimited(found, infoPlistLimit, "Info.plist")
	if err != nil {
		return Identity{}, err
	}
	fields, err := plist.Parse(raw)
	if err != nil {
		return Identity{}, err
	}
	identity := Identity{
		BundleID:     plist.String(fields, "CFBundleIdentifier"),
		ShortVersion: plist.String(fields, "CFBundleShortVersionString"),
		BuildNumber:  plist.String(fields, "CFBundleVersion"),
	}
	if identity.BundleID == "" || identity.ShortVersion == "" || identity.BuildNumber == "" {
		return identity, errors.New("Info.plist in the iOS package is missing CFBundleIdentifier, CFBundleShortVersionString or CFBundleVersion")
	}
	return identity, nil
}

// IsAppInfoPlistPath 判断压缩包里的这一条是不是主 App 的 Info.plist。
func IsAppInfoPlistPath(name string) bool {
	parts, ok := appPath(name)
	return ok && len(parts) == 3 && parts[2] == "Info.plist"
}

// isEmbeddedProfilePath 判断这一条是不是主 App 内嵌的描述文件。
func isEmbeddedProfilePath(name string) bool {
	parts, ok := appPath(name)
	return ok && len(parts) == 3 && parts[2] == "embedded.mobileprovision"
}

// appPath 把 Payload/<x>.app/... 这种路径拆开；压缩包里的路径由不可信一侧写，先排掉能跳出去的形状。
func appPath(name string) ([]string, bool) {
	if !safePath(name) {
		return nil, false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 3 || parts[0] != "Payload" || !strings.HasSuffix(parts[1], ".app") || len(parts[1]) <= len(".app") {
		return nil, false
	}
	return parts, true
}

func safePath(name string) bool {
	trimmed := strings.TrimSuffix(name, "/")
	return trimmed != "" && trimmed == path.Clean(trimmed) && !strings.HasPrefix(trimmed, "/") &&
		!strings.Contains(trimmed, "..") && !strings.Contains(trimmed, "\\")
}

// single 找恰好一个满足条件的条目：找不到或者找到两个都是错。
func single(reader *zip.Reader, match func(string) bool, what string) (*zip.File, error) {
	var found *zip.File
	for _, file := range reader.File {
		if !match(file.Name) {
			continue
		}
		if found != nil {
			return nil, errors.New("the iOS package carries more than one app bundle")
		}
		found = file
	}
	if found == nil {
		return nil, fmt.Errorf("the iOS package has no %s", what)
	}
	return found, nil
}

func readLimited(file *zip.File, limit int64, what string) ([]byte, error) {
	if file.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%s in the iOS package is %d bytes", what, file.UncompressedSize64)
	}
	stream, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	// 解压后的大小是压缩包自己声明的，不采信：按上限截断着读
	raw, err := io.ReadAll(io.LimitReader(stream, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s in the iOS package is larger than it declared", what)
	}
	return raw, nil
}

// Profile 是一份描述文件里核对要用的几项。
type Profile struct {
	// TeamID、BundleID 拆自 Entitlements 的 application-identifier（<TEAMID>.<bundle id>）
	TeamID   string
	BundleID string
	// TeamIdentifiers 是描述文件顶层的 TeamIdentifier 数组
	TeamIdentifiers []string
	ExpiresAt       time.Time
	// GetTaskAllow=true 是开发描述文件（能挂调试器），App Store 包不会有
	GetTaskAllow bool
	// HasDevices：列了设备（开发或 Ad Hoc）。App Store 描述文件没有设备列表
	HasDevices bool
	// ProvisionsAllDevices：企业分发描述文件
	ProvisionsAllDevices bool
}

// ParseProfile 从一份 .mobileprovision 的原文里读出核对要用的几项。
//
// 文件是 CMS 签名块，里面包着一份 XML plist。**不验签**：真正的把关在 Apple 那边——签不出
// Apple 认的包，或者签出来 Apple 拒收。这里要回答的是"这台机器能签哪个 App"（盘点）与
// "交上来的是不是一个 App Store 包"（服务端核对）。
func ParseProfile(raw []byte) (Profile, error) {
	start := bytes.Index(raw, []byte("<?xml"))
	end := bytes.LastIndex(raw, []byte("</plist>"))
	if start < 0 || end < start {
		return Profile{}, errors.New("no XML plist inside the provisioning profile")
	}
	dict, err := plist.ParseXML(raw[start : end+len("</plist>")])
	if err != nil {
		return Profile{}, err
	}
	entitlements := plist.Dict(dict, "Entitlements")
	identifier := plist.String(entitlements, "application-identifier")
	team, bundle, ok := strings.Cut(identifier, ".")
	if !ok || team == "" || bundle == "" {
		return Profile{}, fmt.Errorf("application-identifier %q is not <TEAMID>.<bundle id>", identifier)
	}
	profile := Profile{
		TeamID: team, BundleID: bundle,
		ExpiresAt:            plist.Time(dict, "ExpirationDate"),
		GetTaskAllow:         plist.Bool(entitlements, "get-task-allow"),
		ProvisionsAllDevices: plist.Bool(dict, "ProvisionsAllDevices"),
	}
	if devices, ok := dict["ProvisionedDevices"].([]any); ok && len(devices) > 0 {
		profile.HasDevices = true
	}
	if teams, ok := dict["TeamIdentifier"].([]any); ok {
		for _, value := range teams {
			if text, ok := value.(string); ok {
				profile.TeamIdentifiers = append(profile.TeamIdentifiers, text)
			}
		}
	}
	return profile, nil
}

// storeTopLevel 是 Xcode 按 App Store 方式导出的 .ipa 顶层会出现的目录。Payload 之外的几个
// 由导出选项与 App 的构成决定（Swift 运行库、崩溃符号、watch / iMessage 支持），都是 Xcode 写的。
var storeTopLevel = map[string]bool{
	"Payload": true, "SwiftSupport": true, "Symbols": true, "BCSymbolMaps": true,
	"WatchKitSupport": true, "WatchKitSupport2": true,
	"MessagesApplicationSupport": true, "MessagesApplicationExtensionSupport": true,
}

// Inspection 是服务端对一个自助上传 .ipa 的核对结果。
type Inspection struct {
	Identity Identity
	Profile  Profile
}

// Inspect 读身份、读内嵌描述文件、查压缩包结构。任何一项不对都返回错误，错误文字给人看。
//
// 比 Mac 上那一道多的几项，都是为了让"它是一个只能交给 App Store 的包"从假设变成检查：
// 包会交到租户手里，一个开发或 Ad Hoc 签名的包是能直接装机的。
func Inspect(filePath string) (Inspection, error) {
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return Inspection{}, fmt.Errorf("cannot read the iOS package: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > maxEntries {
		return Inspection{}, fmt.Errorf("the iOS package has %d entries", len(reader.File))
	}
	for _, file := range reader.File {
		if !safePath(file.Name) {
			return Inspection{}, fmt.Errorf("the iOS package has an entry with an unsafe path: %q", file.Name)
		}
		top, _, _ := strings.Cut(file.Name, "/")
		atRoot := !strings.Contains(file.Name, "/") && !file.FileInfo().IsDir()
		if !storeTopLevel[top] || atRoot {
			return Inspection{}, fmt.Errorf("the iOS package has an entry Xcode does not export: %q", file.Name)
		}
	}
	identity, err := identityOf(&reader.Reader)
	if err != nil {
		return Inspection{}, err
	}
	found, err := single(&reader.Reader, isEmbeddedProfilePath, "Payload/<app>.app/embedded.mobileprovision")
	if err != nil {
		return Inspection{}, err
	}
	raw, err := readLimited(found, profileLimit, "embedded.mobileprovision")
	if err != nil {
		return Inspection{}, err
	}
	profile, err := ParseProfile(raw)
	if err != nil {
		return Inspection{}, err
	}
	switch {
	case profile.GetTaskAllow:
		return Inspection{}, errors.New("the embedded provisioning profile allows debugging (get-task-allow): this is a development build, not an App Store build")
	case profile.HasDevices:
		return Inspection{}, errors.New("the embedded provisioning profile lists devices: this is a development or Ad Hoc build, not an App Store build")
	case profile.ProvisionsAllDevices:
		return Inspection{}, errors.New("the embedded provisioning profile provisions all devices: this is an enterprise build, not an App Store build")
	}
	return Inspection{Identity: identity, Profile: profile}, nil
}
