package axml

import (
	_ "embed"
	"strconv"
	"strings"
)

// framework_attrs.txt 由 Android SDK 的 public-final.xml 生成，生成方法见文件头。
//
//go:embed framework_attrs.txt
var frameworkAttrsText string

var (
	frameworkIDByName = map[string]uint32{}
	frameworkNameByID = map[uint32]string{}
)

func init() {
	for n, line := range strings.Split(frameworkAttrsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "0x") {
			panic("axml: framework_attrs.txt line " + strconv.Itoa(n+1) + " is malformed")
		}
		id, err := strconv.ParseUint(fields[1][2:], 16, 32)
		if err != nil || id>>24 != 0x01 {
			panic("axml: framework_attrs.txt line " + strconv.Itoa(n+1) + " has a bad id")
		}
		if _, dup := frameworkIDByName[fields[0]]; dup {
			panic("axml: framework_attrs.txt lists " + fields[0] + " twice")
		}
		if _, dup := frameworkNameByID[uint32(id)]; dup {
			panic("axml: framework_attrs.txt lists id " + fields[1] + " twice")
		}
		frameworkIDByName[fields[0]] = uint32(id)
		frameworkNameByID[uint32(id)] = fields[0]
	}
}

// FrameworkAttrID 返回 android: 属性名对应的框架资源 ID。
func FrameworkAttrID(name string) (uint32, bool) {
	id, ok := frameworkIDByName[name]
	return id, ok
}

// FrameworkAttrName 返回框架资源 ID 对应的属性名。
func FrameworkAttrName(id uint32) (string, bool) {
	name, ok := frameworkNameByID[id]
	return name, ok
}

// 清单解析与测试常用的属性 ID。与表不一致时 init 会 panic（见 attrs_test.go 的交叉核对）。
const (
	AttrName                  uint32 = 0x01010003
	AttrPermission            uint32 = 0x01010006
	AttrProtectionLevel       uint32 = 0x01010009
	AttrSharedUserID          uint32 = 0x0101000b
	AttrDebuggable            uint32 = 0x0101000f
	AttrExported              uint32 = 0x01010010
	AttrValue                 uint32 = 0x01010024
	AttrResource              uint32 = 0x01010025
	AttrScheme                uint32 = 0x01010027
	AttrHost                  uint32 = 0x01010028
	AttrPathPrefix            uint32 = 0x0101002b
	AttrMinSDKVersion         uint32 = 0x0101020c
	AttrVersionCode           uint32 = 0x0101021b
	AttrVersionName           uint32 = 0x0101021c
	AttrTargetSDKVersion      uint32 = 0x01010270
	AttrMaxSDKVersion         uint32 = 0x01010271
	AttrTestOnly              uint32 = 0x01010272
	AttrAllowBackup           uint32 = 0x01010280
	AttrUsesCleartextTraffic  uint32 = 0x010104ec
	AttrAutoVerify            uint32 = 0x010104ee
	AttrNetworkSecurityConfig uint32 = 0x01010527
	AttrVersionCodeMajor      uint32 = 0x01010576
)

func init() {
	for name, id := range map[string]uint32{
		"name": AttrName, "permission": AttrPermission, "protectionLevel": AttrProtectionLevel,
		"sharedUserId": AttrSharedUserID, "debuggable": AttrDebuggable, "exported": AttrExported,
		"value": AttrValue, "resource": AttrResource, "scheme": AttrScheme, "host": AttrHost,
		"pathPrefix": AttrPathPrefix, "minSdkVersion": AttrMinSDKVersion, "versionCode": AttrVersionCode,
		"versionName": AttrVersionName, "targetSdkVersion": AttrTargetSDKVersion, "maxSdkVersion": AttrMaxSDKVersion,
		"testOnly": AttrTestOnly, "allowBackup": AttrAllowBackup, "usesCleartextTraffic": AttrUsesCleartextTraffic,
		"autoVerify": AttrAutoVerify, "networkSecurityConfig": AttrNetworkSecurityConfig, "versionCodeMajor": AttrVersionCodeMajor,
	} {
		if got, ok := frameworkIDByName[name]; !ok || got != id {
			panic("axml: constant for " + name + " disagrees with framework_attrs.txt")
		}
	}
}
