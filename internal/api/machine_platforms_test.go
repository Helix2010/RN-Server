package api

import (
	"reflect"
	"testing"
)

// 加这个字段之前登记的构建机都没有它，而它们全是 Linux。读成"什么都不能构建"
// 会让所有 Android 构建在下一次认领时停摆。
func TestBuildPlatformsDefaultsToAndroid(t *testing.T) {
	builder := buildMachine{Role: machineRoleBuilder}
	if got := builder.buildPlatforms(); !reflect.DeepEqual(got, []string{buildPlatformAndroid}) {
		t.Fatalf("an unmarked builder must default to android, got %v", got)
	}
	if !builder.canBuild(buildPlatformAndroid) || builder.canBuild(buildPlatformIOS) {
		t.Fatalf("an unmarked builder builds android only: %v", builder.buildPlatforms())
	}
	mac := buildMachine{Role: machineRoleBuilder, Platforms: []string{buildPlatformIOS}}
	if mac.canBuild(buildPlatformAndroid) || !mac.canBuild(buildPlatformIOS) {
		t.Fatalf("a mac builds ios only: %v", mac.buildPlatforms())
	}
	// 签名闸什么都不构建
	if got := (buildMachine{Role: machineRoleSigner}).buildPlatforms(); got != nil {
		t.Fatalf("a signer builds nothing, got %v", got)
	}
}

func TestNormalizeBuildPlatforms(t *testing.T) {
	// 顺序固定：审计里的前后对比不该因为顺序不同而看起来像一次改动
	for _, input := range [][]string{
		{"ios", "android"},
		{"android", "ios"},
		{" IOS ", "android", "ios"},
	} {
		got, err := normalizeBuildPlatforms(input)
		if err != nil {
			t.Fatalf("%v: %v", input, err)
		}
		if !reflect.DeepEqual(got, []string{"android", "ios"}) {
			t.Fatalf("%v → %v", input, got)
		}
	}
	for _, input := range [][]string{nil, {}, {"harmony"}, {"android", "windows"}, {""}} {
		if _, err := normalizeBuildPlatforms(input); err == nil {
			t.Fatalf("%v: expected a rejection", input)
		}
	}
}

// 排队时的判据：有没有一台**能认领**的构建机能干这个平台。
// 吊销的、还没装完的都不算——它们都过不了认领时的鉴权。
func TestHasLiveBuilderForOnlyCountsMachinesThatCanClaim(t *testing.T) {
	doc := buildMachinesDoc{Machines: []buildMachine{
		{ID: "mch_a", Role: machineRoleBuilder, Status: machineStatusActive},
		{ID: "mch_b", Role: machineRoleBuilder, Status: machineStatusRevoked, Platforms: []string{buildPlatformIOS}},
		{ID: "mch_c", Role: machineRoleSigner, Status: machineStatusActive},
	}}
	if !doc.hasLiveBuilderFor(buildPlatformAndroid) {
		t.Fatal("the unmarked builder must count for android")
	}
	if doc.hasLiveBuilderFor(buildPlatformIOS) {
		t.Fatal("a revoked mac must not make ios look available")
	}
	// 还在装的机器不算：它还没有令牌，过不了认领时的鉴权。把它算进来，这道闸就会
	// 在"机器还在装"这个最常见的窗口里放行一条没人能领的任务
	doc.Machines = append(doc.Machines, buildMachine{
		ID: "mch_d", Role: machineRoleBuilder, Status: machineStatusPendingEnrollment, Platforms: []string{buildPlatformIOS},
	})
	if doc.hasLiveBuilderFor(buildPlatformIOS) {
		t.Fatal("a mac that has not finished enrolling cannot claim anything")
	}
	doc.Machines = append(doc.Machines, buildMachine{
		ID: "mch_e", Role: machineRoleBuilder, Status: machineStatusActive, Platforms: []string{buildPlatformIOS},
	})
	if !doc.hasLiveBuilderFor(buildPlatformIOS) {
		t.Fatal("an active mac must make ios available")
	}
}

// 登记里出现不合法的值就是有人直接改了库：拒绝，不猜。
func TestMachineRegistryValidateRejectsBadPlatforms(t *testing.T) {
	base := buildMachine{
		ID: "mch_" + "0123456789abcdef0123456789abcdef", Role: machineRoleBuilder, Name: "mac-1",
		Status: machineStatusPendingEnrollment,
		Enrollment: &machineEnrollment{
			CodeSHA256: "aa" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			ExpiresAt:  "2026-09-18T00:00:00Z",
		},
	}
	for name, platforms := range map[string][]string{
		"未知平台":  {"harmony"},
		"没归一化":  {"ios", "android"},
		"大小写不对": {"Android"},
		"有重复":   {"android", "android"},
	} {
		machine := base
		machine.Platforms = platforms
		if err := (buildMachinesDoc{Machines: []buildMachine{machine}}).validate(); err == nil {
			t.Fatalf("%s: expected a rejection for %v", name, platforms)
		}
	}
	good := base
	good.Platforms = []string{buildPlatformAndroid, buildPlatformIOS}
	if err := (buildMachinesDoc{Machines: []buildMachine{good}}).validate(); err != nil {
		t.Fatalf("a normalised pair must be accepted: %v", err)
	}
	// 签名闸带着构建平台说明数据被人改过
	signer := buildMachine{
		ID: "mch_" + "fedcba9876543210fedcba9876543210", Role: machineRoleSigner, SignerRole: signerRoleStandby,
		Name: "sg-1", Status: machineStatusPendingEnrollment, Platforms: []string{buildPlatformAndroid},
		Enrollment: &machineEnrollment{
			CodeSHA256: "bb" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			ExpiresAt:  "2026-09-18T00:00:00Z",
		},
	}
	if err := (buildMachinesDoc{Machines: []buildMachine{signer}}).validate(); err == nil {
		t.Fatal("a signer carrying build platforms must be rejected")
	}
}
