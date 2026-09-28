package api

import "fmt"

// Role 是一个 rn-server 进程承担哪一部分接口（设计 service-and-console-split-2026-09-27 §3）。
// 同一个二进制按角色起三个进程，每个进程只注册自己的路由：App 服务里根本没有 /v1/admin，
// 从 api.* 碰不到管理接口。三个进程共用同一个库。
type Role string

const (
	// RoleAll 承担全部接口：不带子命令时的行为，只给过渡与本地开发用
	RoleAll Role = ""
	// RoleApp：App 用的公开接口（/v1/mobile、/v1/public、/v1/ota、/app、/.well-known）
	RoleApp Role = "app"
	// RoleTenant：租户控制台（/v1/admin，平台部分除外）
	RoleTenant Role = "tenant"
	// RolePlatform：平台控制台（/v1/admin/platform）与打包机、签名闸；打包回收、推送派发两个后台任务也在这里
	RolePlatform Role = "platform"
)

// ParseRole 认子命令里的角色名。
func ParseRole(name string) (Role, error) {
	switch role := Role(name); role {
	case RoleApp, RoleTenant, RolePlatform:
		return role, nil
	default:
		return RoleAll, fmt.Errorf("unknown role %q (want app, tenant or platform)", name)
	}
}

// Name 是日志里的角色名；RoleAll 记作 all。
func (r Role) Name() string {
	if r == RoleAll {
		return "all"
	}
	return string(r)
}

// serves：这个进程承担不承担 part 那部分接口。
func (r Role) serves(part Role) bool { return r == RoleAll || r == part }

// RunsWorkers：打包任务回收、推送派发各只能有一份，放在平台端（不带子命令时也跑）。
func (r Role) RunsWorkers() bool { return r.serves(RolePlatform) }
