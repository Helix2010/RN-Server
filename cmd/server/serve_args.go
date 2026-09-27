package main

import (
	"fmt"
	"strconv"

	"github.com/Helix2010/RN-Server/internal/api"
)

// parseServeArgs 认服务进程的参数（设计 service-and-console-split-2026-09-27 §3.1）：
//
//	rn-server                               承担全部接口（过渡与本地开发）
//	rn-server app|tenant|platform [--port N]  只承担这一个角色
//
// 端口用参数给而不用 unit 里的 Environment=PORT=：EnvironmentFile 里的 PORT 会覆盖它，
// 三个进程就会抢同一个端口。不认识的参数直接报错，不悄悄起一个承担全部接口的进程。
func parseServeArgs(args []string, defaultPort string) (api.Role, string, error) {
	if len(args) == 0 {
		return api.RoleAll, defaultPort, nil
	}
	role, err := api.ParseRole(args[0])
	if err != nil {
		return api.RoleAll, "", err
	}
	switch {
	case len(args) == 1:
		return role, defaultPort, nil
	case len(args) == 3 && args[1] == "--port":
		port, err := strconv.Atoi(args[2])
		if err != nil || port < 1 || port > 65535 {
			return api.RoleAll, "", fmt.Errorf("invalid --port %q", args[2])
		}
		return role, strconv.Itoa(port), nil
	default:
		return api.RoleAll, "", fmt.Errorf("usage: rn-server %s [--port N]", role)
	}
}
