package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Helix2010/RN-Server/internal/api"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// runBackupBucketTest 是 `rn-server backup-bucket-test`：在这台机器上分别测一次
// 备份桶的写对象、读对象、读版本控制状态三项权限。
//
// 和控制台上的「测试连接」是同一套检查（api.CheckBackupBucket）。单独做成命令，
// 是为了两件控制台做不到的事：
//
//   - 凭据不离开这台机器。桶凭据可能加密在库里、也可能在 env 里，这条命令在持有它们
//     的进程里解开、用掉，只打印每一项通没通过，不经过任何人的终端或对话记录
//   - 控制台没起来时也能用。恢复场景 B 里第一个要回答的问题就是「这台新机器连不连
//     得上备份桶」，而那时控制台多半还不在
//
// 在 amos 上以服务身份跑（env 文件对普通账号不可读）：
//
//	sudo systemd-run --pipe --wait --quiet -p User=rnfoundation \
//	  -p EnvironmentFile=/etc/rn-foundation.env /opt/rn-foundation/rn-server backup-bucket-test
//
// 全部通过退出码 0，否则 1。
func runBackupBucketTest(cfg config.Config, database *store.Store) int {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := api.CheckBackupBucket(ctx, cfg, database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "没法连到备份桶：", err)
		return 1
	}

	location := result.Provider
	if result.Prefix != "" {
		location += "，前缀 " + result.Prefix
	}
	fmt.Printf("备份桶 %s（%s）\n", result.Bucket, location)
	for _, check := range result.Checks {
		mark := "通过"
		if !check.OK {
			mark = "缺失"
		}
		fmt.Printf("  [%s] %s  %s\n", mark, check.Label, check.Permission)
		if !check.OK && check.Detail != "" {
			fmt.Printf("         %s\n", check.Detail)
		}
	}
	if result.VersioningDetail != "" {
		fmt.Println(result.VersioningDetail)
	}
	fmt.Println("探针对象：", result.ProbeKey)
	if !result.OK {
		return 1
	}
	fmt.Println("备份桶配对了。")
	return 0
}
