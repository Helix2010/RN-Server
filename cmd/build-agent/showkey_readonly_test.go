package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// show-key 绝不能创建密钥。
//
// 它是「身份文件放没放对」唯一的检查（设计 §2.2、§7.2 第 4 步）。之前它走的是
// loadOrCreateAgentKey，于是恢复时有这么一条路：
//
//	装完环境 → 跑一次 show-key 确认工具能用（很自然的顺序）
//	  → <StateDir>/agent-key 凭空被创建
//	  → 跑 recover.sh，place() 看到目标已存在、问「覆盖它？(yes/NO)」、默认 NO
//	  → 真正那把 agent-key 被「跳过」
//	  → 机器带着新密钥起来，库里每个租户的密封盒子永久打不开
//
// 灾难由恢复流程自己制造出来，而 show-key 打印的指纹只会告诉你「对不上」，
// 不会告诉你原因是文件被跳过了。
func TestShowKeyNeverCreatesAKey(t *testing.T) {
	dir := t.TempDir()

	_, err := loadAgentKeyForDisplay(dir)
	if err == nil {
		t.Fatal("空目录下居然读出了 agent-key —— 说明它自己造了一把")
	}
	if !strings.Contains(err.Error(), "先别起服务") {
		t.Errorf("错误信息没有警告「现在起服务会生成新密钥」，恢复的人不会知道厉害: %v", err)
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		t.Errorf("show-key 在 state dir 里留下了 %s；它必须只读", filepath.Join(dir, e.Name()))
	}

	// 备份签名私钥同理
	if _, err := loadBackupSigningKeyForDisplay(dir); err == nil {
		t.Error("空目录下居然读出了备份签名私钥 —— 说明它自己造了一把")
	}
	entries, readErr = os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		t.Errorf("读备份签名公钥时留下了 %s；它必须只读", filepath.Join(dir, e.Name()))
	}
}
