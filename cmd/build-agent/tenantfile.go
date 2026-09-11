package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

// applyBuildVersion 把任务里的 version / buildNumber 写进 worktree 里的租户文件，
// 并且**只允许这两个字段发生变化**。
//
// 这是"数据库能提供构建参数，不能提供构建身份"那条规则的执行点：服务端下发的
// 请求里只要多影响到第三个字段——applicationId、包名、API 域名——就是在试图改产物
// 身份，必须当场失败，而不是产出一个身份不同却用我们的密钥签名的 APK。
func applyBuildVersion(path, version string, buildNumber int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read tenant file: %w", err)
	}
	var before map[string]any
	if err := json.Unmarshal(raw, &before); err != nil {
		return fmt.Errorf("tenant file is not JSON: %w", err)
	}
	after := map[string]any{}
	if err := json.Unmarshal(raw, &after); err != nil {
		return err
	}
	after["version"] = version
	after["androidVersionCode"] = buildNumber

	if err := assertOnlyVersionChanged(before, after); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(after, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

var versionFields = map[string]bool{"version": true, "androidVersionCode": true}

func assertOnlyVersionChanged(before, after map[string]any) error {
	for key, value := range after {
		if versionFields[key] {
			continue
		}
		if !reflect.DeepEqual(before[key], value) {
			return fmt.Errorf("the build would change %q, which defines what the artifact is", key)
		}
	}
	for key := range before {
		if _, present := after[key]; !present {
			return fmt.Errorf("the build would drop %q from the tenant file", key)
		}
	}
	return nil
}
