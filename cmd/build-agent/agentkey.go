package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

// 这台打包机自己的那对密钥。
//
// 私钥永不离开这台机器，公钥登记到服务端，服务端从此把签名密钥加密给它。这替掉了
// 原来那个全机器共用、要人敲进控制台表单的 BUILD_KEYSTORE_PASSPHRASE——那个设计
// 要求把一个保护所有租户密钥的平台秘密交给操作者手抄，租户不可能知道它，而即使是
// 平台运维也连着抄错过三次。
//
// 文件权限 0600，和 keystore 解出来的临时文件同级。丢了它的后果和丢了封装口令一样：
// 已有的盒子再也打不开，每个租户都要重新上传或重新生成密钥——所以它进备份，而且
// 换机器时要一起搬过去。
const agentKeyFileName = "agent-key"

// loadOrCreateAgentKey 读本机私钥，没有就生成一把。返回私钥和对应的公钥。
func loadOrCreateAgentKey(stateDir string) ([]byte, buildkeystore.Recipient, error) {
	path := filepath.Join(stateDir, agentKeyFileName)
	raw, err := os.ReadFile(path)
	if err == nil {
		private, decodeErr := base64.StdEncoding.DecodeString(string(trimSpaceBytes(raw)))
		if decodeErr != nil {
			return nil, buildkeystore.Recipient{}, fmt.Errorf("%s 不是合法的私钥文件: %w", path, decodeErr)
		}
		recipient, err := buildkeystore.RecipientFor(private)
		if err != nil {
			return nil, buildkeystore.Recipient{}, fmt.Errorf("%s 里的私钥用不了: %w", path, err)
		}
		return private, recipient, nil
	}
	if !os.IsNotExist(err) {
		return nil, buildkeystore.Recipient{}, err
	}
	private, recipient, err := buildkeystore.NewAgentKey()
	if err != nil {
		return nil, buildkeystore.Recipient{}, err
	}
	// 先写再改权限会有一瞬间是 0644，所以用 OpenFile 一次定下来
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, buildkeystore.Recipient{}, fmt.Errorf("写不了 %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(private) + "\n"); err != nil {
		return nil, buildkeystore.Recipient{}, err
	}
	return private, recipient, nil
}

func trimSpaceBytes(raw []byte) []byte {
	start, end := 0, len(raw)
	for start < end && isSpaceByte(raw[start]) {
		start++
	}
	for end > start && isSpaceByte(raw[end-1]) {
		end--
	}
	return raw[start:end]
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
