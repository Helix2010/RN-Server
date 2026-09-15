package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 这台打包机的**备份签名私钥**。
//
// 它和 agent-key 是两把完全不同的钥匙：agent-key 是 X25519，用来开服务端封给
// 本机的签名密钥盒子；这一把是 Ed25519，用来给自己产出的备份内层密文签名。
//
// 为什么要签：备份容器只有保密性没有真实性——RSA-OAEP 用的是公钥，而公钥不是
// 秘密（指纹还印在控制台上）。任何拿到桶写权限的人都能从零封一个 MAC 通过、两层
// 都解得开的包，里面放他写的 recover.sh，而那个脚本恢复时以 root 跑。
//
// 必须**由打包机签**，不能由服务端签：服务端被攻破是本方案自己列出的威胁。
const backupSigningKeyFileName = "backup-signing.key"

// loadOrCreateBackupSigningKey 读备份签名私钥，没有就生成一把。
func loadOrCreateBackupSigningKey(stateDir string) (ed25519.PrivateKey, string, error) {
	path := filepath.Join(stateDir, backupSigningKeyFileName)
	raw, err := os.ReadFile(path)
	if err == nil {
		seed, decodeErr := base64.StdEncoding.DecodeString(string(trimSpaceBytes(raw)))
		if decodeErr != nil || len(seed) != backupcontainer.SigningKeySeedSize {
			return nil, "", fmt.Errorf("%s 不是合法的备份签名私钥文件", path)
		}
		private := ed25519.NewKeyFromSeed(seed)
		encoded, err := backupcontainer.EncodeSigningPublicKey(private.Public().(ed25519.PublicKey))
		return private, encoded, err
	}
	if !os.IsNotExist(err) {
		return nil, "", err
	}

	seed := make([]byte, backupcontainer.SigningKeySeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, "", err
	}
	// 先写再改权限会有一瞬间是 0644，所以用 OpenFile 一次定下来
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("写不了 %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n"); err != nil {
		return nil, "", err
	}
	private := ed25519.NewKeyFromSeed(seed)
	encoded, err := backupcontainer.EncodeSigningPublicKey(private.Public().(ed25519.PublicKey))
	return private, encoded, err
}
