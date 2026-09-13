package main

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

// 验一遍服务端存的盒子开不开得了。
//
// 封装口令只在这台机器上，所以这件事**只有代理能做**。服务端存盒子的时候没有任何
// 办法判断它是不是用对口令封的：存进去一切正常，指纹也登记了，控制台上看着是配好
// 的，要等到有人发起构建、占用了打包机之后才在解盒那一步失败。
//
// 2026-09-12 predict-kim 就是这样：23:15 在控制台生成密钥，23:44 发起构建才拿到
// "wrong passphrase"，中间隔了 29 分钟。
//
// 这里只读不写、不落盘：开出来的 bundle 立刻丢掉，只把"开得了/开不了"报回去。
func verifyPendingKeystores(ctx context.Context, cfg config, api *client) {
	pending, err := api.pendingKeystoreChecks(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("cannot ask which keystores need verifying", "error", err)
		}
		return
	}
	for _, item := range pending {
		ok, reason := openable(item.SealedKeystore, cfg)
		if err := api.reportKeystoreCheck(ctx, item.Tenant, item.Version, ok, reason, cfg.Name); err != nil {
			slog.Warn("cannot report a keystore verification", "tenant", item.Tenant, "error", err)
			continue
		}
		if ok {
			slog.Info("sealed keystore verified", "tenant", item.Tenant, "version", item.Version)
		} else {
			slog.Warn("sealed keystore cannot be opened on this machine",
				"tenant", item.Tenant, "version", item.Version, "reason", reason)
		}
	}
}

// openable 报告能不能打开，以及开不了时那句给人看的原因。
//
// 原因里绝不能出现口令本身。buildkeystore.Open 的错误文字是固定的几种，不含输入，
// 但这里仍然只挑我们自己写的那一句转出去——错误链上游将来加了什么，不会顺着这条
// 通道被送到控制台上显示。
func openable(sealed json.RawMessage, cfg config) (bool, string) {
	if len(sealed) == 0 {
		return false, "服务端没有下发盒子"
	}
	var box buildkeystore.Sealed
	if err := json.Unmarshal(sealed, &box); err != nil {
		return false, "盒子不是合法的 JSON，多半是存的时候就坏了"
	}
	switch {
	case box.Version == 2:
		if _, err := buildkeystore.OpenWith(box, cfg.AgentPrivateKey); err != nil {
			// 只有一种可能：它是加密给另一台打包机的公钥的
			return false, "这个盒子是加密给另一把打包机公钥的，本机私钥解不开。" +
				"多半是打包机换过机器或换过私钥——在平台维护里核对公钥指纹。"
		}
	case cfg.KeystorePassphrase == "":
		return false, "这是旧格式（口令封）的密钥，而本机没有设 BUILD_KEYSTORE_PASSPHRASE。" +
			"在控制台重新生成一次就会换成新格式，不再需要任何口令。"
	default:
		if _, err := buildkeystore.Open(box, cfg.KeystorePassphrase); err != nil {
			return false, "这是旧格式（口令封）的密钥，本机的 BUILD_KEYSTORE_PASSPHRASE 打不开它。" +
				"在控制台重新生成一次就会换成新格式，不再需要任何口令。"
		}
	}
	return true, ""
}
