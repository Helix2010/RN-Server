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
		ok, reason := openable(item.SealedKeystore, cfg.KeystorePassphrase)
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
func openable(sealed json.RawMessage, passphrase string) (bool, string) {
	if len(sealed) == 0 {
		return false, "服务端没有下发盒子"
	}
	if passphrase == "" {
		return false, "这台打包机没有设 BUILD_KEYSTORE_PASSPHRASE"
	}
	var box buildkeystore.Sealed
	if err := json.Unmarshal(sealed, &box); err != nil {
		return false, "盒子不是合法的 JSON，多半是存的时候就坏了"
	}
	bundle, err := buildkeystore.Open(box, passphrase)
	if err != nil {
		return false, "打包机上的 BUILD_KEYSTORE_PASSPHRASE 打不开这个盒子：" +
			"密钥是用另一个封装口令封的。封装口令是整台打包机共用的一个，" +
			"新租户必须填已有的那一个，而不是另想一个。"
	}
	if bundle.KeystoreBase64 == "" {
		return false, "盒子能打开，但里面没有 keystore"
	}
	return true, ""
}
