package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
	"github.com/gin-gonic/gin"
)

// 已登记机器的自升级下载口（设计 ios-mac-builders-home-network-2026-09-18 §5.6）。
//
// 拉模型意味着服务端推不了升级，而每台 Mac 手工 scp 两个二进制在几台以后一定有人忘。
// 但**这是整个方案里唯一一条"服务端能往 Mac 上放可执行代码"的路**，而 Mac 上放着全部租户
// 的签名材料——服务端被攻破时，这条路能把每台 Mac 的钥匙串都掏空。
//
// 所以这两条接口本身**不是**安全边界，它们只是"把文件递过去"：真正的把关在 Mac 那一侧，
// 用离线发布密钥验清单签名、核单调序号、核提交等于平台批准的那一个。服务端手里没有那把
// 私钥，攻破它换不出一个能过验的清单。这里能做的只有一件事：**没有签名就什么都不给**，
// 免得一台机器在"清单还没签"的窗口里下到一份没人背书的程序。

// machineBundleOSArch 把 os/arch 映射到安装包名字。
//
// 只认这两组：linux/amd64（机房构建机）与 darwin/arm64（Mac 打包机）。Intel Mac 跑不了
// 当前的 Xcode，而这条链路的前提就是一台能装当前 Xcode 的机器。
func machineBundleOSArch(os, arch string) (string, bool) {
	switch os + "/" + arch {
	case "linux/amd64":
		return machineRoleBuilder, true
	case "darwin/arm64":
		return machineBundleBuilderDarwin, true
	}
	return "", false
}

// signedBundle 是一组安装包连同它的离线签名。
type signedBundle struct {
	Name      string
	Dir       string
	Manifest  []byte
	Signature bundlesig.Signature
	Bundle    machineBundle
	Commit    string
}

// signedBundleFor 取一组安装包连同它的离线签名，要求清单、签名与归档三者齐备且互相对得上。
//
// 签名来自库（控制台交上来的）或安装包目录里的 manifest.sig，见 bundleSignatureFor。
func (s *server) signedBundleFor(ctx context.Context, name string) (signedBundle, error) {
	dir, manifest, err := s.machineBundles()
	if err != nil {
		return signedBundle{}, err
	}
	// -dirty 的构建不下发：它是某台机器上一个没提交的工作区，签也签不了（bundlesig.Sign
	// 拒绝它），而没有签名的东西不该出现在任何一台 Mac 上
	if strings.Contains(manifest.Commit, "-dirty") {
		return signedBundle{}, errors.New("the deployed bundles were built from a dirty working tree; they are not signed and will not be handed out")
	}
	bundle, err := manifest.bundleFor(name)
	if err != nil {
		return signedBundle{}, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, machineBundleManifest))
	if err != nil {
		return signedBundle{}, err
	}
	signature, err := s.bundleSignatureFor(ctx, dir, raw, manifest.Commit)
	if err != nil {
		return signedBundle{}, err
	}
	// 服务端自己不验签（它没有那把公钥，也不该有），但清单与签名对不上是这台服务器上的
	// 事故，不该让每台 Mac 各下一遍几十 MB 才发现
	if signature.ManifestSHA256 != bundlesig.ManifestSHA256(raw) {
		return signedBundle{}, errors.New("the stored signature does not match " + machineBundleManifest)
	}
	if signature.Commit != manifest.Commit {
		return signedBundle{}, errors.New("the stored signature was made for another commit")
	}
	// 清单里有这一条，不等于归档真的在服务器上。部署那一段是**按文件名逐个拷**的
	// （rn-foundation-apply），漏掉一个不会有任何地方报错——而清单是一次性生成的，它照样
	// 列着那一组。2026-09-19 装第一台 Mac 时就是这样：控制台说 darwin 那组"没问题"，
	// describe 却一直 503，人只能去猜。
	archive := filepath.Join(dir, bundle.Archive)
	info, err := os.Stat(archive)
	switch {
	case err != nil:
		return signedBundle{}, errors.New(bundle.Archive + " is listed in " + machineBundleManifest +
			" but is not on the server: the deploy step ships the bundle files one by one and this one did not make it")
	case !info.Mode().IsRegular() || info.Size() != bundle.ArchiveSize:
		return signedBundle{}, errors.New(bundle.Archive + " on the server does not match the size in " +
			machineBundleManifest + "; the upload was incomplete")
	}
	return signedBundle{Name: name, Dir: dir, Manifest: raw, Signature: signature, Bundle: bundle, Commit: manifest.Commit}, nil
}

// describeAgentBundle GET /v1/build-agent/bundle?os=&arch=：回清单、清单签名与归档地址。
//
// 清单是 base64 的**原始字节**，不是内嵌的 JSON 对象：签名签的是那些字节，重新编码一遍
// 就对不上了。
func (s *server) describeAgentBundle(c *gin.Context) {
	name, ok := machineBundleOSArch(strings.TrimSpace(c.Query("os")), strings.TrimSpace(c.Query("arch")))
	if !ok {
		problem(c, http.StatusNotFound, "MACHINE_BUNDLE_NOT_FOUND", "Bundles exist for linux/amd64 and darwin/arm64")
		return
	}
	signed, err := s.signedBundleFor(c.Request.Context(), name)
	if err != nil {
		bundleUnavailable(c, name, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"bundle":         name,
		"commit":         signed.Commit,
		"manifestBase64": base64.StdEncoding.EncodeToString(signed.Manifest),
		"signature":      json.RawMessage(mustJSON(signed.Signature)),
		"archive": gin.H{
			"name":   signed.Bundle.Archive,
			"sha256": signed.Bundle.ArchiveSHA256,
			"size":   signed.Bundle.ArchiveSize,
			"url":    "/v1/build-agent/bundle/archive?os=" + c.Query("os") + "&arch=" + c.Query("arch"),
		},
	})
}

// downloadAgentBundle GET /v1/build-agent/bundle/archive?os=&arch=：流式给归档本身。
//
// 摘要在清单里，而清单是签过的——下载方自己算一遍对不上就不装。这条路由按路由模板豁免
// 数据库超时（几十 MB 走家用下行，10 秒写不完）。
func (s *server) downloadAgentBundle(c *gin.Context) {
	name, ok := machineBundleOSArch(strings.TrimSpace(c.Query("os")), strings.TrimSpace(c.Query("arch")))
	if !ok {
		problem(c, http.StatusNotFound, "MACHINE_BUNDLE_NOT_FOUND", "Bundles exist for linux/amd64 and darwin/arm64")
		return
	}
	signed, err := s.signedBundleFor(c.Request.Context(), name)
	if err != nil {
		bundleUnavailable(c, name, err)
		return
	}
	file, err := os.Open(filepath.Join(signed.Dir, signed.Bundle.Archive))
	if err != nil {
		bundleUnavailable(c, name, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != signed.Bundle.ArchiveSize {
		bundleUnavailable(c, name, errors.New("the archive is missing, not a regular file, or its size differs from the manifest"))
		return
	}
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
	c.Header("Content-Disposition", `attachment; filename="`+signed.Bundle.Archive+`"`)
	c.Header("x-content-sha256", signed.Bundle.ArchiveSHA256)
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, file); err != nil {
		slog.Error("agent bundle download stream failed", "bundle", name, "error", err)
	}
}

// mustJSON 把签名结构体原样编码进响应。它只有固定字段，编不出错。
func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return []byte("null")
	}
	return raw
}

// deployedBundleView 是控制台「批准打包机程序版本」要看的一组安装包：它现在是哪一版、
// 清单被谁签的、序号多少。
//
// 每组各自带 error 而不是整条请求 503：两组安装包的状态是独立的（darwin 那组可能还没
// 编出来），而这一页存在的理由正是"让人看见现在部署的是什么"——一组坏了就整页看不见，
// 等于把要看的东西藏起来。
func (s *server) deployedBundleView(ctx context.Context, query, name string) gin.H {
	// commit 与 deployedCommit 是两件事，分开是有意的：
	//
	//   - deployedCommit：服务器上现在摆着哪一版。**没签也有值**——那正是要拿去签的那一版。
	//     不答的话运维只能去服务器上 readlink current，而交签名那条路本来就是为了不必登
	//     服务器才开的。
	//   - commit：**可以批准的那一版**，也就是批准按钮的输入。没签就是 null。
	//
	// 合成一个字段会让控制台把"批准"按在一个下载不到的版本上：机器一旦因为版本不符停止
	// 认领，又拿不到那一版的安装包（没签一律 503），队列就安静地死在那里。
	view := gin.H{"bundle": name, "query": query, "commit": nil, "deployedCommit": nil,
		"sequence": nil, "signedAt": nil, "publicKeySha256": nil, "archive": nil, "error": nil}
	if _, doc, deployedErr := s.machineBundles(); deployedErr == nil {
		view["deployedCommit"] = doc.Commit
	}
	signed, err := s.signedBundleFor(ctx, name)
	if err != nil {
		view["error"] = err.Error()
		return view
	}
	view["commit"] = signed.Commit
	view["sequence"] = signed.Signature.Sequence
	view["signedAt"] = signed.Signature.SignedAt
	view["publicKeySha256"] = signed.Signature.PublicKeySHA256
	view["archive"] = gin.H{"name": signed.Bundle.Archive, "sha256": signed.Bundle.ArchiveSHA256, "size": signed.Bundle.ArchiveSize}
	return view
}

// buildAgentVersion GET /v1/admin/platform/build-agent-version：现在部署着哪一版构建机
// 程序、平台批准的是哪一版。
//
// 批准一个提交之前要能看见这个提交是什么、清单签名的序号是多少——否则「批准」就是往
// 输入框里粘一个 40 位十六进制，粘错一位的后果是**所有**机器停止领任务（自报版本与批准
// 的不一致就领不到），而症状是队列安静地不动。
func (s *server) buildAgentVersion(c *gin.Context) {
	snapshot, err := readMachineRegistry(c.Request.Context(), s.db, false)
	if err != nil {
		slog.Error("cannot read the machine registry", "error", err)
		problem(c, http.StatusInternalServerError, "MACHINE_REGISTRY_INVALID", "Stored build.machines configuration cannot be read")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"version":             snapshot.Version,
		"approvedAgentCommit": nullableString(string(snapshot.Doc.ApprovedAgentCommit)),
		"bundles": []gin.H{
			s.deployedBundleView(c.Request.Context(), "linux/amd64", machineRoleBuilder),
			s.deployedBundleView(c.Request.Context(), "darwin/arm64", machineBundleBuilderDarwin),
		},
	})
}
