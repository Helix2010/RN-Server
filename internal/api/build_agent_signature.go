package api

// 安装包清单的离线签名：平台管理员在离线机器上签完，用这两条接口交上来。
//
// 为什么要有接口，而不是继续 scp 一个 manifest.sig 进服务器目录：签名是在**离线机器**上
// 做的，而那台机器按设计不该有服务器的 shell。只认文件等于要求"持有发布私钥的人"同时握着
// 服务器 shell——而这两个角色正是整套设计要分开的。整个前提是"服务端被攻破也换不出能过验
// 的清单"，前提成立要求私钥既不在服务端、也不在能碰服务端的人手上。
//
// **这两条接口不是安全边界。** 签名的权威性来自离线私钥，不来自它怎么送达：服务端拿到一份
// 签名也伪造不出有效的，Mac 上按人给的指纹 pin 的那把公钥才是判据。服务端本来就能对这条
// 链路做拒绝服务（归档是它服务的），多一个写入点不增加任何伪造能力。
//
// 这里做的检查全部是**帮运维当场发现拿错了文件**，不是安全控制：清单摘要对不对得上、提交
// 是不是当前这一版、序号有没有往回退。传错了当场报错，好过等一台 Mac 下完几十 MB 才失败。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
	"github.com/gin-gonic/gin"
)

// bundleSignatureMaxBody 是 manifest.sig 的大小上限。它是一份几百字节的 JSON。
const bundleSignatureMaxBody = int64(bundlesig.MaxSize)

// storedBundleSignature 读库里这个提交的签名。没有就返回 sql.ErrNoRows。
func storedBundleSignature(ctx context.Context, db *sql.DB, commit string) (bundlesig.Signature, error) {
	var raw []byte
	err := db.QueryRowContext(ctx,
		`SELECT signature FROM machine_bundle_signatures WHERE commit_sha = ?`, commit).Scan(&raw)
	if err != nil {
		return bundlesig.Signature{}, err
	}
	return bundlesig.Parse(raw)
}

// bundleSignatureFor 取覆盖**这一份清单**的签名：库里那份优先，不匹配就回退看安装包目录里
// 的 manifest.sig。
//
// 两条路都留着是有意的。库里那条是常规路径（控制台交上来，有审计）；文件那条是
// SIGNING_MATERIAL.md 一直写着的老办法，在能碰服务器文件系统的场景下仍然管用，也是从旧
// 部署升上来时的兜底。
//
// 选的依据是**清单摘要**而不是"库里有没有"。库里是按提交存的，而同一个提交理论上总该构建出
// 同一份清单（build-bundles.sh 可复现）——但那是个前提，不是保证。前提不成立时（非可复现地
// 重建过一次），按"库里有就用库里的"会拿一份覆盖着旧清单的签名去回答，然后在下一步以"签名
// 与清单不符"失败，而那条报错指向的是签名，不是真正的原因。按摘要选就不会。
func (s *server) bundleSignatureFor(ctx context.Context, dir string, manifest []byte, commit string) (bundlesig.Signature, error) {
	digest := bundlesig.ManifestSHA256(manifest)
	stored, err := storedBundleSignature(ctx, s.db, commit)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return bundlesig.Signature{}, err
	}
	haveStored := err == nil
	if haveStored && stored.ManifestSHA256 == digest {
		return stored, nil
	}
	if raw, ferr := os.ReadFile(filepath.Join(dir, bundlesig.FileName)); ferr == nil {
		if fromDisk, perr := bundlesig.Parse(raw); perr == nil && fromDisk.ManifestSHA256 == digest {
			return fromDisk, nil
		}
	}
	if haveStored {
		return bundlesig.Signature{}, errors.New("the stored signature covers another " + machineBundleManifest +
			" (" + stored.ManifestSHA256 + ", deployed is " + digest + "): re-sign the manifest that is deployed now")
	}
	return bundlesig.Signature{}, errors.New("the deployed bundles have no signature yet: a platform admin signs " +
		machineBundleManifest + " offline and uploads it in the console (平台维护 → 打包机与签名闸 → 构建机 → 打包机程序版本)")
}

// deployedManifest GET /v1/admin/platform/build-agent-version/manifest：
// 下发当前部署的 manifest.json **原始字节**，未签名时也给。
//
// 原始字节而不是重新编码的 JSON：签名签的是这些字节的摘要，重新编码一遍（字段顺序、空白、
// 转义有多种写法）就对不上了。所以这里直接把文件递出去，运维存盘之后 bundle-sign 读到的
// 与服务端手里的逐字节相同。
func (s *server) deployedManifest(c *gin.Context) {
	dir, doc, err := s.machineBundles()
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_BUNDLE_UNAVAILABLE", err.Error())
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, machineBundleManifest))
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_BUNDLE_UNAVAILABLE", "cannot read "+machineBundleManifest)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Bundle-Commit", doc.Commit)
	c.Header("Content-Disposition", `attachment; filename="`+machineBundleManifest+`"`)
	c.Data(http.StatusOK, "application/json", raw)
}

// uploadBundleSignature POST /v1/admin/platform/build-agent-version/signature：
// 收下 manifest.sig。请求体就是那个文件的内容。
func (s *server) uploadBundleSignature(c *gin.Context) {
	dir, doc, err := s.machineBundles()
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_BUNDLE_UNAVAILABLE", err.Error())
		return
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, machineBundleManifest))
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_BUNDLE_UNAVAILABLE", "cannot read "+machineBundleManifest)
		return
	}
	body, err := readLimitedBody(c, bundleSignatureMaxBody)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUNDLE_SIGNATURE", "the request body must be the contents of "+bundlesig.FileName)
		return
	}
	signature, err := bundlesig.Parse(body)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUNDLE_SIGNATURE", err.Error())
		return
	}

	// 下面三条都是"拿错文件"的当场反馈，不是安全检查。真正的判据在每台 Mac 上。
	if signature.Commit != doc.Commit {
		problem(c, http.StatusConflict, "BUNDLE_SIGNATURE_COMMIT_MISMATCH",
			"this signature is for commit "+signature.Commit+", but the deployed bundles are "+doc.Commit+
				"; sign the manifest that is deployed now (download it from this console)")
		return
	}
	if got := bundlesig.ManifestSHA256(manifestRaw); signature.ManifestSHA256 != got {
		problem(c, http.StatusConflict, "BUNDLE_SIGNATURE_MANIFEST_MISMATCH",
			"this signature covers manifest sha256 "+signature.ManifestSHA256+", but the deployed "+
				machineBundleManifest+" is "+got+"; download the manifest again and re-sign it")
		return
	}
	if err := verifyAgainstDeployedReleaseKey(dir, manifestRaw, signature); err != nil {
		problem(c, http.StatusConflict, "BUNDLE_SIGNATURE_KEY_MISMATCH", err.Error())
		return
	}
	previous, err := storedBundleSignature(c.Request.Context(), s.db, signature.Commit)
	switch {
	case err == nil && previous.Sequence >= signature.Sequence:
		problem(c, http.StatusConflict, "BUNDLE_SIGNATURE_SEQUENCE_NOT_HIGHER",
			"a signature with sequence "+itoa64(previous.Sequence)+" is already stored for this commit; "+
				"re-signing it needs a higher sequence (machines refuse anything below the highest they have seen)")
		return
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		problem(c, http.StatusInternalServerError, "BUNDLE_SIGNATURE_UNREADABLE", "cannot read the stored signature")
		return
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUNDLE_SIGNATURE_NOT_STORED", "cannot store the signature")
		return
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后回滚是空操作
	encoded, err := json.Marshal(signature)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUNDLE_SIGNATURE_NOT_STORED", "cannot store the signature")
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(),
		`INSERT INTO machine_bundle_signatures
		   (commit_sha, sequence_no, manifest_sha256, public_key_sha256, signature, uploaded_by, uploaded_at)
		 VALUES (?,?,?,?,?,?,UTC_TIMESTAMP(3))
		 ON DUPLICATE KEY UPDATE sequence_no=VALUES(sequence_no), manifest_sha256=VALUES(manifest_sha256),
		   public_key_sha256=VALUES(public_key_sha256), signature=VALUES(signature),
		   uploaded_by=VALUES(uploaded_by), uploaded_at=VALUES(uploaded_at)`,
		signature.Commit, signature.Sequence, signature.ManifestSHA256, signature.PublicKeySHA256,
		encoded, actor(c)); err != nil {
		problem(c, http.StatusInternalServerError, "BUNDLE_SIGNATURE_NOT_STORED", "cannot store the signature")
		return
	}
	event := newAudit(platformTenantID, actor(c), "build_agent_signature_upload", machineAuditTargetType,
		"build-agent", "upload manifest signature", requestID(c),
		map[string]any{"commit": signature.Commit, "sequence": signature.Sequence,
			"publicKeySha256": signature.PublicKeySHA256, "replacedSequence": replacedSequence(previous)})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUNDLE_SIGNATURE_NOT_STORED", "cannot store the signature")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"commit": signature.Commit, "sequence": signature.Sequence,
		"signedAt": signature.SignedAt, "publicKeySha256": signature.PublicKeySHA256,
		"storedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

// verifyAgainstDeployedReleaseKey 拿安装包里那份 release-key.pub 验一遍签名。
//
// **这不是安全检查，是帮运维查错。** 那把公钥和服务端同源（同一个 CI 推上来的），攻破服务端
// 的人两样都能换，所以它证明不了任何事。它能做的是：运维用错了密钥、签了别的清单、或者上传
// 了一个损坏的文件时，当场说清楚，而不是等某台 Mac 装机时报"签名验不过"——那时候人会以为
// 遭到了攻击。
//
// 安装包里没有 release-key.pub 时跳过：那种部署本来就装不了 Mac，errors 由别处报。
func verifyAgainstDeployedReleaseKey(dir string, manifest []byte, signature bundlesig.Signature) error {
	raw, err := os.ReadFile(filepath.Join(dir, machineReleaseKeyFile))
	if err != nil {
		return nil
	}
	public, err := bundlesig.ParsePublicKey(raw)
	if err != nil {
		return nil
	}
	if err := bundlesig.Verify(public, manifest, signature); err != nil {
		return errors.New("this signature does not verify against the " + machineReleaseKeyFile +
			" in the deployed bundles (" + err.Error() + "). " +
			"Check that you signed with the current release key. " +
			"Note this check only catches mistakes: machines verify against the fingerprint the operator pins by hand, not against this file")
	}
	return nil
}

// itoa64 只为拼错误信息。
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

// replacedSequence 进审计：这次上传顶掉的是哪一个序号，没有就是 null。
func replacedSequence(previous bundlesig.Signature) any {
	if previous.Sequence < 1 {
		return nil
	}
	return previous.Sequence
}
