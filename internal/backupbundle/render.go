package backupbundle

import (
	"fmt"
	"strings"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 三份说明都是**产出时生成**的，不是写死的模板。
//
// 模板会过期，生成的不会：里面的租户清单、版本号、指纹、每个文件放到哪，都是产出
// 那一刻的真实值。「拿到东西却不知道怎么用」是这类备份最常见的失败方式，而一份
// 半年前写的、路径早就变了的手册，和没有手册差别不大。

// shellQuote 把一个值安全地放进单引号。
//
// 进来的值在 API 层已经校验过（backup_meta.go 直接拒收带 shell 元字符的路径），
// 这里是第二道：渲染代码离那道校验很远，将来有人加一个新字段忘了校验时，
// 这一层仍然成立。
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func holderOf(byslot map[string]Recipient, slot string) string {
	r, ok := byslot[slot]
	if !ok || strings.TrimSpace(r.Holder) == "" {
		return "（未登记保管人——请在控制台「平台维护 → 备份与恢复」补上）"
	}
	return r.Holder
}

func fingerprintOf(byslot map[string]Recipient, slot string) string {
	if r, ok := byslot[slot]; ok {
		return r.Fingerprint
	}
	return "（缺失）"
}

// renderReadmeFirst 是并排放在桶里、**不加密**的那一页纸（§5.1）。
//
// 它要解开「要先知道怎么解密，才能读到怎么解密」这个死循环，所以里面不能有任何
// 机密，也不能假设读它的人手上有我们的任何工具。
func renderReadmeFirst(in Input, pair backupcontainer.Pair, byslot map[string]Recipient, sha string) string {
	var b strings.Builder
	name := fmt.Sprintf("backup-%08d-%s.rnbk", in.Seq, pair.Name)

	fmt.Fprintf(&b, `打包服务故障恢复备份 —— 先读这一页
=====================================

这个包  : %s
编号    : %d
产出时间: %s
来自    : %s（服务端 %s / 打包机 %s）

第一步：核对 sha256
-------------------
    sha256sum %s

期望值:
    %s

对不上就停下来，不要解包，也不要跑里面的任何脚本。控制台「平台维护 → 备份与
恢复」上有同一个值。两边一致才说明桶里这个对象没有被人换过。

（控制台也没了的时候，跳到「第三步：验签」——那一步不依赖服务端。）

第二步：这个包要谁的钥匙
------------------------
本包需要 **%s 和 %s 两把钥匙**，两个人都要在场。

    先用 %s 的私钥剥外层，再用 %s 的私钥解内层。

    槽位 %s  指纹 %s
              保管人：%s
    槽位 %s  指纹 %s
              保管人：%s

这两个人凑不齐的话，桶里还有另外两个包，换一组开：

`, name, in.Seq, in.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		in.InstanceID, in.ServerVersion, in.AgentVersion,
		name, sha,
		pair.Outer, pair.Inner, pair.Outer, pair.Inner,
		pair.Outer, fingerprintOf(byslot, pair.Outer), holderOf(byslot, pair.Outer),
		pair.Inner, fingerprintOf(byslot, pair.Inner), holderOf(byslot, pair.Inner))

	for _, other := range backupcontainer.Pairs() {
		if other.Name == pair.Name {
			continue
		}
		fmt.Fprintf(&b, "    backup-%08d-%s.rnbk   要 %s 和 %s\n",
			in.Seq, other.Name, other.Outer, other.Inner)
	}

	fmt.Fprintf(&b, `
三个包里装的是同一份内容，只是锁的组合不同。

第三步：开包
------------
把下面这段存成 open-layer.sh，然后跑三次。**每一层解到不同的目录**——三层用的
是同样的四个文件名，不分目录的话第二层会把第一层的中间文件悄悄盖掉。

%s

依次跑（会提示输入各自私钥的密码）：

    bash open-layer.sh %s  ~/%s.key  ./L1
    bash open-layer.sh ./L1/inner.rnbk   ~/%s.key  ./L2-agent
    bash open-layer.sh ./L1/server.rnbk  ~/%s.key  ./L2-server

没有 xxd 的机器上，把 `+"`xxd -p -cN`"+` 换成 `+"`od -An -tx1 | tr -d ' \\n'`"+`，输出逐字节相同。

第四步：验签
------------
    # 把登记在案的备份签名公钥转成 PEM（指纹见下，也在控制台上）
    openssl pkey -pubin -inform DER -in signing.der -out signing.pem
    openssl pkeyutl -verify -pubin -inkey signing.pem \
      -rawin -in L1/inner.rnbk -sigfile L1/inner.rnbk.sig

备份签名公钥指纹: %s

这个指纹应当和三位持有人当初各自抄在纸上的那一行一致。**验签通过之前不要跑
recover.sh** ——那个脚本恢复时以 root 执行。

第五步
------
读 L1/RECOVERY.md。它带的是产出这一刻的真实路径和真实值，不是模板。

`, openLayerScript, name, pair.Outer, pair.Inner, pair.Inner, in.BackupSigningFingerprint)
	return b.String()
}

// openLayerScript 是解开一层的完整脚本。
//
// 它是**脚本而不是给人粘的裸命令**：粘裸命令时，`|| { …; exit 1; }` 里的 exit
// 会直接关掉操作者的终端会话，而他多半会以为是网络断了、重连之后跳过这一步。
const openLayerScript = `    #!/bin/bash
    # 用法: bash open-layer.sh <包文件> <私钥> <解到哪个目录>
    set -euo pipefail
    umask 077

    PKG="$1"; KEY="$2"; OUT="$3"
    work=$(mktemp -d /dev/shm/rnbk.XXXXXX)   # 机密只落在 tmpfs 上
    trap 'rm -rf "$work"' EXIT                # 退出即清

    tar xf "$PKG" -C "$work"
    cd "$work"
    cat meta.json; echo                       # 核对 recipient / seq / layer

    openssl pkeyutl -decrypt -inkey "$KEY" \
      -pkeyopt rsa_padding_mode:oaep \
      -pkeyopt rsa_oaep_md:sha256 \
      -pkeyopt rsa_mgf1_md:sha256 \
      -in key.bin -out k.bin
    [ "$(stat -c%s k.bin)" = 80 ] || { echo "密钥材料长度不是 80，格式不对"; exit 1; }

    ENC=$(dd if=k.bin bs=1 count=32         2>/dev/null | xxd -p -c64)
    MAC=$(dd if=k.bin bs=1 skip=32 count=32 2>/dev/null | xxd -p -c64)
    IV=$( dd if=k.bin bs=1 skip=64 count=16 2>/dev/null | xxd -p -c32)

    # 先验 MAC 再解密。覆盖范围是 meta.json ‖ key.bin ‖ payload.enc，顺序即规范
    cat meta.json key.bin payload.enc \
      | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$MAC" -binary > payload.mac.calc
    cmp payload.mac.calc payload.mac

    openssl enc -d -aes-256-cbc -K "$ENC" -iv "$IV" -in payload.enc -out plain.tar
    mkdir -p "$OUT"
    tar xf plain.tar -C "$OUT"
    echo "OK -> $OUT"`

// renderRecoveryMarkdown 是密文里面那份手册（§5.2）。
func renderRecoveryMarkdown(in Input, pair backupcontainer.Pair) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# 恢复手册（备份 #%d，%s 组）

产出于 %s，来自 %s。
服务端 %s / 打包机 %s / 数据库 schema %d。

这份手册是**产出时生成**的，里面的路径和值就是产出那一刻的真实值。

## 0. 先判断是哪个场景

| 场景 | 情况 | 做什么 |
|---|---|---|
| A | 打包机没了，服务端和数据库还在 | 只做第 2 节。**不要碰 db/**，库里的东西是好的 |
| B | 服务端也没了 | 先做第 1 节，再做第 2 节 |

数据库本身不在这份备份的范围内。`+"`server/db/*.json`"+` 只够把打包相关的那部分
配置补回去，它不是数据库备份。

## 0.1 开包之前

`+"```bash"+`
sha256sum backup-%08d-%s.rnbk    # 和控制台上那一行比对
openssl pkeyutl -verify -pubin -inkey signing.pem \
  -rawin -in inner.rnbk -sigfile inner.rnbk.sig
`+"```"+`

还要核对 manifest.json 里 `+"`inner.rnbk`"+` 和 `+"`server.rnbk`"+` 的 sha256。
这一步防的是拼接：把一个**旧**备份的内层塞进新包，两层 MAC 都会通过，而恢复出来
的是轮换前的旧密钥。

**验签和 sha256 都通过之后，才可以跑 recover.sh。**

`, in.Seq, pair.Name, in.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		in.InstanceID, in.ServerVersion, in.AgentVersion, in.SchemaVersion,
		in.Seq, pair.Name)

	b.WriteString("## 1. 场景 B：先把服务端立起来\n\n")
	b.WriteString("解开 `server.rnbk` 之后，把这些文件放回去：\n\n")
	writeFileTable(&b, in.ServerManifest)
	b.WriteString(`
然后：

` + "```bash" + `
systemctl daemon-reload
systemctl start rn-foundation-server
nginx -t && systemctl reload nginx
` + "```" + `

验证主密钥对不对（这个接口会**真的解密一次**凭据）：

` + "```bash" + `
export ADMIN_API_KEY=<从恢复出来的 rn-foundation.env 里取 ADMIN_API_KEY>
curl -sS -X POST \
  -H "x-admin-key: $ADMIN_API_KEY" \
  -H "Host: <租户域名>" \
  http://127.0.0.1:13080/v1/admin/release-storage/test
` + "```" + `

期望 ` + "`{\"ok\":true,...}`" + `。三件必须填对的事：**端口是 13080**（应用只听
127.0.0.1，443 在 nginx 上）、**鉴权走 x-admin-key**、**Host 头决定解析到哪个租户**。

拿到 403 先查 ` + "`ADMIN_API_ALLOWED_IPS`" + `：它限制这条自动化通道的来源，
127.0.0.1 不在名单里就会被挡。

不要指望用管理员口令登录控制台来做这一步：包里有 ` + "`ADMIN_PASSWORD_HASH`" + `，
**没有明文口令**，那是有意的。

也不要用 ` + "`GET /ota/signing-key`" + ` 代替：它只读明文证书字段、从不解密，
钥匙错了照样返回 200。

再验租户解析：

` + "```bash" + `
curl -sS -H "Host: <租户域名>" http://127.0.0.1:13080/v1/mobile/bootstrap
` + "```" + `

租户必须域名 active、未软删、当前日期在有效期内——演练时特别容易撞有效期。

## 2. 把打包机立起来

新机器先装好：Android SDK / JDK17 / node + pnpm / git。

解开 ` + "`inner.rnbk`" + ` 之后，把这些文件放回去：

`)
	writeFileTable(&b, in.AgentManifest)
	fmt.Fprintf(&b, `
**`+"`BUILD_AGENT_STATE_DIR`"+` 必须在 env 里显式写死。** 它默认从 workspace 推导，
路径差一点就找不到恢复回去的私钥，而打包机会**静默生成一把新的**——日志里区分不出来，
等你发现时全部租户的签名密钥已经打不开了。

起服务之前先核对身份：

`+"```bash"+`
build-agent show-key
`+"```"+`

输出的指纹必须等于 `+"`%s`"+`。不等就是文件放错了位置。

让下一轮校验重新跑一次（不做这步，看到的是灾难前那台机器写下的旧记录）：

`+"```sql"+`
DELETE FROM app_configs WHERE config_key='build.keystore.check';
`+"```"+`

然后 `+"`systemctl start rn-build-agent`"+`，等每个租户出现 checkedAt 晚于此刻的 ok。

**跑通一条真实的 APK 构建并入库，才算恢复完成。** 不能用 OTA 构建当判据——
OTA 根本不碰签名密钥，拿它验等于什么都没验。

## 3. 这份备份里有哪些租户

| slug | 域名 | 有签名密钥 | 证书 SHA-256 |
|---|---|---|---|
`, in.AgentKeyFingerprint)
	for _, tenant := range in.Tenants {
		has := "否"
		if tenant.HasKeystore {
			has = "是"
		}
		signer := tenant.SignerSHA256
		if signer == "" {
			signer = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", tenant.Slug, tenant.Domain, has, signer)
	}
	b.WriteString(`
恢复完成之后，这张表里每一个「有签名密钥」的租户都必须能被打包机打开。
少一个都要当成事故查，不要绕过去。
`)
	return b.String()
}

func writeFileTable(b *strings.Builder, files []FileEntry) {
	b.WriteString("| 包里的路径 | 放到哪 | 权限 | 属主 |\n|---|---|---|---|\n")
	for _, f := range files {
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` | `%s` |\n", f.Path, f.Target, f.Mode, f.Owner)
	}
}

// renderRecoverScript 是密文里面那个交互式脚本（§5.3）。
//
// 它**只做恢复，不做破坏**：目标路径已有文件就停下来问，不覆盖。
func renderRecoverScript(in Input, pair backupcontainer.Pair) string {
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/bash
# 打包服务故障恢复 —— 备份 #%d（%s 组），产出于 %s
#
# 照着 RECOVERY.md 一步步敲容易漏、容易错，所以有这个脚本。但它不替代手册：
# 环境不一样、脚本跑不通时，RECOVERY.md 里每一步都有对应的那条命令。
#
# 用法: sudo bash recover.sh <解开后的目录>
#   <解开后的目录> 里应当有 L2-agent/ 和 L2-server/

set -euo pipefail
umask 077

ROOT="${1:-}"
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then
  echo "用法: sudo bash recover.sh <解开后的目录>" >&2
  exit 2
fi

say()  { printf '\n==> %%s\n' "$1"; }
die()  { printf '\n!! 卡在这一步: %%s\n   下一步该查: %%s\n' "$1" "$2" >&2; exit 1; }

# --- 先验签。验不过就停 -------------------------------------------------
# 这是纵深不是主防线：整包被伪造时这个脚本本身也是伪造的。真正的锚点是
# README-FIRST 里那个 sha256（和控制台比对）以及持有人纸上抄的签名公钥指纹。
say "验证内层签名"
if [ ! -f "$ROOT/inner.rnbk.sig" ]; then
  die "找不到 inner.rnbk.sig" "确认外层是完整解开的，不是只取了几个文件"
fi
if [ -f "$ROOT/signing.pem" ]; then
  openssl pkeyutl -verify -pubin -inkey "$ROOT/signing.pem" \
    -rawin -in "$ROOT/inner.rnbk" -sigfile "$ROOT/inner.rnbk.sig" \
    || die "签名验不过" "这个包不是我们那台机器产出的，停下来找人"
  echo "签名 OK"
else
  echo "!! 没有 signing.pem，跳过验签。"
  echo "   备份签名公钥指纹应当是 %s"
  echo "   强烈建议先按 README-FIRST 第四步验一次再继续。"
  read -r -p "   仍然继续？(yes/NO) " answer
  [ "$answer" = "yes" ] || exit 1
fi

# --- 放文件。已存在就问，不覆盖 -----------------------------------------
place() {
  local src="$1" dst="$2" mode="$3" owner="$4"
  if [ ! -f "$src" ]; then
    die "包里没有 $src" "对照 RECOVERY.md 的文件表，确认这一层是完整解开的"
  fi
  if [ -e "$dst" ]; then
    echo "!! $dst 已经存在。"
    read -r -p "   覆盖它？(yes/NO) " answer
    [ "$answer" = "yes" ] || { echo "   跳过 $dst"; return 0; }
  fi
  install -D -m "$mode" -o "${owner%%%%:*}" -g "${owner##*:}" "$src" "$dst" \
    || die "放不下 $dst" "属主 $owner 存在吗？先建好用户和组"
  echo "  $dst  ($mode $owner)"
}

`, in.Seq, pair.Name, in.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		in.BackupSigningFingerprint)

	b.WriteString("say \"恢复服务端那部分（场景 B；场景 A 可以跳过）\"\n")
	b.WriteString("read -r -p \"服务端也需要恢复吗？(yes/NO) \" want_server\n")
	b.WriteString("if [ \"$want_server\" = \"yes\" ]; then\n")
	for _, f := range in.ServerManifest {
		fmt.Fprintf(&b, "  place \"$ROOT/L2-server/%s\" %s %s %s\n",
			f.Path, shellQuote(f.Target), shellQuote(f.Mode), shellQuote(f.Owner))
	}
	b.WriteString("  systemctl daemon-reload\n")
	b.WriteString("  echo \"  服务端文件已就位。起服务和验证见 RECOVERY.md 第 1 节。\"\n")
	b.WriteString("fi\n\n")

	b.WriteString("say \"恢复打包机那部分\"\n")
	for _, f := range in.AgentManifest {
		fmt.Fprintf(&b, "place \"$ROOT/L2-agent/%s\" %s %s %s\n",
			f.Path, shellQuote(f.Target), shellQuote(f.Mode), shellQuote(f.Owner))
	}

	fmt.Fprintf(&b, `
say "核对打包机身份"
if command -v build-agent >/dev/null 2>&1; then
  got=$(build-agent show-key 2>/dev/null | head -1 || true)
  echo "  本机: $got"
  echo "  期望: %s"
  case "$got" in
    *%s*) echo "  指纹一致" ;;
    *) die "agent-key 指纹对不上" "检查 BUILD_AGENT_STATE_DIR 是不是显式写死了，默认值会让它静默生成一把新的" ;;
  esac
else
  echo "!! build-agent 还不在 PATH 里，跳过核对。起服务之前请手动跑一次 build-agent show-key。"
fi

say "还没做完的事（这个脚本不替你做，因为它们要连数据库或要人判断）"
cat <<'TODO'
  1. 清掉旧的校验记录，否则看到的是灾难前那台机器写下的：
       DELETE FROM app_configs WHERE config_key='build.keystore.check';
  2. 按 source-remote.txt 把 RN-App 检出到 workspace
  3. systemctl start rn-build-agent
  4. 等每个租户出现新的 checkedAt ok
  5. 跑通一条真实的 APK 构建并入库 —— 做到这一步才算恢复完成
TODO

printf '\n恢复脚本做完了它能做的部分。上面五步做完才算完整恢复。\n'
`, in.AgentKeyFingerprint, in.AgentKeyFingerprint)
	return b.String()
}
