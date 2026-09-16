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
	name := PackageBaseName(in.Seq, in.CreatedAt, pair.Name) + ".rnbk"

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
		fmt.Fprintf(&b, "    %s.rnbk   要 %s 和 %s\n",
			PackageBaseName(in.Seq, in.CreatedAt, other.Name), other.Outer, other.Inner)
	}

	fmt.Fprintf(&b, `
三个包里装的是同一份内容，只是锁的组合不同。

第三步：开包
------------
把下面这段存成 open-layer.sh，然后跑三次。**每一层解到不同的目录**——三层用的
是同样的四个文件名，不分目录的话第二层会把第一层的中间文件悄悄盖掉。

%s

**解到内存盘上，不要解到当前目录。** 解出来的是全平台每个租户的签名密钥明文
——落在普通磁盘上，同机任何用户都可能读到，而且 SSD 上 rm 不等于擦除。

    work=$(mktemp -d /dev/shm/rnbk-open.XXXXXX)   # 内存盘，重启即失
    bash open-layer.sh %s  ~/%s.key  "$work/L1"
    bash open-layer.sh "$work/L1/inner.rnbk"   ~/%s.key  "$work/L2-agent"
    bash open-layer.sh "$work/L1/server.rnbk"  ~/%s.key  "$work/L2-server"

做完之后**立刻销毁**：

    rm -rf "$work"

（recover.sh 结束时会提醒你这一步，但它不替你做——万一你还没装完就被清掉，
恢复要从头再来一遍，那在灾难当天是很贵的。）

没有 xxd 的机器上，把 `+"`xxd -p -cN`"+` 换成 `+"`od -An -tx1 | tr -d ' \\n'`"+`，输出逐字节相同。

第四步：验签
------------
备份签名公钥就在 "$work/L1/signing.der"，跟着包一起来的——灾难当天控制台多半
也起不来，从库里取公钥那条路是断的。

它可信**不是因为它在包里**，是因为下面这一步拿它和你手上的纸比对：

    sha256sum "$work/L1/signing.der"

算出来的值应当和三位持有人当初各自抄在纸上的那一行一致：

    %s

（这一行也印在包里，但包里的东西攻击者全都能改，包括这一行。唯一他改不到的
是纸。对不上就停下来找人，不要往下走。）

**验签通过之前不要跑 recover.sh** ——那个脚本恢复时以 root 执行。

对上之后验签：

    openssl pkey -pubin -inform DER -in "$work/L1/signing.der" -out "$work/signing.pem"
    openssl pkeyutl -verify -pubin -inkey "$work/signing.pem" \
      -rawin -in "$work/L1/inner.rnbk" -sigfile "$work/L1/inner.rnbk.sig"

第五步
------
读 L1/RECOVERY.md。它带的是产出这一刻的真实路径和真实值，不是模板。

recover.sh 会把上面这些再自己核一遍（外加一条防拼接的检查），所以你也可以直接：

    sudo bash "$work/L1/recover.sh" "$work" <纸上的那 64 位指纹>

指纹要手敲，理由同上：脚本在包里，纸不在。

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
    # 这一层的 meta.json 也留一份：recover.sh 要拿两层的 seq 比对，
    # 那是唯一能发现「旧备份的内层被塞进新包」的检查。内层的这份在签名
    # 覆盖范围内（签的是整个 inner.rnbk），改不动
    cp meta.json "$OUT/layer-meta.json"
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

让下一轮校验重新跑一次。**不做这步，控制台显示的是灾难前那台机器写下的旧记录**，
而真相要等到第一次构建才暴露——那时明文 keystore 多半已经不在手边了：

`+"```bash"+`
curl -sS -X POST \
  -H "x-admin-key: $ADMIN_API_KEY" \
  -H "Host: <租户域名>" \
  -H "content-type: application/json" \
  -d '{"reason":"restored onto a new build machine","confirm":true}' \
  http://127.0.0.1:13080/v1/admin/platform/build-agent/keystore-checks/reset
`+"```"+`

连不上服务端时的兜底（直接连库）：

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
func renderRecoverScript(in Input, pair backupcontainer.Pair, digests map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/bash
# 打包服务故障恢复 —— 备份 #%d（%s 组），产出于 %s
#
# 照着 RECOVERY.md 一步步敲容易漏、容易错，所以有这个脚本。但它不替代手册：
# 环境不一样、脚本跑不通时，RECOVERY.md 里每一步都有对应的那条命令。
#
# 用法: sudo bash recover.sh <工作目录> <备份签名公钥指纹>
#
#   <工作目录>  README-FIRST 第三步里那个 $work，里面应当有
#               L1/  L2-agent/  L2-server/  三个目录
#   <指纹>      三位持有人当初各自抄在纸上的那 64 位十六进制
#
# 为什么指纹要你手敲：包里的东西——包括 README 上印的指纹——攻击者全都能改。
# 唯一他改不到的是纸。所以锚点在纸上，不在包里。

set -euo pipefail
umask 077

ROOT="${1:-}"
PAPER_FP="${2:-}"
usage() { echo "用法: sudo bash recover.sh <工作目录> <备份签名公钥指纹>" >&2; exit 2; }
[ -n "$ROOT" ] && [ -d "$ROOT" ] || usage
[ -n "$PAPER_FP" ] || usage

L1="$ROOT/L1"

say()  { printf '\n==> %%s\n' "$1"; }
die()  { printf '\n!! 卡在这一步: %%s\n   下一步该查: %%s\n' "$1" "$2" >&2; exit 1; }

for d in "$L1" "$ROOT/L2-agent" "$ROOT/L2-server"; do
  [ -d "$d" ] || die "找不到 $d" "按 README-FIRST 第三步把三层各解到一个目录：L1、L2-agent、L2-server"
done

# $ROOT 里是全平台每个租户的签名密钥明文。它必须在内存盘上：普通磁盘上同机任何
# 用户都可能读到，而且 SSD 上 rm 不等于擦除——删掉之后数据还在闪存里。
# README-FIRST 教的是 mktemp -d /dev/shm/...，但脚本对调用者传什么进来不能想当然
fstype=$(df -P -T "$ROOT" 2>/dev/null | awk 'NR==2{print $2}')
case "$fstype" in
  tmpfs|ramfs) ;;
  *)
    echo "!! $ROOT 在 $fstype 上，不是内存盘。"
    echo "   这里面是全平台每个租户的签名密钥明文，落在普通磁盘上"
    echo "   同机任何用户都可能读到，而且 SSD 上 rm 不等于擦除。"
    echo "   建议按 README-FIRST 第三步重解到 /dev/shm 下再跑。"
    read -r -p "   仍然继续？(yes/NO) " answer
    [ "$answer" = "yes" ] || exit 1
    ;;
esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# --- 一、文件完整性 -----------------------------------------------------
# 外层 MAC 已经覆盖了这些成员，所以这一步抓的不是篡改，是**解包解漏了或解坏了**
# ——在灾难当天这比篡改常见得多，而症状（脚本半路报一个看不懂的错）很难往这边想
say "核对文件完整性"
check_file() {
  local name="$1" want="$2" got
  [ -f "$L1/$name" ] || die "L1/ 里没有 $name" "确认第一层是完整解开的，不是只取了几个文件"
  got=$(sha256_of "$L1/$name")
  [ "$got" = "$want" ] || die "$name 的 sha256 对不上" "这一层没解完整或者文件损坏了，重新解一次"
  echo "  $name  OK"
}
`, in.Seq, pair.Name, in.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))

	for _, name := range []string{nameInner, nameInnerSig, nameServer, nameSigningKey} {
		if digest := digests[name]; digest != "" {
			fmt.Fprintf(&b, "check_file %s %s\n", shellQuote(name), shellQuote(digest))
		}
	}

	fmt.Fprintf(&b, `
# --- 二、这把公钥是不是我们那把（对纸）--------------------------------
# signing.der 跟着包走，因为灾难当天控制台多半也起不来。它可信不是因为它在包里，
# 是因为下面这一行拿它和你手上的纸比对
say "核对备份签名公钥"
got_fp=$(sha256_of "$L1/signing.der")
echo "  包里这把: $got_fp"
echo "  你敲进来的: %s"
if [ "$got_fp" != "$PAPER_FP" ]; then
  die "签名公钥和纸上抄的对不上" "先确认你敲的那 64 位没抄错；确认没错就停下来找人——这个包不是我们产出的"
fi
echo "  一致"

# --- 三、验签。验不过就停，没有跳过这个选项 ----------------------------
# 设计里这是两个真实性锚点之一。之前这里有一个「仍然继续？(yes/NO)」的分支，
# 那等于把锚点变成一句提示——恢复的人在灾难当天是会敲 yes 的
say "验证内层签名"
[ -f "$L1/inner.rnbk.sig" ] || die "找不到 inner.rnbk.sig" "确认第一层是完整解开的"
pem=$(mktemp); trap 'rm -f "$pem"' EXIT
openssl pkey -pubin -inform DER -in "$L1/signing.der" -out "$pem" \
  || die "signing.der 不是一把能用的公钥" "文件在传输中损坏了，重新取一份包"
openssl pkeyutl -verify -pubin -inkey "$pem" \
  -rawin -in "$L1/inner.rnbk" -sigfile "$L1/inner.rnbk.sig" \
  || die "签名验不过" "这个包不是我们那台机器产出的，停下来找人"
echo "  签名 OK"

# --- 四、防拼接：两层的 seq 必须是同一次备份 --------------------------
# 签名挡不住拼接：把一次旧备份的 inner.rnbk 连同它那份 .sig 一起塞进新包，
# 签名照样验得过（同一台机器签的）、外层 MAC 也是攻击者自己算的。
# 但内层的 seq 在签名覆盖范围内、改不动，所以它和外层对不上就是拼接。
# 后果是恢复出来的是旧密钥，而这正是整个方案唯一要防的事
say "核对两层是不是同一次备份"
seq_of() { sed -n 's/.*"seq"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$1" | head -1; }
outer_seq=$(seq_of "$L1/layer-meta.json")
inner_seq=$(seq_of "$ROOT/L2-agent/layer-meta.json")
echo "  外层 seq=$outer_seq  内层 seq=$inner_seq  本包应为 %d"
if [ -z "$outer_seq" ] || [ -z "$inner_seq" ]; then
  die "读不到 layer-meta.json 里的 seq" "确认 L1/ 和 L2-agent/ 都是用包里这一版 open-layer.sh 解出来的"
fi
if [ "$outer_seq" != "$inner_seq" ] || [ "$outer_seq" != "%d" ]; then
  die "两层不是同一次备份（seq 对不上）" "这是拼接的特征：有人把旧备份的内层塞进了新包。停下来找人"
fi
echo "  两层同属备份 #$outer_seq"

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

`, in.BackupSigningFingerprint, in.Seq, in.Seq)

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

# --- 最后一句，也是最容易被忘掉的一句 -----------------------------------
# $ROOT 里是全平台每个租户的签名密钥明文。它不该在这台机器上多留一秒，
# 而 SSD 上 rm 不等于擦除——所以最好一开始就解在内存盘上（README 第三步）。
cat <<CLEANUP

!! 别忘了销毁解出来的明文
   目录: $ROOT
   里面有全平台每个租户的签名密钥明文和 agent-key。

       rm -rf $(printf '%%q' "$ROOT")

   这个脚本不替你做：万一你还没装完就被清掉，恢复要从头再来一遍，
   而那在灾难当天是很贵的。
CLEANUP
`, in.AgentKeyFingerprint, in.AgentKeyFingerprint)
	return b.String()
}
