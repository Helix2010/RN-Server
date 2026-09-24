#!/usr/bin/env bash
# Mac 打包机安装脚本。服务端 GET /v1/machine-setup/install-macos.sh 原样下发（go:embed）。
#
#   curl -fsSLo install-macos.sh <API>/v1/machine-setup/install-macos.sh
#   shasum -a 256 install-macos.sh            # 与 CI 日志「Build machine bundles」那一步的值比
#   sudo bash install-macos.sh --server <API> --code rne_… \
#        --release-key-sha256 <密码管理器里发布公钥的 sha256>
#
# **首次装机是一次对服务端的信任**：脚本本身、安装包、两把要钉死的公钥都来自服务端。
# 所以要有一个从别处来的判据，缺了就拒绝——不给"先装上以后再说"的选项：装上之后再补，
# 中间那一段时间这台机器已经在按服务端说的做事了，而它手上有全部租户的签名材料。
#
# 那个判据只有一个：发布公钥的指纹。其余的摘要都从一份**离线签名背书的清单**里推出来，
# 而签那份清单的私钥服务端和 CI 都没有。让人抄三个值不比抄一个更安全——多两次抄写只是
# 多两次抄错的机会，而其中"归档摘要"那一个还得每次发版去翻 CI 日志找对应的版本。
#
# 步骤（设计 docs/design/ios-mac-builders-home-network-2026-09-18.md §4.5）：
#   1. 前提：Apple Silicon、Xcode（xip 装的，不是 App Store）、git/node/pnpm/pod、磁盘、时钟
#   2. 系统设置：不休眠、断电自启、关自动更新、关自动登录、Spotlight 排除任务目录
#   3. FileVault：必须开（代价见 §6.1）
#   4. 三个角色账户与目录
#   5. 程序：下载核对安装包，核对两把公钥的 sha256，冒烟
#   6. 签名区与上传区：建目录、生成钥匙串与随机口令，材料由人放
#   7. 注册：build-agent enroll，env 文件归 _rnbuildagent
#   8. 仓库镜像：生成 deploy key，人加到 GitHub 后重跑
#   9. 常驻：装两份 plist，launchctl bootstrap system
#
# 可以重复执行：已注册的机器不重新注册、不覆盖已经放好的签名材料，只核对并确保服务在跑。
# 注册码只在第 7 步消耗。
#
# 机密：机器令牌只由 build-agent enroll 写进 env 文件，这个脚本从不读取、打印它；
# 注册码经 stdin 交给 curl，不进命令行参数（`ps` 看得到命令行）。
set -euo pipefail
cd /
umask 077
# 系统目录在前，Homebrew 的两个在后：
#
#   - 在前：curl、git、tar、shasum 这些一律解析到系统那一份。Homebrew 的目录是管理员
#     可写的，被投毒也换不掉这些；
#   - 但必须带上：node、pnpm、pod 只可能装在那两个目录里（macOS 不自带），不放进来的话
#     preflight 的 need_commands 用 command -v 永远找不到它们——这台机器装什么都过不了，
#     而报错说的是"缺少前提：命令 node"，人会一遍遍去装已经装好的东西。
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin
HOME=/var/root
export PATH HOME
for _name in $(compgen -e); do
  case "$_name" in
    PATH | HOME | TERM | LANG | LC_* | http_proxy | https_proxy | no_proxy | HTTP_PROXY | HTTPS_PROXY | NO_PROXY) ;;
    *) unset "$_name" 2>/dev/null || true ;;
  esac
done
for _name in $(compgen -A function); do
  unset -f "$_name"
done
unset _name

readonly SETUP_ROOT=/var/rn-machine-setup
readonly INSTALL_DIR=/opt/rn-build-agent
readonly AGENT_HOME=/var/rn-build-agent
readonly JOBS_ROOT=/var/rn-build-jobs
readonly SIGNING_DIR=/var/rn-build-signing
readonly UPLOAD_DIR=/var/rn-build-upload
# 执行账户在目录服务里的家目录。另外两个角色账户仍是 /var/empty——见 ensure_accounts 里的说明
readonly RUNNER_HOME=/var/rn-build-home
readonly ENV_FILE=$AGENT_HOME/env
readonly AGENT_USER=_rnbuildagent
readonly RUNNER_USER=_rnbuilder
readonly UPLOAD_USER=_rnuploader
readonly JOBS_GROUP=_rnbuildjobs
readonly AGENT_LABEL=win.anyfun.rn-build-agent
readonly UPGRADE_LABEL=win.anyfun.rn-build-agent-upgrade
# 这条 PATH 会写进 env 文件交给执行进程：Homebrew 在 Apple Silicon 上装在 /opt/homebrew
readonly BUILD_PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin
readonly MIN_FREE_GB=60
readonly BUNDLE_NAME=builder-darwin-arm64
# Apple WWDR G3 中间证书：随安装包带（在已验签的清单里），这里再钉一次摘要。见 ensure_wwdr_intermediate
readonly WWDR_G3_FILE=AppleWWDRCAG3.cer
readonly WWDR_G3_SHA256=dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f
readonly SYSTEM_KEYCHAIN=/Library/Keychains/System.keychain

SERVER=""
CODE=""
RELEASE_KEY_SHA256=""
# 两把材料私钥的**本机路径**（内容由人从密码管理器取，不从网上来）。不给就不装，
# 这台机器仍然能用——只是签名材料要按运维手册第 1.3 节人工放
MATERIAL_KEY_BUILDER=""
MATERIAL_KEY_UPLOADER=""
CURL_PROTO="=https"
WORK=""
CACHE=""
BUNDLE=""
BUNDLE_ARCHIVE=""
BUNDLE_SHA256=""
BUNDLE_SIZE=""
BUNDLE_COMMIT=""
BUNDLE_SEQUENCE=""
MACHINE_NAME=""
MISSING=()

step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
warn() { printf '   !! %s\n' "$*" >&2; }
die() {
  printf '\ninstall-macos.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
用法（以 root 执行）：
  sudo bash install-macos.sh --server <API> --code rne_… \
       --release-key-sha256 <发布公钥 sha256> \
       [--material-key-builder <文件>] [--material-key-uploader <文件>]

只有一个带外核对值：
  --release-key-sha256   密码管理器里记的发布公钥指纹（公钥**字节**的 sha256，
                         不是 release-key.pub 这个文件的）

可选，两把**材料私钥**（内容从密码管理器取，放在这台机器上的文件里）：
  --material-key-builder   构建账户那把，解证书与描述文件
  --material-key-uploader  上传账户那把，解 App Store Connect 上传 Key

  给了它们，签名材料就由平台在控制台上传一次、这台机器自己取自己装；不给也能装完，
  只是那三样要按运维手册第 1.3 节人工放。**这两把私钥不从服务端来**——服务端只转发
  它读不懂的密文，这是整套设计的前提。

首次装机是一次对服务端的信任：脚本、安装包与两把公钥都来自服务端，只有这个值是从别处
来的。它是这台机器唯一不依赖服务端的判据，其余全部由它推出来：

  人给的指纹 → 认出发布公钥 → 验清单的离线签名 → 可信清单里的摘要
              → 核对归档 → 核对包内每个文件（含 allowed_signers）

归档摘要因此不再需要人从 CI 日志里抄：它来自一份离线签名背书的清单，而那把私钥服务端
和 CI 都没有。脚本本身的 shasum 仍然要与 CI 日志比对——那是这条链子的第一环。
USAGE
  exit 2
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --server) SERVER="${2:-}"; shift 2 ;;
      --code) CODE="${2:-}"; shift 2 ;;
      --release-key-sha256) RELEASE_KEY_SHA256="${2:-}"; shift 2 ;;
      --material-key-builder) MATERIAL_KEY_BUILDER="${2:-}"; shift 2 ;;
      --material-key-uploader) MATERIAL_KEY_UPLOADER="${2:-}"; shift 2 ;;
      --insecure-http) CURL_PROTO="=https,http"; shift ;;
      -h | --help) usage ;;
      *) printf 'install-macos.sh: 不认识的参数 %s\n' "$1" >&2; usage ;;
    esac
  done
  [ -n "$SERVER" ] || usage
  [ -n "$CODE" ] || usage
  case "$SERVER" in
    https://*) ;;
    http://127.0.0.1* | http://localhost*) CURL_PROTO="=https,http" ;;
    *) die "--server 必须是 https 地址（本机测试可以用 http://127.0.0.1…）" ;;
  esac
  # 没替换的占位符要在这里就认出来。不查的话它会一路走到第七步才以 describe 404 失败，
  # 而那条报错说的是"注册码过期或已用过"——完全错误的方向，人会跑去控制台重发一个。
  case "$CODE$SERVER$RELEASE_KEY_SHA256" in
    *…* | *'<'* | *'>'*)
      die "命令里还有没替换的占位符。控制台「新建机器」会给出完整的四行，把
   <从密码管理器粘贴发布公钥指纹> 换成密码管理器里那个 64 位十六进制，其余原样粘贴。" ;;
  esac
  # rne_ + 43 个 base64url 字符（服务端 signing/machinekey.ValidEnrollmentCode 的口径）
  printf '%s' "$CODE" | grep -Eq '^rne_[A-Za-z0-9_-]{43}$' ||
    die "--code 不是控制台发的注册码：应该是 rne_ 加 43 个字符，你给的是 ${#CODE} 个字符的 \"$CODE\"。
   到控制台「平台维护 → 打包机与签名闸 → 构建机 → 新建」拿一个，类型选 macOS。"
  printf '%s' "$RELEASE_KEY_SHA256" | grep -Eq '^[0-9a-f]{64}$' ||
    die "--release-key-sha256 必须给，且是 64 位小写十六进制。它是这台机器唯一不依赖服务端的判据，见 --help"
  local role path
  for role in BUILDER UPLOADER; do
    eval "path=\$MATERIAL_KEY_$role"
    [ -n "$path" ] || continue
    [ -f "$path" ] || die "--material-key-$(printf '%s' "$role" | tr 'A-Z' 'a-z') 指向的文件不在：${path}"
    # 形状在这里就查：一行 base64、解出来 32 字节。装错了的表现否则是"材料下来了但解不开"
    LC_ALL=C tr -d '[:space:]' <"$path" | openssl base64 -d -A 2>/dev/null | wc -c |
      grep -q '^ *32$' ||
      die "${path} 不是一把 X25519 私钥：它应该是一行 base64，解出来正好 32 字节
   （ios-material keygen 写出来的 builder.x25519 / uploader.x25519 就是这个样子）"
  done
}

curl_api() {
  # -q 必须是第一个参数：不读 ~/.curlrc
  curl -q --silent --show-error --proto "$CURL_PROTO" --connect-timeout 15 "$@"
}

sha256_of() {
  local sum
  sum="$(/usr/bin/shasum -a 256 "$1")"
  printf '%s' "${sum%% *}"
}

# release_key_sha256 算的是**公钥字节**的 sha256，不是 release-key.pub 这个文件的。
#
# 这一条必须和 bundle-sign 一致：`bundle-sign key create` 打印的、清单签名里
# publicKeySha256 那个字段、控制台「批准打包机程序版本」显示的，全都是公钥 32 字节
# 的摘要。运维记进密码管理器的就是那个值，装机时 --release-key-sha256 给的也是它。
# 按文件算会得到另一个数——两边永远对不上，而报错会说"安装包被换过"，让人以为遭到
# 了攻击。
#
# 文件里是 OpenSSH 的一行：`ssh-ed25519 <base64> <注释>`。第二栏解出来是 51 字节的 SSH
# blob（长度域 + "ssh-ed25519" + 长度域 + 32 字节公钥），**末 32 字节**才是公钥本身。
release_key_sha256() {
  local sum
  sum="$(awk '{print $2}' "$1" | /usr/bin/openssl base64 -d -A | tail -c 32 | /usr/bin/shasum -a 256)"
  printf '%s' "${sum%% *}"
}

file_size_of() { /usr/bin/stat -f %z "$1"; }

need_commands() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("命令 $cmd")
  done
}

version_at_least() { # $1 实际 $2 要求（点分数字）
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]
}

# ---- 1. 前提 ---------------------------------------------------------------------------------

preflight() {
  step "检查前提"
  [ "$(id -u)" = 0 ] || die "必须以 root 执行（sudo bash install-macos.sh …）"
  [ "$(uname -s)" = Darwin ] || die "这个脚本只装 Mac 打包机；Linux 构建机用 install.sh"
  MISSING=()
  [ "$(uname -m)" = arm64 ] || MISSING+=("Apple Silicon（安装包只编 darwin/arm64；Intel Mac 也跑不了当前的 Xcode）")
  need_commands curl python3 shasum openssl ssh-keygen tar git node pnpm pod xcodebuild xcrun security dscl dseditgroup launchctl plutil

  if command -v xcodebuild >/dev/null 2>&1; then
    xcodebuild -version >/dev/null 2>&1 ||
      MISSING+=("xcodebuild 跑不起来：先 sudo xcodebuild -license accept 与 sudo xcodebuild -runFirstLaunch")
    # App Store 装的 Xcode 会静默升级，破坏「几台 Mac 同一个 Xcode」这条约定（§5.3）
    local xcode_path
    xcode_path="$(xcode-select -p 2>/dev/null || true)"
    case "$xcode_path" in
      /Applications/Xcode*.app/*) ;;
      *) MISSING+=("xcode-select 指向 ${xcode_path}，不像一个用 xip 装好的 Xcode（不要用 App Store 装：它会静默升级）") ;;
    esac
  fi
  if command -v git >/dev/null 2>&1; then
    local git_version
    git_version="$(git --version | awk '{print $3}')"
    version_at_least "$git_version" 2.30 || MISSING+=("git $git_version 太旧，要 2.30 以上")
  fi
  if command -v node >/dev/null 2>&1; then
    local node_version
    node_version="$(node --version | tr -d v)"
    version_at_least "$node_version" 22.0.0 || MISSING+=("node $node_version 太旧，要 22 以上")
  fi
  # 这条 PATH 会写进 env 文件交给执行进程：装在别处的工具到时候找不到
  local tool
  for tool in node pnpm pod git; do
    if command -v "$tool" >/dev/null 2>&1; then
      case "$(command -v "$tool")" in
        /usr/local/bin/* | /opt/homebrew/bin/* | /usr/bin/* | /bin/*) ;;
        *) MISSING+=("$tool 装在 $(command -v "$tool")，不在交给执行进程的 PATH（${BUILD_PATH}）里") ;;
      esac
    fi
  done
  local free_gb
  free_gb="$(df -g / | awk 'NR==2 {print $4}')"
  [ "${free_gb:-0}" -ge "$MIN_FREE_GB" ] ||
    MISSING+=("根卷空闲 ${free_gb}G，至少要 ${MIN_FREE_GB}G（每任务 1–2G 依赖 + 数 G DerivedData）")
  # CocoaPods 在非 UTF-8 locale 下会以 Ruby 的编码错误失败，而那条报错完全不像 locale 问题
  case "${LANG:-}" in
    *UTF-8 | *utf8) ;;
    *) note "LANG 是 ${LANG:-未设置}；env 文件里会写死 LANG=en_US.UTF-8（CocoaPods 在非 UTF-8 下会报 Ruby 编码错误）" ;;
  esac
  if [ "$(systemsetup -getusingnetworktime 2>/dev/null | awk '{print $NF}')" != "On" ]; then
    MISSING+=("网络对时没开（systemsetup -setusingnetworktime on）：App Store Connect 的 JWT 只有 20 分钟有效期，时钟漂几分钟就是 401")
  fi
  if [ "${#MISSING[@]}" -gt 0 ]; then
    printf '\ninstall-macos.sh: 缺少前提，装好再重新执行（注册码还没有使用）：\n' >&2
    printf '   - %s\n' "${MISSING[@]}" >&2
    exit 1
  fi
  note "前提齐了"
}

# ---- 2. 系统设置 -----------------------------------------------------------------------------

system_settings() {
  step "系统设置：不休眠、断电自启、不自动更新"
  # 睡着的 Mac 领不到任务，正在构建时睡着会让心跳超时、任务被回收重排。
  #
  # 用 `-a`（所有供电状态）而不是 `-c`（只管接着电源时）：2026-09-20 夜里 mac-01 就是
  # 这么丢的——接着电源、`sleep 0` 也设了，合上盖子照样进 clamshell 休眠，当地 23:58
  # 最后一次心跳，第二天早上还是离线，排队的任务整夜没人领。笔记本当打包机时
  # `disablesleep` 才是那个真正管合盖的开关，而原先只在电池那一档设它。
  pmset -a sleep 0 disksleep 0 displaysleep 0 >/dev/null 2>&1 ||
    warn "pmset 设置失败，手工确认电源设置"
  # disablesleep 只有便携机有；台式机上这条不存在，跳过即可
  if pmset -g custom 2>/dev/null | grep -q disablesleep; then
    pmset -a disablesleep 1 >/dev/null 2>&1 ||
      warn "pmset disablesleep 设置失败：合上盖子这台机器还是会睡"
  fi
  systemsetup -setrestartpowerfailure on >/dev/null 2>&1 || warn "断电自启设置失败（笔记本没有这一项，正常）"
  # 自动更新会在没人看着的时候换掉 Xcode 或重启机器：更新由人排期（§5.3 要求几台 Mac 同一个 Xcode）
  softwareupdate --schedule off >/dev/null 2>&1 || warn "关自动更新失败，去系统设置里手工关"
  defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false 2>/dev/null || true
  defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool false 2>/dev/null || true
  # 自动登录 = 冷启动后无人值守地解锁了一个图形会话，等于 FileVault 白开
  defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true
  # Spotlight 索引任务目录纯属浪费：每个任务几 G 文件，用完就删
  install -d -m 0755 "$JOBS_ROOT" 2>/dev/null || true
  mdutil -i off "$JOBS_ROOT" >/dev/null 2>&1 || true
  note "已设置；系统更新与 Xcode 升级由人排期（见运维手册）"
}

# ---- 3. FileVault ----------------------------------------------------------------------------

check_filevault() {
  step "检查 FileVault"
  if fdesetup status 2>/dev/null | grep -q "FileVault is On"; then
    note "FileVault 已开"
    note "计划内重启用 sudo fdesetup authrestart（不用人到机器前输口令）"
    return 0
  fi
  die "FileVault 没开。这台机器上会放全部租户的 Distribution 私钥、上传 Key、机器令牌与
   deploy key；不开 FileVault，任何拿到机器的人从恢复模式重置口令就能把它们读走。
   先 sudo fdesetup enable，把恢复密钥存进密码管理器，再重新执行。
   代价（已知并接受）：冷启动会停在预启动解锁屏，断电后要有人到场解锁，期间队列等待。"
}

# ---- 4. 账户与目录 ---------------------------------------------------------------------------

# group_gid 读一个组的 gid。
group_gid() { # $1 组名
  dscl . -read "/Groups/$1" PrimaryGroupID 2>/dev/null | awk '{print $2}'
}

# next_role_uid 挑一个空闲的 uid。角色账户按 macOS 的惯例落在 200–400：小于 500 的账户
# 不出现在登录窗口里，而 200 以下是系统自己的。
next_role_uid() {
  local uid=200 taken
  taken="$(dscl . -list /Users UniqueID | awk '{print $2}')"
  while printf '%s\n' "$taken" | grep -qx "$uid"; do
    uid=$((uid + 1))
    [ "$uid" -lt 400 ] || die "200–400 之间没有空闲的 uid 了"
  done
  printf '%s' "$uid"
}

# ensure_role_account 建一个不能登录的角色账户。要求同名组已经建好（取它的 gid 当主组）。
#
# **用 dscl 一条条写属性，不用 sysadminctl。** sysadminctl 在 macOS 15 上建角色账户会留下
# 一条**空记录**——UniqueID、PrimaryGroupID、NFSHomeDirectory、UserShell 一个都没有——而且
# **返回 0**。于是脚本打着"已建角色账户"一路往下，三步之后在建目录时以
# `install: unknown user _rnbuildagent` 失败，指向完全错误的方向。装第一台机器时就是这样。
#
# 判据也换成 `id`（getpwnam）能不能解析，不是 `dscl . -read` 有没有记录：那条空记录 dscl
# 读得到，getpwnam 解析不了，两者会给出相反的答案。
#
# 主组用同名私有组而不是 staff：这个账户以后建出来的文件就不会落进一个每个本地用户都在的组。
ensure_role_account() { # $1 用户名
  if id "$1" >/dev/null 2>&1; then
    note "账户 $1 已存在"
    return 0
  fi
  # 有记录但解析不了 = 上一次留下的空壳。它什么都拥有不了，删掉重建是安全的
  if dscl . -read "/Users/$1" >/dev/null 2>&1; then
    dscl . -delete "/Users/$1" >/dev/null 2>&1 ||
      die "账户 $1 有一条残缺的记录，删不掉：手工 sudo dscl . -delete /Users/$1 之后重来"
    warn "清掉了 $1 的残缺记录（有记录但没有 uid），重新建"
  fi
  local uid gid
  uid="$(next_role_uid)"
  gid="$(group_gid "$1")"
  [ -n "$gid" ] || die "同名组 $1 不存在，建不了账户"
  dscl . -create "/Users/$1" >/dev/null 2>&1 || die "建不出角色账户 $1"
  dscl . -create "/Users/$1" RealName "$1" >/dev/null 2>&1
  dscl . -create "/Users/$1" UniqueID "$uid" >/dev/null 2>&1
  dscl . -create "/Users/$1" PrimaryGroupID "$gid" >/dev/null 2>&1
  dscl . -create "/Users/$1" NFSHomeDirectory /var/empty >/dev/null 2>&1
  dscl . -create "/Users/$1" UserShell /usr/bin/false >/dev/null 2>&1
  # 不能登录：口令写成 *（没有可用的认证方式），并隐藏出登录窗口
  dscl . -create "/Users/$1" Password '*' >/dev/null 2>&1
  dscl . -create "/Users/$1" IsHidden 1 >/dev/null 2>&1
  id "$1" >/dev/null 2>&1 || die "角色账户 $1 建完仍然解析不了（uid ${uid}、gid ${gid}）"
  note "已建角色账户 ${1}（uid ${uid}）"
}

# ensure_role_group 建一个组。
#
# **macOS 与 Linux 在这里不一样，照搬会装不上**：Linux 的 useradd 顺带建一个同名私有组，
# 所以 `install -g "$用户名"` 直接可用；macOS 的 sysadminctl 只建用户、把主组设成 staff，
# **不建同名组**。下面那几个 0700 目录用的正是 -g "$用户名"，没有同名组就会以
# `install: unknown group _rnbuildagent` 失败——而那条报错不说这是平台差异，人只会以为
# 账户没建成。
#
# 不去改账户的主组：那要读 gid、要改账户记录，失败面比收益大。这些目录是 0700 的，属主
# 之外谁都进不去；同名组在这里的作用只是"别用 staff"——staff 是每个本地用户都在的组。
ensure_role_group() { # $1 组名
  dseditgroup -o read "$1" >/dev/null 2>&1 && return 0
  dseditgroup -o create "$1" >/dev/null 2>&1 || die "建不出组 $1"
  note "已建组 $1"
}

ensure_accounts() {
  step "账户与目录"
  # 组先于账户：账户要拿同名组的 gid 当主组
  ensure_role_group "$AGENT_USER"
  ensure_role_group "$RUNNER_USER"
  ensure_role_group "$UPLOAD_USER"
  ensure_role_group "$JOBS_GROUP"
  ensure_role_account "$AGENT_USER"
  ensure_role_account "$RUNNER_USER"
  ensure_role_account "$UPLOAD_USER"
  local user
  for user in "$AGENT_USER" "$RUNNER_USER" "$UPLOAD_USER"; do
    dseditgroup -o edit -a "$user" -t user "$JOBS_GROUP" >/dev/null 2>&1 || true
    dseditgroup -o edit -a "$user" -t user "$user" >/dev/null 2>&1 || true
  done
  install -d -o root -g wheel -m 0755 "$INSTALL_DIR"
  install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$AGENT_HOME" "$AGENT_HOME/state" "$AGENT_HOME/repos" "$AGENT_HOME/.ssh"
  # 任务根目录 setgid：三个账户都在组里，执行进程建出来的文件仍然属于这个组
  install -d -o "$AGENT_USER" -g "$JOBS_GROUP" -m 2750 "$JOBS_ROOT"
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0700 "$SIGNING_DIR" "$SIGNING_DIR/profiles"
  install -d -o "$UPLOAD_USER" -g "$UPLOAD_USER" -m 0700 "$UPLOAD_DIR"
  # 执行账户要有一个**可写的**家目录，而角色账户的惯例是 /var/empty（跨任务不留状态）。
  # 让步是被 Xcode 逼出来的：任务的 HOME 由 jobspec 设成 <work>/home，但 xcodebuild 读的是
  # **密码数据库里的**家目录、不认 ${HOME}——2026-09-21 真机日志里它把默认 DerivedData 算在
  # /var/empty/Library/Developer/Xcode/ 下；描述文件也是在那个 ~ 底下找的，/var/empty 只读，
  # 于是 archive 必然倒在 "No profile for team … matching … found"。
  # 代价是跑第三方代码的账户有了一个跨任务可写的目录（与共享缓存同一类风险面），收尾方向
  # 记在 RN-Server 的实现文档里：每个任务开始前清空，白名单保留 Xcode 自己的缓存。
  # 只改执行账户：控制进程与上传账户不跑 Xcode，没有理由给它们家目录。
  install -d -o "$RUNNER_USER" -g "$JOBS_GROUP" -m 0700 "$RUNNER_HOME"
  dscl . -create "/Users/$RUNNER_USER" NFSHomeDirectory "$RUNNER_HOME" >/dev/null 2>&1 ||
    die "设不了 $RUNNER_USER 的家目录：手工 sudo dscl . -create /Users/$RUNNER_USER NFSHomeDirectory $RUNNER_HOME"
  note "目录齐了"
}

# ---- 5. describe 与安装包 ---------------------------------------------------------------------

describe() {
  step "查询注册码（不消耗）"
  local code_sha status body="$WORK/describe.json"
  code_sha="$(printf '%s' "$CODE" | /usr/bin/shasum -a 256)"
  CACHE="$SETUP_ROOT/${code_sha%% *}"
  status="$(printf '{"code":"%s"}' "$CODE" |
    curl_api --max-time 60 -o "$body" -w '%{http_code}' -H 'content-type: application/json' \
      --data-binary @- "$SERVER/v1/machine-setup/describe")" || status="000"
  if [ "$status" != 200 ]; then
    # 服务端在 problem+json 里写了具体原因，带出来——不带的话运维只看得到一个状态码
    local detail
    detail="$(python3 -I - "$body" 2>/dev/null <<'PY' || true
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(0)
print(str(doc.get("detail") or doc.get("title") or "").strip())
PY
)"
    if [ -f "$CACHE/describe.json" ]; then
      warn "describe 返回 ${status}，用第一次执行时留下的结果继续（注册码可能已经用过）"
      cp "$CACHE/describe.json" "$body"
    else
      # 逐个状态码分开说。原来所有非 200 都套"注册码过期或已用过"，而 503 跟注册码毫无
      # 关系（这一步本来就不消耗它）——人照着去重发一个码，换来一模一样的 503。
      case "${status}" in
        503) die "服务端上的安装包还没签，所以什么都不下发。
   平台管理员要在离线机器上签一份清单，再用控制台「平台维护 → 打包机与签名闸 → 构建机
   → 打包机程序版本」的「选择 manifest.sig」交上去。
   **注册码没有被消耗**，签完重跑同一条命令即可。${detail:+
   服务端说：${detail}}" ;;
        404 | 410) die "注册码过期或已经用过（60 分钟有效、一次性）。
   到控制台「平台维护 → 打包机与签名闸 → 构建机 → 新建」重发一个，类型选 macOS。${detail:+
   服务端说：${detail}}" ;;
        000) die "连不上 ${SERVER}。检查网络，以及这台机器能不能解析到那个域名。" ;;
        *) die "describe 返回 ${status}。${detail:+服务端说：${detail}}" ;;
      esac
    fi
  else
    install -d -o root -g wheel -m 0700 "$SETUP_ROOT" "$CACHE"
    install -o root -g wheel -m 0600 "$body" "$CACHE/describe.json"
  fi
  parse_description "$body"
}

# parse_description 是整条链子闭合的地方。三步，每一步只信上一步验过的东西：
#
#   人给的指纹 -> 认出发布公钥 -> 验清单的离线签名 -> 可信清单里的摘要
#               -> 核对归档 -> 核对包内每个文件（含 allowed_signers）
#
# 这里**一行密码学都没有**：验签交给 macOS 自带的 ssh-keygen -Y verify。自带一个 ed25519
# 实现当然也能验，但运维在执行前要把这个脚本从头读一遍——那是这条链子的第一环，而一段
# 曲线运算没人读得动。能读完的脚本才配得上"比对 shasum"这个动作。
parse_description() {
  local body="$1"

  # ---- 1) 拆包。这一步拿到的东西全是服务端说的，一律按不可信处理：只取值、只查形状 ----
  # 失败原因（python 写在 stderr 上的那一行）要跟着 die 一起出来，否则运维只看到
  # "describe 的结果不能用"，得自己往上翻
  local why
  why="$(python3 -I - "$body" "$WORK" 2>&1 <<'PY'
import base64, json, struct, sys

path, work = sys.argv[1:3]
with open(path) as f:
    doc = json.load(f)

role, machine_os = doc.get("role"), doc.get("os")
if role != "builder":
    sys.exit("这个注册码是给 %s 的，不是 Mac 打包机" % role)
if machine_os != "darwin":
    sys.exit("这台机器在控制台里登记的是 %s，不是 macOS：新建机器时要选 macOS" % machine_os)

# 发布公钥：OpenSSH 的一行公钥，与 allowed_signers 里的写法一致。这里把它拆开验形状再
# **重新拼一遍**写出去——写出去的那一行因此必然是 51 字节的规范编码，末 32 字节就是公钥
# 本身。下一步在 shell 里算指纹靠的正是这个保证
key_text = (doc.get("releaseKeyPub") or "").strip()
if not key_text:
    sys.exit("服务端没给发布公钥：安装包目录里缺 release-key.pub，先把签过的安装包部署上去")
fields = key_text.split()
if len(fields) < 2 or fields[0] != "ssh-ed25519":
    sys.exit("服务端给的发布公钥不是一行 ssh-ed25519 公钥")
try:
    blob = base64.b64decode(fields[1], validate=True)
except Exception:
    sys.exit("服务端给的发布公钥不是 base64")

def read(buf):
    if len(buf) < 4:
        sys.exit("服务端给的发布公钥格式不对")
    n = struct.unpack(">I", buf[:4])[0]
    if n > len(buf) - 4:
        sys.exit("服务端给的发布公钥格式不对")
    return buf[4:4 + n], buf[4 + n:]

algo, rest = read(blob)
public, rest = read(rest)
if algo != b"ssh-ed25519" or len(public) != 32 or rest:
    sys.exit("服务端给的发布公钥不是一把干净的 32 字节 ed25519 公钥")
canonical = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public
with open(work + "/release-key.pub", "w") as out:
    out.write("ssh-ed25519 " + base64.b64encode(canonical).decode() + " rn-release-key\n")

# 清单与它的签名
manifest_b64 = doc.get("manifestBase64") or ""
signature = doc.get("manifestSignature") or {}
if not manifest_b64 or not signature:
    sys.exit("服务端没给清单签名：安装包还没签，不能装。签名在离线机器上用 bundle-sign 生成")
if signature.get("format") != "rn-machine-bundles-signature/v1":
    sys.exit("清单签名的 format 不认识：%r" % signature.get("format"))
armoured = signature.get("signature") or ""
if not armoured.lstrip().startswith("-----BEGIN SSH SIGNATURE-----"):
    sys.exit("清单签名不是一个 SSH 签名块")
with open(work + "/manifest.sig", "w") as out:
    out.write(armoured if armoured.endswith("\n") else armoured + "\n")
with open(work + "/manifest.json", "wb") as out:
    out.write(base64.b64decode(manifest_b64))

# 被签的是每字段一行的规范化字节，**不是 JSON**：JSON 的字段顺序、空白与转义有多种写法，
# 签它等于把"同一份内容的不同写法"也算进签名里。与 signing/bundlesig 逐字节一致。
# 这几个值现在还不可信——它们是拼出来喂给验签的**候选**，验过了才算数
for key in ("commit", "sequence", "manifestSha256"):
    if signature.get(key) in (None, ""):
        sys.exit("清单签名里缺 %s" % key)
with open(work + "/signed-bytes", "w") as out:
    out.write("\n".join(["rn-machine-bundles-signature/v1",
                         "commit=" + str(signature["commit"]),
                         "sequence=" + str(signature["sequence"]),
                         "manifestSha256=" + str(signature["manifestSha256"])]) + "\n")
PY
)" || die "describe 的结果不能用：$why"

  # ---- 2) 人给的指纹认出发布公钥。这是整条链子上唯一的外部输入 ----
  local got_key_sha
  got_key_sha="$(release_key_sha256 "$WORK/release-key.pub")"
  if [ "$got_key_sha" != "$RELEASE_KEY_SHA256" ]; then
    die "服务端给的发布公钥指纹是 ${got_key_sha}，与 --release-key-sha256 $RELEASE_KEY_SHA256 不符。
   这个值是公钥**字节**的摘要（bundle-sign key create / key public 打印的那一行、控制台上显示的那一个），
   不是 release-key.pub 这个文件的摘要。确认手里的值取自密码管理器；仍然不符就不要继续装。"
  fi

  # ---- 3) 用它验清单的离线签名。allowed_signers 是拿刚认过指纹的那把公钥当场生成的，
  # 只有一个签名人；namespace 写死，免得同一把密钥在别处签的东西被拿来当清单签名用 ----
  printf 'release-key %s\n' "$(cat "$WORK/release-key.pub")" > "$WORK/allowed_signers"
  if ! ssh-keygen -Y verify -f "$WORK/allowed_signers" -I release-key \
    -n rn-machine-bundles -s "$WORK/manifest.sig" \
    <"$WORK/signed-bytes" >/dev/null 2>"$WORK/verify.err"; then
    die "清单的离线签名验不过：服务端上的安装包不是那把发布密钥签出来的，拒绝安装
   ssh-keygen 说：$(tr '\n' ' ' <"$WORK/verify.err")"
  fi

  # 验过之后，signed-bytes 里的三个值才可信。清单要与其中记的摘要对上，它才是被签的那一份
  local want_manifest got_manifest
  want_manifest="$(sed -n 's/^manifestSha256=//p' "$WORK/signed-bytes")"
  got_manifest="$(sha256_of "$WORK/manifest.json")"
  if [ "$want_manifest" != "$got_manifest" ]; then
    die "服务端给的清单摘要是 ${got_manifest}，签名覆盖的是 ${want_manifest}：这不是被签的那一份清单"
  fi
  BUNDLE_COMMIT="$(sed -n 's/^commit=//p' "$WORK/signed-bytes")"
  BUNDLE_SEQUENCE="$(sed -n 's/^sequence=//p' "$WORK/signed-bytes")"

  # ---- 4) 到这里清单可信了，剩下的摘要全从它里面取 ----
  local parsed
  parsed="$(python3 -I - "$body" "$WORK/manifest.json" "$WORK/files.sha256" "$BUNDLE_NAME" "$BUNDLE_COMMIT" 2>&1 <<'PY'
# 这一段读的是**已经验过签**的清单。describe 响应里 bundle 那个对象只用来对照，不采信
import json, sys

body_path, manifest_path, files_out, want_bundle, want_commit = sys.argv[1:6]
with open(manifest_path) as f:
    manifest = json.load(f)
with open(body_path) as f:
    doc = json.load(f)

if manifest.get("format") != "rn-machine-bundles/v1":
    sys.exit("清单 format 不认识：%r" % manifest.get("format"))
if manifest.get("commit") != want_commit:
    sys.exit("清单里的提交与签名覆盖的提交不同")
bundle = (manifest.get("bundles") or {}).get(want_bundle)
if not bundle:
    sys.exit("已验签的清单里没有 %s 这一组安装包" % want_bundle)
files = bundle.get("files") or []
if not files:
    sys.exit("已验签的清单里 %s 没有文件" % want_bundle)
with open(files_out, "w") as out:
    for item in files:
        name, digest = item["name"], item["sha256"]
        if not name or ".." in name or name.startswith("/"):
            sys.exit("清单里有不该出现的文件名 %r" % name)
        out.write("%s  %s\n" % (digest, name))

# 服务端自报的那一份不一致，说明这台服务器上的清单与它回的话不是一回事，值得当场停下
said = doc.get("bundle") or {}
if said.get("archiveSha256") and said["archiveSha256"] != bundle.get("archiveSha256"):
    sys.exit("服务端自报的归档摘要与已验签清单里的不一致，拒绝安装")

print("\n".join([doc.get("name") or "", bundle.get("archive") or "",
                 bundle.get("archiveSha256") or "", str(bundle.get("archiveSize") or 0)]))
PY
)" || die "已验签的清单不能用：$parsed"
  MACHINE_NAME="$(printf '%s' "$parsed" | sed -n 1p)"
  BUNDLE_ARCHIVE="$(printf '%s' "$parsed" | sed -n 2p)"
  BUNDLE_SHA256="$(printf '%s' "$parsed" | sed -n 3p)"
  BUNDLE_SIZE="$(printf '%s' "$parsed" | sed -n 4p)"
  note "发布公钥指纹与带外给的值一致，清单的离线签名验过（序号 ${BUNDLE_SEQUENCE}）"
  note "机器 ${MACHINE_NAME}，安装包 ${BUNDLE_ARCHIVE}（提交 ${BUNDLE_COMMIT:-未知}）"
}

fetch_bundle() {
  step "下载并核对安装包"
  # 归档摘要来自已验签的清单（parse_description 里验的），不再需要人从 CI 日志抄一份
  local archive="$CACHE/$BUNDLE_ARCHIVE"
  if [ -f "$archive" ] && [ "$(sha256_of "$archive")" = "$BUNDLE_SHA256" ]; then
    note "用上次下载的 $archive"
  else
    rm -f "$archive.part"
    # 注册码走 stdin 里的 curl 配置，不进命令行参数
    if ! printf 'header = "x-enrollment-code: %s"\n' "$CODE" |
      curl_api --config - --fail --max-time 1800 -o "$archive.part" \
        "$SERVER/v1/machine-setup/bundle/$BUNDLE_NAME.tar.gz"; then
      rm -f "$archive.part"
      die "下载安装包失败（见上面 curl 的报错）"
    fi
    local size actual
    size="$(file_size_of "$archive.part")"
    actual="$(sha256_of "$archive.part")"
    if [ "$size" != "$BUNDLE_SIZE" ] || [ "$actual" != "$BUNDLE_SHA256" ]; then
      rm -f "$archive.part"
      die "下载的是 $size 字节、sha256 ${actual}，清单说是 $BUNDLE_SIZE 字节、${BUNDLE_SHA256}：拒绝安装"
    fi
    chmod 0600 "$archive.part"
    mv -f "$archive.part" "$archive"
  fi
  BUNDLE="$CACHE/bundle"
  rm -rf "$BUNDLE.new"
  install -d -o root -g wheel -m 0700 "$BUNDLE.new"
  tar --no-same-owner -xzf "$archive" -C "$BUNDLE.new" || die "安装包解不开"
  [ -z "$(find "$BUNDLE.new" -mindepth 1 ! -type f ! -type d -print -quit)" ] ||
    die "安装包里有普通文件与目录以外的东西（符号链接、设备……），拒绝安装"
  # BSD 的 shasum 没有 --strict，自己逐行核
  python3 -I - "$WORK/files.sha256" "$BUNDLE.new" <<'PY' || die "安装包里有文件与清单不符，拒绝安装"
import hashlib, os, sys
listed_path, root = sys.argv[1:3]
listed = {}
with open(listed_path) as f:
    for line in f:
        digest, name = line.rstrip("\n").split("  ", 1)
        listed[name] = digest
found = set()
for dirpath, _, names in os.walk(root):
    for name in names:
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        found.add(rel)
        if rel not in listed:
            sys.exit("安装包里多了一个清单没有的文件：%s" % rel)
        h = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != listed[rel]:
            sys.exit("%s 的 sha256 与清单不符" % rel)
missing = sorted(set(listed) - found)
if missing:
    sys.exit("清单里有安装包缺的文件：%s" % ", ".join(missing))
PY
  rm -rf "$BUNDLE"
  mv "$BUNDLE.new" "$BUNDLE"
  note "安装包核对通过（归档 sha256 ${BUNDLE_SHA256}）"
}

put_file() { # $1 源 $2 目标 $3 属主 $4 属组 $5 权限
  if [ -f "$2" ] && cmp -s "$1" "$2"; then
    chown "$3:$4" "$2"
    chmod "$5" "$2"
    return 0
  fi
  install -o "$3" -g "$4" -m "$5" "$1" "$2"
  note "已装 $2"
}

install_programs() {
  step "安装程序"
  local name
  for name in build-agent build-runner ios-upload rn-build-agent-upgrade; do
    [ -f "$BUNDLE/bin/$name" ] || die "安装包里没有 bin/$name"
    put_file "$BUNDLE/bin/$name" "$INSTALL_DIR/$name" root wheel 0755
  done
  put_file "$BUNDLE/run-agent" "$INSTALL_DIR/run-agent" root wheel 0755
  # 两把信任根。它们的完整性已经由**已验签的清单**保证（fetch_bundle 逐文件核过），
  # 所以这里不再要第二、第三个命令行参数——多两次抄写只是多两次抄错的机会。
  #
  # 归档里这一份 release-key.pub 还要再与 describe 用过的那把比一次：链子是"人给的指纹
  # 认那一把公钥"，装到机器上的必须就是它，否则这台机器以后按另一把公钥验自升级
  local key_sha
  [ -f "$BUNDLE/release-key.pub" ] || die "安装包里没有 release-key.pub；先在控制台部署一份签过的安装包"
  [ -f "$BUNDLE/allowed_signers" ] || die "安装包里没有 allowed_signers"
  key_sha="$(release_key_sha256 "$BUNDLE/release-key.pub")"
  [ "$key_sha" = "$RELEASE_KEY_SHA256" ] ||
    die "归档里发布公钥的指纹是 ${key_sha}，与 --release-key-sha256 不符。
   清单验过签、包内文件也与清单一致，却出现这个，说明签出这份清单的密钥不是运维手里的
   那一把——不该继续装。"
  put_file "$BUNDLE/release-key.pub" "$INSTALL_DIR/release-key.pub" root wheel 0644
  put_file "$BUNDLE/allowed_signers" "$INSTALL_DIR/allowed_signers" root wheel 0644
  note "两把信任根就位（发布公钥指纹 ${key_sha}）"
  if [ -f "$BUNDLE/github_known_hosts" ]; then
    put_file "$BUNDLE/github_known_hosts" "$INSTALL_DIR/github_known_hosts" root wheel 0644
  elif [ ! -f "$INSTALL_DIR/github_known_hosts" ]; then
    ssh-keyscan -t ed25519 github.com 2>/dev/null >"$WORK/known_hosts" || true
    [ -s "$WORK/known_hosts" ] || die "取不到 GitHub 的主机公钥，手工放一份到 $INSTALL_DIR/github_known_hosts"
    put_file "$WORK/known_hosts" "$INSTALL_DIR/github_known_hosts" root wheel 0644
    warn "github_known_hosts 是现取的，请与 GitHub 官方公布的指纹核对一次"
  fi
  put_file "$BUNDLE/rn-build-agent.sudoers" /etc/sudoers.d/rn-build-agent root wheel 0440
  visudo -c -f /etc/sudoers.d/rn-build-agent >/dev/null || die "sudoers 片段不合法"
  smoke_test
  # 换过程序了，上一次升级失败的记录就不再成立——它只会在控制台上一直挂着一条吓人的
  # 错。只有"升级成功"才会删它（upgrade/main.go），而这个脚本换二进制是不走升级的，
  # 真机上就这么留了一条指向已经装上的版本的失败记录。
  rm -f "$AGENT_HOME/state/upgrade-failed.json"
}

smoke_test() {
  step "冒烟"
  local code=0
  env -i "$INSTALL_DIR/build-agent" >/dev/null 2>&1 || code=$?
  [ "$code" = 2 ] || die "空环境下 build-agent 的退出码是 ${code}，应该是 2（配置不全）"
  # 必须**从控制进程那个账户**发起，不能以 root 直接切过去。self-check 会核对任务根目录属于
  # "调用 sudo 的那个人"（SUDO_UID），而生产路径里那个人正是 ${AGENT_USER}——目录也正属于它。
  # 以 root 跑的话 SUDO_UID 是 0，和目录属主永远对不上，冒烟必失败，而它验的根本不是生产路径。
  #
  # 套两层还有个好处：这一下真的走了一遍 sudoers 里那条规则，而不是绕过它（root 切谁都不需要
  # 规则）。失败时说"检查 sudoers"这才名副其实。
  local out
  out="$(sudo -n -u "$AGENT_USER" sudo -n -u "$RUNNER_USER" "$INSTALL_DIR/build-runner" self-check \
    --jobs-root "$JOBS_ROOT" --protocol 1 --expect-separated 2>&1)" ||
    die "build-runner 以 ${RUNNER_USER} 自检失败。它说：$(printf '%s' "${out}" | tr '\n' ' ')"
  note "两个程序都能跑（${out}）"
}

# ---- 6. 签名区与上传区 -----------------------------------------------------------------------

prepare_signing() {
  step "签名区与上传区"
  local keychain="$SIGNING_DIR/rn-signing.keychain-db"
  local password_file="$SIGNING_DIR/rn-signing.password"
  if [ ! -f "$password_file" ]; then
    # 口令的字母表与执行进程那侧的校验一致（只有字母数字与 _-）：带空格或引号的口令
    # 会让交给 security 的那一行被切成别的命令。
    #
    # **不能写成 `tr </dev/urandom | head -c 48`。** /dev/urandom 是无限的生产者，head 取够
    # 就退出，tr 于是吃到 SIGPIPE（141）；脚本开着 pipefail，管道的退出码变成 141，set -e
    # 当场把脚本**静默**杀掉——没有报错、没有 die，只是回到提示符。装第一台机器时就是这样
    # 停在"签名区与上传区"下面一片空白，最难查的那种。
    #
    # 脚本里别处那些 `printf … | grep -q` 不受影响：生产者只写几十字节，一次就写进管道
    # 缓冲区并退出，轮不到 SIGPIPE。区别在于生产者有没有边界。
    local password
    password="$(LC_ALL=C tr -dc 'A-Za-z0-9_-' < <(dd if=/dev/urandom bs=1024 count=8 2>/dev/null))"
    password="${password:0:48}"
    [ "${#password}" = 48 ] || die "生成不出钥匙串口令"
    printf '%s\n' "${password}" >"$WORK/keychain-password"
    install -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0600 "$WORK/keychain-password" "$password_file"
    note "已生成钥匙串口令 $password_file"
  fi
  if [ ! -f "$keychain" ]; then
    sudo -n -u "$RUNNER_USER" /usr/bin/security -i <<EOF || die "建不出签名钥匙串"
create-keychain -p $(cat "$password_file") $keychain
set-keychain-settings $keychain
EOF
    note "已建签名钥匙串 $keychain"
  fi
  chown "$RUNNER_USER:$RUNNER_USER" "$keychain" "$password_file" 2>/dev/null || true
  chmod 0600 "$keychain" "$password_file" 2>/dev/null || true
  ensure_wwdr_intermediate
  ensure_system_keychain_search_list "$keychain"
  cat <<EOF

   下面这些**由人放**，脚本不碰（设计 §4.4）：
     1. 每个 Team 的 Apple Distribution 证书（.p12）导进 ${keychain}：
          sudo -u $RUNNER_USER security unlock-keychain -p "\$(sudo cat $password_file)" $keychain
        （重启之后钥匙串是锁着的，不先解锁 import 只会说 User interaction is not allowed）
          sudo -u $RUNNER_USER security import <证书>.p12 -k $keychain -T /usr/bin/codesign
          sudo -u $RUNNER_USER security set-key-partition-list -S apple-tool:,apple: \\
               -s -k "\$(sudo cat $password_file)" $keychain
        （最后这一步不做的话，codesign 第一次用会弹 UI 授权，而这台机器没有图形会话）
     2. 每个 App 的 App Store 描述文件放
          $SIGNING_DIR/profiles/<TEAMID>/<bundle id>.mobileprovision   （$RUNNER_USER 0600）
     3. 这台机器在每个 Team 的上传 Key：
          $UPLOAD_DIR/<TEAMID>/key.json           {"issuerId":"…","keyId":"…"}
          $UPLOAD_DIR/<TEAMID>/AuthKey_<KEYID>.p8                      （$UPLOAD_USER 0600）
   放好之后重启代理，控制台上这台机器就会报出它能打哪些 Team 的包。
EOF
  install_material_keys
}

# ensure_wwdr_intermediate 把 Apple WWDR G3 中间证书装进系统钥匙串。
#
# 签名钥匙串里本来就有一份（材料归档带着），但**信任评估不用它**：2026-09-23 mac-01 上，
# 只用本机证书验叶子证书（`security verify-cert -p codeSign -L`）报 CSSMERR_TP_NOT_TRUSTED，
# 放开网络才过——系统是按证书里的 AIA 地址现下载的中间证书。家用网络一抖、下载失败，
# Xcode 就判"没有有效的签名证书"，一次 archive 白跑。装进系统钥匙串之后 `-L` 也过。
#
# 中间证书是公开的，装进系统钥匙串不新增任何信任根（它自己还要链到系统里的 Apple Root CA）。
ensure_wwdr_intermediate() {
  local cert="$BUNDLE/$WWDR_G3_FILE" out
  if [ ! -f "$cert" ]; then
    warn "安装包里没有 ${WWDR_G3_FILE}（旧版安装包）。手工补一次：
     curl -fsSLo /tmp/${WWDR_G3_FILE} https://www.apple.com/certificateauthority/${WWDR_G3_FILE}
     shasum -a 256 /tmp/${WWDR_G3_FILE}     # 应为 ${WWDR_G3_SHA256}
     sudo security add-certificates -k ${SYSTEM_KEYCHAIN} /tmp/${WWDR_G3_FILE}"
    return 0
  fi
  [ "$(sha256_of "$cert")" = "$WWDR_G3_SHA256" ] ||
    die "安装包里的 ${WWDR_G3_FILE} 摘要不对（应为 ${WWDR_G3_SHA256}）。清单验过签还出现这个，不该继续装"
  if out="$(/usr/bin/security add-certificates -k "$SYSTEM_KEYCHAIN" "$cert" 2>&1)"; then
    note "Apple WWDR G3 中间证书已装进系统钥匙串"
  elif printf '%s' "$out" | grep -qi 'already exists'; then
    note "Apple WWDR G3 中间证书已在系统钥匙串里"
  else
    die "装不进 Apple WWDR G3 中间证书：$out"
  fi
}

# ensure_system_keychain_search_list 把签名钥匙串加进**系统域**的钥匙串搜索列表。
#
# 代理是 LaunchDaemon，那个会话里 Security 框架只读系统域的列表：用户域的
# `list-keychains -d user`、`default-keychain -d user` 设了、回读也对，生效的那份
# （不带 -d）却只有 System.keychain，于是 Xcode 找不到证书（2026-09-23 build 20–25 一路查到
# 的）。桌面终端里 `sudo -u _rnbuilder` 读的是用户域，所以在那里复现不出来。
#
# 这只让后台进程**知道**有这个钥匙串：文件仍是 _rnbuilder 0600，别的账户打不开。
# 原有条目原样保留，签名钥匙串追加在后面；已经在列表里就什么也不做。
ensure_system_keychain_search_list() { # $1 签名钥匙串
  local keychain="$1" listed line
  listed="$(/usr/bin/security list-keychains -d system)" || die "读不出系统域的钥匙串搜索列表"
  listed="$(printf '%s\n' "$listed" | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')"
  # security 打印的是解析过符号链接的路径（/var → /private/var），两种写法都认
  if printf '%s\n' "$listed" | grep -qxF -e "$keychain" -e "/private$keychain"; then
    note "签名钥匙串已在系统域的钥匙串搜索列表里"
    return 0
  fi
  set --
  while IFS= read -r line; do
    [ -n "$line" ] && set -- "$@" "$line"
  done <<<"$listed"
  [ $# -gt 0 ] || set -- "$SYSTEM_KEYCHAIN"
  /usr/bin/security list-keychains -d system -s "$@" "$keychain" ||
    die "签名钥匙串加不进系统域的钥匙串搜索列表"
  note "签名钥匙串已加进系统域的钥匙串搜索列表（后台构建靠它找到签名证书）"
}

# install_material_keys 装那两把**材料私钥**，并打印各自的公钥指纹让人与控制台核对。
#
# 有了它们，上面那三样就不用人逐台放了：平台在控制台上传一次密文，这台机器自己取、自己解、
# 自己装（设计 ios-signing-material-distribution-2026-09-19）。私钥从密码管理器来，
# **不从服务端来**——服务端只转发它读不懂的密文，这是整套设计的前提。
install_material_keys() {
  if [ -z "$MATERIAL_KEY_BUILDER" ] && [ -z "$MATERIAL_KEY_UPLOADER" ]; then
    note "没给材料私钥（--material-key-builder / --material-key-uploader）：
   这台机器不会自动收证书与上传 Key，上面那三样按运维手册第 1.3 节人工放。"
    return 0
  fi
  put_material_key "$MATERIAL_KEY_BUILDER" "$RUNNER_USER" "$SIGNING_DIR/material-key.x25519" "构建账户"
  put_material_key "$MATERIAL_KEY_UPLOADER" "$UPLOAD_USER" "$UPLOAD_DIR/material-key.x25519" "上传账户"
  # 指纹要与控制台上登记的那两把**对得上**。对不上的表现否则是"材料下来了但解不开"，
  # 而那条错要等第一次下发才出现，还容易被当成服务端的问题
  # 算不出来的时候要让人看见**为什么**：这两条的 stderr 不吞。吞掉它换来的是一句
  # "（算不出来）"，而装机现场唯一能判断的线索正好在那条错误里——show-key 就这样查过一轮
  local builder_fp uploader_fp
  if [ -n "$MATERIAL_KEY_BUILDER" ]; then
    builder_fp="$(sudo -n -u "$RUNNER_USER" "$INSTALL_DIR/build-runner" material-key-fingerprint \
      --signing-dir "$SIGNING_DIR")" || builder_fp=""
  fi
  if [ -n "$MATERIAL_KEY_UPLOADER" ]; then
    uploader_fp="$(sudo -n -u "$UPLOAD_USER" "$INSTALL_DIR/ios-upload" --material-key-fingerprint \
      --keys "$UPLOAD_DIR")" || uploader_fp=""
  fi
  cat <<EOF

   这两个指纹要与控制台「平台维护 → Apple 证书与密钥 → 平台加密公钥」上登记的那两把**一致**，
   不一致就是私钥放错了——那台机器会取到材料但解不开：
     构建账户 ${builder_fp:-（算不出来，看上面有没有报错）}
     上传账户 ${uploader_fp:-（算不出来，看上面有没有报错）}
EOF
}

# put_material_key 把一把材料私钥装到对应账户名下，并把它的**公钥指纹**打出来。
#
# 指纹由对应的程序算（它们读得到自己那把私钥），不在这个脚本里算：算它要做一次标量乘法，
# 而这个脚本的第一环是"人能把它从头读一遍"——一段曲线运算没人读得动（见文件开头那段）。
put_material_key() {
  local source="$1" account="$2" target="$3" label="$4"
  [ -n "$source" ] || return 0
  install -o "$account" -g "$account" -m 0600 "$source" "$target" ||
    die "装不上 ${label} 的材料私钥"
  # 装完不动源文件：它是人放上来的，删别人的文件不是这个脚本该做的事。但要提醒——
  # 一把明文私钥留在 /tmp 或某个用户的家目录里，比放在这台机器上那份还容易被顺走
  note "已装 ${label} 的材料私钥 ${target}（${account} 0600）
   源文件 ${source} 还在，装完请自行删掉。"
}

# ---- 7. env 与注册 ---------------------------------------------------------------------------

write_env() {
  step "env 文件"
  if [ -f "$ENV_FILE" ]; then
    note "$ENV_FILE 已存在，不覆盖（要改配置就直接编辑它）"
  else
    cat >"$WORK/env" <<EOF
BUILD_AGENT_SERVER=$SERVER
BUILD_AGENT_MACHINE_TOKEN=
BUILD_AGENT_REPO=$AGENT_HOME/repos/rn-app.git
BUILD_AGENT_WORKSPACE=$JOBS_ROOT
BUILD_AGENT_STATE_DIR=$AGENT_HOME/state
BUILD_AGENT_SSH_KEY=$AGENT_HOME/.ssh/id_ed25519
BUILD_AGENT_SSH_KNOWN_HOSTS=$INSTALL_DIR/github_known_hosts
BUILD_AGENT_PLATFORMS=ios
BUILD_AGENT_TIMEOUT_MINUTES=120
BUILD_AGENT_RUNNER=$INSTALL_DIR/build-runner
BUILD_AGENT_RUNNER_USER=$RUNNER_USER
BUILD_AGENT_ALLOWED_SIGNERS=$INSTALL_DIR/allowed_signers
RN_IOS_SIGNING_DIR=$SIGNING_DIR
BUILD_AGENT_IOS_UPLOAD=true
BUILD_AGENT_IOS_UPLOADER=$INSTALL_DIR/ios-upload
BUILD_AGENT_IOS_UPLOAD_USER=$UPLOAD_USER
BUILD_AGENT_IOS_UPLOAD_KEYS=$UPLOAD_DIR
BUILD_AGENT_MIN_FREE_GB=40
PATH=$BUILD_PATH
LANG=en_US.UTF-8
# 出网代理。**默认注释掉**：直连能用就别加这一层。
#
# 什么时候需要它：构建要从公网取东西，而 CocoaPods 装**每一个** pod 都是去 clone 它的
# git 源（trunk 上的 podspec 写的就是 source: {git: …, tag: …}）。家用网络上 github.com
# 的 443 常常连不通；上传 TestFlight 要连 api.appstoreconnect.apple.com，家用网络上
# 可能整个连不上（2026-09-23 mac-01：TCP 超时）。
#
# **只写这一个键**。代理会把它展开成构建工具要的大小写两套变量、传给上传程序的参数
# （上传程序经 sudo 启动，环境变量进不去），这里直接写 HTTPS_PROXY 之类会被拒绝启动。
# 服务端（BUILD_AGENT_SERVER 的主机）总是直连，不用写进 NO_PROXY。
# 地址里**不许带账号口令**——这个值对构建进程可读，而那里跑着第三方依赖的代码。
#BUILD_AGENT_PROXY=http://127.0.0.1:7897
#BUILD_AGENT_NO_PROXY=anyfun.win
EOF
    # env 文件属于控制进程那个账户，不是 root：launchd 在 exec 之前就切用户，
    # root 0600 的文件它读不到（§4.1）
    install -o "$AGENT_USER" -g "$AGENT_USER" -m 0600 "$WORK/env" "$ENV_FILE"
    note "已写 $ENV_FILE"
  fi
}

enroll_machine() {
  step "注册"
  if grep -q '^BUILD_AGENT_MACHINE_TOKEN=rnm_' "$ENV_FILE" 2>/dev/null; then
    note "这台机器已经注册过，跳过（注册码不消耗）"
    return 0
  fi
  # 注册码经环境变量 RN_ENROLLMENT_CODE 交给 enroll，**不进命令行参数**：本机其他用户
  # `ps` 就能看到别人的命令行。以 root 跑（sudo 到别的用户会把这个变量带进 argv），
  # 跑完把生成的东西归还给控制进程那个账户——launchd 在 exec 之前就切用户，root 拥有的
  # env 文件与出处密钥它一个都读不到
  RN_ENROLLMENT_CODE="$CODE" "$INSTALL_DIR/build-agent" enroll \
    --server "$SERVER" --env-file "$ENV_FILE" --state-dir "$AGENT_HOME/state" ||
    die "注册失败（注册码过期或已用过就到控制台重发）"
  chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_HOME"
  chmod 0600 "$ENV_FILE"
  chmod 0700 "$AGENT_HOME" "$AGENT_HOME/state"
  note "已注册，机器令牌写进了 ${ENV_FILE}（这个脚本没有读它）"
}

# ---- 8. 仓库镜像 -----------------------------------------------------------------------------

# 装机要在这里停一次：deploy key 是这台机器现场生成的，GitHub 上还没有它，而脚本没有
# 任何办法替人去加。停下来印出公钥，人加完再执行同一条命令——那一次就该真的克隆。
#
# 返回 0 = 镜像就位，继续往下装；返回 1 = 印过公钥了，等人加完再来。
ensure_mirror() {
  step "仓库镜像"
  local key="$AGENT_HOME/.ssh/id_ed25519" fresh=0
  if [ ! -f "$key" ]; then
    sudo -n -u "$AGENT_USER" ssh-keygen -q -t ed25519 -N '' -C "rn-build-agent@$MACHINE_NAME" -f "$key" ||
      die "生成 deploy key 失败"
    note "已生成这台机器的 deploy key"
    fresh=1
  fi
  if [ -d "$AGENT_HOME/repos/rn-app.git" ]; then
    note "仓库镜像已存在"
    normalize_mirror_config
    return 0
  fi
  # 这一轮刚生成的 key 不可能已经在 GitHub 上，别拿一次必然失败的克隆去浪费人的时间；
  # key 是上一轮留下的，就说明人这一趟是加完回来的，该克隆了
  if [ "$fresh" = 0 ] && clone_mirror; then
    normalize_mirror_config
    return 0
  fi
  cat <<EOF

   这台机器的 deploy key（只读）还没加到 GitHub。把下面这一行加进 RN-App 仓库的
   Settings → Deploy keys（不要勾 Allow write access），然后**重新执行同一条命令**，
   脚本会克隆镜像并把服务起起来：

$(cat "$key.pub")

EOF
  return 1
}

# 防护与 Linux 那台构建机一模一样（install.sh 里的同一段）：
#
#   - 先克隆到 .part 再改名。半个目录只可能叫 .part，rn-app.git 要么完整要么不存在——
#     不然下一次执行会把残缺的仓库当成"镜像已存在"跳过去，错要到跑任务时才冒出来，而且
#     看着跟装机毫无关系；
#   - env -i：本机其他用户设的 GIT_* 一个都别带进来；
#   - 不读系统与全局 git 配置、不跑 hook、不用模板目录（模板里的 hook 会以 _rnbuildagent
#     的身份执行）、除 ssh 之外什么协议都不许、终端不许弹提示（这台机器没人盯着）。
# macOS 上 git clone 会往镜像的 config 里写 core.ignorecase 与 core.precomposeunicode
# （文件系统属性）。代理只认一张白名单，多一个键就判"镜像配置不可信"、一条任务都不领。
#
# 为什么由装机脚本摘、而不是只等代理放宽：代理来自**安装包**，它那张名单是哪一版由安装包
# 决定，而安装包要等平台签一版新清单、再走一遍升级才换得掉；这个脚本是服务端当场下发的。
# 摘掉是安全的——裸仓库没有工作区，这两个键对 fetch 没有任何作用。
normalize_mirror_config() {
  local repo="$AGENT_HOME/repos/rn-app.git" key
  for key in core.ignorecase core.precomposeunicode; do
    if sudo -n -u "$AGENT_USER" git --git-dir="$repo" config --local --get "$key" >/dev/null 2>&1; then
      sudo -n -u "$AGENT_USER" git --git-dir="$repo" config --local --unset-all "$key" ||
        die "摘不掉镜像 config 里的 ${key}"
      note "已从镜像 config 摘掉 ${key}（macOS 上 git 自己写的，代理的白名单里没有）"
    fi
  done
}

clone_mirror() {
  step "克隆仓库镜像"
  local part="$AGENT_HOME/repos/rn-app.git.part"
  sudo -n -u "$AGENT_USER" rm -rf "$part"
  if sudo -n -u "$AGENT_USER" env -i \
    PATH="$PATH" HOME="$AGENT_HOME" LANG=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    GIT_SSH_COMMAND="ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -i $AGENT_HOME/.ssh/id_ed25519 -o UserKnownHostsFile=$INSTALL_DIR/github_known_hosts -o StrictHostKeyChecking=yes" \
    git -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.ssh.allow=always \
    clone --mirror --template= git@github.com:Helix2010/RN-App.git "$part" &&
    sudo -n -u "$AGENT_USER" chmod 0700 "$part" &&
    sudo -n -u "$AGENT_USER" chmod -R go-w "$part" &&
    sudo -n -u "$AGENT_USER" mv "$part" "$AGENT_HOME/repos/rn-app.git"; then
    note "镜像已克隆"
    return 0
  fi
  sudo -n -u "$AGENT_USER" rm -rf "$part"
  warn "克隆没成（上面是 git 的原话）。Permission denied (publickey) 就是 deploy key 还没加上或者加错了仓库；
   连不上 github.com 是网络；Host key verification failed 是安装包里的 github_known_hosts 与 GitHub 现在的主机密钥对不上"
  return 1
}

# ---- 9. 常驻 ---------------------------------------------------------------------------------

# plist_value 读 plist 里的一个键；没有这个键回空串。
plist_value() {
  /usr/bin/plutil -extract "$2" raw -o - "$1" 2>/dev/null || true
}

# ensure_daemon_logs 把 plist 写明的日志文件先建出来，属主是这个 job 将要用的账户。
#
# 非建不可：launchd 在 exec **之前**就切到 UserName，**建 StandardOutPath 用的也是那个
# 身份**。/var/log 是 root:wheel 0755，_rnbuildagent 在里面建不出文件，于是 launchd 判定
# 这个 job 不可用、以 EX_CONFIG(78) 收场——程序一行都没跑过，日志文件也不存在，屏幕上、
# 日志里、状态目录里都没有任何线索，只有 `launchctl print` 里一个 78 和不断长大的 runs。
#
# 路径与账户都从 plist 里读，不写死：plist 来自**安装包**，而这个脚本是服务端单独下发的，
# 两者可以不同版本（describe 走缓存时装的就是旧安装包）。写死等于赌它们一致。
ensure_daemon_logs() {
  local plist="$1" user group key path dir
  user="$(plist_value "$plist" UserName)"
  group="$(plist_value "$plist" GroupName)"
  [ -n "$user" ] || user=root
  [ -n "$group" ] || group=wheel
  for key in StandardOutPath StandardErrorPath; do
    path="$(plist_value "$plist" "$key")"
    if [ -z "$path" ]; then
      die "读不出 ${plist} 的 ${key}。没有它就没法把日志文件按 job 的身份先建好，而 launchd
   会以 EX_CONFIG(78) 失败且不留任何线索。确认 /usr/bin/plutil 能读这个文件。"
    fi
    if [ -e "$path" ]; then
      # 已经在了：内容一个字不动（重复执行不该清掉正在被人读的日志），但属主要摆正——
      # 属主不对的话 launchd 打不开它，照样是 78
      chown "$user:$group" "$path" || die "改不了 ${path} 的属主"
      chmod 0640 "$path"
      continue
    fi
    dir="$(dirname "$path")"
    [ -d "$dir" ] || install -d -o root -g wheel -m 0755 "$dir"
    install -o "$user" -g "$group" -m 0640 /dev/null "$path" ||
      die "建不出日志文件 $path"
    note "已建日志文件 ${path}（${user}:${group}）"
  done
}

install_daemons() {
  step "常驻"
  put_file "$BUNDLE/$AGENT_LABEL.plist" "/Library/LaunchDaemons/$AGENT_LABEL.plist" root wheel 0644
  put_file "$BUNDLE/$UPGRADE_LABEL.plist" "/Library/LaunchDaemons/$UPGRADE_LABEL.plist" root wheel 0644
  ensure_daemon_logs "/Library/LaunchDaemons/$AGENT_LABEL.plist"
  ensure_daemon_logs "/Library/LaunchDaemons/$UPGRADE_LABEL.plist"
  # 停机标记在的话代理不会被拉起来：装机时它不该存在（升级或吊销之后由对应的流程删）
  if [ -f "$AGENT_HOME/state/halt" ]; then
    warn "$AGENT_HOME/state/halt 还在：代理不会启动。确认这台机器不是被吊销的，再删掉它"
  fi
  local label
  for label in "$AGENT_LABEL" "$UPGRADE_LABEL"; do
    launchctl bootout "system/$label" >/dev/null 2>&1 || true
    launchctl bootstrap system "/Library/LaunchDaemons/$label.plist" ||
      die "launchctl bootstrap $label 失败"
  done
  note "已加载 $AGENT_LABEL 与 $UPGRADE_LABEL"
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$AGENT_HOME/state/runner-mode.json" ]; then
      break
    fi
    sleep 2
  done
  if [ ! -f "$AGENT_HOME/state/runner-mode.json" ]; then
    warn "代理还没写出 state/runner-mode.json。
   先看日志：sudo tail -n 40 $(plist_value "/Library/LaunchDaemons/$AGENT_LABEL.plist" StandardOutPath)
   日志是空的或者不存在，就看 launchd 那边：sudo launchctl print system/$AGENT_LABEL
     last exit code = 78 (EX_CONFIG)：launchd 自己没能把 job 摆起来（程序一行没跑），
       多半是日志文件或程序路径的属主/权限不对；
     last exit code = 2：程序跑了但配置不全，日志里有具体是哪一项。"
  fi
}

finish() {
  step "装好了"
  # 必须切到控制进程那个账户：出处密钥与状态目录归它，而 build-agent 认的是"跑它的人就得是
  # 属主"（checkPrivate 用 geteuid）。以 root 跑 show-key 会以"state 必须属于 uid 0"失败，
  # 而下面那句写着"核对**上面**这个 sha256"——上面什么都没有。
  #
  # 也不许把 stderr 丢掉：这一行印不出来，人就没得核对，得当场看见是为什么。
  if ! sudo -n -u "$AGENT_USER" "$INSTALL_DIR/build-agent" show-key --state-dir "$AGENT_HOME/state"; then
    warn "show-key 没能打印出处公钥指纹（上面是它的原话）。
   指纹在注册那一步也打过一次（provenance public key sha256），往上翻；
   或者装完之后自己跑：sudo -u $AGENT_USER $INSTALL_DIR/build-agent show-key --state-dir $AGENT_HOME/state"
  fi
  cat <<EOF

   接下来（都在控制台 平台维护 → 构建机）：
     1. 核对上面这个出处公钥 sha256，点「接受」——没接受之前这台机器不领任务；
     2. 按第 6 步的提示放证书、描述文件与上传 Key，然后
          sudo launchctl kickstart -k system/$AGENT_LABEL
     3. 机器卡片上每个租户的 Team 都不标黄之后，排一条测试任务。

   日志：/var/log/rn-build-agent.log、/var/log/rn-build-agent-upgrade.log
EOF
}

main() {
  parse_args "$@"
  preflight
  WORK="$(mktemp -d /tmp/rn-install-macos.XXXXXX)"
  trap 'rm -rf "$WORK"' EXIT
  chmod 0700 "$WORK"
  system_settings
  check_filevault
  ensure_accounts
  describe
  fetch_bundle
  install_programs
  prepare_signing
  write_env
  enroll_machine
  if ! ensure_mirror; then
    note "加完 deploy key 之后重新执行同一条命令"
    exit 0
  fi
  install_daemons
  finish
}

main "$@"
exit
