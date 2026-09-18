#!/usr/bin/env bash
# Mac 打包机安装脚本。服务端 GET /v1/machine-setup/install-macos.sh 原样下发（go:embed）。
#
#   curl -fsSLo install-macos.sh <API>/v1/machine-setup/install-macos.sh
#   shasum -a 256 install-macos.sh            # 与 CI 日志「Build machine bundles」那一步的值比
#   sudo bash install-macos.sh --server <API> --code rne_… \
#        --expect-sha256 <CI 日志里 builder-darwin-arm64.tar.gz 的 sha256> \
#        --release-key-sha256 <密码管理器里发布公钥的 sha256> \
#        --allowed-signers-sha256 <密码管理器里 allowed_signers 的 sha256>
#
# **首次装机是一次对服务端的信任**：脚本本身、安装包、两把要钉死的公钥都来自服务端。
# 所以那三样东西必须从带外渠道核对，缺参数就拒绝——不给"先装上以后再说"的选项：
# 装上之后再补，中间那一段时间这台机器已经在按服务端说的做事了，而它手上有全部租户的
# 签名材料。
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
PATH=/usr/bin:/bin:/usr/sbin:/sbin
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

SERVER=""
CODE=""
EXPECT_SHA256=""
RELEASE_KEY_SHA256=""
ALLOWED_SIGNERS_SHA256=""
CURL_PROTO="=https"
WORK=""
CACHE=""
BUNDLE=""
BUNDLE_ARCHIVE=""
BUNDLE_SHA256=""
BUNDLE_SIZE=""
BUNDLE_COMMIT=""
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
       --expect-sha256 <归档 sha256> \
       --release-key-sha256 <发布公钥 sha256> \
       --allowed-signers-sha256 <allowed_signers sha256>

四个核对值都是必填的，都要从带外渠道拿：
  --expect-sha256           CI 日志「Build machine bundles」那一步打印的 builder-darwin-arm64.tar.gz
  --release-key-sha256      密码管理器里记的发布公钥指纹（自升级的信任根）
  --allowed-signers-sha256  密码管理器里记的 allowed_signers 指纹（提交签名的信任根）

首次装机是一次对服务端的信任：脚本、安装包与这两把公钥都来自服务端，只有这几个值是
从别处来的。它们是这台机器唯一不依赖服务端的判据。
USAGE
  exit 2
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --server) SERVER="${2:-}"; shift 2 ;;
      --code) CODE="${2:-}"; shift 2 ;;
      --expect-sha256) EXPECT_SHA256="${2:-}"; shift 2 ;;
      --release-key-sha256) RELEASE_KEY_SHA256="${2:-}"; shift 2 ;;
      --allowed-signers-sha256) ALLOWED_SIGNERS_SHA256="${2:-}"; shift 2 ;;
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
  case "$CODE" in rne_*) ;; *) die "--code 看起来不是控制台发的注册码（rne_ 开头）" ;; esac
  local value
  for value in "$EXPECT_SHA256" "$RELEASE_KEY_SHA256" "$ALLOWED_SIGNERS_SHA256"; do
    printf '%s' "$value" | grep -Eq '^[0-9a-f]{64}$' ||
      die "--expect-sha256、--release-key-sha256、--allowed-signers-sha256 三个都必须给，且是 64 位小写十六进制。这三个值是这台机器唯一不依赖服务端的判据，见 --help"
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
# 了攻击。文件里是 base64 加一个换行，先解回原始字节再算。
release_key_sha256() {
  local sum
  sum="$(/usr/bin/openssl base64 -d -A <"$1" | /usr/bin/shasum -a 256)"
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
  need_commands curl python3 shasum tar git node pnpm pod xcodebuild xcrun security sysadminctl dseditgroup launchctl

  if command -v xcodebuild >/dev/null 2>&1; then
    xcodebuild -version >/dev/null 2>&1 ||
      MISSING+=("xcodebuild 跑不起来：先 sudo xcodebuild -license accept 与 sudo xcodebuild -runFirstLaunch")
    # App Store 装的 Xcode 会静默升级，破坏「几台 Mac 同一个 Xcode」这条约定（§5.3）
    local xcode_path
    xcode_path="$(xcode-select -p 2>/dev/null || true)"
    case "$xcode_path" in
      /Applications/Xcode*.app/*) ;;
      *) MISSING+=("xcode-select 指向 $xcode_path，不像一个用 xip 装好的 Xcode（不要用 App Store 装：它会静默升级）") ;;
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
        *) MISSING+=("$tool 装在 $(command -v "$tool")，不在交给执行进程的 PATH（$BUILD_PATH）里") ;;
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
  # 睡着的 Mac 领不到任务，正在构建时睡着会让心跳超时、任务被回收重排
  pmset -c sleep 0 disksleep 0 >/dev/null 2>&1 || warn "pmset 设置失败，手工确认电源设置"
  if pmset -g custom 2>/dev/null | grep -q disablesleep; then
    pmset -b disablesleep 1 >/dev/null 2>&1 || true
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

ensure_role_account() { # $1 用户名
  if dscl . -read "/Users/$1" >/dev/null 2>&1; then
    note "账户 $1 已存在"
    return 0
  fi
  sysadminctl -addUser "$1" -fullName "$1" -home /var/empty -shell /usr/bin/false -roleAccount >/dev/null 2>&1 ||
    die "建不出角色账户 $1"
  # 角色账户不该能登录：口令随机且不可用，隐藏出登录窗口
  dscl . -create "/Users/$1" IsHidden 1 >/dev/null 2>&1 || true
  note "已建角色账户 $1"
}

ensure_accounts() {
  step "账户与目录"
  ensure_role_account "$AGENT_USER"
  ensure_role_account "$RUNNER_USER"
  ensure_role_account "$UPLOAD_USER"
  if ! dseditgroup -o read "$JOBS_GROUP" >/dev/null 2>&1; then
    dseditgroup -o create "$JOBS_GROUP" >/dev/null 2>&1 || die "建不出组 $JOBS_GROUP"
  fi
  local user
  for user in "$AGENT_USER" "$RUNNER_USER" "$UPLOAD_USER"; do
    dseditgroup -o edit -a "$user" -t user "$JOBS_GROUP" >/dev/null 2>&1 || true
  done
  install -d -o root -g wheel -m 0755 "$INSTALL_DIR"
  install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$AGENT_HOME" "$AGENT_HOME/state" "$AGENT_HOME/repos" "$AGENT_HOME/.ssh"
  # 任务根目录 setgid：三个账户都在组里，执行进程建出来的文件仍然属于这个组
  install -d -o "$AGENT_USER" -g "$JOBS_GROUP" -m 2750 "$JOBS_ROOT"
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0700 "$SIGNING_DIR" "$SIGNING_DIR/profiles"
  install -d -o "$UPLOAD_USER" -g "$UPLOAD_USER" -m 0700 "$UPLOAD_DIR"
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
    if [ -f "$CACHE/describe.json" ]; then
      warn "describe 返回 $status，用第一次执行时留下的结果继续（注册码可能已经用过）"
      cp "$CACHE/describe.json" "$body"
    else
      die "describe 返回 $status：注册码过期或已用过就到控制台重发一个"
    fi
  else
    install -d -o root -g wheel -m 0700 "$SETUP_ROOT" "$CACHE"
    install -o root -g wheel -m 0600 "$body" "$CACHE/describe.json"
  fi
  parse_description "$body"
}

parse_description() {
  local parsed
  parsed="$(python3 -I - "$1" "$WORK/files.sha256" "$BUNDLE_NAME" <<'PY'
import json, sys
path, files_out, want_bundle = sys.argv[1:4]
with open(path) as f:
    doc = json.load(f)
bundle = doc.get("bundle") or {}
role = doc.get("role")
machine_os = doc.get("os")
if role != "builder":
    sys.exit("这个注册码是给 %s 的，不是 Mac 打包机" % role)
if machine_os != "darwin":
    sys.exit("这台机器在控制台里登记的是 %s，不是 macOS：新建机器时要选 macOS" % machine_os)
if bundle.get("role") != want_bundle:
    sys.exit("服务端要给的安装包是 %s，不是 %s" % (bundle.get("role"), want_bundle))
files = bundle.get("files") or []
if not files:
    sys.exit("安装包清单里没有文件")
with open(files_out, "w") as out:
    for item in files:
        name, digest = item["name"], item["sha256"]
        if not name or ".." in name or name.startswith("/"):
            sys.exit("安装包清单里有不该出现的文件名 %r" % name)
        out.write("%s  %s\n" % (digest, name))
print("\n".join([doc.get("name") or "", bundle.get("archive") or "", bundle.get("archiveSha256") or "",
                 str(bundle.get("archiveSize") or 0), doc.get("commit") or bundle.get("commit") or ""]))
PY
)" || die "describe 的结果不能用：$parsed"
  MACHINE_NAME="$(printf '%s' "$parsed" | sed -n 1p)"
  BUNDLE_ARCHIVE="$(printf '%s' "$parsed" | sed -n 2p)"
  BUNDLE_SHA256="$(printf '%s' "$parsed" | sed -n 3p)"
  BUNDLE_SIZE="$(printf '%s' "$parsed" | sed -n 4p)"
  BUNDLE_COMMIT="$(printf '%s' "$parsed" | sed -n 5p)"
  note "机器 $MACHINE_NAME，安装包 $BUNDLE_ARCHIVE（提交 ${BUNDLE_COMMIT:-未知}）"
}

fetch_bundle() {
  step "下载并核对安装包"
  [ "$EXPECT_SHA256" = "$BUNDLE_SHA256" ] ||
    die "服务端清单里的归档 sha256 是 $BUNDLE_SHA256，与 --expect-sha256 $EXPECT_SHA256 不符，拒绝安装"
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
      die "下载的是 $size 字节、sha256 $actual，清单说是 $BUNDLE_SIZE 字节、$BUNDLE_SHA256：拒绝安装"
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
  note "安装包核对通过（归档 sha256 $BUNDLE_SHA256）"
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
  # 两把信任根：**与命令行给的 sha256 比对**，不符即停。它们是这台机器唯一不依赖服务端
  # 的判据——发布公钥决定它肯装哪一版程序，allowed_signers 决定它肯构建谁签的提交
  local key_sha signers_sha
  [ -f "$BUNDLE/release-key.pub" ] || die "安装包里没有 release-key.pub；先在控制台部署一份签过的安装包"
  [ -f "$BUNDLE/allowed_signers" ] || die "安装包里没有 allowed_signers"
  key_sha="$(release_key_sha256 "$BUNDLE/release-key.pub")"
  signers_sha="$(sha256_of "$BUNDLE/allowed_signers")"
  [ "$key_sha" = "$RELEASE_KEY_SHA256" ] ||
    die "安装包里发布公钥的 sha256 是 $key_sha，与 --release-key-sha256 不符。
   这个值是**公钥字节**的摘要（bundle-sign key create 打印的那一行、控制台上显示的那一个），
   不是 release-key.pub 这个文件的摘要——先确认手里的值取自密码管理器里记的那一条。
   确认无误还不符，那么要么服务端上的安装包被换过，要么这不是同一把密钥,两种都不该继续装。"
  [ "$signers_sha" = "$ALLOWED_SIGNERS_SHA256" ] ||
    die "安装包里的 allowed_signers sha256 是 $signers_sha，与 --allowed-signers-sha256 不符，拒绝安装"
  put_file "$BUNDLE/release-key.pub" "$INSTALL_DIR/release-key.pub" root wheel 0644
  put_file "$BUNDLE/allowed_signers" "$INSTALL_DIR/allowed_signers" root wheel 0644
  note "两把公钥的指纹与带外给的值一致"
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
}

smoke_test() {
  step "冒烟"
  local code=0
  env -i "$INSTALL_DIR/build-agent" >/dev/null 2>&1 || code=$?
  [ "$code" = 2 ] || die "空环境下 build-agent 的退出码是 $code，应该是 2（配置不全）"
  sudo -n -u "$RUNNER_USER" "$INSTALL_DIR/build-runner" self-check \
    --jobs-root "$JOBS_ROOT" --protocol 1 --expect-separated >/dev/null ||
    die "build-runner 以 $RUNNER_USER 自检失败：检查 sudoers 与 $JOBS_ROOT 的权限"
  note "两个程序都能跑"
}

# ---- 6. 签名区与上传区 -----------------------------------------------------------------------

prepare_signing() {
  step "签名区与上传区"
  local keychain="$SIGNING_DIR/rn-signing.keychain-db"
  local password_file="$SIGNING_DIR/rn-signing.password"
  if [ ! -f "$password_file" ]; then
    # 口令的字母表与执行进程那侧的校验一致（只有字母数字与 _-）：带空格或引号的口令
    # 会让交给 security 的那一行被切成别的命令
    LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 48 >"$WORK/keychain-password"
    printf '\n' >>"$WORK/keychain-password"
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
  cat <<EOF

   下面这些**由人放**，脚本不碰（设计 §4.4）：
     1. 每个 Team 的 Apple Distribution 证书（.p12）导进 $keychain：
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
  note "已注册，机器令牌写进了 $ENV_FILE（这个脚本没有读它）"
}

# ---- 8. 仓库镜像 -----------------------------------------------------------------------------

ensure_mirror() {
  step "仓库镜像"
  local key="$AGENT_HOME/.ssh/id_ed25519"
  if [ ! -f "$key" ]; then
    sudo -n -u "$AGENT_USER" ssh-keygen -q -t ed25519 -N '' -C "rn-build-agent@$MACHINE_NAME" -f "$key" ||
      die "生成 deploy key 失败"
    note "已生成这台机器的 deploy key"
  fi
  if [ -d "$AGENT_HOME/repos/rn-app.git" ]; then
    note "仓库镜像已存在"
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

clone_mirror() {
  step "克隆仓库镜像"
  sudo -n -u "$AGENT_USER" env \
    GIT_SSH_COMMAND="ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i $AGENT_HOME/.ssh/id_ed25519 -o UserKnownHostsFile=$INSTALL_DIR/github_known_hosts -o StrictHostKeyChecking=yes" \
    git clone --mirror git@github.com:Helix2010/RN-App.git "$AGENT_HOME/repos/rn-app.git" ||
    die "克隆失败：确认 deploy key 已经加到 RN-App 仓库"
  note "镜像已克隆"
}

# ---- 9. 常驻 ---------------------------------------------------------------------------------

install_daemons() {
  step "常驻"
  put_file "$BUNDLE/$AGENT_LABEL.plist" "/Library/LaunchDaemons/$AGENT_LABEL.plist" root wheel 0644
  put_file "$BUNDLE/$UPGRADE_LABEL.plist" "/Library/LaunchDaemons/$UPGRADE_LABEL.plist" root wheel 0644
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
    warn "代理还没写出 state/runner-mode.json，看 /var/log/rn-build-agent.log"
  fi
}

finish() {
  step "装好了"
  "$INSTALL_DIR/build-agent" show-key --state-dir "$AGENT_HOME/state" 2>/dev/null || true
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
  if ensure_mirror; then
    clone_mirror
  else
    note "加完 deploy key 之后重新执行同一条命令"
    exit 0
  fi
  install_daemons
  finish
}

main "$@"
exit
