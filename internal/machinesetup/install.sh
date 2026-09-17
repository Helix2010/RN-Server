#!/usr/bin/env bash
# 新机器安装脚本：签名闸或构建机。服务端 GET /v1/machine-setup/install.sh 原样下发（go:embed）。
#
#   curl -fsSL https://api.example.com/v1/machine-setup/install.sh \
#     | sudo bash -s -- --server https://api.example.com --code rne_… [--recovery-sha256 <恢复公钥指纹>]
#
# 参数：
#   --server URL            API 源（必填）
#   --code rne_…            控制台新建机器时发的一次性注册码（必填，60 分钟内有效，只能用一次）
#   --recovery-sha256 HEX   签名闸必填：离线恢复公钥的完整 sha256，从密码管理器粘贴，不取控制台的值
#   --expect-sha256 HEX     可选：安装包归档的 sha256（与 CI 构建日志核对过的值），不符即拒绝
#   --instance NAME         签名闸可选：实例名，默认取机器名，2–22 个字符（系统用户 rn-signer-<实例> 受 Linux 32 字符上限）；
#                           系统用户、env 文件、unit、状态目录都用它：rn-signer-<实例>、/etc/rn-signer-<实例>.env、/var/lib/rn-signer-<实例>
#   --apksigner-jar PATH    签名闸可选：Android build-tools 35.0.0 的 apksigner.jar（默认在常见 SDK 位置找）
#
# 步骤（设计 docs/design/android-signing-gate-automation-2026-09-16.md「2. 新机器」）：
#   1. 检查前提，缺什么列出来退出（不自动装 SDK、JDK）
#   2. describe：查注册码对应的机器名、角色、主备与安装包清单（不消耗注册码）
#   3. 下载安装包，核对归档与每个文件的 sha256
#   4. 按角色安装：签名闸按模板渲染 unit；构建机含从旧结构迁移（旧文件留存）
#   5. 注册：signer enroll / build-agent enroll 生成本机密钥、换回机器令牌、直接写进 env 文件
#   6. 启动，打印机器名、完整指纹与下一步的完整命令
#
# 可以重复执行：
#   - 已注册（env 文件里有机器令牌）的实例不重新注册、不替换已经装好的文件，只核对并确保服务在跑；
#   - 注册码只在第 5 步消耗。用过的注册码 describe 会失败，这时改用第一次执行时留在
#     /var/lib/rn-machine-setup/<注册码 sha256>/ 的 describe 结果与安装包（root 0700，没有机密，可以删）。
#
# 机密：机器令牌只由 enroll 程序写进 env 文件，这个脚本从不读取、打印它；注册码经 stdin 交给 curl，
# 不放进 curl 的命令行参数。
set -euo pipefail
# 以 root 执行：当前目录、umask、PATH 与环境一律换成固定的，之后调用的程序（python3、java、git、tar、
# sha256sum……）不从执行者所在的目录（例如任何人都能写的 /tmp）或继承来的环境变量里加载任何东西。
# 装出来的文件都用 install -m 显式给权限，umask 只兜底脚本自己写的临时文件。
cd /
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
# 导出的环境变量只留这几个（代理留着：curl 要经它连服务端）；从环境导入的 shell 函数一律丢掉
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

readonly SETUP_ROOT=/var/lib/rn-machine-setup
# 签名闸实例名：系统用户 rn-signer-<实例> 受 Linux 用户名 32 字符上限，所以最多 22 个字符（与服务端对签名闸机器名的限制一致）
readonly INSTANCE_PATTERN='^[a-z0-9][a-z0-9-]{1,21}$'

readonly SERVICE_PATH=/usr/local/bin:/usr/bin:/bin
# Android build-tools 35.0.0（build-tools_r35_linux.zip，sha1 2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc，
# 与 dl.google.com 的 repository2-3.xml 一致）里 android-15/lib/apksigner.jar 的 sha256
readonly APKSIGNER_JAR_SHA256=00ef9948f843fe395d2440ae3ef41405b8040a6d5d46493bd1902ac0ee6deae7
readonly SIGNER_BUILD_TOOLS=/opt/rn-signer/build-tools/35.0.0
readonly SIGNER_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
# GitHub 公布的 ed25519 主机公钥（https://api.github.com/meta 的 ssh_keys）
readonly GITHUB_KNOWN_HOST='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
readonly APP_REPO_URL=git@github.com:Helix2010/RN-App.git
readonly AGENT_HOME=/var/lib/rn-build-agent
readonly AGENT_ENV=/etc/rn-build-agent.env
readonly AGENT_STATE=/var/lib/rn-build-agent/state
readonly AGENT_MIRROR=/var/lib/rn-build-agent/repos/rn-app.git
# 控制进程 fetch 时唯一认的 GitHub 主机公钥文件：root 所有，rn-build-agent 改不了（BUILD_AGENT_SSH_KNOWN_HOSTS 的默认值）
readonly AGENT_KNOWN_HOSTS=/opt/rn-build-agent/github_known_hosts

SERVER="" CODE="" RECOVERY_SHA256="" EXPECT_SHA256="" INSTANCE="" APKSIGNER_JAR=""
CURL_PROTO="=https"
WORK="" CACHE="" BUNDLE=""
MACHINE_ID="" MACHINE_NAME="" ROLE="" SIGNER_ROLE="" PRIMARY_NAME=""
BUNDLE_COMMIT="" BUNDLE_ARCHIVE="" BUNDLE_SHA256="" BUNDLE_SIZE=""
RECOVERY_KEYS=""
# describe 这次是不是真的查到了（yes），还是注册码已经无效、用的是本机缓存（no）
DESCRIBED_LIVE=no
LEGACY_MIGRATED=no
LEGACY_HOME=""
MIRROR_READY=no
# 签名闸出站地址：--server 是回环或 IP 字面量时渲染 drop-in 收紧，PINNED=yes；是域名时留给运维手工加
SIGNER_NETWORK_PINNED=no
SIGNER_NETWORK_DROPIN=""
SIGNER_NETWORK_ALLOW=""

step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
warn() { printf '   !! %s\n' "$*" >&2; }
die() {
  printf '\ninstall.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
usage: curl -fsSL <API>/v1/machine-setup/install.sh | sudo bash -s -- --server <API> --code rne_…
         [--recovery-sha256 HEX]   signing gates: the offline recovery key sha256 from the password manager
         [--expect-sha256 HEX]     the bundle archive sha256 checked against the CI build log
         [--instance NAME]         signing gates: instance name (default: the machine name, at most 22 characters)
         [--apksigner-jar PATH]    signing gates: apksigner.jar from Android build-tools 35.0.0
USAGE
  exit 2
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --server | --code | --recovery-sha256 | --expect-sha256 | --instance | --apksigner-jar)
        [ "$#" -ge 2 ] || { printf 'install.sh: %s needs a value\n' "$1" >&2; usage; }
        case "$1" in
          --server) SERVER="$2" ;;
          --code) CODE="$2" ;;
          --recovery-sha256) RECOVERY_SHA256="$2" ;;
          --expect-sha256) EXPECT_SHA256="$2" ;;
          --instance) INSTANCE="$2" ;;
          --apksigner-jar) APKSIGNER_JAR="$2" ;;
        esac
        shift 2
        ;;
      -h | --help) usage ;;
      *)
        printf 'install.sh: unknown argument %s\n' "${1:0:40}" >&2
        usage
        ;;
    esac
  done

  SERVER="${SERVER%/}"
  if [[ "$SERVER" =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$ ]]; then
    CURL_PROTO="=https"
  elif [[ "$SERVER" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?$ ]]; then
    CURL_PROTO="=http"
  else
    printf 'install.sh: --server must be an https origin such as https://api.example.com (http only for 127.0.0.1/localhost), got %q\n' "${SERVER:0:80}" >&2
    usage
  fi
  # 注册码格式不对时不回显它
  [[ "$CODE" =~ ^rne_[A-Za-z0-9_-]{43}$ ]] ||
    { printf 'install.sh: --code must look like rne_ followed by 43 base64url characters (got %d characters)\n' "${#CODE}" >&2; usage; }
  RECOVERY_SHA256="$(normalize_sha256 "$RECOVERY_SHA256")"
  if [ -n "$RECOVERY_SHA256" ] && ! [[ "$RECOVERY_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'install.sh: --recovery-sha256 must be the full 64-character sha256\n' >&2
    usage
  fi
  EXPECT_SHA256="$(normalize_sha256 "$EXPECT_SHA256")"
  if [ -n "$EXPECT_SHA256" ] && ! [[ "$EXPECT_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'install.sh: --expect-sha256 must be the full 64-character sha256\n' >&2
    usage
  fi
  if [ -n "$INSTANCE" ] && ! [[ "$INSTANCE" =~ $INSTANCE_PATTERN ]]; then
    printf 'install.sh: --instance must be 2–22 characters of a-z, 0-9 and -, starting with a letter or digit (the user rn-signer-<instance> must fit in 32 characters)\n' >&2
    usage
  fi
  if [ -n "$APKSIGNER_JAR" ] && [[ "$APKSIGNER_JAR" != /* ]]; then
    printf 'install.sh: --apksigner-jar must be an absolute path\n' >&2
    usage
  fi
}

# 去掉冒号与空白、转小写（从密码管理器或 keytool 粘贴的写法）
normalize_sha256() {
  local value="${1//:/}"
  value="${value//[[:space:]]/}"
  printf '%s' "${value,,}"
}

curl_api() {
  # -q 必须是第一个参数：不读 ~/.curlrc
  curl -q --silent --show-error --proto "$CURL_PROTO" --connect-timeout 15 "$@"
}

sha256_of() {
  local sum
  sum="$(sha256sum "$1")"
  printf '%s' "${sum%% *}"
}

need_commands() { # 把缺的命令追加进全局数组 MISSING
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("命令 $cmd")
  done
}

# ---- 1a. 能跑 describe 的最低前提 -------------------------------------------------------------

preflight_basic() {
  [ "$(id -u)" = 0 ] || die "必须以 root 执行（curl … | sudo bash -s -- …）"
  MISSING=()
  need_commands curl python3 sha256sum tar gzip install
  if [ "${#MISSING[@]}" -gt 0 ]; then
    printf '\ninstall.sh: 缺少前提，先装好再重新执行（注册码还没有使用）：\n' >&2
    printf '   - %s\n' "${MISSING[@]}" >&2
    exit 1
  fi
}

# ---- 2. describe ----------------------------------------------------------------------------

describe() {
  step "查询注册码（不消耗）"
  local code_sha status body="$WORK/describe.json"
  code_sha="$(printf '%s' "$CODE" | sha256sum)"
  CACHE="$SETUP_ROOT/${code_sha%% *}"
  status="$(printf '{"code":"%s"}' "$CODE" |
    curl_api --max-time 60 -o "$body" -w '%{http_code}' -H 'content-type: application/json' \
      --data-binary @- "$SERVER/v1/machine-setup/describe")" || status="000"

  case "$status" in
    200)
      install -d -o root -g root -m 0700 "$SETUP_ROOT" "$CACHE"
      install -o root -g root -m 0600 "$body" "$CACHE/describe.json"
      DESCRIBED_LIVE=yes
      ;;
    404)
      if [ -f "$CACHE/describe.json" ]; then
        note "注册码已经无效（这台机器上次执行时用过它，或已过期），按上次的查询结果继续：$CACHE"
      else
        local enrolled_here="" f
        for f in "$AGENT_ENV" /etc/rn-signer-*.env; do
          if has_machine_token "$f" BUILD_AGENT_MACHINE_TOKEN || has_machine_token "$f" SIGNER_MACHINE_TOKEN; then
            enrolled_here="$enrolled_here $f"
          fi
        done
        die "注册码无效：它 60 分钟后过期、只能用一次，也可能抄错了。在控制台重发注册码后重新执行。（${SERVER}，$(problem_code "$body")）${enrolled_here:+
这台机器上已经有注册过的实例（${enrolled_here# }）：如果就是这台机器用过这个注册码，它已经装好了，不需要再执行。}"
      fi
      ;;
    503) die "服务端暂时没有安装包（$(problem_code "$body")）：等服务端部署完成后重新执行" ;;
    429) die "查询太频繁，服务端限流了：一分钟后重新执行" ;;
    000) die "连不上 $SERVER（见上面 curl 的报错）" ;;
    *) die "查询注册码失败：HTTP $status（$(problem_code "$body")）" ;;
  esac

  parse_description "$CACHE/describe.json" >"$WORK/describe.env"
  local key value
  while IFS='=' read -r key value; do
    case "$key" in
      MACHINE_ID) MACHINE_ID="$value" ;;
      MACHINE_NAME) MACHINE_NAME="$value" ;;
      ROLE) ROLE="$value" ;;
      SIGNER_ROLE) SIGNER_ROLE="$value" ;;
      PRIMARY_NAME) PRIMARY_NAME="$value" ;;
      BUNDLE_COMMIT) BUNDLE_COMMIT="$value" ;;
      BUNDLE_ARCHIVE) BUNDLE_ARCHIVE="$value" ;;
      BUNDLE_SHA256) BUNDLE_SHA256="$value" ;;
      BUNDLE_SIZE) BUNDLE_SIZE="$value" ;;
      RECOVERY_KEYS) RECOVERY_KEYS="$value" ;;
    esac
  done <"$WORK/describe.env"

  note "机器：$MACHINE_NAME（$MACHINE_ID）"
  if [ "$ROLE" = signer ]; then
    note "角色：签名闸（$SIGNER_ROLE）"
  else
    note "角色：构建机"
  fi
  note "安装包：$BUNDLE_ARCHIVE，提交 $BUNDLE_COMMIT，sha256 $BUNDLE_SHA256"
}

# 服务端 Problem Details 里的 code（只取形状合法的，别的不打印）
problem_code() {
  # python3 一律 -I（隔离模式）：sys.path 里没有当前目录与用户 site-packages，也不读 PYTHON* 环境变量
  python3 -I - "$1" <<'PY' 2>/dev/null || printf 'no problem code'
import json, re, sys
try:
    code = json.load(open(sys.argv[1])).get("code", "")
except Exception:
    code = ""
print(code if isinstance(code, str) and re.fullmatch(r"[A-Z0-9_]{1,64}", code) else "no problem code", end="")
PY
}

# 校验 describe 的回答并输出 KEY=VALUE 行。每个值都按形状校验过，只含安全字符；文件清单写进
# 同目录的 files.sha256（sha256sum -c 的格式）。服务端给的字符串不进 eval，不原样打印。
parse_description() {
  python3 -I - "$1" "$WORK/files.sha256" <<'PY'
import json, re, sys

def fail(what):
    print("install.sh: the server's description of this enrollment is malformed (%s)" % what, file=sys.stderr)
    sys.exit(1)

def match(pattern, value, what):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        fail(what)
    return value

try:
    d = json.load(open(sys.argv[1]))
except Exception:
    fail("not JSON")
if not isinstance(d, dict):
    fail("not an object")
out = {}
out["MACHINE_ID"] = match(r"mch_[A-Za-z0-9_-]{4,64}", d.get("machineId"), "machineId")
out["MACHINE_NAME"] = match(r"[a-z0-9][a-z0-9-]{1,39}", d.get("name"), "name")
role = match(r"builder|signer", d.get("role"), "role")
out["ROLE"] = role
if role == "signer":
    out["SIGNER_ROLE"] = match(r"primary|standby", d.get("signerRole"), "signerRole")
    keys = d.get("recoveryKeys")
    if not isinstance(keys, list):
        fail("recoveryKeys")
    out["RECOVERY_KEYS"] = " ".join(
        match(r"[0-9a-f]{64}", k.get("x25519PublicKeySha256") if isinstance(k, dict) else None, "recoveryKeys")
        for k in keys)
    primary = d.get("primarySigner")
    if isinstance(primary, dict):
        out["PRIMARY_NAME"] = match(r"[a-z0-9][a-z0-9-]{1,39}", primary.get("name"), "primarySigner.name")
    elif primary is not None:
        fail("primarySigner")
b = d.get("bundle")
if not isinstance(b, dict):
    fail("bundle")
if b.get("role") != role:
    fail("bundle.role")
out["BUNDLE_ARCHIVE"] = match(re.escape(role) + r"\.tar\.gz", b.get("archive"), "bundle.archive")
out["BUNDLE_COMMIT"] = match(r"[0-9a-f]{7,40}(-dirty)?", b.get("commit"), "bundle.commit")
out["BUNDLE_SHA256"] = match(r"[0-9a-f]{64}", b.get("archiveSha256"), "bundle.archiveSha256")
size = b.get("archiveSize")
if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 1 << 30:
    fail("bundle.archiveSize")
out["BUNDLE_SIZE"] = str(size)
files = b.get("files")
if not isinstance(files, list) or not files:
    fail("bundle.files")
lines, seen = [], set()
for f in files:
    if not isinstance(f, dict):
        fail("bundle.files")
    name = match(r"[A-Za-z0-9@_.-]+(/[A-Za-z0-9@_.-]+)*", f.get("name"), "bundle.files.name")
    if any(part in ("", ".", "..") for part in name.split("/")) or name in seen:
        fail("bundle.files.name")
    seen.add(name)
    fsize = f.get("size")
    if not isinstance(fsize, int) or isinstance(fsize, bool) or fsize < 0:
        fail("bundle.files.size")
    lines.append("%s  %s" % (match(r"[0-9a-f]{64}", f.get("sha256"), "bundle.files.sha256"), name))
with open(sys.argv[2], "w") as fh:
    fh.write("\n".join(sorted(lines, key=lambda l: l[66:])) + "\n")
for k, v in out.items():
    print("%s=%s" % (k, v))
PY
}

# ---- 2b. 装到哪里 ---------------------------------------------------------------------------

# 签名闸定下实例名：--instance，否则这个注册码注册成功时记下的实例名，否则机器名。
# 注册码还没用过（describe 真的查到了）而目标已经注册过时拒绝：那是另一台机器的码，
# 继续下去会用新机器的身份覆盖一台在跑的机器。
resolve_target() {
  if [ "$ROLE" = signer ]; then
    local cached_instance=""
    if [ -f "$CACHE/instance" ]; then
      cached_instance="$(cat "$CACHE/instance")"
    fi
    if [ -z "$INSTANCE" ]; then
      INSTANCE="${cached_instance:-$MACHINE_NAME}"
    elif [ -n "$cached_instance" ] && [ "$cached_instance" != "$INSTANCE" ]; then
      die "这个注册码已经注册成了实例 $cached_instance，这次 --instance 是 $INSTANCE；去掉 --instance 或写成 $cached_instance"
    fi
    if [ "$DESCRIBED_LIVE" = yes ] && has_machine_token "/etc/rn-signer-$INSTANCE.env" SIGNER_MACHINE_TOKEN; then
      die "实例 $INSTANCE 已经注册过（/etc/rn-signer-$INSTANCE.env 里有机器令牌），而这个注册码还没用过：它属于另一台机器。给新机器换一个 --instance；注册码没有使用"
    fi
  elif [ "$DESCRIBED_LIVE" = yes ] && has_machine_token "$AGENT_ENV" BUILD_AGENT_MACHINE_TOKEN; then
    die "这台主机已经注册了构建机（$AGENT_ENV 里有机器令牌），而这个注册码还没用过：一台主机只跑一个构建机。注册码没有使用"
  fi
}

# ---- 1b. 按角色检查前提 ----------------------------------------------------------------------

java_is_17() { # $1 = JAVA_HOME
  local version
  [ -x "$1/bin/java" ] || return 1
  # 空环境（不吃 JAVA_TOOL_OPTIONS 之类），不往 /tmp/hsperfdata_root 写性能计数文件
  version="$(env -i "$1/bin/java" -XX:-UsePerfData -version 2>&1)" || return 1
  [[ "$version" == *'version "17'* ]]
}

# 找一份 sha256 对得上的 apksigner.jar：指定了 --apksigner-jar 就只认它，否则依次看已装的副本与常见 SDK 位置
find_apksigner_jar() {
  local candidate candidates=("$APKSIGNER_JAR")
  if [ -z "$APKSIGNER_JAR" ]; then
    candidates=("$SIGNER_BUILD_TOOLS/lib/apksigner.jar" /opt/android-sdk/build-tools/35.0.0/lib/apksigner.jar
      /usr/lib/android-sdk/build-tools/35.0.0/lib/apksigner.jar)
  fi
  for candidate in "${candidates[@]}"; do
    if [ -f "$candidate" ] && [ "$(sha256_of "$candidate")" = "$APKSIGNER_JAR_SHA256" ]; then
      APKSIGNER_JAR="$candidate"
      return 0
    fi
  done
  return 1
}

env_value() { # $1 文件 $2 键：只取这一个非机密键（不用于令牌），文件或键不在时输出空
  [ -f "$1" ] || return 0
  awk -F= -v key="$2" '$1 == key { value = substr($0, length(key) + 2) } END { gsub(/^["'\'']|["'\'']$/, "", value); printf "%s", value }' "$1"
}

has_machine_token() { # $1 文件 $2 键：只判断有没有，不读出来
  [ -f "$1" ] && grep -Eq "^[[:space:]]*$2=[\"']?rnm_[A-Za-z0-9_-]{43}[\"']?[[:space:]]*$" "$1"
}

has_nonempty_key() { # $1 文件 $2 键：只判断这个键有没有非空的值，不读出来
  [ -f "$1" ] && grep -Eq "^[[:space:]]*$2=[\"']?[^\"'[:space:]]" "$1"
}

version_at_least() { # $1 实际 $2 要求（点分数字）
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

preflight_role() {
  step "检查前提"
  MISSING=()
  [ "$(uname -m)" = x86_64 ] || MISSING+=("x86_64 机器（安装包是 linux/amd64）")
  [ -d /run/systemd/system ] || MISSING+=("systemd（这台机器不是由 systemd 启动的）")
  [ "$(stat -f -c %T /run 2>/dev/null || true)" = tmpfs ] || MISSING+=("tmpfs 上的 /run")
  need_commands systemctl useradd groupadd usermod getent sudo git cmp awk sed
  if [ "$ROLE" = signer ]; then
    [ -n "$RECOVERY_SHA256" ] || MISSING+=("参数 --recovery-sha256 <从密码管理器粘贴的恢复公钥完整 sha256>")
    if [ -n "$RECOVERY_SHA256" ] && [[ " $RECOVERY_KEYS " != *" $RECOVERY_SHA256 "* ]]; then
      MISSING+=("与 --recovery-sha256 一致的恢复公钥：服务端登记的恢复公钥里没有它（核对密码管理器里的指纹；平台没登记恢复公钥时先在控制台登记）")
    fi
    java_is_17 "$SIGNER_JAVA_HOME" || MISSING+=("JDK 17：$SIGNER_JAVA_HOME（apt install openjdk-17-jre-headless）")
    if find_apksigner_jar; then
      :
    elif [ -n "$APKSIGNER_JAR" ]; then
      MISSING+=("--apksigner-jar 指定的 $APKSIGNER_JAR 不是 Android build-tools 35.0.0 的 apksigner.jar（sha256 应为 $APKSIGNER_JAR_SHA256）")
    else
      MISSING+=("Android build-tools 35.0.0 的 apksigner.jar（sha256 $APKSIGNER_JAR_SHA256）：从 https://dl.google.com/android/repository/build-tools_r35_linux.zip（sha1 2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc）取 android-15/lib/apksigner.jar，用 --apksigner-jar <路径> 指定")
    fi
    # 系统用户 rn-signer-<实例> 不能超过 32 个字符
    [[ "$INSTANCE" =~ $INSTANCE_PATTERN ]] ||
      MISSING+=("实例名：rn-signer-$INSTANCE 超过 Linux 用户名的 32 个字符上限，用 --instance <2–22 个字符的短名> 指定")
  else
    need_commands visudo setpriv ssh ssh-keygen zip pgrep pkill
    local java_home android_home git_version node_version
    java_home="$(env_value "$AGENT_ENV" JAVA_HOME)"
    android_home="$(env_value "$AGENT_ENV" ANDROID_HOME)"
    java_is_17 "${java_home:-/usr/lib/jvm/java-17-openjdk-amd64}" || MISSING+=("JDK 17：${java_home:-/usr/lib/jvm/java-17-openjdk-amd64}")
    [ -d "${android_home:-/opt/android-sdk}" ] || MISSING+=("Android SDK：${android_home:-/opt/android-sdk}（root 所有、全局可读，NDK 预装齐）")
    if command -v git >/dev/null 2>&1; then
      git_version="$(git --version | awk '{print $3}')"
      version_at_least "$git_version" 2.30 || MISSING+=("git ≥ 2.30（现在是 $git_version）")
    fi
    if node_version="$(PATH="$SERVICE_PATH" node --version 2>/dev/null)"; then
      version_at_least "${node_version#v}" 22 || MISSING+=("Node.js 22（现在是 $node_version）")
    else
      MISSING+=("Node.js 22（在 $SERVICE_PATH 里）")
    fi
    PATH="$SERVICE_PATH" command -v pnpm >/dev/null 2>&1 || MISSING+=("pnpm（在 $SERVICE_PATH 里）")
    PATH="$SERVICE_PATH" command -v syft >/dev/null 2>&1 || MISSING+=("syft（固定版本，见 deploy/amos/install-syft.sh）")
  fi
  if [ "${#MISSING[@]}" -gt 0 ]; then
    printf '\ninstall.sh: 缺少前提，装好后重新执行同一条命令（注册码还没有使用）：\n' >&2
    printf '   - %s\n' "${MISSING[@]}" >&2
    exit 1
  fi
  note "前提齐全"
}

# ---- 3. 下载并核对安装包 --------------------------------------------------------------------

fetch_bundle() {
  step "下载并核对安装包"
  if [ -n "$EXPECT_SHA256" ] && [ "$EXPECT_SHA256" != "$BUNDLE_SHA256" ]; then
    die "服务端清单里的安装包 sha256 是 $BUNDLE_SHA256，与 --expect-sha256 $EXPECT_SHA256 不符，拒绝安装"
  fi
  local archive="$CACHE/$BUNDLE_ARCHIVE"
  if [ -f "$archive" ] && [ "$(sha256_of "$archive")" = "$BUNDLE_SHA256" ]; then
    note "使用上次下载的 $archive"
  else
    rm -f "$archive.part"
    # 注册码走 stdin 里的 curl 配置，不进命令行参数
    if ! printf 'header = "x-enrollment-code: %s"\n' "$CODE" |
      curl_api --config - --fail --max-time 900 -o "$archive.part" "$SERVER/v1/machine-setup/bundle/$ROLE.tar.gz"; then
      rm -f "$archive.part"
      die "下载安装包失败（见上面 curl 的报错）；注册码过期或已用过时在控制台重发"
    fi
    local size actual
    size="$(stat -c %s "$archive.part")"
    actual="$(sha256_of "$archive.part")"
    if [ "$size" != "$BUNDLE_SIZE" ] || [ "$actual" != "$BUNDLE_SHA256" ]; then
      rm -f "$archive.part"
      die "下载的安装包是 $size 字节、sha256 $actual，清单说是 $BUNDLE_SIZE 字节、$BUNDLE_SHA256：拒绝安装"
    fi
    chmod 0600 "$archive.part"
    mv -f "$archive.part" "$archive"
  fi
  if [ -n "$EXPECT_SHA256" ] && [ "$(sha256_of "$archive")" != "$EXPECT_SHA256" ]; then
    die "安装包 sha256 与 --expect-sha256 不符，拒绝安装"
  fi

  # 每次都重新解包核对，不信任上次解出来的目录
  BUNDLE="$CACHE/bundle"
  rm -rf "$BUNDLE.new"
  install -d -o root -g root -m 0700 "$BUNDLE.new"
  tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$BUNDLE.new" ||
    die "安装包解不开"
  if [ -n "$(find "$BUNDLE.new" -mindepth 1 ! -type f ! -type d -print -quit)" ]; then
    die "安装包里有普通文件与目录以外的东西（符号链接、设备……），拒绝安装"
  fi
  local listed actual_files
  listed="$(awk '{ print substr($0, 67) }' "$WORK/files.sha256")"
  actual_files="$(cd "$BUNDLE.new" && find . -type f -printf '%P\n' | LC_ALL=C sort)"
  [ "$actual_files" = "$(printf '%s\n' "$listed" | LC_ALL=C sort)" ] ||
    die "安装包里的文件与清单不一致，拒绝安装"
  (cd "$BUNDLE.new" && sha256sum --quiet --strict -c "$WORK/files.sha256") ||
    die "安装包里有文件的 sha256 与清单不符，拒绝安装"
  rm -rf "$BUNDLE"
  mv "$BUNDLE.new" "$BUNDLE"
  note "安装包核对通过（归档 sha256 $BUNDLE_SHA256，提交 $BUNDLE_COMMIT）"
}

# ---- 公共：装文件、等服务 -------------------------------------------------------------------

# 装一个文件：已存在且相同就跳过。$1 源 $2 目标 $3 属主 $4 属组 $5 权限
put_file() {
  if [ -f "$2" ] && cmp -s "$1" "$2"; then
    chown "$3:$4" "$2"
    chmod "$5" "$2"
    return 0
  fi
  install -o "$3" -g "$4" -m "$5" "$1" "$2"
  note "已装 $2"
}

# 已注册的实例不替换文件，只报告与安装包不同的地方。$1 源 $2 目标
report_file() {
  if [ ! -f "$2" ]; then
    warn "$2 不存在（安装包里有）"
  elif ! cmp -s "$1" "$2"; then
    note "保留现有的 $2（与安装包不同；升级已注册的机器见 SIGNING_GATE_ROLLOUT.md）"
  fi
}

# 等服务起来并稳定跑一小会儿：Type=exec/simple 的服务一 fork 就算 active，启动后几秒内因为配置、
# 权限或连不上服务端退出的，要在这里发现，而不是报“在运行”。$1 unit
wait_active() {
  local state="" pid="" restarts="" i stable=0 first_restarts
  first_restarts="$(systemctl show -p NRestarts --value "$1" 2>/dev/null || true)"
  for i in $(seq 1 60); do
    state="$(systemctl show -p ActiveState --value "$1" 2>/dev/null || true)"
    if [ "$state" = active ]; then
      local now_pid now_restarts
      now_pid="$(systemctl show -p MainPID --value "$1" 2>/dev/null || true)"
      now_restarts="$(systemctl show -p NRestarts --value "$1" 2>/dev/null || true)"
      if [ -n "$pid" ] && [ "$now_pid" = "$pid" ] && [ "$now_restarts" = "$restarts" ]; then
        stable=$((stable + 1))
      else
        stable=0
      fi
      pid="$now_pid"
      restarts="$now_restarts"
      [ "$stable" -ge 10 ] && return 0
    else
      pid=""
      stable=0
      [ "$state" = failed ] && break
      # 这次等待期间已经被 systemd 重启过两次：不会自己好起来
      restarts="$(systemctl show -p NRestarts --value "$1" 2>/dev/null || true)"
      if [[ "$restarts" =~ ^[0-9]+$ && "$first_restarts" =~ ^[0-9]+$ ]] && [ "$restarts" -ge $((first_restarts + 2)) ]; then
        break
      fi
    fi
    [ "$i" = 60 ] || sleep 1
  done
  journalctl -u "$1" -n 30 --no-pager -o cat >&2 || true
  die "$1 没有稳定运行（状态 ${state:-unknown}），见上面的日志；修好之后重新执行同一条命令"
}

# ---- 4–6. 签名闸 ----------------------------------------------------------------------------

# is_ipv4：点分四段、每段 0–255
is_ipv4() {
  local ip="$1" seg
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local IFS=.
  for seg in $ip; do
    [ "$seg" -le 255 ] || return 1
  done
  return 0
}

# is_ipv6：只认十六进制与冒号（够用来判 IP 字面量，不做完整合法性校验）
is_ipv6() { [[ "$1" =~ ^[0-9A-Fa-f:]+$ && "$1" == *:* ]]; }

# render_signer_network_dropin：--server 是回环或 IP 字面量时，渲染
# /etc/systemd/system/<unit>.service.d/network.conf，把签名闸的出站地址收紧到该地址（模板已去掉写死的
# IPAddress*）。是域名时不渲染（还需要 DNS 解析器地址，因机器而异），留给运维手工加，并在“下一步”提示。
# 只在这个函数里判定 SIGNER_NETWORK_PINNED，两处（下一步、note）都读它。
render_signer_network_dropin() {
  local unit="$1" host allow dropin
  host="${SERVER#*://}"
  host="${host%%/*}"
  case "$host" in
  \[*\]*)
    host="${host#\[}"
    host="${host%%\]*}"
    ;;
  *:*) host="${host%:*}" ;;
  esac
  case "$host" in
  localhost | 127.0.0.1 | ::1) allow="127.0.0.1/32 ::1/128" ;;
  *)
    if is_ipv4 "$host"; then
      allow="$host/32"
    elif is_ipv6 "$host"; then
      allow="$host/128"
    else
      # 域名：签名闸还要连 DNS 解析器，地址因机器而异，不猜
      SIGNER_NETWORK_PINNED=no
      return 0
    fi
    ;;
  esac
  dropin="/etc/systemd/system/$unit.service.d"
  install -d -o root -g root -m 0755 "$dropin"
  printf '# install.sh 按 --server 渲染：只允许连服务端与回环。域名部署要改成 API 与 DNS 解析器地址。\n[Service]\nIPAddressDeny=any\nIPAddressAllow=%s\n' \
    "$allow" >"$WORK/network.conf"
  put_file "$WORK/network.conf" "$dropin/network.conf" root root 0644
  systemctl daemon-reload
  SIGNER_NETWORK_PINNED=yes
  SIGNER_NETWORK_DROPIN="$dropin/network.conf"
  SIGNER_NETWORK_ALLOW="$allow"
}

install_signer() {
  local user="rn-signer-$INSTANCE" env="/etc/rn-signer-$INSTANCE.env" unit="rn-signer-$INSTANCE"
  local templates="$BUNDLE/templates" rendered="$CACHE/rendered" name enrolled=no
  local -a units=("$unit.service" "$unit-check.socket" "$unit-check@.service")
  has_machine_token "$env" SIGNER_MACHINE_TOKEN && enrolled=yes

  step "渲染签名闸模板（实例 $INSTANCE）"
  rm -rf "$rendered"
  install -d -m 0700 "$rendered"
  local template base
  for template in "$templates"/*@INSTANCE@*; do
    [ -f "$template" ] || continue
    base="${template##*/}"
    sed "s/@INSTANCE@/$INSTANCE/g" "$template" >"$rendered/${base//@INSTANCE@/$INSTANCE}"
  done
  for name in "${units[@]}" "rn-signer-$INSTANCE.env"; do
    [ -f "$rendered/$name" ] || die "安装包的 templates/ 里没有 ${name//$INSTANCE/@INSTANCE@} 的模板"
  done

  step "安装签名闸"
  local others=() f
  for f in /etc/rn-signer-*.env; do
    if [ "$f" != "$env" ] && has_machine_token "$f" SIGNER_MACHINE_TOKEN; then
      others+=("$f")
    fi
  done

  if [ "$enrolled" = yes ]; then
    note "实例 $INSTANCE 已注册（$env 里有机器令牌）：不重新注册、不替换已装的文件"
    report_file "$BUNDLE/bin/signer" /opt/rn-signer/bin/signer
    report_file "$BUNDLE/bin/signer-check" /opt/rn-signer/bin/signer-check
    for name in "${units[@]}"; do
      report_file "$rendered/$name" "/etc/systemd/system/$name"
    done
  else
    # 签名闸程序与 apksigner 副本是本机所有实例共用的：本机已有注册过的实例在用、而内容不同时不替换
    local shared_src shared_dst
    for shared_src in "$BUNDLE/bin/signer" "$BUNDLE/bin/signer-check" "$APKSIGNER_JAR"; do
      case "$shared_src" in
        */apksigner.jar) shared_dst="$SIGNER_BUILD_TOOLS/lib/apksigner.jar" ;;
        *) shared_dst="/opt/rn-signer/bin/${shared_src##*/}" ;;
      esac
      if [ "${#others[@]}" -gt 0 ] && [ -f "$shared_dst" ] && ! cmp -s "$shared_src" "$shared_dst"; then
        die "本机已注册的签名闸（${others[*]}）在用 $shared_dst，它与这次要装的不同。先按 SIGNING_GATE_ROLLOUT.md 升级本机的签名闸程序（sha256 与 CI 构建日志核对），再重新执行；注册码没有使用"
      fi
    done
    if getent passwd "$user" >/dev/null; then
      note "系统用户 $user 已存在"
    else
      useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin --user-group "$user"
      note "已建系统用户 $user"
    fi
    install -d -o root -g root -m 0755 /opt/rn-signer /opt/rn-signer/bin /opt/rn-signer/build-tools \
      "$SIGNER_BUILD_TOOLS" "$SIGNER_BUILD_TOOLS/lib"
    put_file "$BUNDLE/bin/signer" /opt/rn-signer/bin/signer root root 0755
    put_file "$BUNDLE/bin/signer-check" /opt/rn-signer/bin/signer-check root root 0755
    if [ "$APKSIGNER_JAR" != "$SIGNER_BUILD_TOOLS/lib/apksigner.jar" ]; then
      put_file "$APKSIGNER_JAR" "$SIGNER_BUILD_TOOLS/lib/apksigner.jar" root root 0644
    fi
    [ ! -f "$BUNDLE/README.md" ] || put_file "$BUNDLE/README.md" /opt/rn-signer/README.md root root 0644
    # 没有令牌的 env 文件里没有机密，按模板重写（上次执行留下的半成品也一样）
    install -o root -g "$user" -m 0640 "$rendered/rn-signer-$INSTANCE.env" "$env"
    note "已写 $env（root:$user 0640，还没有令牌）"
    for name in "${units[@]}"; do
      put_file "$rendered/$name" "/etc/systemd/system/$name" root root 0644
    done
    systemctl daemon-reload
    local verify unit_paths=()
    for name in "${units[@]}"; do
      unit_paths+=("/etc/systemd/system/$name")
    done
    if ! verify="$(systemd-analyze verify "${unit_paths[@]}" 2>&1)"; then
      warn "systemd-analyze verify 有提示（不阻止安装）："
      printf '%s\n' "$verify" | sed 's/^/      /' >&2
    fi
  fi

  # 出站地址：--server 是回环或 IP 字面量时直接渲染 drop-in 收紧；是域名时留给运维手工加（见下一步）
  render_signer_network_dropin "$unit"

  # 注册：已注册时也照样调一次。signer enroll 是幂等的——已有令牌就不连服务端，只清掉可能残留的
  # enroll.incomplete 标记（否则 signer run 会因为它拒绝启动，而且再没有别的机会清掉）。
  step "注册"
  RN_ENROLLMENT_CODE="$CODE" /opt/rn-signer/bin/signer enroll --server "$SERVER" --env-file "$env" \
    --recovery-sha256 "$RECOVERY_SHA256" --name-check "$MACHINE_NAME" ||
    die "signer enroll 失败（见上面的输出）。修好之后重新执行同一条命令"
  has_machine_token "$env" SIGNER_MACHINE_TOKEN || die "signer enroll 报告成功，但 $env 里没有机器令牌"
  # 记下这个注册码落在哪个实例上：之后不带 --instance 重复执行时用它
  printf '%s\n' "$INSTANCE" >"$CACHE/instance"

  step "启动"
  systemctl enable --now "$unit-check.socket" "$unit.service"
  wait_active "$unit.service"
  note "$unit.service 在运行"

  step "本机身份（公开信息：控制台接受与 trust-peer 时逐位核对）"
  sudo -u "$user" /opt/rn-signer/bin/signer show-key --env-file "$env" || warn "signer show-key 失败"

  # signer enroll 已经按控制台登记的主/备、以及服务端有没有主，打印了完整的下一步命令。
  # 这里只补 install.sh 自己负责的两条：出站地址（域名时要手工加）、以及把关键动作汇总一遍。
  local here="sudo -u $user /opt/rn-signer/bin/signer"
  step "下一步（signer enroll 上面已打印详细命令，这里是要点）"
  cat <<NEXT
   1. 控制台「平台维护 → 打包机与签名闸」：$MACHINE_NAME 显示的 X25519 与 Ed25519 完整指纹与上面一致后，点「接受」。
      本机记录里这台一律是「备」：控制台的主/备只决定派活。
NEXT
  if [ "$SIGNER_ROLE" = primary ]; then
    cat <<NEXT
   2. 控制台把这台登记为「主」。若它是平台的第一台主签名闸，在本机把它提升为主（promote 要运行锁，先停服务）：
        systemctl stop $unit.service
        $here promote --first --env-file $env
        systemctl start $unit.service
      若是替换旧主，改用 --import 或 --manual（见 /opt/rn-signer/README.md 第 9 节），不要用 --first。
   3. 让每台备签名闸信任这台主（在每台备本机，指纹取本机 show-key 上面那两行）：
        sudo -u rn-signer-<备实例> /opt/rn-signer/bin/signer trust-peer --peer $MACHINE_NAME --env-file /etc/rn-signer-<备实例>.env
      并在这台机器上信任每台备：$here trust-peer --peer <备签名闸机器名> --env-file $env
NEXT
  elif [ -n "$PRIMARY_NAME" ]; then
    cat <<NEXT
   2. 在这台机器上信任主签名闸 $PRIMARY_NAME（指纹取主签名闸本机 show-key 或它的安装输出，不要取控制台的）：
        $here trust-peer --peer $PRIMARY_NAME --env-file $env
      并登上主签名闸，让它信任这台备（粘贴上面这台的两个完整指纹）：
        sudo -u rn-signer-<主实例> /opt/rn-signer/bin/signer trust-peer --peer $MACHINE_NAME --env-file /etc/rn-signer-<主实例>.env
      实例名默认就是机器名；amos 上手工部署的两台是 rn-signer-a、rn-signer-b。
NEXT
  else
    cat <<NEXT
   2. 服务端还没有主签名闸：先装主签名闸，再在这台机器上信任它：
        $here trust-peer --peer <主签名闸机器名> --env-file $env
NEXT
  fi
  cat <<NEXT
   4. 在这台机器上信任每台构建机（粘贴构建机安装输出里的出处公钥完整 sha256）：
        $here trust-builder --builder <构建机机器名> --env-file $env
NEXT
  if [ "$SIGNER_NETWORK_PINNED" = yes ]; then
    note "出站地址已按 --server 收紧：$SIGNER_NETWORK_DROPIN（IPAddressDeny=any + 允许 $SIGNER_NETWORK_ALLOW）"
  else
    cat <<NEXT
   5. 【上线必做】收紧出站地址：--server 是域名，install.sh 没有替你写 drop-in。装完手工加
        /etc/systemd/system/$unit.service.d/network.conf
        [Service]
        IPAddressDeny=any
        IPAddressAllow=<API 地址> <DNS 解析器地址>
      然后 systemctl daemon-reload && systemctl restart $unit.service（见 /opt/rn-signer/README.md）。
NEXT
  fi
}

# ---- 4–6. 构建机 ----------------------------------------------------------------------------

# 改造前的构建机：以 builder 跑 build-agent，env 里是共用令牌 BUILD_AGENT_TOKEN，家目录里有 agent-key
builder_is_legacy() {
  if has_nonempty_key "$AGENT_ENV" BUILD_AGENT_TOKEN || has_nonempty_key "$AGENT_ENV" BUILD_KEYSTORE_PASSPHRASE; then
    return 0
  fi
  if [ -f /etc/systemd/system/rn-build-agent.service ] && grep -q '^User=builder$' /etc/systemd/system/rn-build-agent.service; then
    return 0
  fi
  if [ -d "$AGENT_HOME" ] && [ "$(stat -c %U "$AGENT_HOME")" = builder ]; then
    return 0
  fi
  [ -e "$AGENT_HOME/agent-key" ] || [ -e "$AGENT_HOME/backup-signing.key" ]
}

# 以 rn-build-agent 身份执行。rn-build-agent 自己的目录树里的操作一律用它，root 不去碰：
# 那些路径的任何一段都可能被它换成符号链接（例如机器令牌被清空后重新注册，控制进程此前跑过任务）。
as_agent() {
  sudo -u rn-build-agent -- "$@"
}

# 留存目录里的新名字：同一天重复迁移时不覆盖上次留下的
legacy_name() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    path="$path.$(date -u +%H%M%S%N)"
  fi
  printf '%s' "$path"
}

# 从改造前的结构迁移：停旧进程、留存旧配置与密钥、清掉 builder 写过的缓存。
#
# 旧结构里 builder 的家目录就是 /var/lib/rn-build-agent：仓库镜像、~/.ssh、别的点文件都曾归 builder 可写，
# 而控制进程 git fetch 会读镜像的本地配置、ssh 会读 ~/.ssh/config 与 known_hosts。所以家目录整个挪进留存目录，
# 新家目录从空的建起：仓库镜像以 rn-build-agent 重新克隆，deploy key 只取回两个文件（restore_legacy_deploy_key），
# known_hosts 按脚本里固定的主机公钥重写。留存目录 root 0700，新链路稳定后按上线手册销毁。
migrate_legacy_builder() {
  local legacy f i
  legacy="/root/rn-build-agent-legacy-$(date -u +%Y-%m-%d)"
  step "从旧结构迁移构建机（旧文件留存在 $legacy）"
  systemctl stop rn-build-agent 2>/dev/null || true
  if id builder >/dev/null 2>&1; then
    # 先去掉 builder 的 crontab（留一份），免得杀完进程又被 cron 拉起来
    if command -v crontab >/dev/null 2>&1 && crontab -l -u builder >/dev/null 2>&1; then
      install -d -o root -g root -m 0700 "$legacy"
      crontab -l -u builder >"$(legacy_name "$legacy/builder.crontab")" 2>/dev/null || true
      crontab -r -u builder 2>/dev/null || true
    fi
    pkill -KILL -u builder 2>/dev/null || true
    for i in $(seq 1 30); do
      pgrep -u builder >/dev/null 2>&1 || break
      [ "$i" = 30 ] && die "builder 的进程 30 秒还没退出，手工处理后重新执行"
      sleep 1
    done
  fi
  install -d -o root -g root -m 0700 "$legacy"
  if [ -f "$AGENT_ENV" ]; then
    mv "$AGENT_ENV" "$(legacy_name "$legacy/rn-build-agent.env")"
    note "旧 $AGENT_ENV 移进留存目录（含旧令牌，不再使用）"
  fi
  if [ -f /etc/systemd/system/rn-build-agent.service ] && [ ! -e "$legacy/rn-build-agent.service" ]; then
    cp -a /etc/systemd/system/rn-build-agent.service "$legacy/rn-build-agent.service"
  fi
  if [ -f /opt/rn-build-agent/build-agent ] && [ ! -e "$legacy/build-agent.previous" ]; then
    cp -a /opt/rn-build-agent/build-agent "$legacy/build-agent.previous"
  fi
  if [ -d "$AGENT_HOME" ] && [ ! -L "$AGENT_HOME" ]; then
    for f in agent-key backup-signing.key .gitconfig; do
      if [ -e "$AGENT_HOME/$f" ] || [ -L "$AGENT_HOME/$f" ]; then
        mv "$AGENT_HOME/$f" "$(legacy_name "$legacy/$f")"
      fi
    done
    # builder 写过的缓存与工作区按被下毒处理：删掉（不值得留存，体积也大）
    rm -rf "$AGENT_HOME/.android" "$AGENT_HOME/.cache" "$AGENT_HOME/.expo" "$AGENT_HOME/.gradle" "$AGENT_HOME/.kotlin" \
      "$AGENT_HOME/.local" "$AGENT_HOME/.m2" "$AGENT_HOME/.npm" "$AGENT_HOME/.pnpm-store" "$AGENT_HOME/workspace"
    # 剩下的（仓库镜像、~/.ssh、其余点文件）整个挪走
    LEGACY_HOME="$(legacy_name "$legacy/home")"
    mv "$AGENT_HOME" "$LEGACY_HOME"
    note "旧家目录（仓库镜像、~/.ssh 等）移进 $LEGACY_HOME；仓库镜像稍后以 rn-build-agent 重新克隆"
  fi
  rm -rf /var/cache/rn-build-agent/gradle /var/cache/rn-build-agent/pnpm-store
  if id builder >/dev/null 2>&1; then
    find /tmp /var/tmp /dev/shm -maxdepth 1 -user builder -exec rm -rf {} + 2>/dev/null || true
  fi
  LEGACY_MIGRATED=yes
}

# 迁移时取回旧 deploy key：只要 id_ed25519 与 id_ed25519.pub 两个普通文件（不是符号链接、不属于 root、
# 公钥与私钥配对），属主改成 rn-build-agent。别的（config、known_hosts、authorized_keys……）都留在留存目录。
# 取不回来就生成新的 deploy key（下一步会提示加到 GitHub）。
restore_legacy_deploy_key() {
  local from="$LEGACY_HOME/.ssh" name src private="$AGENT_HOME/.ssh/id_ed25519"
  [ -n "$LEGACY_HOME" ] && [ -d "$from" ] && [ ! -L "$from" ] || return 0
  for name in id_ed25519 id_ed25519.pub; do
    src="$from/$name"
    if [ ! -f "$src" ] || [ -L "$src" ] || [ "$(stat -c %u "$src")" = 0 ] || [ "$(stat -c %s "$src")" -gt 16384 ]; then
      [ ! -e "$src" ] || warn "旧的 $src 不是 builder 的普通小文件，不沿用；会生成新的 deploy key"
      return 0
    fi
  done
  install -o rn-build-agent -g rn-build-agent -m 0600 "$from/id_ed25519" "$private"
  install -o rn-build-agent -g rn-build-agent -m 0644 "$from/id_ed25519.pub" "$private.pub"
  if [ "$(as_agent ssh-keygen -y -f "$private" 2>/dev/null | awk '{ print $1, $2 }')" != "$(awk '{ print $1, $2 }' "$private.pub")" ]; then
    rm -f "$private" "$private.pub"
    warn "旧 deploy key 的公钥与私钥对不上，不沿用；会生成新的 deploy key"
    return 0
  fi
  note "沿用旧的 GitHub deploy key（只取回 id_ed25519 与 id_ed25519.pub；旧 ~/.ssh 的其余文件留在 $from）"
  warn "这把 deploy key 的私钥曾经对 builder 可读：建议在 GitHub 上换一把（见 SIGNING_GATE_ROLLOUT.md「重建仓库镜像与 ~/.ssh」）"
}

# fetch 仓库镜像用的 ssh：不读任何 ssh 配置，只用 deploy key，主机公钥只认 root 所有的固定 known_hosts。
# 与控制进程（cmd/build-agent/checkout.go 的 sshCommand）一致。
agent_ssh_command() {
  printf 'ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i %s -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15' \
    "$AGENT_HOME/.ssh/id_ed25519" "$AGENT_KNOWN_HOSTS"
}

install_builder() {
  local enrolled=no had_deploy_key=no name
  has_machine_token "$AGENT_ENV" BUILD_AGENT_MACHINE_TOKEN && enrolled=yes
  printf '%s\n' "$GITHUB_KNOWN_HOST" >"$WORK/github_known_hosts"

  step "安装构建机"
  if [ "$enrolled" = yes ]; then
    note "已注册（$AGENT_ENV 里有机器令牌）：不重新注册、不替换已装的文件"
    report_file "$BUNDLE/bin/build-agent" /opt/rn-build-agent/build-agent
    report_file "$BUNDLE/bin/build-runner" /opt/rn-build-agent/build-runner
    report_file "$BUNDLE/rn-build-agent.service" /etc/systemd/system/rn-build-agent.service
    report_file "$BUNDLE/rn-build-agent.sudoers" /etc/sudoers.d/rn-build-agent
    # 固定 known_hosts 是新版控制进程 fetch 的前提：没有就补上，有但内容不同只报告
    if [ -f "$AGENT_KNOWN_HOSTS" ]; then
      report_file "$WORK/github_known_hosts" "$AGENT_KNOWN_HOSTS"
    else
      put_file "$WORK/github_known_hosts" "$AGENT_KNOWN_HOSTS" root root 0644
    fi
  else
    if builder_is_legacy; then
      migrate_legacy_builder
    fi
    getent group rn-build-jobs >/dev/null || groupadd --system rn-build-jobs
    if ! id rn-build-agent >/dev/null 2>&1; then
      useradd --system --home-dir "$AGENT_HOME" --no-create-home --shell /usr/sbin/nologin \
        --user-group --groups rn-build-jobs rn-build-agent
      note "已建系统用户 rn-build-agent"
    fi
    usermod -aG rn-build-jobs rn-build-agent
    if id builder >/dev/null 2>&1; then
      usermod -d /nonexistent -s /usr/sbin/nologin -aG rn-build-jobs builder
    else
      useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin \
        --user-group --groups rn-build-jobs builder
      note "已建系统用户 builder"
    fi
    for f in /etc/cron.deny /etc/at.deny; do
      # 显式 0644：crontab 是 setgid 程序，读不到 deny 文件时 Debian 的 cron 按“允许”处理
      [ -e "$f" ] || install -o root -g root -m 0644 /dev/null "$f"
      grep -qx builder "$f" || printf 'builder\n' >>"$f"
    done

    # 家目录本身由 root 建（它在 root 所有的 /var/lib 下），里面的目录以 rn-build-agent 建
    install -d -o rn-build-agent -g rn-build-agent -m 0700 "$AGENT_HOME"
    as_agent install -d -m 0700 "$AGENT_HOME/.ssh" "$AGENT_STATE" "$AGENT_HOME/repos"
    if [ "$LEGACY_MIGRATED" = yes ]; then
      restore_legacy_deploy_key
    fi
    # 旧的 known_hosts 不沿用：按脚本里固定的 GitHub 主机公钥重写（控制进程不读它，用的是下面 root 所有的那份）
    # shellcheck disable=SC2016  # $1、$2 由 sh -c 展开
    as_agent sh -c 'umask 077 && printf "%s\n" "$1" >"$2.new" && mv -f "$2.new" "$2"' sh "$GITHUB_KNOWN_HOST" "$AGENT_HOME/.ssh/known_hosts"
    install -d -o rn-build-agent -g rn-build-jobs -m 2750 /var/lib/rn-build-jobs
    install -d -o root -g root -m 0755 /opt/rn-build-agent

    put_file "$BUNDLE/bin/build-agent" /opt/rn-build-agent/build-agent root root 0755
    put_file "$BUNDLE/bin/build-runner" /opt/rn-build-agent/build-runner root root 0755
    put_file "$WORK/github_known_hosts" "$AGENT_KNOWN_HOSTS" root root 0644
    visudo -cf "$BUNDLE/rn-build-agent.sudoers" >/dev/null || die "安装包里的 sudoers 语法检查没过"
    put_file "$BUNDLE/rn-build-agent.sudoers" /etc/sudoers.d/rn-build-agent root root 0440
    put_file "$BUNDLE/rn-build-agent.service" /etc/systemd/system/rn-build-agent.service root root 0644
    for name in rn-build-agent.env.example README.md; do
      [ ! -f "$BUNDLE/$name" ] || put_file "$BUNDLE/$name" "/opt/rn-build-agent/$name" root root 0644
    done
    systemctl daemon-reload

    # 冒烟：以权限更小的 builder、空环境各跑一次，必须以 2 退出。它们按设计以非 0 退出，不能让 set -e 当成失败
    local code builder_uid builder_gid
    builder_uid="$(id -u builder)"
    builder_gid="$(id -g builder)"
    code=0
    setpriv --reuid="$builder_uid" --regid="$builder_gid" --clear-groups --no-new-privs \
      env -i /opt/rn-build-agent/build-agent >/dev/null 2>&1 || code=$?
    [ "$code" = 2 ] || die "build-agent 空环境冒烟退出码 $code，应为 2"
    code=0
    setpriv --reuid="$builder_uid" --regid="$builder_gid" --clear-groups --no-new-privs \
      env -i /opt/rn-build-agent/build-runner >/dev/null 2>&1 || code=$?
    [ "$code" = 2 ] || die "build-runner 无参数冒烟退出码 $code，应为 2"
    note "冒烟通过：build-agent、build-runner 都以 2 退出"
  fi

  step "GitHub 只读 deploy key 与仓库镜像"
  if as_agent test -d "$AGENT_MIRROR"; then
    MIRROR_READY=yes
    note "仓库镜像已存在：$AGENT_MIRROR"
  else
    if as_agent test -f "$AGENT_HOME/.ssh/id_ed25519"; then
      had_deploy_key=yes
    else
      as_agent ssh-keygen -q -t ed25519 -N "" -C "rn-build-agent@$(hostname)" -f "$AGENT_HOME/.ssh/id_ed25519"
      note "已生成 deploy key（要先加到 GitHub，见下一步）"
    fi
    if [ "$had_deploy_key" = yes ]; then
      note "以 rn-build-agent 克隆仓库镜像（deploy key 要已经加到 GitHub）"
      as_agent rm -rf "$AGENT_MIRROR.part"
      # 与控制进程同样的防护：不读系统与全局 git 配置、不跑 hook、只许 ssh、空模板
      if as_agent env -i PATH="$SERVICE_PATH" HOME="$AGENT_HOME" LANG=C GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$(agent_ssh_command)" \
        git -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.ssh.allow=always \
        clone --quiet --mirror --template= "$APP_REPO_URL" "$AGENT_MIRROR.part" &&
        as_agent chmod 0700 "$AGENT_MIRROR.part" && as_agent mv -T "$AGENT_MIRROR.part" "$AGENT_MIRROR"; then
        MIRROR_READY=yes
        note "仓库镜像已就位"
      else
        as_agent rm -rf "$AGENT_MIRROR.part"
        warn "克隆失败：deploy key 多半还没加到 GitHub（见下一步第 1 条）"
      fi
    fi
  fi

  # 注册：已注册时也照样调一次（幂等——已有令牌就不连服务端、直接核对本机密钥）。注册码经环境变量
  # RN_ENROLLMENT_CODE 交给它，不进进程参数（本机其他用户读得到 /proc/<pid>/cmdline 与 sudo 日志）。
  step "注册"
  RN_ENROLLMENT_CODE="$CODE" /opt/rn-build-agent/build-agent enroll --server "$SERVER" --env-file "$AGENT_ENV" --state-dir "$AGENT_STATE" ||
    die "build-agent enroll 失败（见上面的输出）。修好之后重新执行同一条命令"
  has_machine_token "$AGENT_ENV" BUILD_AGENT_MACHINE_TOKEN || die "build-agent enroll 报告成功，但 $AGENT_ENV 里没有机器令牌"

  step "启动"
  systemctl enable --quiet rn-build-agent
  if [ "$enrolled" = no ] || [ "$(systemctl show -p ActiveState --value rn-build-agent)" != active ]; then
    local marker="$WORK/started"
    touch "$marker"
    systemctl restart rn-build-agent
    wait_active rn-build-agent.service
    # show-key 的 "build runner:" 一行取自常驻进程启动时写的 runner-mode.json：等这次启动写完再读
    local i
    for i in $(seq 1 30); do
      [ "$AGENT_STATE/runner-mode.json" -nt "$marker" ] && break
      [ "$i" = 30 ] || sleep 1
    done
  fi
  wait_active rn-build-agent.service
  note "rn-build-agent.service 在运行"

  step "本机身份（公开信息：控制台接受与签名闸 trust-builder 时逐位核对）"
  sudo -u rn-build-agent /opt/rn-build-agent/build-agent show-key --state-dir "$AGENT_STATE" || warn "build-agent show-key 失败"

  step "下一步"
  local n=1
  if [ "$MIRROR_READY" != yes ]; then
    cat <<NEXT
   $n. 把这台机器的 deploy key 加到 GitHub 仓库 Helix2010/RN-App → Settings → Deploy keys（只读，不勾 write access）：
        $(as_agent cat "$AGENT_HOME/.ssh/id_ed25519.pub")
      然后重新执行同一条安装命令（会克隆仓库镜像，其余步骤跳过）。
NEXT
    n=$((n + 1))
  fi
  cat <<NEXT
   $n. 控制台「平台维护 → 打包机与签名闸」：$MACHINE_NAME 显示的出处公钥 sha256 与上面一致后，点「接受」。
   $((n + 1)). 在每台签名闸本机信任这台构建机（粘贴上面的出处公钥完整 sha256）：
        sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer trust-builder --builder $MACHINE_NAME --env-file /etc/rn-signer-<实例>.env
      实例名默认就是签名闸的机器名；amos 上手工部署的两台是 rn-signer-a、rn-signer-b。
NEXT
}

main() {
  # curl … | bash 时脚本本身从 stdin 读：之后的命令一律不许读 stdin
  exec </dev/null
  parse_args "$@"
  preflight_basic
  WORK="$(mktemp -d /tmp/rn-machine-setup.XXXXXX)"
  trap 'rm -rf "$WORK"' EXIT
  describe
  resolve_target
  preflight_role
  fetch_bundle
  if [ "$ROLE" = signer ]; then
    install_signer
  else
    install_builder
  fi
  printf '\n安装完成。\n'
}

main "$@"
exit
