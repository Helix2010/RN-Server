#!/usr/bin/env bash
# 打印「打包机构建输入最后一次变化的提交」（agent 提交），设计 docs/design/agent-version-from-build-inputs-2026-09-25.md。
#
#   deploy/setup/agent-commit.sh            打印提交
#   deploy/setup/agent-commit.sh --paths    打印参与计算的路径（排查用）
#
# 安装包里的程序、清单里的 commit、归档的 mtime、CI 给 amos 编的 build-agent 的 main.commit 都取它，
# 而不是 HEAD：只改服务端的提交不改变它，build-bundles.sh 又可复现，于是清单逐字节相同、已有的签名与
# 批准继续有效，不用为一个服务端改动再离线签一次。
#
# 输入分两部分：
#   - Go 代码按依赖算，不手写清单：安装包里每个程序在它实际编译的平台上 `go list -deps`，取仓库内的包，
#     每个包只算**这一层**的 .go 文件（不递归进子目录，不算 _test.go）加上它 go:embed 的文件。删掉一个
#     .go 文件也会被 `dir/*.go` 匹配到。外部依赖在模块缓存里，由下面的 go.mod / go.sum 覆盖。
#   - 非 Go 的输入写死：build-bundles.sh 拷进归档或决定怎么编的文件。**build-bundles.sh 多拷一样东西，
#     这里就要多一行**；漏了的话 CI 的守门（同一 agent 提交、不同字节）会拦下安装包与打包机的部署。
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
# 与 build-bundles.sh 同一组编译条件；GOFLAGS / GOWORK 清掉，免得环境里的设置让依赖清单变样
export GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS='' GOWORK=off

# $1 = module 目录（相对仓库根），$2 = GOOS/GOARCH，其余 = 包。与 build-bundles.sh 的编译目标一一对应
# 每行输出「包目录<TAB>embed 文件（逗号分隔）」
list_deps() {
  local module="$1" target="$2" out
  shift 2
  out="$(cd "$ROOT/$module" && GOOS="${target%/*}" GOARCH="${target#*/}" \
    go list -deps -f '{{if not .Standard}}{{.Dir}}{{"\t"}}{{join .EmbedFiles ","}}{{end}}' "$@")"
  [ -n "$out" ] || { echo "go list 没有输出（$module $target $*）" >&2; exit 1; }
  printf '%s\n' "$out"
}

paths() {
  {
    list_deps . linux/amd64 ./cmd/build-agent ./cmd/build-agent/build-runner
    list_deps . darwin/arm64 ./cmd/build-agent ./cmd/build-agent/build-runner \
      ./cmd/build-agent/ios-upload ./cmd/build-agent/upgrade
    list_deps signing linux/amd64 ./cmd/signer ./cmd/signer-check
  } | while IFS=$'\t' read -r dir embeds; do
    case "$dir" in
    "$ROOT"/*) ;;
    *) continue ;;
    esac
    rel="${dir#"$ROOT"/}"
    printf ':(glob)%s/*.go\n' "$rel"
    if [ -n "$embeds" ]; then
      tr ',' '\n' <<<"$embeds" | while IFS= read -r f; do printf '%s/%s\n' "$rel" "$f"; done
    fi
  done
  # 逐个对着 build-bundles.sh 的 cp / install 写，不整目录收：同目录下的运维手册（MAC_SETUP_RUNBOOK.md、
  # SIGNING_MATERIAL.md）不进归档，把它们算进来的话改一次文档就要重签一次
  printf '%s\n' \
    go.mod go.sum signing/go.mod signing/go.sum \
    deploy/setup/build-bundles.sh deploy/setup/agent-commit.sh \
    deploy/signer/templates deploy/signer/README.md internal/machinesetup/install.sh \
    deploy/build-agent/rn-build-agent.service deploy/build-agent/rn-build-agent.sudoers \
    deploy/build-agent/rn-build-agent.env.example deploy/build-agent/README.md \
    deploy/build-agent-macos/release-key.pub deploy/build-agent-macos/allowed_signers \
    deploy/build-agent-macos/rn-build-agent-macos.env.example deploy/build-agent-macos/AppleWWDRCAG3.cer \
    deploy/build-agent-macos/rn-build-agent.sudoers deploy/build-agent-macos/run-agent \
    deploy/build-agent-macos/win.anyfun.rn-build-agent.plist \
    deploy/build-agent-macos/win.anyfun.rn-build-agent-upgrade.plist
}

if [ "${1:-}" = --paths ]; then
  paths | sort -u
  exit 0
fi

if [ "$(git -C "$ROOT" rev-parse --is-shallow-repository)" = true ]; then
  echo "浅克隆里算不出 agent 提交（CI 的 checkout 要 fetch-depth: 0）" >&2
  exit 1
fi
mapfile -t inputs < <(paths | sort -u)
# rev-list 而不是 log：不受 log.showSignature 之类的个人配置影响
commit="$(git -C "$ROOT" rev-list -1 HEAD -- "${inputs[@]}" ':(exclude,glob)**/*_test.go')"
[ -n "$commit" ] || { echo "算不出 agent 提交" >&2; exit 1; }
printf '%s\n' "$commit"
