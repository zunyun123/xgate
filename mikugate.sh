#!/usr/bin/env bash
# Miku Gate short installer entry point (self-use version).
#
# 自用版指向：不要再用上游 vioIetMiku/miku-gate。
# 发布前把下面 YOUR_GITHUB_USER 换成你自己的 GitHub 用户名，
# 或者运行时传环境变量，二者都行，环境变量优先：
  MIKU_GATE_REPO=zunyun123/xgate bash <(curl -fsSL https://raw.githubusercontent.com/zunyun123/xgate/main/mikugate.sh)
# 占位没换就直接报错停下，避免悄悄又装回上游版本。
set -euo pipefail
repo="${MIKU_GATE_REPO:-YOUR_GITHUB_USER/miku-gate}"
if [[ "$repo" == YOUR_GITHUB_USER/* ]]; then
  echo '请先把 mikugate.sh 里的 YOUR_GITHUB_USER 换成你自己的 GitHub 用户名，或设置 MIKU_GATE_REPO=你的用户名/miku-gate 再运行。' >&2
  exit 1
fi
url="https://github.com/${repo}/releases/latest/download/install-online.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/mikugate.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$tmp/install-online.sh"
bash "$tmp/install-online.sh" "$@"
