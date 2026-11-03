#!/usr/bin/env bash
# Miku Gate short installer entry point.
set -euo pipefail
url='https://raw.githubusercontent.com/zunyun123/xgate/main/install-online.sh'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/mikugate.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$tmp/install-online.sh"
bash "$tmp/install-online.sh" "$@"
