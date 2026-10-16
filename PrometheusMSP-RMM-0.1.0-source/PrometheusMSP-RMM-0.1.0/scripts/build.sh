#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist="$root/dist"
mkdir -p "$dist"

build() {
  os=$1 arch=$2 package=$3 output=$4
  echo "Building $output"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$dist/$output" "$package"
}

cd "$root"
build linux amd64 ./control-plane/cmd/control-plane control-plane-linux-amd64
build linux amd64 ./agent/cmd/prometheus-agent prometheus-rmm-agent-linux-amd64
build linux arm64 ./agent/cmd/prometheus-agent prometheus-rmm-agent-linux-arm64
build windows amd64 ./agent/cmd/prometheus-agent prometheus-rmm-agent-windows-amd64.exe
rm -f "$dist/SHA256SUMS"
sha256sum "$dist"/* > "$dist/SHA256SUMS"
