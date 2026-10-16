#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${VERSION:-dev}
archive="$root/dist/prometheus-rmm-$version-source.tar.gz"
mkdir -p "$root/dist"
git -C "$root" archive --format=tar.gz --prefix="prometheus-rmm-$version/" -o "$archive" HEAD
sha256sum "$archive" > "$archive.sha256"
echo "$archive"
