#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="docker://busybox:musl"
OCI_DIR="busybox-oci"
BUNDLE_DIR="bundle"
BUNDLE_TAR="mnt/bundle.tar"

rm -rf "$OCI_DIR" "$BUNDLE_DIR" "$BUNDLE_TAR"
mkdir -p "$(dirname "$BUNDLE_DIR")"

skopeo copy "$IMAGE" "oci:$OCI_DIR:latest"
umoci unpack --rootless --image "$OCI_DIR:latest" "$BUNDLE_DIR"

rm -f "$BUNDLE_DIR"/umoci.json "$BUNDLE_DIR"/sha256_*.mtree
tar --format=posix --numeric-owner -C "$BUNDLE_DIR" -cf "$BUNDLE_TAR" .

rm -rf "$OCI_DIR" "$BUNDLE_DIR"
