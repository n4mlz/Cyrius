#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="docker://busybox:musl"
OCI_DIR="busybox-oci"
BUNDLE_DIR="mnt/bundle"

rm -rf "$OCI_DIR" "$BUNDLE_DIR"

skopeo copy "$IMAGE" "oci:$OCI_DIR:latest"
umoci unpack --rootless --image "$OCI_DIR:latest" "$BUNDLE_DIR"

rm -rf "$OCI_DIR" "$BUNDLE_DIR"/umoci.json "$BUNDLE_DIR"/sha256_*.mtree

