#!/usr/bin/env bash
# Opt-in node-only conformance checks against an ALREADY RUNNING driver.
set -euo pipefail
if ! command -v csi-sanity >/dev/null 2>&1; then
    echo 'skip: kubernetes-csi/csi-test csi-sanity is not installed'
    exit 0
fi
: "${CSI_ENDPOINT:?set CSI_ENDPOINT to an isolated running driver socket}"
# Upstream csi-test v5.3.1 calls ControllerGetCapabilities even in Node's
# BeforeEach, and its successful mount tests require CreateVolume. Neither
# exists on this node-only plugin. Run its applicable Identity suite; the
# Rust generated-client tests and test-kind.sh exercise the Node lifecycle.
csi-sanity --csi.endpoint="$CSI_ENDPOINT" \
    --ginkgo.focus='Identity Service' "$@"
