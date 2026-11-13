#!/usr/bin/env bash
#
# Checks that a release build contains none of the test-only hooks (the `test-store` feature):
# no plaintext test store, no forced-interactive switch, no API URL override.
#
# Usage: scripts/check-release-build.sh [path-to-binary]   (builds a release binary when none given)

set -euo pipefail

binary="${1:-}"
if [[ -z "$binary" ]]; then
  cargo build --release --locked
  binary="target/release/cf-vault"
fi

# Read the strings once: `strings | grep -q` would fail under pipefail when grep exits early
listing="$(mktemp)"
trap 'rm -f "$listing"' EXIT
strings "$binary" > "$listing"

status=0
for marker in CF_VAULT_STORE_DIR CF_VAULT_STORE_UNAVAILABLE CF_VAULT_FORCE_INTERACTIVE \
  CF_VAULT_API_URL CF_VAULT_CALLBACK_TIMEOUT_MS CF_VAULT_RETRY_DELAY_MS; do
  if grep -q "$marker" "$listing"; then
    echo "FAIL: $marker found in $binary (test-store feature leaked into the build)" >&2
    status=1
  fi
done
[[ $status -eq 0 ]] && echo "ok: $binary has no test-only hooks"
exit $status
