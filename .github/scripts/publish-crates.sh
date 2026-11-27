#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?Set VERSION to the version being published}"
test -n "${CARGO_REGISTRY_TOKEN:-}" || { echo '::error::CARGO_REGISTRY_TOKEN is not configured'; exit 1; }
crates=(forge-error forge-audit forge-config forge-manifest forge-sandbox forge-sandbox-worker forge-server forge-client forgemax)
log=$(mktemp "${RUNNER_TEMP:-/tmp}/crate-publication.XXXXXX")
trap 'rm -f "$log"' EXIT
for crate in "${crates[@]}"; do
  echo "::group::Publishing $crate $VERSION"
  for attempt in 1 2 3 4 5; do
    if cargo publish --locked --registry crates-io -p "$crate" >"$log" 2>&1; then
      cat "$log"
      break
    fi
    cat "$log" >&2
    if grep -Eqi '(status|HTTP response).*(401|403)|unauthorized|forbidden|invalid.*token|token.*invalid|authentication|requires a token|not authorized|not enough permissions' "$log"; then
      echo '::error::crates.io authentication or authorization failed; no retry'
      exit 1
    fi
    if grep -Eqi 'already uploaded|already been uploaded' "$log"; then
      echo "$crate $VERSION is already published"
      break
    fi
    if [ "$attempt" -eq 5 ] || ! grep -Eqi 'no matching package named|failed to select a version|failed to download|failed to get|failed to query|failed to fetch|timed out|timeout|could not resolve host|connection reset|429|50[0-9]|bad gateway|service unavailable' "$log"; then
      exit 1
    fi
    echo "Retrying $crate after a transient registry or dependency-index error ($attempt/5)"
    sleep 30
  done
  echo '::endgroup::'
done
