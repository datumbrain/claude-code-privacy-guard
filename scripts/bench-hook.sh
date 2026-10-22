#!/usr/bin/env bash
# Compare per-invocation hook time with and without the on-disk rule cache.
# Usage: scripts/bench-hook.sh [runs]   (default 100)
# Needs a built dist/ (npm run build). Uses a throwaway cache dir, so it never
# touches your real Privacy Guard cache.
set -euo pipefail

RUNS="${1:-100}"
HOOK="$(cd "$(dirname "$0")" && pwd)/prompt-guard.js"
CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT
INPUT='{"session_id":"bench","prompt":"refactor the parser to stream tokens"}'

now_ms() { node -e 'process.stdout.write(String(Date.now()))'; }

run_batch() {
  local label="$1"; shift
  local start end
  start=$(now_ms)
  for _ in $(seq "$RUNS"); do
    printf '%s' "$INPUT" | env XDG_CACHE_HOME="$CACHE" LOCALAPPDATA="$CACHE" "$@" node "$HOOK" >/dev/null
  done
  end=$(now_ms)
  awk -v l="$label" -v t="$((end - start))" -v n="$RUNS" 'BEGIN { printf "%-22s %7.2f ms/run  (%d runs)\n", l, t / n, n }'
}

# Warm-up so file-system caches are hot for both variants.
printf '%s' "$INPUT" | env XDG_CACHE_HOME="$CACHE" LOCALAPPDATA="$CACHE" node "$HOOK" >/dev/null

run_batch "no cache" PRIVACY_GUARD_NO_CACHE=1
run_batch "rule cache (warm)"
