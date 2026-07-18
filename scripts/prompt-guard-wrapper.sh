#!/bin/bash

# Debug logging is opt-in: set PRIVACY_GUARD_DEBUG=1 to enable.
# Never write matched secret values here - only execution metadata.
if [ "$PRIVACY_GUARD_DEBUG" = "1" ]; then
  CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/claude-code-privacy-guard"
  mkdir -p "$CACHE_DIR"
  LOG_FILE="$CACHE_DIR/debug.log"

  {
    echo "=== Hook Execution $(date) ==="
    echo "CLAUDE_PLUGIN_ROOT: ${CLAUDE_PLUGIN_ROOT}"
    echo "CWD: $(pwd)"
    echo "Node version: $(node --version)"
  } >> "$LOG_FILE" 2>&1
fi

# Run the actual script - stdin flows through, stdout goes to stdout.
# stderr goes to the debug log when enabled, otherwise it's discarded
# (Claude Code renders the block reason from stdout JSON, not stderr).
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  if [ "$PRIVACY_GUARD_DEBUG" = "1" ]; then
    node "${CLAUDE_PLUGIN_ROOT}/scripts/prompt-guard.js" 2>> "$LOG_FILE"
    EXIT_CODE=$?
    echo "Exit code: $EXIT_CODE" >> "$LOG_FILE"
  else
    node "${CLAUDE_PLUGIN_ROOT}/scripts/prompt-guard.js" 2>/dev/null
    EXIT_CODE=$?
  fi
  exit $EXIT_CODE
else
  echo "ERROR: CLAUDE_PLUGIN_ROOT not set" >&2
  if [ "$PRIVACY_GUARD_DEBUG" = "1" ]; then
    echo "ERROR: CLAUDE_PLUGIN_ROOT not set" >> "$LOG_FILE"
  fi
  exit 1
fi
