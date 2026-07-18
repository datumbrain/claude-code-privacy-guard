#!/bin/bash

LOG_FILE="/tmp/claude-code-privacy-guard.log"

# Log debug info to file
{
  echo "=== Hook Execution $(date) ==="
  echo "CLAUDE_PLUGIN_ROOT: ${CLAUDE_PLUGIN_ROOT}"
  echo "CWD: $(pwd)"
  echo "Node version: $(node --version)"
} >> "$LOG_FILE" 2>&1

# Run the actual script - stdin flows through, stdout goes to stdout, stderr to logfile
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  node "${CLAUDE_PLUGIN_ROOT}/scripts/prompt-guard.js" 2>> "$LOG_FILE"
  EXIT_CODE=$?
  echo "Exit code: $EXIT_CODE" >> "$LOG_FILE"
  exit $EXIT_CODE
else
  echo "ERROR: CLAUDE_PLUGIN_ROOT not set" | tee -a "$LOG_FILE" >&2
  exit 1
fi
