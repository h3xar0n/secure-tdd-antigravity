#!/bin/bash
# Semgrep Scanner Engine Module
# Sourced by security_gate_hook.sh

run_semgrep_gate() {
  command -v semgrep >/dev/null 2>&1 || handle_scan_error "semgrep" "the 'semgrep' CLI is not on PATH"

  # 1. Discover modified files
  local MODIFIED_FILES
  MODIFIED_FILES=$(git diff --name-only origin/main 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || true)
  if [ -z "$MODIFIED_FILES" ]; then
    allow
  fi

  local MODIFIED_FILES_ARR
  read_lines_into_array MODIFIED_FILES_ARR "$MODIFIED_FILES"
  local FILES_TO_SCAN=()
  for file in "${MODIFIED_FILES_ARR[@]}"; do
    [ -f "$file" ] && FILES_TO_SCAN+=("$file")
  done

  if [ ${#FILES_TO_SCAN[@]} -eq 0 ]; then
    allow
  fi

  echo "Running Semgrep scan on: ${FILES_TO_SCAN[*]}" >&2
  local SEMGREP_ERR_FILE
  SEMGREP_ERR_FILE=$(mktemp)
  local SEMGREP_OUTPUT SEMGREP_EXIT
  if SEMGREP_OUTPUT=$(semgrep scan --config auto --json "${FILES_TO_SCAN[@]}" 2>"$SEMGREP_ERR_FILE"); then
    SEMGREP_EXIT=0
  else
    SEMGREP_EXIT=$?
  fi
  if [ "$SEMGREP_EXIT" -ne 0 ] || ! echo "$SEMGREP_OUTPUT" | jq -e . >/dev/null 2>&1; then
    local ERR_DETAIL
    ERR_DETAIL=$(tail -c 500 "$SEMGREP_ERR_FILE" 2>/dev/null)
    rm -f "$SEMGREP_ERR_FILE"
    handle_scan_error "semgrep" "semgrep exited $SEMGREP_EXIT: ${ERR_DETAIL:-no output}"
  fi
  rm -f "$SEMGREP_ERR_FILE"

  local FINDINGS_COUNT
  FINDINGS_COUNT=$(echo "$SEMGREP_OUTPUT" | jq '.results | length' 2>/dev/null || echo 0)
  if [ "$FINDINGS_COUNT" -eq 0 ]; then
    echo "No vulnerabilities found. Allowing push." >&2
    allow
  fi

  # 2. Split findings by severity
  local BLOCKING_JSON ADVISORY_JSON
  BLOCKING_JSON=$(echo "$SEMGREP_OUTPUT" | jq -c '.results[]' | while IFS= read -r r; do
    local SEV RANK THRESH
    SEV=$(echo "$r" | jq -r '.extra.severity // "UNKNOWN"')
    RANK=$(severity_rank "$SEV")
    THRESH=$(severity_rank "$SECURITY_GATE_BLOCK_SEVERITY")
    [ "$RANK" -ge "$THRESH" ] && echo "$r"
  done | jq -s '.')
  ADVISORY_JSON=$(echo "$SEMGREP_OUTPUT" | jq -c '.results[]' | while IFS= read -r r; do
    local SEV RANK THRESH
    SEV=$(echo "$r" | jq -r '.extra.severity // "UNKNOWN"')
    RANK=$(severity_rank "$SEV")
    THRESH=$(severity_rank "$SECURITY_GATE_BLOCK_SEVERITY")
    [ "$RANK" -lt "$THRESH" ] && echo "$r"
  done | jq -s '.')

  local ADV_COUNT
  ADV_COUNT=$(echo "$ADVISORY_JSON" | jq 'length')
  if [ "$ADV_COUNT" -gt 0 ]; then
    log_event "ADVISORY" "semgrep" "$(jq -n --argjson f "$ADVISORY_JSON" '{findings:$f}')"
    notify "ADVISORY" "$ADV_COUNT finding(s) below the $SECURITY_GATE_BLOCK_SEVERITY block threshold were pushed without blocking. Review $SECURITY_GATE_LOG." \
      "$(jq -n --argjson f "$ADVISORY_JSON" '{findings:$f}')"
  fi

  local BLOCK_COUNT
  BLOCK_COUNT=$(echo "$BLOCKING_JSON" | jq 'length')
  if [ "$BLOCK_COUNT" -eq 0 ]; then
    echo "Only advisory-severity findings (below $SECURITY_GATE_BLOCK_SEVERITY). Allowing push." >&2
    allow
  fi

  # 3. Format blocking findings and deny
  local FINDINGS_DESC
  FINDINGS_DESC=$(echo "$BLOCKING_JSON" | jq -r '
    .[] |
    "File: \(.path) Line: \(.start.line)\nRule: \(.check_id)\nDescription: \(.extra.message)\nSeverity: \(.extra.severity)\n---"
  ')

  echo "Detected $BLOCK_COUNT blocking-severity vulnerabilit(y/ies)." >&2
  echo "$FINDINGS_DESC" >&2

  log_event "BLOCKED" "semgrep" "$(jq -n --argjson f "$BLOCKING_JSON" '{findings:$f}')"

  local REASON
  REASON="Semgrep detected $BLOCK_COUNT security issue(s) at/above the $SECURITY_GATE_BLOCK_SEVERITY threshold in your changes. You must fix them before pushing:
$FINDINGS_DESC"

  deny "$REASON"
}
