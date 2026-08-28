#!/bin/bash
# Semgrep Scanner Engine Module (Stage 1: Deterministic Scan)
# Sourced by security_gate_hook.sh

run_semgrep_gate() {
  local in_pipeline="${1:-false}"
  _init_pipeline_dir

  if ! command -v semgrep >/dev/null 2>&1; then
    if [ "$in_pipeline" = "true" ]; then
      echo "Deterministic scanner (semgrep) not installed - proceeding to Stage 2." >&2
      return 0
    else
      handle_scan_error "semgrep" "the 'semgrep' CLI is not on PATH"
    fi
  fi

  # 1. Discover modified files
  local MODIFIED_FILES
  MODIFIED_FILES=$(git diff --name-only origin/main 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || true)
  if [ -z "$MODIFIED_FILES" ]; then
    [ "$in_pipeline" = "true" ] && return 0 || allow
  fi

  local MODIFIED_FILES_ARR
  read_lines_into_array MODIFIED_FILES_ARR "$MODIFIED_FILES"
  local FILES_TO_SCAN=()
  for file in "${MODIFIED_FILES_ARR[@]}"; do
    [ -f "$file" ] && FILES_TO_SCAN+=("$file")
  done

  if [ ${#FILES_TO_SCAN[@]} -eq 0 ]; then
    [ "$in_pipeline" = "true" ] && return 0 || allow
  fi

  echo "Stage 1: Running Deterministic AST Scan (semgrep) on: ${FILES_TO_SCAN[*]}" >&2
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
    if [ "$in_pipeline" = "true" ]; then
      handle_scan_error "semgrep" "semgrep exited $SEMGREP_EXIT: ${ERR_DETAIL:-no output}" false
      return 0
    else
      handle_scan_error "semgrep" "semgrep exited $SEMGREP_EXIT: ${ERR_DETAIL:-no output}" false
    fi
  fi
  rm -f "$SEMGREP_ERR_FILE"

  local FINDINGS_COUNT
  FINDINGS_COUNT=$(echo "$SEMGREP_OUTPUT" | jq '.results | length' 2>/dev/null || echo 0)
  if [ "$FINDINGS_COUNT" -eq 0 ]; then
    echo "Deterministic scan clean. No AST vulnerabilities found." >&2
    [ "$in_pipeline" = "true" ] && return 0 || allow
  fi

  # 2. Split findings by threat model & severity
  local WORK_DIR
  WORK_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'sg_work')
  echo "$SEMGREP_OUTPUT" | jq -c '.results[]' > "$WORK_DIR/all.jsonl"
  : > "$WORK_DIR/blocking.jsonl"
  : > "$WORK_DIR/advisory.jsonl"

  while IFS= read -r finding; do
    [ -z "$finding" ] && continue
    local SEV FILE CHECK_ID
    SEV=$(echo "$finding" | jq -r '.extra.severity // "UNKNOWN"')
    FILE=$(echo "$finding" | jq -r '.path')
    CHECK_ID=$(echo "$finding" | jq -r '.check_id // "unknown"')

    if is_blocking_severity "$SEV" && matches_threat_model "$CHECK_ID" "$FILE" "$CHECK_ID"; then
      echo "$finding" >> "$WORK_DIR/blocking.jsonl"
    else
      echo "$finding" >> "$WORK_DIR/advisory.jsonl"
    fi
  done < "$WORK_DIR/all.jsonl"

  local ADV_COUNT
  ADV_COUNT=$(wc -l < "$WORK_DIR/advisory.jsonl" | tr -d ' ')
  if [ "$ADV_COUNT" -gt 0 ]; then
    local ADV_JSON
    ADV_JSON=$(jq -s '.' "$WORK_DIR/advisory.jsonl")
    log_event "ADVISORY" "semgrep" "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
    notify "ADVISORY" "$ADV_COUNT deterministic finding(s) treated as advisory." \
      "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
  fi

  local BLOCK_COUNT
  BLOCK_COUNT=$(wc -l < "$WORK_DIR/blocking.jsonl" | tr -d ' ')
  if [ "$BLOCK_COUNT" -eq 0 ]; then
    rm -rf "$WORK_DIR"
    [ "$in_pipeline" = "true" ] && return 0 || allow
  fi

  if [ "$in_pipeline" = "true" ]; then
    echo "Detected $BLOCK_COUNT in-scope deterministic finding(s). Exporting to Stage 2 for contextual evaluation..." >&2
    cat "$WORK_DIR/blocking.jsonl" >> "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl"
    rm -rf "$WORK_DIR"
    return 0
  fi

  # Standalone Semgrep mode: Evaluate attempt budget per finding and prompt agent
  local ACTIONABLE_COUNT=0
  local ACTIONABLE_SUMMARY=""

  while IFS= read -r finding; do
    [ -z "$finding" ] && continue
    local FILE CHECK_ID SEV DESC
    FILE=$(echo "$finding" | jq -r '.path')
    CHECK_ID=$(echo "$finding" | jq -r '.check_id // "unknown"')
    SEV=$(echo "$finding" | jq -r '.extra.severity // "UNKNOWN"')
    DESC=$(echo "$finding" | jq -r '.extra.message // ""')

    local PREV_ATTEMPTS
    PREV_ATTEMPTS=$(get_finding_attempt_count "$CHECK_ID" "$FILE")
    local CURRENT_ATTEMPT=$((PREV_ATTEMPTS + 1))

    if [ "$CURRENT_ATTEMPT" -gt "$SECURITY_GATE_MAX_RETRIES" ]; then
      log_event "BLOCKED" "semgrep" "$(jq -n --arg cid "$CHECK_ID" --arg f "$FILE" '{finding_id:$cid, file:$f, reason:"max_attempts_exhausted"}')"
      rm -rf "$WORK_DIR"
      deny "Finding $CHECK_ID ($SEV) in $FILE remained unresolved after $SECURITY_GATE_MAX_RETRIES attempts. Manual security review required. See $SECURITY_GATE_LOG."
    fi

    log_event "DENIED_TO_AGENT" "semgrep" "$(jq -n --arg cid "$CHECK_ID" --arg f "$FILE" --arg sev "$SEV" --argjson a "$CURRENT_ATTEMPT" '{finding_id:$cid, file:$f, severity:$sev, attempt:$a}')"
    ACTIONABLE_COUNT=$((ACTIONABLE_COUNT + 1))
    ACTIONABLE_SUMMARY+=$'\n'"- [$CHECK_ID] ($SEV) in $FILE (Attempt $CURRENT_ATTEMPT/$SECURITY_GATE_MAX_RETRIES): $DESC"
  done < "$WORK_DIR/blocking.jsonl"

  rm -rf "$WORK_DIR"

  local REJECTION_PROMPT="Security Gate blocked push ($ACTIONABLE_COUNT unresolved deterministic finding(s)).

Action Required: Execute the Secure TDD Loop sequentially for each finding:
For each finding below (one at a time):
  1. Invoke 'security_test_writer' to author one failing boundary test in tests/ (assert RED).
  2. Invoke 'defensive_developer' to apply the minimal defensive fix (assert GREEN).
  3. Run the local test to confirm it passes before moving to the next finding.
Once all findings are resolved, run the full regression test suite ($SECURITY_GATE_TEST_CMD) and retry 'git push'.

Open Findings:${ACTIONABLE_SUMMARY}"

  deny "$REJECTION_PROMPT"
}
