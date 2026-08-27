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

  echo "Detected $BLOCK_COUNT in-scope deterministic finding(s). Attempting 3-attempt TDD autofix..." >&2

  # 3. 3-Attempt TDD Autofix Loop
  local UNRESOLVED_COUNT=0
  while IFS= read -r finding; do
    [ -z "$finding" ] && continue
    local FILE CHECK_ID SEV DESC
    FILE=$(echo "$finding" | jq -r '.path')
    CHECK_ID=$(echo "$finding" | jq -r '.check_id // "unknown"')
    SEV=$(echo "$finding" | jq -r '.extra.severity // "UNKNOWN"')
    DESC=$(echo "$finding" | jq -r '.extra.message // ""')

    local RETRY=0
    local RESOLVED=false

    while [ "$RETRY" -lt "$SECURITY_GATE_MAX_RETRIES" ]; do
      RETRY=$((RETRY+1))
      echo "Applying deterministic autofix for $CHECK_ID in $FILE (Attempt $RETRY)..." >&2

      # Attempt autofix with semgrep
      semgrep scan --autofix --config auto "$FILE" >/dev/null 2>&1 || true

      if [ -n "$SECURITY_GATE_TEST_CMD" ]; then
        if ! sh -c "$SECURITY_GATE_TEST_CMD" >/dev/null 2>&1; then
          echo "Autofix broke regression tests on attempt $RETRY. Reverting..." >&2
          git checkout -- . 2>/dev/null || true
          continue
        fi
      fi

      # Check if semgrep confirms finding resolved
      local RESCAN_COUNT
      RESCAN_COUNT=$(semgrep scan --config auto --json "$FILE" 2>/dev/null | jq --arg cid "$CHECK_ID" '[.results[] | select(.check_id == $cid)] | length' 2>/dev/null || echo 0)
      if [ "$RESCAN_COUNT" -eq 0 ]; then
        commit_fix "$CHECK_ID" "$FILE" "$DESC"
        log_event "FIXED" "semgrep" "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
        evolve_context_and_skills "$CHECK_ID" "$FILE" "$DESC"
        echo "$finding" >> "$SECURITY_GATE_PIPELINE_DIR/imported_fixes.jsonl"
        RESOLVED=true
        break
      else
        git checkout -- . 2>/dev/null || true
      fi
    done

    if [ "$RESOLVED" != "true" ]; then
      echo "Deterministic autofix for $CHECK_ID could not satisfy tests after $SECURITY_GATE_MAX_RETRIES attempts." >&2
      git checkout -- . 2>/dev/null || true
      echo "$finding" >> "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl"
      UNRESOLVED_COUNT=$((UNRESOLVED_COUNT+1))
    fi
  done < "$WORK_DIR/blocking.jsonl"

  rm -rf "$WORK_DIR"

  if [ "$in_pipeline" = "true" ]; then
    # In pipeline mode, unresolved findings pass to Stage 2
    return 0
  fi

  if [ "$UNRESOLVED_COUNT" -gt 0 ]; then
    log_event "BLOCKED" "semgrep" "{}"
    deny "Semgrep detected $UNRESOLVED_COUNT unresolved security issue(s). Fix and verify before pushing."
  fi

  allow
}
