#!/bin/bash
# CodeMender Scanner Engine Module (Stage 2: Semantic Scan & Remediation)
# Sourced by security_gate_hook.sh

run_codemender_gate() {
  local in_pipeline="${1:-false}"
  _init_pipeline_dir

  if ! command -v cm >/dev/null 2>&1; then
    if [ "$in_pipeline" = "true" ]; then
      # If in pipeline and semgrep had unresolved findings, deny; otherwise allow
      if [ -f "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl" ] && [ -s "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl" ]; then
        local IMPORTED_COUNT
        IMPORTED_COUNT=$(wc -l < "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl" | tr -d ' ')
        deny "Stage 1 found $IMPORTED_COUNT unresolved finding(s) and CodeMender is not installed to perform Stage 2 remediation."
      fi
      allow
    else
      handle_scan_error "codemender" "the 'cm' CLI is not on PATH" true
    fi
  fi

  # 1. Discover modified files
  local MODIFIED_FILES
  MODIFIED_FILES=$(git diff --name-only origin/main 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || true)
  if [ -z "$MODIFIED_FILES" ]; then
    allow
  fi
  local MODIFIED_FILES_ARR
  read_lines_into_array MODIFIED_FILES_ARR "$MODIFIED_FILES"

  # 2. Run CodeMender scan on modified files
  echo "Stage 2: Running Semantic Analysis & Verification (CodeMender)..." >&2
  for file in "${MODIFIED_FILES_ARR[@]}"; do
    cm find "$file" -y --bypass-warning >/dev/null 2>&1 || true
  done

  local REPORT_ERR_FILE
  REPORT_ERR_FILE=$(mktemp)
  local REPORT_RAW REPORT_EXIT
  if REPORT_RAW=$(cm report --status OPEN --format json 2>"$REPORT_ERR_FILE"); then
    REPORT_EXIT=0
  else
    REPORT_EXIT=$?
  fi
  if [ "$REPORT_EXIT" -ne 0 ] || ! echo "$REPORT_RAW" | jq -e . >/dev/null 2>&1; then
    local ERR_DETAIL
    ERR_DETAIL=$(tail -c 500 "$REPORT_ERR_FILE" 2>/dev/null)
    rm -f "$REPORT_ERR_FILE"
    handle_scan_error "codemender" "'cm report' failed (exit $REPORT_EXIT): ${ERR_DETAIL:-no output}" true
  fi
  rm -f "$REPORT_ERR_FILE"

  # Filter findings to modified files
  local SCAN_RESULT
  SCAN_RESULT=$(echo "$REPORT_RAW" | jq --arg files "$MODIFIED_FILES" '
    ($files | split("\n")) as $mod_files |
    [ .[] | select((.FilePath | gsub("\\\\"; "/")) as $fp | any($mod_files[]; . as $mf | $mf != "" and ($fp | endswith($mf)))) ]
  ' 2>/dev/null || echo '[]')

  # 3. Ingest imported findings from Stage 1 if present
  local WORK_DIR
  WORK_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'cm_work')
  echo "$SCAN_RESULT" | jq -c '.[]' > "$WORK_DIR/all.jsonl"

  if [ -f "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl" ]; then
    while IFS= read -r imp; do
      [ -z "$imp" ] && continue
      local IMP_ID IMP_FILE IMP_SEV
      IMP_ID=$(echo "$imp" | jq -r '.check_id // .FindingID // "imported_issue"')
      IMP_FILE=$(echo "$imp" | jq -r '.path // .FilePath // "unknown"')
      IMP_SEV=$(echo "$imp" | jq -r '.extra.severity // .Severity // "HIGH"')
      jq -n -c --arg id "$IMP_ID" --arg file "$IMP_FILE" --arg sev "$IMP_SEV" \
        '{FindingID:$id, FilePath:$file, Severity:$sev, Source:"stage1_imported"}' >> "$WORK_DIR/all.jsonl"
    done < "$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl"
  fi

  : > "$WORK_DIR/blocking.jsonl"
  : > "$WORK_DIR/advisory.jsonl"

  while IFS= read -r finding; do
    [ -z "$finding" ] && continue
    local SEV FILE FID
    SEV=$(echo "$finding" | jq -r '.Severity // .severity // "UNKNOWN"')
    FILE=$(echo "$finding" | jq -r '.FilePath // .path // ""')
    FID=$(echo "$finding" | jq -r '.FindingID // .check_id // ""')

    if is_blocking_severity "$SEV" && matches_threat_model "$FID" "$FILE" "$FID"; then
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
    log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
    notify "ADVISORY" "$ADV_COUNT finding(s) treated as advisory." \
      "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
  fi

  local BLOCK_COUNT
  BLOCK_COUNT=$(wc -l < "$WORK_DIR/blocking.jsonl" | tr -d ' ')
  if [ "$BLOCK_COUNT" -eq 0 ]; then
    rm -rf "$WORK_DIR"
    echo "No blocking vulnerabilities detected. Code verified clean." >&2

    # Check if there were unresolved findings from prior attempts that are now fixed
    if [ -s "$SECURITY_GATE_LOG" ]; then
      local PREV_DENIED
      PREV_DENIED=$(jq -r 'select(.event == "DENIED_TO_AGENT") | "\(.finding_id // .FindingID // "")|\(.file // .FilePath // "")|\(.severity // .Severity // "")"' "$SECURITY_GATE_LOG" 2>/dev/null | sort -u || true)
      while IFS= read -r item; do
        [ -z "$item" ] && continue
        local PREV_ID PREV_FILE PREV_SEV
        PREV_ID=$(echo "$item" | cut -d'|' -f1)
        PREV_FILE=$(echo "$item" | cut -d'|' -f2)
        PREV_SEV=$(echo "$item" | cut -d'|' -f3)
        [ -z "$PREV_ID" ] && continue

        local IS_FIXED
        IS_FIXED=$(jq -s --arg fid "$PREV_ID" --arg f "$PREV_FILE" '
          [ .[] | select((.finding_id == $fid or .FindingID == $fid) and (.file == $f or .FilePath == $f)) ] as $h |
          ($h | map(select(.event == "FIXED")) | length) > 0
        ' "$SECURITY_GATE_LOG" 2>/dev/null || echo false)
        if [ "$IS_FIXED" != "true" ]; then
          log_event "FIXED" "codemender" "$(jq -n --arg fid "$PREV_ID" --arg f "$PREV_FILE" '{finding_id:$fid, file:$f}')"
          evolve_context_and_skills "$PREV_ID" "$PREV_FILE" "$PREV_SEV"
        fi
      done <<< "$PREV_DENIED"
    fi

    allow
  fi

  echo "Detected $BLOCK_COUNT blocking vulnerabilit(y/ies). Evaluating attempt budget per finding..." >&2

  # 4. Process each blocking finding against its attempt budget
  local ACTIONABLE_COUNT=0
  local ACTIONABLE_SUMMARY=""

  while IFS= read -r finding <&3; do
    [ -z "$finding" ] && continue
    local FINDING_ID FILE SEV DESC
    FINDING_ID=$(echo "$finding" | jq -r '.FindingID // .check_id')
    FILE=$(echo "$finding" | jq -r '.FilePath // .path')
    SEV=$(echo "$finding" | jq -r '.Severity // .severity // "UNKNOWN"')
    DESC=$(echo "$finding" | jq -r '.Description // .extra.message // "Security constraint violation"')

    local PREV_ATTEMPTS
    PREV_ATTEMPTS=$(get_finding_attempt_count "$FINDING_ID" "$FILE")
    local CURRENT_ATTEMPT=$((PREV_ATTEMPTS + 1))

    echo "Finding $FINDING_ID ($SEV) in $FILE: Attempt $CURRENT_ATTEMPT/$SECURITY_GATE_MAX_RETRIES" >&2

    # If attempts exceeded budget (> 3), run cm verify to evaluate exploitability
    if [ "$CURRENT_ATTEMPT" -gt "$SECURITY_GATE_MAX_RETRIES" ]; then
      echo "Fix budget exhausted for $FINDING_ID ($PREV_ATTEMPTS prior attempts). Running 'cm verify'..." >&2
      local VERIFY_EXIT=0
      if cm verify "$FINDING_ID" -y --bypass-warning >/dev/null 2>&1; then
        VERIFY_EXIT=0
      else
        VERIFY_EXIT=$?
      fi

      # Exit code 1 indicates conclusively NOT exploitable / false positive in context
      if [ "$VERIFY_EXIT" -eq 1 ]; then
        echo "cm verify confirmed $FINDING_ID is not exploitable in this context. Recording as advisory." >&2
        log_event "ADVISORY" "codemender" "$(jq -n --arg fid "$FINDING_ID" --arg f "$FILE" '{finding_id:$fid, file:$f, note:"cm verify clarified non-exploitable after max attempts"}')"
        notify "ADVISORY" "Finding $FINDING_ID remained after $SECURITY_GATE_MAX_RETRIES failed fix attempts, but cm verify confirmed non-exploitable." "{}"
        continue
      else
        echo "cm verify confirmed finding $FINDING_ID is exploitable or verify crashed (exit $VERIFY_EXIT)." >&2
        log_event "BLOCKED" "codemender" "$(jq -n --arg fid "$FINDING_ID" --arg f "$FILE" --argjson a "$CURRENT_ATTEMPT" '{finding_id:$fid, file:$f, attempt:$a, reason:"exploitable_after_max_attempts"}')"
        rm -rf "$WORK_DIR"
        deny "Finding $FINDING_ID ($SEV) in $FILE confirmed exploitable by verification after $SECURITY_GATE_MAX_RETRIES attempts. Escalating to human security review. See $SECURITY_GATE_LOG."
      fi
    fi

    # Record attempt in audit log
    log_event "DENIED_TO_AGENT" "codemender" "$(jq -n --arg fid "$FINDING_ID" --arg f "$FILE" --arg sev "$SEV" --argjson a "$CURRENT_ATTEMPT" '{finding_id:$fid, file:$f, severity:$sev, attempt:$a}')"
    ACTIONABLE_COUNT=$((ACTIONABLE_COUNT + 1))
    ACTIONABLE_SUMMARY+=$'\n'"- [$FINDING_ID] ($SEV) in $FILE (Attempt $CURRENT_ATTEMPT/$SECURITY_GATE_MAX_RETRIES): $DESC"
  done 3< "$WORK_DIR/blocking.jsonl"

  rm -rf "$WORK_DIR"

  # If all blocking findings were converted to advisory via cm verify, allow push
  if [ "$ACTIONABLE_COUNT" -eq 0 ]; then
    echo "All findings resolved or confirmed non-exploitable. Allowing push." >&2
    allow
  fi

  # 5. STOP and return structured rejection to agent to trigger Secure TDD workflow
  local REJECTION_PROMPT="Security Gate blocked push ($ACTIONABLE_COUNT unresolved finding(s)).

Action Required: Execute the Secure TDD Loop sequentially for each finding:
For each finding below (one at a time):
  1. Invoke 'security_test_writer' to author one failing boundary test in tests/ (assert RED).
  2. Invoke 'defensive_developer' to apply the minimal defensive fix (assert GREEN).
  3. Run the local test to confirm it passes before moving to the next finding.
Once all findings are resolved, run the full regression test suite ($SECURITY_GATE_TEST_CMD) and retry 'git push'.

Open Findings:${ACTIONABLE_SUMMARY}"

  deny "$REJECTION_PROMPT"
}
