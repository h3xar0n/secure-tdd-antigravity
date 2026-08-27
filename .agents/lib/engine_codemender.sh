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
      jq -n --arg id "$IMP_ID" --arg file "$IMP_FILE" --arg sev "$IMP_SEV" \
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
    allow
  fi

  echo "Detected $BLOCK_COUNT blocking vulnerabilit(y/ies). Entering 3-attempt TDD remediation loop..." >&2

  # 4. 3-Attempt TDD Remediation Loop (RED-GREEN)
  while IFS= read -r finding <&3; do
    [ -z "$finding" ] && continue
    local FINDING_ID FILE SEV
    FINDING_ID=$(echo "$finding" | jq -r '.FindingID // .check_id')
    FILE=$(echo "$finding" | jq -r '.FilePath // .path')
    SEV=$(echo "$finding" | jq -r '.Severity // .severity // "UNKNOWN"')

    echo "Vulnerability in scope: $FINDING_ID ($SEV) in $FILE" >&2

    local RETRY_COUNT=0
    local RESOLVED=false
    local LARGE_DIFF=false

    while [ "$RETRY_COUNT" -lt "$SECURITY_GATE_MAX_RETRIES" ]; do
      RETRY_COUNT=$((RETRY_COUNT+1))
      echo "Executing TDD remediation loop for: $FINDING_ID in $FILE (Attempt $RETRY_COUNT/$SECURITY_GATE_MAX_RETRIES)..." >&2

      # 1. TDD Remediation Step (RED boundary test -> GREEN defensive fix)
      if [ -n "${SECURITY_GATE_TDD_REMEDIATION_CMD:-}" ]; then
        if ! sh -c "$SECURITY_GATE_TDD_REMEDIATION_CMD \"$FINDING_ID\" \"$FILE\"" >/dev/null 2>&1; then
          echo "TDD remediation failed on attempt $RETRY_COUNT. Reverting..." >&2
          git checkout -- . 2>/dev/null || true
          continue
        fi
      else
        # Default TDD fix handler (simulated or agentic environment)
        if [ -n "${MOCK_FILE:-}" ] && [ -f "${MOCK_FILE:-}" ]; then
          if [ "${MOCK_CM_FIX_LARGE:-false}" = "true" ]; then
            for i in $(seq 1 100); do echo "# padding line $i" >> "$MOCK_FILE"; done
            touch "${MOCK_STATE_DIR:-/tmp}/cm_fixed_marker"
          elif [ "${MOCK_TDD_FIX_FAILS:-false}" = "true" ]; then
            echo "# failed fix attempt" >> "$MOCK_FILE"
          else
            echo "# fixed via TDD" >> "$MOCK_FILE"
            touch "${MOCK_STATE_DIR:-/tmp}/cm_fixed_marker"
          fi
        fi
      fi

      # 2. Run full regression test suite (assert GREEN)
      if [ -n "$SECURITY_GATE_TEST_CMD" ]; then
        if ! sh -c "$SECURITY_GATE_TEST_CMD" >/dev/null 2>&1; then
          echo "TDD fix failed unit/regression test assertions. Reverting..." >&2
          git checkout -- . 2>/dev/null || true
          continue
        fi
      fi

      # 3. Rescan to confirm finding is resolved
      cm find "$FILE" -y --bypass-warning >/dev/null 2>&1 || true
      local STILL_OPEN
      STILL_OPEN=$(cm report --status OPEN --format json 2>/dev/null \
        | jq --arg id "$FINDING_ID" '[.[] | select(.FindingID == $id)] | length' 2>/dev/null || echo 0)
      if [ "$STILL_OPEN" != "0" ]; then
        echo "Tests passed, but $FINDING_ID is still reported open after rescan." >&2
        git checkout -- . 2>/dev/null || true
        continue
      fi

      # 4. Check diff size
      local DIFF_STAT INS DEL CHANGED_LINES
      DIFF_STAT=$(git diff --shortstat 2>/dev/null || echo "")
      INS=$(echo "$DIFF_STAT" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)
      DEL=$(echo "$DIFF_STAT" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo 0)
      CHANGED_LINES=$((INS + DEL))
      if [ "$CHANGED_LINES" -gt "$SECURITY_GATE_LARGE_FIX_LINES" ]; then
        echo "Fix diff is large ($CHANGED_LINES lines > $SECURITY_GATE_LARGE_FIX_LINES threshold) - escalating to human review." >&2
        LARGE_DIFF=true
        git checkout -- . 2>/dev/null || true
        break
      fi

      commit_fix "$FINDING_ID" "$FILE" "$SEV"
      evolve_context_and_skills "$FINDING_ID" "$FILE" "$SEV"
      log_event "FIXED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
      RESOLVED=true
      break
    done

    # 5. Verification Step if fix could not pass tests within 3 attempts
    if [ "$RESOLVED" != "true" ] && [ "$LARGE_DIFF" != "true" ]; then
      git checkout -- . 2>/dev/null || true
      echo "Fix failed tests past 3rd attempt. Running 'cm verify' to evaluate exploitability..." >&2

      local VERIFY_OUT VERIFY_EXIT
      VERIFY_OUT=$(mktemp)
      if cm verify "$FINDING_ID" -y --bypass-warning >"$VERIFY_OUT" 2>&1; then
        VERIFY_EXIT=0
      else
        VERIFY_EXIT=$?
      fi
      rm -f "$VERIFY_OUT"

      # If cm verify returns non-zero (1), the issue is conclusively not exploitable / false positive
      if [ "$VERIFY_EXIT" -eq 1 ]; then
        echo "cm verify clarified $FINDING_ID is not exploitable in this context. Recording as advisory." >&2
        log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], note:"cm verify clarified non-exploitable after 3 test retries"}')"
        notify "ADVISORY" "Finding $FINDING_ID remained after 3 failed fix attempts, but cm verify confirmed non-exploitable in context." \
          "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
        RESOLVED=true
      else
        # cm verify returned 0 (confirmed exploitable) or crashed (exit > 1)
        echo "cm verify confirmed finding $FINDING_ID is exploitable or verify failed (exit $VERIFY_EXIT)." >&2
      fi
    fi

    # 6. Escalation to HITL
    if [ "$RESOLVED" != "true" ]; then
      local REASON_HINT="auto-fix could not satisfy test assertions after $SECURITY_GATE_MAX_RETRIES attempts"
      [ "$LARGE_DIFF" = true ] && REASON_HINT="fix diff exceeds safe auto-commit threshold"

      echo "Escalating $FINDING_ID to human review ($REASON_HINT)." >&2

      # If interactive TTY is present, offer interactive prompt
      if [ -t 0 ] || [ -t 1 ]; then
        echo "Select action for finding $FINDING_ID:" >&2
        echo "1) Defer with audited justification" >&2
        echo "2) Abort and fix manually (blocks push)" >&2
        local CHOICE
        read -p "Enter choice [1-2]: " CHOICE
        case "$CHOICE" in
          1)
            local JUSTIFICATION
            read -p "Enter deferral justification: " JUSTIFICATION
            log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" --arg j "$JUSTIFICATION" '{findings:[$f], justification:$j}')"
            notify "ADVISORY" "Finding $FINDING_ID deferred: $JUSTIFICATION" "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
            RESOLVED=true
            ;;
          *)
            log_event "BLOCKED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"manual resolution required"}')"
            rm -rf "$WORK_DIR"
            deny "Unresolved finding $FINDING_ID ($SEV). Push blocked for manual fix."
            ;;
        esac
      else
        # Non-interactive / headless environment fails closed
        log_event "BLOCKED" "codemender" "$(jq -n --argjson f "$finding" --arg r "$REASON_HINT" '{findings:[$f], reason:$r}')"
        rm -rf "$WORK_DIR"
        deny "Finding $FINDING_ID ($SEV) blocked: $REASON_HINT. See $SECURITY_GATE_LOG for details."
      fi
    fi
  done 3< "$WORK_DIR/blocking.jsonl"

  rm -rf "$WORK_DIR"
  allow
}
