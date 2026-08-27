#!/bin/bash
# CodeMender Scanner Engine Module
# Sourced by security_gate_hook.sh

run_codemender_gate() {
  command -v cm >/dev/null 2>&1 || handle_scan_error "codemender" "the 'cm' CLI is not on PATH"

  # 1. Discover modified files
  local MODIFIED_FILES
  MODIFIED_FILES=$(git diff --name-only origin/main 2>/dev/null || git diff --name-only HEAD~1 2>/dev/null || true)
  if [ -z "$MODIFIED_FILES" ]; then
    allow
  fi
  local MODIFIED_FILES_ARR
  read_lines_into_array MODIFIED_FILES_ARR "$MODIFIED_FILES"

  # 2. Run CodeMender scan on modified files
  echo "Running CodeMender scan on changed files..." >&2
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
    handle_scan_error "codemender" "'cm report' failed (exit $REPORT_EXIT): ${ERR_DETAIL:-no output}"
  fi
  rm -f "$REPORT_ERR_FILE"

  # Filter findings to modified files
  local SCAN_RESULT FINDINGS_COUNT
  SCAN_RESULT=$(echo "$REPORT_RAW" | jq --arg files "$MODIFIED_FILES" '
    ($files | split("\n")) as $mod_files |
    [ .[] | select((.FilePath | gsub("\\\\"; "/")) as $fp | any($mod_files[]; . as $mf | $mf != "" and ($fp | endswith($mf)))) ]
  ' 2>/dev/null || echo '[]')
  FINDINGS_COUNT=$(echo "$SCAN_RESULT" | jq 'length' 2>/dev/null || echo 0)

  if [ -z "$FINDINGS_COUNT" ] || [ "$FINDINGS_COUNT" -eq 0 ]; then
    echo "No vulnerabilities found. Allowing push." >&2
    allow
  fi

  # 3. Split findings by severity
  local WORK_DIR
  WORK_DIR=$(mktemp -d)
  echo "$SCAN_RESULT" | jq -c '.[]' > "$WORK_DIR/all.jsonl"
  : > "$WORK_DIR/blocking.jsonl"
  : > "$WORK_DIR/advisory.jsonl"
  while IFS= read -r finding; do
    [ -z "$finding" ] && continue
    local SEV
    SEV=$(echo "$finding" | jq -r '.Severity // .severity // "UNKNOWN"')
    if is_blocking_severity "$SEV"; then
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
    notify "ADVISORY" "$ADV_COUNT finding(s) below the $SECURITY_GATE_BLOCK_SEVERITY block threshold were pushed without blocking. Review $SECURITY_GATE_LOG." \
      "$(jq -n --argjson f "$ADV_JSON" '{findings:$f}')"
  fi

  local BLOCK_COUNT
  BLOCK_COUNT=$(wc -l < "$WORK_DIR/blocking.jsonl" | tr -d ' ')
  if [ "$BLOCK_COUNT" -eq 0 ]; then
    rm -rf "$WORK_DIR"
    allow
  fi

  echo "Detected $BLOCK_COUNT blocking-severity vulnerabilit(y/ies). Attempting automatic remediation..." >&2

  # 4. Remediate & test loop (RED-GREEN)
  while IFS= read -r finding <&3; do
    local FINDING_ID FILE SEV
    FINDING_ID=$(echo "$finding" | jq -r '.FindingID')
    FILE=$(echo "$finding" | jq -r '.FilePath')
    SEV=$(echo "$finding" | jq -r '.Severity // .severity // "UNKNOWN"')

    echo "Vulnerability detected: $FINDING_ID ($SEV) in $FILE" >&2
    echo "Before applying the fix, you must write a reproducing test that fails (RED)." >&2
    read -p "Add the test and press Enter once it is verified failing..."

    local RETRY_COUNT=0
    local RESOLVED=false
    local LARGE_DIFF=false

    while [ "$RETRY_COUNT" -le "$SECURITY_GATE_MAX_RETRIES" ]; do
      echo "Attempting cm fix for: $FINDING_ID (Attempt: $((RETRY_COUNT+1)))" >&2
      if ! cm fix "$FINDING_ID" -y --bypass-warning; then
        echo "cm fix itself failed. Reverting and retrying." >&2
        git checkout -- .
        RETRY_COUNT=$((RETRY_COUNT+1))
        continue
      fi

      if ! sh -c "$SECURITY_GATE_TEST_CMD"; then
        echo "Fix broke the tests. Reverting changes..." >&2
        git checkout -- .
        RETRY_COUNT=$((RETRY_COUNT+1))
        continue
      fi

      cm find "$FILE" -y --bypass-warning >/dev/null 2>&1 || true
      local STILL_OPEN
      STILL_OPEN=$(cm report --status OPEN --format json 2>/dev/null \
        | jq --arg id "$FINDING_ID" '[.[] | select(.FindingID == $id)] | length' 2>/dev/null || echo 1)
      if [ "$STILL_OPEN" != "0" ]; then
        echo "Tests passed, but $FINDING_ID is still reported open after rescan - not trusting this fix." >&2
        git checkout -- .
        RETRY_COUNT=$((RETRY_COUNT+1))
        continue
      fi

      local DIFF_STAT INS DEL CHANGED_LINES
      DIFF_STAT=$(git diff --shortstat)
      INS=$(echo "$DIFF_STAT" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)
      DEL=$(echo "$DIFF_STAT" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo 0)
      CHANGED_LINES=$((INS + DEL))
      if [ "$CHANGED_LINES" -gt "$SECURITY_GATE_LARGE_FIX_LINES" ]; then
        echo "Fix diff is large ($CHANGED_LINES lines > $SECURITY_GATE_LARGE_FIX_LINES) - escalating for human review instead of auto-committing." >&2
        LARGE_DIFF=true
        break
      fi

      git add -A
      if git diff --cached --quiet; then
        echo "cm fix confirmed the finding closed but left no working-tree changes to commit." >&2
      else
        git commit -q -m "security: automated fix for $FINDING_ID ($FILE)"
      fi
      echo "Fix successful, verified by rescan, and committed (GREEN)!" >&2
      log_event "FIXED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
      RESOLVED=true
      break
    done

    # 5. Escalation
    if [ "$RESOLVED" != true ]; then
      local REASON_HINT="auto-fix could not make tests (and a rescan) pass"
      [ "$LARGE_DIFF" = true ] && REASON_HINT="fix diff too large to auto-trust without review"
      echo "Escalating $FINDING_ID to human review ($REASON_HINT)." >&2
      echo "Select action for finding $FINDING_ID:" >&2
      echo "1) Defer/mute with justification (logged + notified; push proceeds)" >&2
      echo "2) Check exploitability via 'cm verify' (slow - only use this if you need the answer to decide)" >&2
      echo "3) Abort and fix manually (blocks push)" >&2
      local CHOICE
      read -p "Enter choice [1-3]: " CHOICE

      case "$CHOICE" in
        1)
          local JUSTIFICATION
          read -p "Enter deferral justification: " JUSTIFICATION
          git checkout -- .
          log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" --arg j "$JUSTIFICATION" '{findings:[$f], justification:$j}')"
          notify "ADVISORY" "Finding $FINDING_ID ($SEV) deferred by $(git config user.email 2>/dev/null || echo unknown): $JUSTIFICATION" \
            "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
          ;;
        2)
          echo "Running cm verify - this can take a while..." >&2
          if cm verify "$FINDING_ID" -y --bypass-warning; then
            git checkout -- .
            log_event "BLOCKED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"confirmed exploitable via cm verify"}')"
            notify "BLOCKED - HELP NEEDED" "Finding $FINDING_ID confirmed exploitable by cm verify and could not be auto-fixed. Push blocked - needs help from another team." \
              "$(jq -n --argjson f "$finding" '{findings:[$f]}')"
            rm -rf "$WORK_DIR"
            deny "Exploitable vulnerability $FINDING_ID confirmed by 'cm verify' and could not be auto-fixed. See $SECURITY_GATE_LOG - loop in security/another team for help before pushing."
          else
            echo "cm verify found this non-exploitable - treating as advisory and proceeding." >&2
            git checkout -- .
            log_event "ADVISORY" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"cm verify found non-exploitable"}')"
          fi
          ;;
        *)
          git checkout -- .
          log_event "BLOCKED" "codemender" "$(jq -n --argjson f "$finding" '{findings:[$f], reason:"unresolved - no fix, deferral, or verification decision"}')"
          rm -rf "$WORK_DIR"
          deny "Unresolved finding $FINDING_ID ($SEV): no fix, deferral, or verification decision was made. See $SECURITY_GATE_LOG."
          ;;
      esac
    fi
  done 3< "$WORK_DIR/blocking.jsonl"

  rm -rf "$WORK_DIR"
  allow
}
