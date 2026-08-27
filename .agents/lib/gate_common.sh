#!/bin/bash
# Shared helpers for the Antigravity and Claude Code security gate hooks.
# Sourced, not executed directly.
# Implements the Secure TDD verification lifecycle, dual-envelope output,
# structured audit logging, fail-open tagging, and continuous evolution.

# --- Config (override via env, or hook env config) ---
: "${SECURITY_GATE_BLOCK_SEVERITY:=HIGH}"        # findings at/above this rank block; below are advisory
: "${SECURITY_GATE_ALLOW_ON_ERROR:=false}"       # true = let push through when scanner itself fails to run
: "${SECURITY_GATE_LARGE_FIX_LINES:=50}"         # fix diffs larger than this escalate instead of auto-committing
: "${SECURITY_GATE_MAX_RETRIES:=3}"              # max TDD fix attempts
: "${SECURITY_GATE_TEST_CMD:=python3 -m unittest discover -s tests}"
: "${SECURITY_GATE_NOTIFY_CMD:=}"                # optional; receives a JSON event on stdin
: "${SECURITY_GATE_EVOLVE_CONTEXT:=true}"        # append verified conventions to CONTEXT.md on successful fix
: "${SECURITY_GATE_STATE_DB:=$HOME/.codemender/state.db}"

_gate_repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

: "${SECURITY_GATE_LOG:=$(_gate_repo_root)/.security-gate/findings-log.ndjson}"

# Shared pipeline context directory for cross-stage handoff
: "${SECURITY_GATE_PIPELINE_DIR:=}"

_init_pipeline_dir() {
  if [ -z "$SECURITY_GATE_PIPELINE_DIR" ]; then
    SECURITY_GATE_PIPELINE_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'sec_gate_pipeline')
  fi
  mkdir -p "$SECURITY_GATE_PIPELINE_DIR"
}

# --- Dual Platform Hook Envelopes (Antigravity & Claude Code) ---
_is_claude_code() {
  [ -n "${CLAUDE_PROJECT_DIR:-}" ] || [ -n "${CLAUDE_CONVERSATION_ID:-}" ] || [ "${AGENT_PLATFORM:-}" = "claude_code" ]
}

allow() {
  if [ -n "$SECURITY_GATE_PIPELINE_DIR" ] && [ -d "$SECURITY_GATE_PIPELINE_DIR" ]; then
    rm -rf "$SECURITY_GATE_PIPELINE_DIR" 2>/dev/null || true
  fi
  if _is_claude_code; then
    echo '{"hookSpecificOutput": {"permissionDecision": "allow"}}'
  else
    echo '{"allow_tool": true}'
  fi
  exit 0
}

deny() {
  local reason="$1"
  if [ -n "$SECURITY_GATE_PIPELINE_DIR" ] && [ -d "$SECURITY_GATE_PIPELINE_DIR" ]; then
    rm -rf "$SECURITY_GATE_PIPELINE_DIR" 2>/dev/null || true
  fi
  if _is_claude_code; then
    jq -n --arg reason "$reason" '{"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": $reason}}'
  else
    jq -n --arg reason "$reason" '{"allow_tool": false, "reason": $reason}'
  fi
  exit 0
}

# --- Severity & Threat Model Matching ---
severity_rank() {
  case "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')" in
    CRITICAL) echo 4 ;;
    HIGH|ERROR) echo 3 ;;
    MEDIUM|WARNING) echo 2 ;;
    LOW|INFO) echo 1 ;;
    *) echo 4 ;;
  esac
}

is_blocking_severity() {
  [ "$(severity_rank "$1")" -ge "$(severity_rank "$SECURITY_GATE_BLOCK_SEVERITY")" ]
}

# Evaluate finding against local threat model (threat_model.md)
matches_threat_model() {
  local finding_id="$1" file_path="$2" rule_id="$3"
  local tm_file="$(_gate_repo_root)/threat_model.md"

  # If threat_model.md does not exist, fall back to standard severity evaluation
  if [ ! -f "$tm_file" ]; then
    return 0
  fi

  # Check if threat_model.md references the rule, finding, or file
  if grep -qiE "$finding_id|$rule_id|$(basename "$file_path")" "$tm_file" 2>/dev/null; then
    return 0
  fi

  # If threat model is present and does not reference this rule/file, treat as advisory
  return 1
}

# --- Audit Logging & Notification ---
log_event() {
  local event="$1" tool="$2" extra="$3"
  [ -z "$extra" ] && extra="{}"
  mkdir -p "$(dirname "$SECURITY_GATE_LOG")" 2>/dev/null || true
  if ! jq -n \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg event "$event" \
    --arg tool "$tool" \
    --arg actor "$(git config user.email 2>/dev/null || echo unknown)" \
    --arg commit "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
    --argjson extra "$extra" \
    '{ts:$ts, event:$event, tool:$tool, actor:$actor, commit:$commit} + $extra' \
    >> "$SECURITY_GATE_LOG" 2>/dev/null; then
    echo "(warning: failed to write audit log entry to $SECURITY_GATE_LOG)" >&2
  fi
}

notify() {
  local event="$1" message="$2" extra="$3"
  [ -z "$extra" ] && extra="{}"
  {
    echo ""
    echo "==== SECURITY GATE: $event ===="
    echo "$message"
    echo "================================"
  } >&2
  if [ -n "$SECURITY_GATE_NOTIFY_CMD" ]; then
    local payload
    payload=$(jq -n --arg event "$event" --arg message "$message" --argjson extra "$extra" \
      '{event:$event, message:$message} + $extra')
    if ! echo "$payload" | sh -c "$SECURITY_GATE_NOTIFY_CMD" >/dev/null 2>&1; then
      echo "(notify command failed - see $SECURITY_GATE_LOG for the record)" >&2
    fi
  fi
}

handle_scan_error() {
  local tool="$1" reason="$2" is_stage2="${3:-false}"
  log_event "ERROR" "$tool" "$(jq -n --arg r "$reason" '{reason:$r}')"
  notify "ERROR" "Security scan ($tool) could not run: $reason" "{}"

  if [ "$SECURITY_GATE_ALLOW_ON_ERROR" = "true" ]; then
    if [ "$is_stage2" = "true" ]; then
      tag_unverified_scan "$tool" "$reason"
      echo "SECURITY_GATE_ALLOW_ON_ERROR=true - allowing push with [unverified-scan] tag (logged above)." >&2
      allow
    else
      echo "SECURITY_GATE_ALLOW_ON_ERROR=true - proceeding to next stage despite $tool failure." >&2
      return 0
    fi
  fi

  deny "Security scan ($tool) failed to run: $reason
Push blocked because the gate could not confirm the code is clean.
Set SECURITY_GATE_ALLOW_ON_ERROR=true to allow scan failures through if intended policy.
See $SECURITY_GATE_LOG for the record."
}

# --- Commit, Tag & Continuous Evolution Helpers ---

tag_unverified_scan() {
  local tool="$1" reason="$2"
  local tag_name="unverified-scan-$(date +%Y%m%d%H%M%S)"
  git tag -a "$tag_name" -m "Security Gate: $tool scan did not complete ($reason). Unverified commit allowed via fail-open configuration." 2>/dev/null || true
  echo "Tagged current commit as '$tag_name' due to unverified scan fail-open." >&2
}

commit_fix() {
  local finding_id="$1" file_path="$2" rule_desc="${3:-defensive boundary fix}"
  git add -A
  if git diff --cached --quiet; then
    echo "Fix confirmed finding resolved but left no working-tree changes to commit." >&2
    return 0
  fi

  local commit_msg
  commit_msg=$(cat <<EOF
security: automated fix for $finding_id ($file_path)

- Finding ID / Rule: $finding_id ($rule_desc)
- File Modified: $file_path
- Verification: Boundary test verified RED, defensive fix verified GREEN
- Full Test Suite: All unit and integration tests passing via $SECURITY_GATE_TEST_CMD
EOF
)
  git commit -q -m "$commit_msg"
  echo "Committed automated fix for $finding_id ($file_path) with structured verification details." >&2
}

evolve_context_and_skills() {
  local finding_id="$1" file_path="$2" rule_desc="${3:-boundary convention}"
  local repo_root
  repo_root="$(_gate_repo_root)"
  local context_file="$repo_root/CONTEXT.md"

  if [ "$SECURITY_GATE_EVOLVE_CONTEXT" = "true" ] && [ -f "$context_file" ]; then
    local entry="- **Auto-Evolved Convention ($finding_id)**: In \`$file_path\`, maintain defensive validation for: $rule_desc."
    if ! grep -Fq "$finding_id" "$context_file" 2>/dev/null; then
      if grep -Fq "## 4. Continuous Evolution" "$context_file" 2>/dev/null; then
        # Append under existing section
        echo "$entry" >> "$context_file"
      else
        # Append section and entry
        echo -e "\n## 4. Continuous Evolution: Auto-Evolved Conventions\n$entry" >> "$context_file"
      fi
      git add "$context_file" 2>/dev/null || true
      git commit -q -m "docs(context): record auto-evolved convention for $finding_id" 2>/dev/null || true
      echo "Updated CONTEXT.md with auto-evolved convention for $finding_id." >&2
    fi
  fi

  echo "Continuous Evolution Suggestion: Consider updating relevant SKILL.md files (e.g. security_test_writer / defensive_developer) to encode $rule_desc." >&2
}

read_lines_into_array() {
  local __arr_name="$1" __input="$2"
  local __line
  eval "$__arr_name=()"
  while IFS= read -r __line; do
    [ -z "$__line" ] && continue
    eval "$__arr_name+=(\"\$__line\")"
  done <<< "$__input"
}
