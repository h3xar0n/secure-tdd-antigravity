#!/bin/bash
# Universal Modular Security Gate - Pre-Push Hook
# Executes the sequential Secure TDD pipeline:
# Stage 1: Deterministic Scan & AST Autofix (Semgrep)
# Stage 2: Semantic Analysis & TDD Remediation (CodeMender)
#
# Configuration:
#   SECURITY_GATE_SCANNER        - 'auto' (default pipeline), 'codemender' (or 'cm'), or 'semgrep'
#   SECURITY_GATE_BLOCK_SEVERITY - 'HIGH' (default), 'CRITICAL', 'MEDIUM', 'LOW'
#   SECURITY_GATE_ALLOW_ON_ERROR - false (default) / true

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/gate_common.sh
source "$SCRIPT_DIR/lib/gate_common.sh"
# shellcheck source=lib/engine_semgrep.sh
source "$SCRIPT_DIR/lib/engine_semgrep.sh"
# shellcheck source=lib/engine_codemender.sh
source "$SCRIPT_DIR/lib/engine_codemender.sh"

SCANNER="${SECURITY_GATE_SCANNER:-auto}"

case "$(printf '%s' "$SCANNER" | tr '[:upper:]' '[:lower:]')" in
  codemender|cm)
    run_codemender_gate false
    ;;
  semgrep)
    run_semgrep_gate false
    ;;
  auto|pipeline|"")
    # Sequential Pipeline Execution: each installed engine runs in sequence.
    # If an engine is not installed, the pipeline skips it and proceeds to the next.
    ran_any=false
    if command -v semgrep >/dev/null 2>&1; then
      run_semgrep_gate true
      ran_any=true
    fi
    if command -v cm >/dev/null 2>&1; then
      run_codemender_gate true
      ran_any=true
    fi
    if [ "$ran_any" = "false" ]; then
      echo "No security scanner CLI (semgrep or cm) found on PATH. Proceeding without local SAST verification." >&2
      allow
    fi
    allow
    ;;
  *)
    handle_scan_error "scanner" "Unknown SECURITY_GATE_SCANNER '$SCANNER'. Supported: 'auto', 'pipeline', 'codemender', 'semgrep'." false
    ;;
esac
