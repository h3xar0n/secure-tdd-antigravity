#!/bin/bash
# Universal Modular Security Gate - Pre-Push Hook
# Automatically routes to CodeMender or Semgrep based on availability & configuration.
#
# Configuration:
#   SECURITY_GATE_SCANNER   - 'auto' (default), 'codemender' (or 'cm'), or 'semgrep'
#   SECURITY_GATE_BLOCK_SEVERITY - 'HIGH' (default), 'CRITICAL', 'MEDIUM', 'LOW'
#   SECURITY_GATE_ALLOW_ON_ERROR - false (default) / true

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/gate_common.sh
source "$SCRIPT_DIR/lib/gate_common.sh"
# shellcheck source=lib/engine_codemender.sh
source "$SCRIPT_DIR/lib/engine_codemender.sh"
# shellcheck source=lib/engine_semgrep.sh
source "$SCRIPT_DIR/lib/engine_semgrep.sh"

SCANNER="${SECURITY_GATE_SCANNER:-auto}"

case "$(printf '%s' "$SCANNER" | tr '[:upper:]' '[:lower:]')" in
  codemender|cm)
    run_codemender_gate
    ;;
  semgrep)
    run_semgrep_gate
    ;;
  auto|"")
    if command -v cm >/dev/null 2>&1; then
      run_codemender_gate
    elif command -v semgrep >/dev/null 2>&1; then
      run_semgrep_gate
    else
      handle_scan_error "scanner" "Neither 'cm' nor 'semgrep' CLI found on PATH. Install semgrep via 'pip install semgrep' or ensure CodeMender is installed."
    fi
    ;;
  *)
    handle_scan_error "scanner" "Unknown SECURITY_GATE_SCANNER '$SCANNER'. Supported: 'auto', 'codemender', 'semgrep'."
    ;;
esac
