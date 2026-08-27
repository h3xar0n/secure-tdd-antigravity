---
name: local_refactor_scanner
description: Refactors code for quality and maintainability, executes full test suite regression passes, and runs local deterministic security/lint scans (Phase D: REFACTOR).
---

# Code Refactoring, Quality & Local Scanner Skill (Phase D: REFACTOR Phase)

## Overview
Refactor implementation for clean code structure, modularity, and maintainability while ensuring 100% passing test regressions and blocking pattern-based security flaws locally prior to commit.

## Verification Guardrails
1. **Code Quality & Refactoring**:
   - Clean up boilerplate, eliminate dead code, and centralize common utilities.
   - Improve variable naming, modularity, and type annotations without altering verified behavior.
2. **Deterministic Scans (Fast & Offline)**:
   - **Secrets**: Check diffs for plaintext credentials, tokens, or private keys.
   - **Dependencies**: Flag unpinned dependencies or known CVEs in new packages.
   - **Rules-Based SAST**: Run local SAST rules on modified files (`semgrep scan --config auto --json` or `cm find`).
3. **Guided AI Review**:
   - Audit architecture and design issues that static tools miss.
   - Review business logic and edge cases for bypasses or regression risks.
4. **Small Diffs & Regression QA**:
   - Run the complete project test suite to verify zero regressions across existing and new tests.
   - Ensure the diff contains only surgical changes directly related to the task scope.

## Execution Sequence
1. Review the git diff of modified files (`git diff`).
2. Refactor code for clarity, maintainability, and helper reuse.
3. Run local linters and security scanners on changed files.
4. Run the full test suite to guarantee 100% passing tests.
5. **Continuous Evolution**: Capture new conventions in `CONTEXT.md` and suggest/apply updates to `SKILL.md` instructions via `skill_evolution_updater` to permanently prevent recurrence of issues.


