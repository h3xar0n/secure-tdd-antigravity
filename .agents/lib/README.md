# Security Gate Hook Engine Architecture

> **Modular pre-push verification pipeline uniting deterministic AST checks, contextual semantic analysis, and the Test-Driven Development (TDD) loop.**

---

## 1. Overview & Module Responsibilities

The pre-push hook intercepts `git push` commands locally to verify code correctness and defensive boundaries before commits reach remote repositories. The logic is divided into modular bash components:

| Module | Location | Purpose |
| :--- | :--- | :--- |
| **Hook Entrypoint** | [`.agents/security_gate_hook.sh`](../security_gate_hook.sh) | Sourced on `git push`. Detects available tools on `PATH` and runs the sequential pipeline (Stage 1 $\rightarrow$ Stage 2). |
| **Common Library** | [`gate_common.sh`](gate_common.sh) | Formats dual platform responses (Antigravity & Claude Code), manages NDJSON logging, generates structured commits (`commit_fix`), evolves `CONTEXT.md`, and handles fail-open tagging. |
| **Stage 1 Engine** | [`engine_semgrep.sh`](engine_semgrep.sh) | Executes deterministic AST pattern scanning, matches findings to `threat_model.md`, runs 3-attempt autofixes, and exports unresolved issues to Stage 2. |
| **Stage 2 Engine** | [`engine_codemender.sh`](engine_codemender.sh) | Performs contextual semantic analysis (`cm find` / `cm report`), ingests Stage 1 handoffs, runs the 3-attempt TDD remediation loop, evaluates exploitability via `cm verify`, and escalates to human review. |

---

## 2. Pipeline Workflow Diagram

```
                    [ git push intercepted by Hook ]
                                   │
                                   ▼
                    [ Inspect Modified Files in Push ]
                                   │
                                   ▼
                     [ Stage 1: Deterministic Scan ]
                       (AST Checks & Autofixes)
                                   │
            ┌──────────────────────┼──────────────────────┐
      (Scan Error)           (No Findings)          (Threat-Model Findings)
            │                      │                      │
            ▼                      │                      ▼
    [ Check Fail-Open ]            │            [ 3-Attempt TDD Loop ]
    SECURITY_GATE_ALLOW_ON_ERROR   │        (Add Test -> Fix -> Run Suite)
            │                      │                      │
     ┌──────┴──────┐               │               ┌──────┴──────┐
  (false)        (true)            │         (Fixed in <= 3)  (Fails Past 3)
     │             │               │               │             │
     ▼             ▼               │               ▼             ▼
[ Deny Push  ] [ Log Error ]       │       [ Import Fix & ] [ Import Unresolved ]
[& Escalate  ] [ Proceed   ]       │       [ Context to   ] [ Finding to        ]
                   │               │       [ Stage 2      ] [ Stage 2           ]
                   │               │               │             │
                   └───────────────┼───────────────┴─────────────┘
                                   │
                                   ▼
                       [ Stage 2: Semantic Scan ]
                      (Contextual AI / CodeMender)
                       - Verify Imported Fixes
                       - Ingest Remaining Findings
                                   │
            ┌──────────────────────┼──────────────────────┐
      (Scan Error)           (No Findings /         (Threat-Model Findings)
            │                Verified Clean)              │
            ▼                      │                      ▼
    [ Check Fail-Open ]      [ Allow Push ]     [ 3-Attempt TDD Loop ]
    SECURITY_GATE_ALLOW_ON_ERROR               (Add Test -> Fix -> Run Suite)
            │                                             │
     ┌──────┴──────┐                       ┌──────────────┴──────────────┐
  (false)        (true)               (Fails Tests                  (Passes in
     │             │                Past 3rd Attempt)             <= 3 Attempts)
     ▼             ▼                       │                             │
[ Deny Push  ] [ Tag Commit with           ▼                             ▼
[& Escalate  ]   'unverified-scan' ] [ Revert Changes ]            [ Auto-Commit ]
               [ Allow Push        ] [ git checkout . ]            [ Allow Push  ]
                                           │
                                           ▼
                                  [ Run 'cm verify' ]
                                           │
                      ┌────────────────────┴────────────────────┐
             (Conclusively Not                     (Confirms Issue OR
                Exploitable)                         Verify Crashes)
                      │                                     │
                      ▼                                     ▼
            [ Append Advisory to ]                 [ Escalate to HITL ]
            [ Commit / Audit Log ]                 - Non-TTY: Deny Push
            [    Allow Push      ]
```

---

## 3. How the Pipeline Works

### 1. File Discovery
The hook examines outgoing commits (`git diff --name-only origin/main` or `HEAD~1`) to identify modified source files. Untracked and unmodified files are excluded.

### 2. Stage 1: Deterministic AST Scan (`engine_semgrep.sh`)
- Scans modified files using fast local AST pattern matching.
- **Threat Model Evaluation**: Matches detected findings against rules in `threat_model.md` and severity thresholds.
- **3-Attempt TDD Loop**: If a blocking finding is found, applies the defensive change, runs the regression suite (`SECURITY_GATE_TEST_CMD`), and rescans.
- **Handoff**: Fixed changes are recorded for Stage 2 verification; unresolved findings are exported to `$SECURITY_GATE_PIPELINE_DIR/imported_findings.jsonl`.

### 3. Stage 2: Contextual Semantic Analysis (`engine_codemender.sh`)
- Ingests both native CodeMender findings (`cm find` / `cm report`) and imported Stage 1 findings.
- **3-Attempt TDD Loop**: When findings match threat model criteria, the engine executes the TDD cycle:
  1. Authors a security boundary test reproducing the condition.
  2. Applies the minimal defensive implementation.
  3. Executes the full test suite (`SECURITY_GATE_TEST_CMD`).
  4. Rescans to confirm the issue is resolved and verifies diff size (< 50 lines).
- **Auto-Commit**: Successful fixes generate structured commit messages and append conventions to `CONTEXT.md`.

### 4. Exploitability Verification (`cm verify`)
- If the 3-attempt TDD loop cannot satisfy tests, changes are reverted (`git checkout -- .`) and the finding is passed to `cm verify`.
- **Conclusively Non-Exploitable (Exit Code 1)**: Logged as `ADVISORY` in `.security-gate/findings-log.ndjson` and push is allowed.
- **Exploitable or Crash (Exit Code 0 or >1)**: Escalates to interactive human-in-the-loop review (or denies push in non-interactive CI).

---

## 4. Troubleshooting Guide

### Issue 1: Scanner CLI Not Found on `PATH`
- **Symptom**: Hook outputs `Deterministic scanner (semgrep) not installed - proceeding to Stage 2` or `No security scanner CLI found on PATH`.
- **Explanation**: Both scanners are optional. If neither is installed, the hook allows the push.
- **Remedy**:
  - For Semgrep: `brew install semgrep` or `pip install semgrep`.
  - For CodeMender: Download `cm` CLI from Artifact Registry and run `cm init`.

### Issue 2: CodeMender Authentication Error
- **Symptom**: `cm: authentication failed - run 'gcloud auth application-default login'`.
- **Explanation**: CodeMender requires Google Cloud Application Default Credentials.
- **Remedy**:
  ```bash
  gcloud auth application-default login
  cm init --verify
  ```

### Issue 3: Fix Reverted Due to Broken Regression Tests
- **Symptom**: Hook logs `TDD fix failed unit/regression test assertions. Reverting...` and exhausts 3 retries.
- **Explanation**: An automated patch broke functional acceptance tests. The hook reverts the working tree to preserve stability.
- **Remedy**: Inspect the failing assertion in your test runner (`python3 -m unittest` or `pytest`), update the implementation defensively to satisfy functional requirements, and re-push.

### Issue 4: Diff Exceeds Safe Auto-Commit Threshold
- **Symptom**: Hook logs `Fix diff is large (> 50 lines) - escalating to human review` and blocks push.
- **Explanation**: Automated commits are constrained to small diffs (< 50 lines by default) to keep changes auditable.
- **Remedy**: Review the change manually, commit it with your own message, and push. You can adjust the threshold via `export SECURITY_GATE_LARGE_FIX_LINES=100`.

### Issue 5: Network Outage or Offline Development (Fail-Open Mode)
- **Symptom**: Hook errors when offline or unable to reach scanner services.
- **Explanation**: By default, scanner execution errors fail closed (`deny`) to prevent unverified code from reaching remote branches.
- **Remedy**: To allow urgent offline pushes while tagging the commit for subsequent audit, set:
  ```bash
  export SECURITY_GATE_ALLOW_ON_ERROR=true
  git push
  ```
  The commit will be tagged with `unverified-scan-<timestamp>` in Git.

### Issue 6: Running the Test Suite Locally
- To verify all 38 hook decision paths locally without external dependencies:
  ```bash
  bash .agents/tests/run_tests.sh
  ```
