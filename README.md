# Secure TDD for Antigravity

> **Antigravity workspace distribution of the Secure TDD framework.** Integrates Test-Driven Development (TDD) and QA with proactive security guardrails into Antigravity coding agents.

This repository is a downstream distribution generated from the canonical upstream repository:
**[secure-tdd-agent-framework](https://github.com/example/secure-tdd-agent-framework)**.

---

## What's Included

- **`.agents/rules/secure_tdd_workflow.md`**: Always-on 4-phase Secure TDD inner loop (Plan -> Red -> Green -> Refactor & Evolve).
- **`.agents/skills/`**: Modular Antigravity skills:
  - `threat_model_assessor`: Scopes features and maps STRIDE boundaries in `threat_model.md`.
  - `security_test_writer`: Writes failing functional QA & security boundary tests (RED).
  - `defensive_developer`: Implements clean production code and defensive patterns (GREEN).
  - `local_refactor_scanner`: Cleans code, runs regression tests, and executes local SAST scans (REFACTOR).
  - `skill_evolution_updater`: Captures systemic lessons into `CONTEXT.md` and `SKILL.md`.
  - `history_context_seeder`: Seeds context from VCS commit history on onboarding.
- **`.agents/hooks.json` & `.agents/security_gate_hook.sh`**: Deterministic `git push` security gate interceptors (CodeMender & Semgrep).
- **`AGENTS.md` & `CONTEXT.md`**: Agent reference guidelines and architectural boundaries.

---

## Quickstart

1. Clone or copy `.agents/`, `AGENTS.md`, and `CONTEXT.md` into your project root.
2. Ensure `semgrep` or `cm` is installed on your `PATH`:
   ```bash
   pip install semgrep
   ```
3. Run the offline hook test suite to verify:
   ```bash
   bash .agents/tests/run_tests.sh
   ```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
