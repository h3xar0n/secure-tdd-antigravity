# Agent Reference Guide: Test-Driven Development with Integrated Security (Secure TDD)

This document is the canonical reference guide for AI coding agents operating in this repository. It defines the core philosophy, the 4-phase Secure TDD inner-loop workflow, data contracts, and tool conventions.

---

## 1. Paradigm: TDD with Integrated Security

Test-Driven Development (TDD) involves writing tests before implementation clarifies requirements, verifies functional correctness, documents system behavior, and catches regressions early.

Traditionally, software teams treat **functional development** and **security testing** as disconnected workflows—features are written first, and security is bolted on later via delayed post-merge scans or third-party audits (leading to 20–70 day remediation cycles and high rework costs).

This framework unites functional engineering and security into a single test-first workflow:
- **TDD for Features & Quality**: Features, enhancements, and bug fixes are developed using incremental, test-first cycles (RED -> GREEN -> REFACTOR).
- **Security as Part of Quality**: Security is an inseparable aspect of software quality. When security patches are developed in isolation without functional tests, they risk breaking production behavior and introducing regressions. Co-verifying security and functionality supports operational stability.
- **Security Added at Every Phase**: Architectural trust zones and threat models are considered during planning; security invariants (authentication, input allow-lists, safe sinks, least privilege) are codified into tests alongside functional acceptance criteria.
- **Fast, Local Feedback**: Developers and AI agents catch functional bugs and security flaws locally before code is committed or pushed.

---

## 2. The Secure TDD Inner-Loop

```
                 +-----------------------------------------+
                 |                 1. PLAN                 |
                 |  - Ingest CONTEXT.md                    |
                 |  - Functional Specs & Scoping           |
                 |  - STRIDE Threat Model (threat_model.md)|
                 +--------------------+--------------------+
                                      |
                                      v
                 +-----------------------------------------+
                 |                 2. RED                  |
                 |  - Functional QA Tests (Happy Paths)    |
                 |  - Edge Cases & Boundary Handling       |
                 |  - Security Boundary Tests (Assert RED) |
                 +--------------------+--------------------+
                                      |
                                      v
                 +-----------------------------------------+
                 |                3. GREEN                 |
                 |  - Clean, Functional & Defensive Code   |
                 |  - Satisfy Functional & Security Tests  |
                 +--------------------+--------------------+
                                      |
                                      v
                 +-----------------------------------------+
                 |          4. REFACTOR & EVOLVE           |
                 |  - Code Quality & Regression Tests      |
                 |  - Local Scans & Guided Review          |
                 |  - Update CONTEXT.md & Evolve Skills    |
                 +--------------------+--------------------+
                                      |
                                      +--- Continuous Evolution ---+
```

### Phase A: Planning, Functional Scoping & Threat Modeling (Plan Phase)
- **Skill**: `threat_model_assessor`
- Ingest `CONTEXT.md` to identify existing architecture, trust boundaries, and approved helpers.
- Decompose the task into functional deliverables, user stories, and acceptance criteria.
- Perform STRIDE assessment on the proposed change to identify trust boundaries and security constraints.
- Generate or update `threat_model.md` at the workspace root, establishing both Functional and Security Acceptance Criteria.

### Phase B: Functional & Security Test-First Case Creation (Red Phase)
- **Skill**: `security_test_writer`
- Author unit and integration tests asserting:
  1. *Functional Correctness*: Happy-path user journeys, business logic execution, expected outputs (e.g. HTTP 200/302).
  2. *Edge Cases & Error Handling*: Missing parameters, malformed payloads, out-of-boundary values.
  3. *Security Boundaries*: Access control rejections (HTTP 401/403), input validation failures (HTTP 400), injection resistance.
- Adhere to the Three Verification Pillars:
  1. *Behavior-driven HTTP/API outcomes* (assert on contract responses and status codes).
  2. *Strict test isolation* (transaction rollbacks, fresh contexts).
  3. *Integration over fragile mocking* (real test contexts over superficial mocks).
- Run the test suite and verify tests fail for the expected assertion reason (**RED**).

### Phase C: Clean & Defensive Implementation (Green Phase)
- **Skill**: `defensive_developer`
- Author clean, modular, and maintainable production code to satisfy all failing tests and deliver the feature.
- Adhere to the Three Defensive Pillars:
  1. *Strict input validation* (allow-lists, typed schemas with `pydantic`).
  2. *Explicit authorization & caller identity verification*.
  3. *Least privilege data payloads & parameterized sinks*.
- Run the test suite and confirm all tests pass cleanly (**GREEN**).

### Phase D: Local Refactoring, Quality & Scanning (Refactor Phase)
- **Skill**: `local_refactor_scanner`
- Clean up code, eliminate duplication, improve maintainability, and verify 100% passing regression tests.
- Execute fast deterministic scans locally (secrets, dependencies, Semgrep / CodeMender).
- Conduct a guided AI review to verify business logic, edge cases, and eliminate design flaws.
- Keep diffs small, surgical, and focused on preserving baseline stability.

### Continuous Evolution: Updating Skills & Context
- **Skill**: `skill_evolution_updater`
- On resolving a tricky bug, establishing a new pattern, or introducing a helper, extract the systemic rule.
- Append the rule to `CONTEXT.md` under `## 4. Continuous Evolution: Auto-Evolved Conventions` or update `SKILL.md` instructions.
- All future agent sessions inherit these rules upfront.

---

## 3. Tool Conventions & State Management
- **No Database Required**: All state is managed via plain Markdown (`CONTEXT.md`, `threat_model.md`) and append-only logs (`.security-gate/findings-log.ndjson`).
- **Deterministic Pre-Push Gate**: On `git push`, the local hook intercepts the push to scan modified files so clean, tested code reaches remote repositories.

