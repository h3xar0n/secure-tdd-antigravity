---
trigger: always_on
---

# Test-Driven Development with Integrated Security (Secure TDD) Workflow Rule

You MUST strictly follow this 4-phase cyclical workflow for all feature implementations, refactors, and bug fixes:

1. **Phase A (Plan, Scope & Threat Model)**:
   - Ingest `CONTEXT.md` to review established project conventions, approved helpers, and trust zones.
   - Decompose feature requirements, user stories, and acceptance criteria.
   - Invoke the **Threat Model Assessor Skill** to perform a STRIDE evaluation and generate/update `threat_model.md`.

2. **Phase B (Functional & Security Test-First - RED)**:
   - Invoke the **Security Test Writer Skill**.
   - Author unit and integration tests asserting functional behavior (happy paths, business logic), edge cases, AND security boundaries (rejecting invalid inputs, unauthenticated requests, unauthorized role access).
   - Execute the tests and confirm they FAIL for the expected assertion reason (RED).

3. **Phase C (Feature Implementation & Defensive Code - GREEN)**:
   - Invoke the **Defensive Developer Skill**.
   - Author clean, modular production code strictly required to satisfy the functional tests and security assertions.
   - Apply input validation allow-lists, parameterized queries, and least-privilege payload returns.
   - Run the tests to confirm they are GREEN.

4. **Phase D (Refactor, Quality & Scan)**:
   - Invoke the **Local Refactor & Scanner Skill**.
   - Clean up code, eliminate duplication, and verify 100% passing test regressions.
   - Run fast deterministic checks (secrets, dependencies, local SAST).
   - Conduct a guided AI review to verify architectural boundaries and eliminate logic bypasses.
   - Ensure diffs remain small, surgical, and preserve baseline stability.

5. **Continuous Evolution**:
   - If a new pattern, helper function, or architectural convention was introduced, invoke the **Skill Evolution Updater Skill** to document the lesson into `CONTEXT.md` or the appropriate `SKILL.md`.

