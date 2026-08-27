---
name: defensive_developer
description: Implements clean, maintainable production code to deliver features and satisfy functional and security test assertions (Phase C: GREEN).
---

# Feature Implementation & Defensive Developer Skill (Phase C: GREEN Phase)

## Overview
Implement clean, modular production code that delivers the requested feature or bug fix and satisfies all functional, edge-case, and security assertions from Phase B while adhering to defensive design principles and project conventions in `CONTEXT.md`.

## Three Defensive Pillars
1. **Simple Input Validation**:
   - Enforce type, size, and strict allow-list validation on all incoming data.
   - Prefer structured parsing libraries (`pydantic`, `urllib.parse`) over complex regex which may be vulnerable to ReDoS.
2. **Explicit Authorization**:
   - Validate caller identity and match required permissions before invoking business logic.
3. **Least Privilege & Safe Operations**:
   - Parameterize all SQL/database queries.
   - Use canonical path checks (`os.path.realpath`) with prefix boundary validation.
   - Return only the minimal data payload required by the client.
   - Mask credentials, PII, and omit internal stack traces in error messages.

## Execution Sequence
1. **Inspect Failing Tests & Rules**: Review the functional requirements, failing tests from Phase B, and conventions in `CONTEXT.md`.
2. **Author Clean Production Code**:
   - Implement the business logic and algorithms required to satisfy the functional feature requirements.
   - Apply defensive patterns (e.g. `utils.security.resolve_safe_path`, parameterized SQL statements, `pydantic` schemas).
3. **Confirm GREEN State**:
   - Run the project test suite.
   - Verify that all functional and security tests pass cleanly without errors.

