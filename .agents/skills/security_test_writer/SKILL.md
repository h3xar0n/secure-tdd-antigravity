---
name: security_test_writer
description: Authors test-first unit and integration tests covering functional behavior, edge cases, and security boundaries (Phase B: RED).
---

# QA & Security Test Writer Skill (Phase B: RED Phase)

## Overview
Translate functional requirements and security criteria from `threat_model.md` and `CONTEXT.md` into executable test cases that fail initially (RED), asserting expected business logic, edge-case handling, and security boundaries before production code is authored.

## Three Verification Pillars
1. **Behavior-Driven Outcomes**:
   - Assert strictly on API/HTTP outcomes (status codes 200/302 for valid requests, 400/401/403 for invalid/unauthorized, expected JSON responses) rather than mocking internal private methods.
2. **Strict Test Isolation**:
   - Ensure test setup and teardown cleanly isolate state (e.g., transaction rollbacks, fresh test contexts) so state never bleeds between test runs.
3. **Integration Over Fragile Mocking**:
   - Utilize local test databases or real server contexts rather than fragile fake mocks to verify realistic functional and security behavior.

## Execution Sequence
1. **Consume Requirements & Threat Model**: Read the task scope, `threat_model.md`, and `CONTEXT.md` for functional requirements and security acceptance criteria.
2. **Author Test Cases**:
   - **Functional Happy Path**: Test validating standard user workflows and expected output payloads.
   - **Functional Edge Cases**: Test missing optional/required parameters, boundary limits, and unexpected data types.
   - **Authentication Boundary**: Assert requests without valid credentials return `401 Unauthorized`.
   - **Authorization Boundary**: Assert requests with insufficient role/scope return `403 Forbidden`.
   - **Input Validation**: Assert malformed, oversized, or un-whitelisted data returns `400 Bad Request`.
   - **Exploit Payloads**: Assert dangerous inputs (SQLi, path traversal `../../`, XSS) are rejected cleanly.
3. **Execute & Verify RED**:
   - Run the project's test command (e.g., `pytest`, `python3 -m unittest discover -s tests`).
   - **Requirement**: Confirm the tests fail due to the expected missing feature logic/boundary assertion and not due to a syntax or import error.
4. **Multi-Finding Handling**:
   - When remediating multiple scanner findings, write and verify one boundary test for one finding at a time before proceeding to defensive implementation.

