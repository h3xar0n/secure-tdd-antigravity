---
name: threat_model_assessor
description: Plans feature architecture, functional requirements, and evaluates STRIDE security boundaries (Phase A: Plan).
---

# Planning, Requirements & Threat Model Assessor Skill (Phase A: Plan Phase)

## Overview
Decompose feature requirements, establish functional acceptance criteria, and map trust boundaries before any production code is authored. This skill pairs functional engineering scoping with STRIDE threat modeling at the planning stage, establishing the functional and security acceptance criteria consumed by downstream test writers.

## System Sequence
1. **Ingest Context**: Read `CONTEXT.md` to identify existing architecture, trust boundaries, approved libraries, and conventions.
2. **Decompose Requirements**:
   - Define user stories, input/output data contracts, and functional acceptance criteria.
   - Break complex tasks into bite-sized, testable implementation stages.
3. **Apply STRIDE Threat Modeling**:
   - **Spoofing**: Authentication boundaries, session validation, caller identity checks.
   - **Tampering**: Input payload validation, integrity checks, parameter tampering.
   - **Repudiation**: Audit logging of critical state transitions.
   - **Information Disclosure**: Restrict error responses, prevent stack trace leaks, mask PII/secrets.
   - **Denial of Service**: Resource limits, payload size constraints, timeout limits.
   - **Elevation of Privilege**: Role-Based Access Control (RBAC), caller authorization checks.
4. **Generate/Update `threat_model.md`**:
   - Store or update `threat_model.md` at the workspace root with both Functional & Security Acceptance Criteria.

## Target Output Artifact (`threat_model.md`)
```markdown
# Feature Plan & Threat Model: [Feature Name]

## 1. Functional Scope & Requirements
- **Goal**: [Description of feature or bug fix]
- **Deliverables**: [Endpoints, functions, or modules to create/modify]
- **Functional Acceptance Criteria**: [Expected behaviors and outputs]

## 2. Entry Points & Data Inputs
- Endpoint / Input: [Path / Name]
- Format & Constraints: [Schema / Type]

## 3. Trust Boundaries & Access Controls
- Authentication: [Required / Public]
- Authorization Role: [User / Admin]

## 4. STRIDE Threat Matrix & Security Acceptance Criteria
- [STRIDE Category]: [Threat Description] -> [Required Mitigation & Test Assertion]
```
