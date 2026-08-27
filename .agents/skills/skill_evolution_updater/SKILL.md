---
name: skill_evolution_updater
description: Extracts systemic conventions from resolved bugs, patterns, and refactors to update CONTEXT.md and agent skills (Continuous Evolution).
---

# Skill & Conventions Evolution Updater (Continuous Evolution)

## Overview
Ensure the development team and agent fleet continuously learn from local fixes, architecture decisions, and refactoring patterns so that systemic quality and security standards are retained permanently.

## Continuous Feedback Mechanism
```
+-----------------------------------------------------------------+
|                    CONTINUOUS FEEDBACK LOOP                     |
|                                                                 |
|   1. Local Fix / Feature Verified (Refactor Phase)              |
|                               v                                 |
|   2. Systemic Lesson Extracted (Best practices & conventions)   |
|                               v                                 |
|   3. Feed Back to Shared Specs (Update SKILL.md/CONTEXT.md)     |
|                               v                                 |
|   4. Context Seeding (All future agents inherit rules upfront)  |
+-----------------------------------------------------------------+
```

## Execution Sequence
1. **Analyze Remediation Diff**: Review the code change or bug fix just completed.
2. **Extract the Systemic Rule**:
   - Formulate an actionable, project-specific rule.
   - Example: *"When implementing redirects, always use `utils.security.safe_redirect()` with allow-listed domains."*
   - Example: *"All JSON endpoints must validate request body using Pydantic schemas."*
3. **Update Shared Specifications**:
   - **Update `CONTEXT.md`**: Append the rule under `## 4. Continuous Evolution: Auto-Evolved Conventions`.
   - **Update Skills (if applicable)**: If a general coding anti-pattern or QA procedure was refined, update the relevant `SKILL.md`.
4. **Persist Insight**: Append the raw structured event to `.security-gate/findings-log.ndjson` for audit traceability.

