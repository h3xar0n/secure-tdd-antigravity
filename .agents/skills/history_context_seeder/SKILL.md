---
name: history_context_seeder
description: Analyzes repository Git history for past bug fixes, architectural conventions, and security patterns to seed CONTEXT.md on onboarding.
---

# History & Architectural Context Seeder Skill (Repository Onboarding)

## Overview
Analyzes the repository's Git history and past fix commits to extract recurring bug patterns, architectural conventions, and security patterns, seeding `CONTEXT.md` during initial repository onboarding.

## Execution Sequence
1. **Analyze Git Log**:
   - Inspect commits touching bug fixes, refactors, and sensitive modules:
     `git log --grep="fix\|bug\|refactor\|vuln\|security\|patch" -n 50 --oneline`
2. **Extract Historical Lessons**:
   - Identify which files and modules have historically been prone to bugs or regressions.
   - Extract past patterns and architectural conventions established by maintainers.
3. **Seed `CONTEXT.md`**:
   - Populate `CONTEXT.md` with known architectural risk areas, sensitive directories, approved helpers, and custom project conventions.

