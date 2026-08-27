# Secure TDD for Antigravity

> **Secure Test-Driven Development (Secure TDD) agent skills, rules, and pre-push hooks for Antigravity AI coding agents.**

This repository is the dedicated Antigravity distribution of the **[Secure TDD Agent Framework](https://github.com/h3xar0n/secure-tdd-agent-framework)**.

## What's Included

- `.agents/rules/secure_tdd_workflow.md`: Always-on 4-phase workflow rule (`PLAN` -> `RED` -> `GREEN` -> `REFACTOR`).
- `.agents/skills/`: Specialized agent skills for threat modeling, security test writing, defensive coding, local refactor scanning, and skill evolution.
- `.agents/hooks.json` & `.agents/security_gate_hook.sh`: Local pre-push hook enforcing test-first verification before code reaches remote repositories.
- `CONTEXT.md`: Living repository context, trust boundaries, and approved helpers.
- `AGENTS.md`: Universal agent reference guide.

## Getting Started

1. Open this repository or copy `.agents/`, `AGENTS.md`, and `CONTEXT.md` into your Antigravity project root.
2. The agent automatically discovers the workflow rules and skills.
3. Test the local pre-push hook:
   ```bash
   bash .agents/tests/run_tests.sh
   ```

## Upstream Canonical Framework

All skills, rules, and threat models are maintained in the canonical upstream repository:  
🔗 **[h3xar0n/secure-tdd-agent-framework](https://github.com/h3xar0n/secure-tdd-agent-framework)**

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
