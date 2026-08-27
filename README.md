# Secure TDD for Antigravity

> **Secure Test-Driven Development (Secure TDD) agent skills, rules, and pre-push hooks for Antigravity AI coding agents.**

> [!CAUTION]
> **Use at Your Own Risk**: This repository is a demonstration of an approach and is not an officially supported product or framework. AI coding agents generate and execute code that may be unstable or perform unexpected actions. Run agentic workflows only in isolated development environments and never on systems with access to production credentials, sensitive customer data, or internal networks.

> [!IMPORTANT]
> **Responsible Use & Manual Verification**: AI models are non-deterministic and can generate incorrect patches or hallucinate findings. All automated code changes and findings must be manually reviewed and verified by a developer or security practitioner before deployment. Do not mass-file unverified, AI-generated reports to open-source maintainers. You are expected to inspect, adapt, and take full responsibility for using this code.

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

## Optional Scanner Engines & Installation

The pre-push security gate hook supports modular scanning engines. Both scanners are **optional**:
- The hook checks which tools are available on your system `PATH`.
- If `semgrep` is not installed, the pipeline skips Stage 1 and proceeds directly to Stage 2 (`cm`).
- If neither scanner is installed, the hook logs an informational notice and allows the push to proceed normally.
- The hook engine is designed to be extended with additional scanners (such as Wiz Code for Stage 1) down the road.

### 1. Semgrep (Stage 1: Open-Source Deterministic AST Scanner)
```bash
# Via Homebrew:
brew install semgrep

# Or via pip:
pip install semgrep
```

### 2. CodeMender CLI (`cm` - Stage 2: Semantic Analysis & Remediation)
```bash
# Authenticate with Google Cloud:
gcloud auth application-default login

# Download and install binary (macOS ARM64 example):
gcloud artifacts generic download     --project=cmoc-prod     --location=us     --repository=codemender-cli-production     --package=cm     --version=stable     --name=cm-darwin-arm64.zip     --destination=./

unzip cm-*.zip && chmod +x cm && sudo mv cm /usr/local/bin/cm
cm init && cm init --verify
```

## Upstream Canonical Framework

All skills, rules, and threat models are maintained in the canonical upstream repository:  
🔗 **[h3xar0n/secure-tdd-agent-framework](https://github.com/h3xar0n/secure-tdd-agent-framework)**

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
