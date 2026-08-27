# Project Context & Architectural Rules (CONTEXT.md)

This document is the living single source of truth for repository context, architectural boundaries, coding conventions, and learned security rules. Coding agents must ingest this file prior to planning or authoring any code.

---

## 1. System Overview & Deployment Intent
- **Repository Purpose**: Secure Test-Driven Development (Secure TDD) agent framework and orchestration.
- **Target Stack**: Python 3.10+ (AppSec, CLI tools, REST/Microservices), Shell/Bash (hooks, automation).
- **Deployment Intent**: `Intent: PRODUCTION`
- **Solo Developer Paradigm**: Fast, test-first iteration. Security guardrails run locally and proactively in the inner-loop, never slowing down the developer with heavyweight multi-stage batch reviews.

---

## 2. Architectural Boundaries & Trust Zones

```
+-------------------------------------------------------------------------+
| UNTRUSTED EXTERNAL ZONE                                                 |
| - Public HTTP requests, CLI arguments, webhook payloads, search queries |
+------------------------------------+------------------------------------+
                                     | (Strict Allow-list Validation)
                                     v
+------------------------------------+------------------------------------+
| AUTHENTICATED WORKSPACE ZONE                                            |
| - Session tokens, JWT verification, user-scoped data access             |
+------------------------------------+------------------------------------+
                                     | (Explicit RBAC & Ownership Checks)
                                     v
+------------------------------------+------------------------------------+
| PRIVILEGED SYSTEM & DATA SINK ZONE                                      |
| - File system access (canonicalized sandbox paths only)                 |
| - Database queries (parameterized only; no f-strings or raw SQL)        |
| - External command executions (list-form subprocess, shell=False)       |
+-------------------------------------------------------------------------+
```

### Trust Boundary Rules
1. **Public Zone -> Authenticated Zone**: All incoming inputs MUST be parsed and validated against typed schemas (e.g., Pydantic models or strict allow-lists) before reaching business logic.
2. **Authenticated Zone -> Privileged Sinks**: Caller identity and permissions MUST be checked explicitly. Default to least privilege in returned data payloads.
3. **No Dynamic Execution**: `eval()`, `exec()`, `os.system()`, and `subprocess(shell=True)` are strictly prohibited.

---

## 3. Approved Helpers & Standard Security Patterns

Whenever implementing security-critical functionality, use the standardized project helpers located in `sample_app/utils/security.py`:

| Vulnerability Class | Prohibited Pattern | Required Helper / Safe Pattern |
| :--- | :--- | :--- |
| **SQL Injection** | `f"SELECT * FROM users WHERE name='{name}'"` | Parameterized query: `cursor.execute("SELECT * FROM users WHERE name = ?", (name,))` or ORM. |
| **Path Traversal** | `open(os.path.join(base_dir, user_filename))` | `utils.security.resolve_safe_path(base_dir, user_filename)` |
| **Open Redirect** | `return redirect(request.args.get('next'))` | `utils.security.safe_redirect(url, allowed_hosts)` |
| **Command Injection** | `os.system(f"ping {host}")` | `subprocess.run(["ping", "-c", "1", host], shell=False, check=True)` |
| **Insecure Hashing** | `hashlib.md5(password)` | `hashlib.sha256()` for tokens, `bcrypt` / `argon2` for passwords. |
| **Secrets & Tokens** | Hardcoded API keys / credentials | Read dynamically from environment (`os.getenv(...)`) or Secret Manager. |

---

## 4. Continuous Evolution: Auto-Evolved Conventions

> **Notice for Agents**: When you remediate a security issue or refactor code to use a new helper, invoke the `skill_evolution_updater` to append the new convention below so all future cycles inherit it.

- *Rule 2026-08-01*: Always use `resolve_safe_path` with an explicit base directory to ensure path traversal attempts (e.g., `../../etc/passwd`) raise a `ValueError`.
- *Rule 2026-08-15*: For URL redirection, validate against the local server origin before issuing an HTTP 302 response.
- *Rule 2026-08-20*: Output error messages must omit internal exception stack traces and return clean, standardized error JSON payloads.
