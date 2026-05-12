---
name: secure-coding
description: >
  Provides implementation-ready secure coding guidance grounded in AppSec best practices.
  Use when writing or reviewing code that touches authentication, authorization, input
  validation, secrets management, cryptography, session handling, database queries, or
  cloud infrastructure (AWS, Azure). Also use for questions about injection, XSS, CSRF,
  IDOR, mass assignment, deserialization, memory safety, OWASP Top 10, or any
  "how do I securely..." question. Covers C#, Rust, Go, Python, PowerShell, and bash.
  Loads language-specific examples and cloud-specific patterns from references/ on demand.
---

# Secure Coding

Provides authoritative, implementation-ready secure coding guidance. Give direct answers
with concrete code. Show the vulnerable pattern first (labeled), then the correct pattern.
Explain the risk in one sentence. Always recommend a verification step.

When a question touches a specific language or cloud provider, load the relevant
reference file alongside the vulnerability reference. Both together take seconds and
produce a far more useful answer than either alone.

---

## Core Principles (Apply Always)

**1. Never Trust Input**
All input is untrusted until validated server-side against an allowlist. Sources developers
forget: URL parameters, HTTP headers, cookies, hidden fields, database values (may have been
modified by another path), third-party API responses, file contents, environment variables
set by external systems, script arguments passed from calling processes.

**2. Principle of Least Privilege**
Grant only permissions actually required. Applies to: database users, IAM roles and policies,
service accounts, API tokens (scope-limited), OS process users, S3 bucket policies,
Lambda execution roles, Azure RBAC assignments. When injection succeeds, blast radius is
bounded by the compromised process's permissions.

**3. Defense in Depth**
No single control is sufficient. Layer: input validation at the boundary, parameterized
queries at the data layer, output encoding at rendering, auth middleware at the route layer,
WAF at the edge, monitoring everywhere. When one layer fails, the next catches it.

**4. Fail Securely**
On error, default to the restrictive state: deny access, return a generic message, log the
detail internally. Never expose stack traces, connection strings, internal paths, or query
text to end users or API consumers.

**5. Buy or Borrow Before Building**
For authentication, authorization, cryptography, and session management: use a proven
platform or framework feature first; build from scratch only as a last resort. Custom
implementations of these systems are the source of a disproportionate share of critical
vulnerabilities.

**6. Secrets Never in Code**
No credentials, API keys, connection strings, or tokens in source code, config files
committed to version control, container images, or log output. Use a secrets manager.
See `references/cloud-aws.md` or `references/cloud-azure.md` for platform-specific patterns,
and `references/lang/<lang>.md` for loading secrets in each language.

---

## Vulnerability Reference Files

Load the relevant file(s) before giving implementation advice. If more than one applies,
load all of them — they are intentionally short.

| Topic | File | Load when... |
|-------|------|-------------|
| Injection (SQL, command, LDAP, template) | `references/injection.md` | Queries, shell calls, or any user input concatenated into a command string |
| Output Encoding & XSS | `references/xss-output.md` | Rendering user-controlled content in HTML, JS, or templates |
| Authentication & Sessions | `references/authn-sessions.md` | Login, MFA, password reset, session cookies, JWTs, OAuth |
| Authorization & Access Control | `references/authz-access.md` | Permissions, roles, resource ownership, IDOR, mass assignment |
| Secrets & Cryptography | `references/secrets-crypto.md` | API keys, password hashing, encryption, TLS, CSPRNG |
| CSRF & Request Integrity | `references/csrf.md` | State-changing endpoints or forms consumed by browsers |
| Deserialization | `references/deserialization.md` | Parsing JSON/XML/YAML/binary from untrusted sources |
| Memory Safety | `references/memory-safety.md` | C, C++, Rust unsafe blocks, low-level buffer handling |
| Dependency & Supply Chain | `references/dependencies.md` | Adding packages, auditing, SCA tooling |

## Language Reference Files

Load alongside the vulnerability file for the user's language.

| Language | File |
|----------|------|
| C# / ASP.NET Core | `references/lang/csharp.md` |
| Rust | `references/lang/rust.md` |
| Go | `references/lang/go.md` |
| Python | `references/lang/python.md` |
| JavaScript / TypeScript | `references/lang/javascript-typescript.md` |
| PowerShell / bash (infra scripts) | `references/lang/scripting.md` |

## Cloud Reference Files

Load when the question involves cloud infrastructure, secrets, IAM, storage, or serverless.

| Platform | File |
|----------|------|
| AWS | `references/cloud-aws.md` |
| Azure | `references/cloud-azure.md` |
| CI/CD Pipelines | `references/cicd-pipeline.md` | GitHub Actions, CodeBuild, OIDC role assumption, secrets in pipelines |
| Containers & Docker | `references/containers.md` | Dockerfile, ECS, EKS, AKS, image scanning, runtime security |

---

## Inline Quick Reference

Use for rapid answers when the scope doesn't warrant loading a reference file.

**SQL injection (any language):** Never concatenate user values into SQL strings.
Use parameterized queries or ORM. Watch for raw-query escape hatches even in ORMs.

**Secrets:** Never hardcode. Load from environment variables or a secrets manager.
AWS: Secrets Manager or SSM Parameter Store. Azure: Key Vault. Local dev: `.env` in
`.gitignore`, never committed.

**Password hashing:** Argon2id > bcrypt (cost ≥ 12) > scrypt. Never MD5, SHA-1, or
any fast hash for passwords. Never plaintext. Never roll your own.

**CSPRNG:** Use the platform's cryptographically secure generator for all security tokens,
session IDs, nonces, and reset links. Never use a general-purpose RNG.

**Output encoding:** Use your framework's auto-escaping. Never use raw string concatenation
to build HTML. Context matters: HTML body, attribute, JS, CSS, and URL contexts each
require different encoding.

**Error messages:** Return the same message for all authentication failures ("Invalid
username or password"). Never reveal which field was wrong.

---


## Commands

| Command | File | What it does |
|---------|------|-------------|
| `/find-secrets` | `commands/find-secrets.md` | Scans the working tree for hardcoded secrets, proposes the correct language-specific replacement for each finding, and applies edits after confirmation |

## New Feature Security Checklist

Before marking complete:

- [ ] All inputs validated: type, length, format, allowlist
- [ ] No user input concatenated into SQL, shell commands, or system calls
- [ ] Output encoded for rendering context
- [ ] Authentication on every endpoint that requires it
- [ ] Authorization: ownership/permission checked for every resource access
- [ ] No secrets in code, config files, or image layers
- [ ] Sensitive data not logged (passwords, tokens, PII, full request bodies)
- [ ] Error messages don't expose internals
- [ ] Dependencies checked for known CVEs (`cargo audit`, `govulncheck`, `dotnet list package --vulnerable`, `trivy`)
- [ ] HTTPS enforced; no mixed content
- [ ] Rate limiting on auth and sensitive endpoints
- [ ] IAM / RBAC roles follow least privilege