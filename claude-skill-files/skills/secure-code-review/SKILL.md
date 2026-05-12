---
name: secure-code-review
description: >
  Provides a structured security-focused code review methodology for C#, Rust, Go,
  Python, PowerShell, and bash codebases on AWS and Azure. Use when asked to review
  code for security issues, audit a pull request, check if code is safe before release,
  or when code is pasted with questions like "is this safe" or "any issues here". Also
  use when setting up SAST/SCA pipeline tooling (Semgrep, cargo-audit, govulncheck,
  dotnet list package --vulnerable, Trivy, Gitleaks) or reviewing penetration test
  findings and CVE reports. Loads language-specific grep patterns and cloud-specific
  checks from references/ on demand. Runs automated tools when bash is available.
---

# Secure Code Review

Security code review asks "How could an attacker abuse this?" — not "Is this clean?"

The goal is real, exploitable findings with enough context to understand the risk and
fix the code. Do not produce theoretical concerns without evidence. Always include a
concrete fix alongside every finding.

---

## Phase 0: Scope and Context

Before reviewing code, establish:

1. **What does this do?** Purpose of the feature or module. Ask if not obvious.
2. **What data does it handle?** PII, credentials, financial data, health data?
   Sensitivity raises the priority of every finding.
3. **Who calls it?** Unauthenticated internet users? Internal services? Admins?
   Unauthenticated paths get the highest scrutiny.
4. **What is the trust boundary?** What inputs does it accept, from where?
5. **What language and cloud platform?** Load the relevant reference files below.

---

## Reference Files

Load the relevant files before starting the review. Combination is typical:
a vulnerability file plus a language file, plus a cloud file if AWS/Azure is involved.

**Vulnerability references:**
- `references/injection.md` — SQL, command, LDAP, template injection
- `references/authn-sessions.md` — auth flows, sessions, JWTs
- `references/authz-access.md` — IDOR, mass assignment, privilege escalation
- `references/secrets-crypto.md` — hardcoded secrets, hashing, encryption
- `references/xss-output.md` — output encoding, CSP
- `references/csrf.md` — CSRF tokens, SameSite
- `references/deserialization.md` — pickle, ObjectInputStream, XXE
- `references/memory-safety.md` — buffer overflows, unsafe blocks
- `references/dependencies.md` — SCA tooling, supply chain

**Language references (grep patterns + framework-specific checks):**
- `references/lang/csharp.md`
- `references/lang/rust.md`
- `references/lang/go.md`
- `references/lang/python.md`
- `references/lang/javascript-typescript.md` — JS / TS (Node.js, React, NestJS)
- `references/lang/scripting.md` — PowerShell + bash infra scripts

**Cloud references:**
- `references/cloud-aws.md` — IAM, Secrets Manager, S3, Lambda, CloudTrail
- `references/cloud-azure.md` — Managed Identity, Key Vault, RBAC, Defender
- `references/cicd-pipeline.md` — pipeline secrets, OIDC, GitHub Actions, CodeBuild
- `references/containers.md` — Dockerfile, ECS/AKS, image scanning, runtime config

---

## Phase 1: High-Value Surface Area

Focus initial effort here — these surfaces are most attacked and most commonly
misconfigured:

- Authentication and login flows
- Password reset and account recovery
- Authorization checks — resource ownership, role elevation
- Database queries incorporating external input
- Shell / subprocess calls incorporating external input
- File upload and download handling
- External API calls where response data is used without validation
- Cryptographic operations and password hashing
- Session creation, token generation, and logout
- Admin and privileged functionality
- IAM role policies and trust policies
- Secrets loading and rotation
- CI/CD pipeline scripts (secret exposure, injection into build commands)

---

## Phase 2: Vulnerability Checklist

For each category: is it present? Is it implemented correctly?
Load the relevant `references/` file for detailed grep patterns and fix examples.

**A. Injection**
- SQL: all queries parameterized? ORM raw-query escape hatches used safely?
- Command: user input passed to subprocess/exec/shell?
- Template: user input reaching a template engine as the template source?

**B. Broken Access Control**
- Every endpoint authenticated where it should be?
- Ownership/permission checked before returning a resource (IDOR)?
- Admin actions enforced server-side, not just hidden in UI?
- Mass assignment: DTOs / allowlists used to prevent privilege field injection?

**C. Cryptographic Failures**
- Secrets hardcoded in source, config, or image layers?
- Passwords hashed with bcrypt/Argon2id, not MD5/SHA/fast hash?
- AES-GCM (authenticated) or a CBC/ECB mode without authentication?
- CSPRNG used for all tokens, nonces, IDs?
- TLS 1.2+ enforced; no SSLv3 or TLS 1.0/1.1?

**D. XSS / Output Encoding**
- User-controlled content rendered in HTML without encoding?
- Framework auto-escaping disabled for any template or route?
- `innerHTML`, `document.write()`, or `dangerouslySetInnerHTML` with untrusted data?
- CSP headers set?

**E. Security Misconfiguration**
- Debug mode, verbose errors, or stack traces in production config?
- Security headers set? (HSTS, X-Content-Type-Options, X-Frame-Options, CSP)
- CORS: `Access-Control-Allow-Origin: *` on credentialed endpoints?
- Unused endpoints, methods, or services exposed?

**F. Authentication & Session Failures**
- Session IDs from CSPRNG? `HttpOnly`, `Secure`, `SameSite` on cookies?
- New session ID issued after login?
- Sessions invalidated server-side on logout?
- Rate limiting on auth endpoints?

**G. CSRF**
- State-changing requests protected by CSRF token or `SameSite=Strict`?
- GET requests free of state-changing side effects?

**H. Deserialization**
- Untrusted data reaching `pickle`, `ObjectInputStream`, `unserialize`, `yaml.load`?

**I. Dependencies**
- Known-vulnerable packages? Run the relevant audit tool (see Phase 3).

**J. Secrets in Code / Logs**
- Hardcoded credentials, API keys, connection strings in source?
- Logging statements emitting passwords, tokens, or PII?
- `.gitignore` present and covering `.env`, key files?

**K. Business Logic**
These are what automated tools miss most. Ask:
- Can a step in a multi-step process be skipped?
- Can numeric values be negative (negative price, balance manipulation)?
- Can a one-time action (token, payment) be replayed?
- Can a non-owner perform an action on behalf of another user?

**L. Cloud / IAM (if applicable)**
- IAM roles / Azure RBAC follow least privilege?
- No wildcard policies on production roles?
- Secrets loaded from Secrets Manager / Key Vault, not hardcoded?
- S3 buckets / Storage accounts not publicly accessible?
- CloudTrail / Azure Monitor enabled?

---

## Phase 3: Automated Tools

Run these alongside manual review. Tools find depth; humans find business logic and
architecture-level flaws.

```bash
# C# / .NET
dotnet list package --vulnerable --include-transitive
npx semgrep --config "p/csharp" .

# Rust
cargo audit
cargo clippy -- -D warnings
npx semgrep --config "p/rust" .

# Go
govulncheck ./...
npx semgrep --config "p/golang" .

# Python
pip-audit
npx semgrep --config "p/python" .

# PowerShell / bash
npx semgrep --config "p/bash" .

# Secret scanning (all languages)
gitleaks detect --source=. --verbose

# Container / filesystem scan (all languages)
trivy fs .
```

**False negatives:** Zero findings from SAST does not mean secure.
Business logic, authorization, and architecture-level issues require human review.

---

## Phase 4: Severity Classification

| Severity | Examples |
|----------|---------|
| Critical | Unauthenticated RCE, SQLi on public endpoint, auth bypass, credential exposure |
| High | Authenticated RCE, IDOR on sensitive data, plaintext password storage, stored XSS |
| Medium | CSRF on sensitive action, IDOR on lower-sensitivity data, missing auth rate limiting |
| Low | Missing security headers, verbose error messages, reflected XSS with low impact |
| Info | No-CVE dependency updates, minor code quality issues with negligible security impact |

Report Critical and High first. Fix before release. Medium: triage and schedule.

---

## Phase 5: Finding Format

For each finding:

1. **Title** — one line (e.g., "SQL injection in user search endpoint")
2. **Location** — file, function, line number
3. **Severity** — Critical / High / Medium / Low / Info
4. **Description** — what it is and why it's exploitable (one paragraph)
5. **Evidence** — the specific vulnerable code
6. **Fix** — corrected code or pattern, with the specific library/function to use
7. **Reference** — OWASP link or CVE if applicable

Lead with highest severity. Do not pad with low-confidence theoretical issues
when high-confidence real ones exist.

---

## Phase 6: Threat Modeling (for new/design-stage code)

Apply Shostack's Four Question Frame:
1. **What are we building?** (data flow, trust boundaries, entry points)
2. **What can go wrong?** STRIDE per component:
    - **S**poofing: can an attacker impersonate a user, service, or data source?
    - **T**ampering: can data be modified in transit or at rest?
    - **R**epudiation: can actions be denied? Are they logged?
    - **I**nformation Disclosure: can an attacker access data they shouldn't?
    - **D**enial of Service: can availability be degraded?
    - **E**levation of Privilege: can an attacker gain more access than intended?
3. **What are we going to do about it?** (mitigations per threat)
4. **Did we do a good job?** (are mitigations adequate and tracked?)

---

## AI/ML Code — Additional Checks

When reviewing code that uses an LLM or ML model:

- **Prompt injection:** Is user-controlled text passed into a prompt without sanitization?
  Can an attacker override system behavior via embedded instructions?
- **Output trust:** Is model output used directly in SQL, shell, or HTML without validation?
- **Access scope:** Does the AI component have broader permissions than it needs?
- **Logging:** Are AI inputs and outputs logged for incident investigation?
- **Failure mode:** If the model returns unexpected output, does the fallback fail securely?