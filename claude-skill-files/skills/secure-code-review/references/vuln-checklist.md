# Vulnerability Checklist — Grep Patterns & Fix Patterns

Detailed per-class patterns for use during a review session.
Load the relevant section alongside the appropriate language reference file.

---

## #injection

### Grep Patterns

```bash
# C# — dangerous query and process patterns
grep -rn "FromSqlRaw\|ExecuteSqlRaw" --include="*.cs" .   # check for interpolation
grep -rn "new SqlCommand" --include="*.cs" . | grep -v "Parameters\|@"
grep -rn 'UseShellExecute\s*=\s*true' --include="*.cs" .
grep -rn '"cmd\.exe"\|"bash"\|"sh"' --include="*.cs" .

# Rust — format! into queries, shell execution
grep -rn 'format!.*SELECT\|format!.*INSERT\|format!.*UPDATE\|format!.*DELETE' --include="*.rs" .
grep -rn 'Command::new.*"sh"\|Command::new.*"bash"\|arg("-c")' --include="*.rs" .

# Go — Sprintf into queries, shell execution
grep -rn 'Sprintf.*SELECT\|Sprintf.*INSERT\|Sprintf.*UPDATE' --include="*.go" .
grep -rn 'exec\.Command.*"sh"\|exec\.Command.*"bash"' --include="*.go" .
grep -rn 'text/template' --include="*.go" .    # should be html/template for HTML

# Python — cursor.execute with format, os.system
grep -rn 'cursor\.execute.*%\|cursor\.execute.*format\|cursor\.execute.*f"' --include="*.py" .
grep -rn 'os\.system\|subprocess.*shell=True' --include="*.py" .

# PowerShell/bash
grep -rn 'Invoke-Expression\|iex ' . --include="*.ps1"
grep -rn 'eval ' . --include="*.sh"
```

### Verdict: Safe vs. Unsafe

```
UNSAFE (any language):
  - Concatenation/interpolation of user input into query string
  - Shell interpreter (sh, bash, cmd.exe) with user-controlled -c argument
  - format!/fmt.Sprintf/f-string/string + into query or command

SAFE:
  - .bind() / parameterized placeholder with value passed separately
  - ORM query builder methods (filter, Where with struct)
  - Fixed executable path with arguments as separate items (not shell string)
```

---

## #broken-access-control

### What to Look For

```bash
# C# — endpoints without RequireAuthorization or [Authorize]
grep -rn 'app\.Map\(Get\|Post\|Put\|Delete\)' --include="*.cs" . | grep -v "RequireAuthorization\|Authorize"
# Missing ownership check in EF Core queries
grep -rn '\.FindAsync\|\.FirstOrDefaultAsync' --include="*.cs" . | grep -v "UserId\|OwnerId\|owner"

# Rust — handlers not behind auth middleware
grep -rn 'async fn.*Handler\|async fn.*handler' --include="*.rs" .  # review each for auth extractor

# Go — direct handler registration without middleware
grep -rn 'http\.HandleFunc\|router\.Get\|router\.Post' --include="*.go" . | grep -v "Use("

# All languages — look for mass assignment risk
grep -rn 'role\|isAdmin\|is_admin\|IsAdmin' --include="*.cs" --include="*.rs" --include="*.go" --include="*.py" .
```

### IDOR Pattern (Any Language)

Every resource load must include an ownership or permission check:
```
MISSING:  load(id)
CORRECT:  load(id, owner_id=current_user.id)
          → 404 if not found (not 403)
```

---

## #cryptographic-failures

### Grep Patterns

```bash
# Hardcoded secrets (all languages)
gitleaks detect --source=. --verbose
grep -rn 'password\s*=\s*["\x27][^"\x27{][^"\x27]*["\x27]' .
grep -rn 'api.key\s*=\s*["\x27]\|secret\s*=\s*["\x27]\|token\s*=\s*["\x27]' .
grep -rn 'AKIA[0-9A-Z]{16}' .      # AWS access key pattern
grep -rn 'AccountKey=\|SharedAccessSignature=' .  # Azure storage

# Weak hashing
grep -rn 'MD5\|SHA1\b\|SHA256\b' --include="*.cs" .     # flag if used for passwords
grep -rn '::md5\|::sha1\|::sha2' --include="*.rs" .
grep -rn 'md5\.\|sha1\.\|sha256\.' --include="*.go" --include="*.py" .

# Non-CSPRNG usage for security values
grep -rn 'new Random()\|System\.Random' --include="*.cs" .
grep -rn 'rand::thread_rng\b' --include="*.rs" .   # ok for non-security; flag context
grep -rn 'math/rand' --include="*.go" .
grep -rn 'random\.' --include="*.py" .  # flag if used for tokens/sessions
```

---

## #deserialization

### High-Risk Patterns

```bash
# Python
grep -rn 'pickle\.loads\|pickle\.load\b' --include="*.py" .    # CRITICAL if from untrusted source
grep -rn 'yaml\.load\b' --include="*.py" .                     # use yaml.safe_load instead
grep -rn 'marshal\.loads' --include="*.py" .

# C#
grep -rn 'BinaryFormatter\|NetDataContractSerializer\|SoapFormatter' --include="*.cs" .
grep -rn 'TypeNameHandling' --include="*.cs" .  # Newtonsoft.Json — flag if not None

# Go
grep -rn 'encoding/gob' --include="*.go" .  # flag if source is untrusted

# Rust
grep -rn 'from_slice.*bincode\|deserialize_from' --include="*.rs" .  # check source
```

### Fix Principles
- Python: `yaml.safe_load` instead of `yaml.load`; JSON instead of pickle
- C#: Use `System.Text.Json` with default settings; avoid `BinaryFormatter` (deprecated in .NET 9)
- Never deserialize to dynamic types based on a type hint supplied by the request

---

## #secrets-in-code

### Grep Patterns

```bash
# High-entropy strings and known patterns
gitleaks detect --source=. --verbose
trufflehog git file://. --only-verified

# Manual patterns
grep -rn '"password"\s*:\s*"[^{]' .          # JSON with literal password
grep -rn 'ConnectionString.*Password=' .      # connection strings with passwords
grep -rn 'BEGIN.*(RSA|EC|PRIVATE) KEY' .      # private keys
grep -rn 'AKIA[0-9A-Z]{16}' .                # AWS access key IDs
grep -rn 'AccountKey=[a-zA-Z0-9+/]{50}' .    # Azure storage account keys

# Check git history
git log --all --oneline --diff-filter=D -- "*.env" "*.pem" "*.key"
git grep -i "password\|secret\|apikey" $(git rev-list --all)
```

---

## #security-headers

Headers to verify on HTTP responses:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; [directives]
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Framework Quick-Add

**C# (NWebsec / built-in)**
```csharp
app.UseHsts();
app.UseXContentTypeOptions();
app.UseXfo(o => o.Deny());
app.UseCsp(opts => opts.DefaultSources(s => s.Self()));
```

**Rust (tower-http / tower-helmet)**
```rust
use tower_http::set_header::SetResponseHeaderLayer;
// or: use tower_helmet::HelmetLayer;
```

**Go (unrolled/secure)**
```go
sm := secure.New(secure.Options{
    FrameDeny: true, ContentTypeNosniff: true,
    STSSeconds: 31536000, STSIncludeSubdomains: true,
})
```

**Python (Flask-Talisman / Django settings)**
```python
Talisman(app)                     # Flask
SECURE_HSTS_SECONDS = 31536000    # Django
```

---

## #dependency-audit

```bash
# C# / .NET
dotnet list package --vulnerable --include-transitive

# Rust
cargo audit
cargo deny check

# Go
govulncheck ./...

# Python
pip-audit

# All languages — container/filesystem
trivy fs .
grype dir:.

# Secret scanning
gitleaks detect --source=. --verbose
```

---

## #logging-sensitive-data

```bash
# Grep for logging of sensitive field names
grep -rn 'password\|token\|secret\|api.key\|apikey' \
    --include="*.cs" --include="*.rs" --include="*.go" --include="*.py" . \
    | grep -i 'log\|print\|fmt\|write\|debug\|info\|warn\|error'
```

**Rust-specific:** Verify that `Secret<T>` wraps all sensitive fields — its `Debug`
impl prints `[REDACTED]` rather than the value.

**C#-specific:** Verify that structured logging (Serilog, NLog, ILogger) destructuring
(`@object`) does not expand objects containing passwords or tokens.

---

## #rate-limiting

Where it must be applied:
- Login / authentication endpoints
- Password reset request
- Account enumeration endpoints (user lookup, forgot password)
- Any endpoint that sends email or SMS
- Expensive operations (search, export, report generation)
- Payment / transaction processing

### Framework Quick-Add

**C# (ASP.NET Core 8)**
```csharp
builder.Services.AddRateLimiter(opts =>
    opts.AddFixedWindowLimiter("login", o => {
        o.PermitLimit = 10; o.Window = TimeSpan.FromMinutes(15);
    }));
app.MapPost("/auth/login", Handler).RequireRateLimiting("login");
```

**Rust (tower-governor)**
```rust
GovernorConfigBuilder::default().per_second(1).burst_size(10).finish()
```

**Go (golang.org/x/time/rate)**
```go
rate.NewLimiter(rate.Every(15*time.Minute/10), 10)
```

**Python (flask-limiter / django-ratelimit)**
```python
@limiter.limit("10 per 15 minutes")   # Flask
@ratelimit(key="ip", rate="10/15m")   # Django
```

---

## #cicd-pipeline

### What to Look For

```bash
# Hardcoded secrets in workflow files
grep -rn 'password\|secret\|token\|key' .github/workflows/ --include="*.yml"
# Check for literal values (not ${{ secrets.* }} references)

# Third-party actions pinned to mutable tags instead of SHA
grep -rn 'uses:' .github/workflows/ --include="*.yml" | grep -v '@[a-f0-9]\{40\}'

# set -x in steps that have access to secrets (traces all variable expansions)
grep -rn 'set -x' .github/workflows/ --include="*.yml"

# Missing permissions block (defaults to over-permissive)
grep -rL 'permissions:' .github/workflows/*.yml

# AWS credentials hardcoded in buildspec
grep -rn 'AWS_ACCESS_KEY_ID\|AWS_SECRET_ACCESS_KEY' . --include="buildspec.yml"
```

### Verdict Patterns

```
UNSAFE: uses: some-action@v2                  (mutable tag)
SAFE:   uses: some-action@a1b2c3d4e5...       (pinned SHA)

UNSAFE: env: DB_PASSWORD: "hunter2"           (hardcoded)
SAFE:   env: DB_PASSWORD: ${{ secrets.DB_PASSWORD }}

UNSAFE: role-to-assume condition uses StringLike with wildcard repo
SAFE:   condition scoped to exact repo and branch with StringEquals
```

---

## #containers

### What to Look For

```bash
# Running as root (no USER instruction)
grep -rn 'FROM\|USER' Dockerfile* --include="Dockerfile*" | grep -v 'USER'

# Secrets in ENV or ARG
grep -rn '^ENV\|^ARG' Dockerfile* | grep -i 'password\|secret\|key\|token'

# Mutable base image tags (no digest pin)
grep -rn '^FROM' Dockerfile* | grep -v '@sha256:'

# Missing resource limits in ECS task definitions
grep -rn '"memory"\|"cpu"' . --include="*.json" | grep -v '"memoryReservation"'

# Containers not running as non-root in Kubernetes
grep -rn 'runAsNonRoot\|runAsUser' . --include="*.yaml" --include="*.yml"
# Flag any pod spec without these set
```

### Verdict Patterns

```
UNSAFE: No USER instruction in Dockerfile         → runs as root
UNSAFE: ENV DB_PASSWORD=hunter2                   → secret in image layer
UNSAFE: FROM node:20                              → mutable tag; may change
SAFE:   FROM node:20@sha256:abc123...             → pinned to specific digest
SAFE:   USER appuser (non-root, after COPY)
SAFE:   secrets injected via ECS task definition secretsmanager reference
```
