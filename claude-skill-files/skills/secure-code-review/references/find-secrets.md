# Find and Replace Hardcoded Secrets

Scans the current working tree for hardcoded secrets, presents each finding with
context, proposes the correct language-appropriate replacement, and makes the edit
after confirmation. Does not modify files without explicit approval.

---

## Step 1: Run the scanner

First check whether gitleaks is available. If yes, use it. If not, fall back to grep.

```bash
# Preferred: gitleaks (structured JSON output)
if command -v gitleaks &>/dev/null; then
    gitleaks detect --source=. --report-format=json --report-path=/tmp/secrets-scan.json \
        --no-git 2>/dev/null
    echo "SCANNER=gitleaks"
else
    echo "gitleaks not found — falling back to grep patterns"
    echo "SCANNER=grep"
fi
```

If gitleaks is not installed, offer to install it:
```bash
# macOS
brew install gitleaks

# Linux
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks
```

If the user declines installation, proceed with grep fallback patterns (see Step 1b).

### Step 1b: Grep fallback (if gitleaks unavailable)

```bash
grep -rn \
    -e 'password\s*=\s*["'"'"'][^"'"'"'$({][^"'"'"']*["'"'"']' \
    -e 'api.key\s*=\s*["'"'"'][^"'"'"'$({][^"'"'"']*["'"'"']' \
    -e 'secret\s*=\s*["'"'"'][^"'"'"'$({][^"'"'"']*["'"'"']' \
    -e 'token\s*=\s*["'"'"'][^"'"'"'$({][^"'"'"']*["'"'"']' \
    -e 'connection.string.*Password=[^;$]' \
    -e 'AccountKey=[A-Za-z0-9+/]\{40,\}' \
    -e 'AKIA[0-9A-Z]\{16\}' \
    -e 'BEGIN\s\(RSA\|EC\|OPENSSH\) PRIVATE KEY' \
    --include="*.cs" --include="*.rs" --include="*.go" \
    --include="*.py" --include="*.sh" --include="*.ps1" \
    --include="*.json" --include="*.yaml" --include="*.yml" \
    --include="*.toml" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
    --include="*.env" \
    --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="target" \
    --exclude-dir="bin" --exclude-dir="obj" \
    . 2>/dev/null
```

---

## Step 2: Parse and filter findings

Read `/tmp/secrets-scan.json` if gitleaks ran, or process the grep output.

Exclude false positives before presenting:
- Lines in test files that contain clearly fake values (`"test"`, `"fake"`, `"example"`,
  `"placeholder"`, `"YOUR_KEY_HERE"`, `"xxx"`, `"<redacted>"`)
- Lines inside comments that document expected format (not actual values)
- Files matching: `*_test.go`, `*Test.cs`, `*_test.rs`, `test_*.py`, `*.test.*`,
  `*.spec.*`, `testdata/`, `fixtures/`, `examples/`, `docs/`

If no findings remain after filtering, report: "No hardcoded secrets found." and stop.

---

## Step 3: Present findings one at a time

For each finding, show:

```
─────────────────────────────────────────────
Finding 1 of N
File:     src/config/database.cs  (line 42)
Type:     Hardcoded password
Content:  var dbPassword = "hunter2";
─────────────────────────────────────────────
```

Then determine the language from the file extension:
- `.cs` → C#
- `.rs` → Rust
- `.go` → Go
- `.py` → Python
- `.js`, `.ts`, `.jsx`, `.tsx` → JavaScript / TypeScript
- `.sh`, `.bash` → bash
- `.ps1` → PowerShell
- `.yaml`, `.yml`, `.json`, `.toml` → config file
- `.env` → env file (already correct format; flag that it must be in `.gitignore`)

---

## Step 4: Propose the replacement

Use the replacement templates below for the detected language and secret type.

After showing the proposed replacement, ask:
**"Apply this fix? (yes / skip / quit)"**

- `yes` → make the edit (see Step 5)
- `skip` → move to the next finding without changing this file
- `quit` → stop processing; summarize what was fixed and what was skipped

Never apply any edit without an explicit "yes" from the user.

---

## Replacement Templates by Language and Secret Type

### C# / ASP.NET Core

**Database password / connection string:**
```csharp
// BEFORE
var dbPassword = "hunter2";
var connStr = "Server=db;Password=hunter2;";

// AFTER — IConfiguration (backed by env var or Key Vault)
var dbPassword = builder.Configuration["DB_PASSWORD"]
    ?? throw new InvalidOperationException("DB_PASSWORD is not configured");

// AFTER — Azure Key Vault reference (App Service setting)
// Set app setting value to: @Microsoft.KeyVault(SecretUri=https://vault.azure.net/secrets/db-password/)
var dbPassword = builder.Configuration["db-password"];
```

**API key / token:**
```csharp
// BEFORE
var apiKey = "sk-abc123";

// AFTER
var apiKey = builder.Configuration["EXTERNAL_API_KEY"]
    ?? throw new InvalidOperationException("EXTERNAL_API_KEY is not configured");
```

**AWS credentials (should never appear in C# code):**
```csharp
// BEFORE
var accessKey = "AKIAIOSFODNN7EXAMPLE";

// AFTER — use DefaultAzureCredential / DefaultAWSCredential / instance role
// Remove the credential entirely; use DefaultAWSOptions with no explicit keys:
builder.Services.AddDefaultAWSOptions(builder.Configuration.GetAWSOptions());
// Credentials come from instance role / environment automatically
```

### Rust

**Any secret:**
```rust
// BEFORE
let db_password = "hunter2";
let api_key = "sk-abc123";

// AFTER — env var wrapped in Secret<T>
use secrecy::{Secret, ExposeSecret};
let db_password = Secret::new(
    std::env::var("DB_PASSWORD")
        .expect("DB_PASSWORD environment variable must be set")
);
// Use only where needed: db_password.expose_secret()
```

**In a config struct:**
```rust
// BEFORE
struct Config {
    db_password: String,  // "hunter2"
}

// AFTER
use secrecy::Secret;
struct Config {
    db_password: Secret<String>,
}
impl Config {
    fn from_env() -> Self {
        Self {
            db_password: Secret::new(
                std::env::var("DB_PASSWORD").expect("DB_PASSWORD must be set")
            ),
        }
    }
}
```

### Go

**Any secret:**
```go
// BEFORE
const dbPassword = "hunter2"
var apiKey = "sk-abc123"

// AFTER — os.Getenv with explicit empty-check
dbPassword := os.Getenv("DB_PASSWORD")
if dbPassword == "" {
    log.Fatal("DB_PASSWORD environment variable must be set")
}
```

**In a config struct loaded at startup:**
```go
// BEFORE
type Config struct {
    DBPassword string // "hunter2"
}

// AFTER
type Config struct {
    DBPassword string
}

func LoadConfig() Config {
    pw := os.Getenv("DB_PASSWORD")
    if pw == "" {
        log.Fatal("DB_PASSWORD must be set")
    }
    return Config{DBPassword: pw}
}
```

### Python

**Any secret:**
```python
# BEFORE
db_password = "hunter2"
api_key = "sk-abc123"

# AFTER — os.environ with KeyError on missing (fail loud)
import os
db_password = os.environ["DB_PASSWORD"]   # raises KeyError if not set
api_key     = os.environ["EXTERNAL_API_KEY"]
```

**In a settings/config module:**
```python
# AFTER — with helpful error message
import os

def get_required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(f"{name} environment variable must be set")
    return value

DB_PASSWORD = get_required_env("DB_PASSWORD")
```

### Bash

**Any secret:**
```bash
# BEFORE
DB_PASSWORD="hunter2"
API_KEY="sk-abc123"

# AFTER — fail loud if unset (${VAR:?message} syntax)
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD environment variable must be set}"
API_KEY="${API_KEY:?API_KEY environment variable must be set}"
```

**Loading from AWS Secrets Manager in a script:**
```bash
# AFTER — fetch at runtime, never store in script
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id "prod/db/password" \
    --query SecretString \
    --output text | jq -r '.password')
export DB_PASSWORD
```


### JavaScript / TypeScript

**Any secret:**
```typescript
// BEFORE
const apiKey = "sk-abc123";
const dbPassword = "hunter2";

// AFTER — process.env with explicit missing check
const apiKey    = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
if (!apiKey)     throw new Error("API_KEY environment variable must be set");
if (!dbPassword) throw new Error("DB_PASSWORD environment variable must be set");
```

**Loading from AWS Secrets Manager:**
```typescript
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({ region: "us-east-1" });
const response = await client.send(
    new GetSecretValueCommand({ SecretId: "prod/db/password" })
);
const { password: dbPassword } = JSON.parse(response.SecretString!);
```

**Loading from Azure Key Vault:**
```typescript
import { SecretClient } from "@azure/keyvault-secrets";
import { DefaultAzureCredential } from "@azure/identity";

const kvClient = new SecretClient(process.env.KEY_VAULT_URI!, new DefaultAzureCredential());
const secret = await kvClient.getSecret("db-password");
const dbPassword = secret.value!;
```

**Note on `.env` files:** If the finding is in a `.env` file, check `.gitignore`
rather than replacing the content — see the `.env files` section below.

### PowerShell

**Any secret:**
```powershell
# BEFORE
$dbPassword = "hunter2"

# AFTER — environment variable with explicit null check
$dbPassword = [System.Environment]::GetEnvironmentVariable("DB_PASSWORD")
if (-not $dbPassword) {
    throw "DB_PASSWORD environment variable must be set"
}
```

**Loading from AWS Secrets Manager:**
```powershell
# AFTER
$secret = aws secretsmanager get-secret-value `
    --secret-id "prod/db/password" `
    --query SecretString `
    --output text | ConvertFrom-Json
$dbPassword = $secret.password
Remove-Variable secret
```

### Config files (YAML, JSON, TOML)

These files should never contain literal secret values. Replace with a reference
to the environment variable or secrets manager.

```yaml
# BEFORE (docker-compose.yml or app config)
environment:
  DB_PASSWORD: hunter2

# AFTER — reference the environment variable
environment:
  DB_PASSWORD: ${DB_PASSWORD}
```

```json
// BEFORE (appsettings.json)
{
  "ConnectionStrings": {
    "Default": "Server=db;Password=hunter2;"
  }
}

// AFTER — use environment variable override or Key Vault reference
// appsettings.json should contain only non-secret defaults
// Secrets injected via environment: ConnectionStrings__Default__Password
// Or: Azure Key Vault reference in App Service configuration
```

```toml
# BEFORE (Rust config or similar)
[database]
password = "hunter2"

# AFTER — remove value; load from env in application code
[database]
# password loaded from DB_PASSWORD environment variable at startup
```

### .env files

If a `.env` file containing real secrets is found, do not replace the content —
`.env` files are the correct place for local development secrets. Instead:

1. Check whether `.env` is in `.gitignore`. If not, add it:
   ```bash
   echo ".env" >> .gitignore
   echo "*.env" >> .gitignore
   ```
2. Verify a `.env.example` (with placeholder values, no real secrets) exists for
   developer onboarding. If not, create one with the same keys but empty or example values.
3. Report the finding as: "`.env` file found — confirmed not in `.gitignore`" (if
   that was the issue) or "`.env` file found — already in `.gitignore`, no action needed."

---

## Step 5: Apply the edit

When the user confirms a fix:

1. Read the file
2. Locate the exact line(s) matching the finding
3. Replace with the proposed pattern, preserving indentation and surrounding context
4. Write the file
5. Show a diff of the change
6. Move to the next finding

If the replacement requires an import or `using` statement that isn't present,
add it at the top of the file with the other imports.

---

## Step 6: Final summary

After all findings are processed, show:

```
─────────────────────────────────────────────
Secrets scan complete
Fixed:   3 findings
Skipped: 1 finding (src/legacy/old_config.cs:17)
─────────────────────────────────────────────

Next steps:
1. Set the corresponding environment variables in your deployment environment:
   DB_PASSWORD, EXTERNAL_API_KEY, STRIPE_SECRET_KEY

2. For production: store these in AWS Secrets Manager or Azure Key Vault,
   not as plaintext environment variables.

3. Run `gitleaks detect --source=. --verbose` to confirm no secrets remain.

4. If any secrets were previously committed, rotate them now — the git history
   may have been scraped. Then scrub history:
   git filter-repo --path <file> --invert-paths
```

If any finding was skipped, remind the user that skipped secrets are still at risk
and should be addressed before the code is committed or deployed.
