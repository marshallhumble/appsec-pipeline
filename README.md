# Zero Budget AppSec Tooling

Open source application security tooling for CI/CD pipelines. No licensing costs. No per-seat fees.

Part of a LinkedIn article series on building a complete AppSec program without enterprise tooling.

---

## Contents

- [GitHub Actions Security Pipeline](#github-actions-security-pipeline)
- [Custom Semgrep Rules](#custom-semgrep-rules)
- [Usage](#usage)
- [Adding to Your Repository](#adding-to-your-repository)

---

## GitHub Actions Security Pipeline

`.github/workflows/security-scanning.yml`

A pull request security scanning workflow that runs on every PR, covers multiple languages and file types, and posts an aggregated report directly to the PR as a comment.

### Design Principles

**Only scan what changed.** Every job checks which files were modified in the PR before running. A frontend-only change does not wait for .NET restore and vulnerability scanning. Developers see findings relevant to what they actually touched.

**One report per PR.** Every scanner outputs SARIF. A final aggregation job collects all results, parses severity levels, and generates a single markdown summary posted to the PR. No hunting through separate job logs.

**All actions pinned by SHA.** Every action is pinned to a full commit SHA rather than a mutable tag. Tags can be silently redirected to different code - the tj-actions compromise in 2025 demonstrated this attack vector directly. SHA pins are immutable. Version comments preserve readability and allow Dependabot to track updates automatically.

### Tools

| Tool | Coverage | Notes |
|------|----------|-------|
| [Semgrep](https://semgrep.dev) | Go, C#, Python, JS/TS, PHP, Ruby, Rust | OWASP Top 10 rules, secrets detection, custom rules |
| [Gosec](https://github.com/securego/gosec) | Go | Go-specific security analysis |
| [Staticcheck](https://staticcheck.io) | Go | Go linting with security relevance |
| [Brakeman](https://brakemanscanner.org) | Ruby/Rails | Rails security scanning |
| [Checkov](https://www.checkov.io) | Terraform, Docker, Kubernetes, CloudFormation | IaC misconfiguration detection |
| [Trivy](https://aquasecurity.github.io/trivy) | Filesystem | Vulnerability and secret scanning |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Git history | Secret detection across commit history |
| [SQLFluff](https://www.sqlfluff.com) | SQL | SQL linting and analysis |
| [TSQLLint](https://github.com/tsqllint/tsqllint) | T-SQL | T-SQL analysis |
| [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) | PowerShell | PowerShell security analysis |
| [cargo-audit](https://rustsec.org) | Rust | Dependency scanning against RustSec advisory database |
| [dotnet list package --vulnerable](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-list-package) | .NET 8, 9, 10 | NuGet vulnerability detection |

### A Note on Location Data

Code scanners (Semgrep, Gosec, Brakeman, Checkov, Staticcheck, PSScriptAnalyzer) emit precise file, line, and column information. Findings link directly to the relevant code.

Dependency scanners (cargo-audit, dotnet vulnerable packages, TruffleHog) point to the manifest file at line 1. The finding is about a package version, not a specific line of code. This is expected behavior, not a scanner limitation.

### .NET Version Support

The workflow covers .NET 8, 9, and 10 - all currently supported versions. .NET 6 reached end of life in November 2024 and is not included.

---

## Custom Semgrep Rules

`rules/`

Four custom rules for .NET/C# and Go environments. Community Semgrep packs cover common patterns broadly. These rules cover framework-specific patterns that require knowledge of the stack, with remediation guidance specific to the technology.

Run alongside community packs:

```bash
semgrep --config p/owasp-top-ten \
        --config p/secrets \
        --config ./rules/ \
        --sarif \
        --output semgrep.sarif \
        .
```

### Rules

#### `csharp-binaryformatter-unsafe-deserialization`

**Severity**: ERROR | **CWE**: CWE-502 | **OWASP**: A8:2021

Detects usage of `BinaryFormatter`, which deserializes arbitrary types and enables remote code execution. Microsoft deprecated it in .NET 5 and removed it entirely in .NET 9.

```csharp
// Flagged
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);

// Fix
var obj = JsonSerializer.Deserialize<MyType>(stream);
```

---

#### `csharp-controller-missing-authorize`

**Severity**: WARNING | **CWE**: CWE-306 | **OWASP**: A1:2021

Detects ASP.NET Core controllers with neither `[Authorize]` nor `[AllowAnonymous]`. An access control decision made by omission is still a decision - this rule forces it to be explicit.

```csharp
// Flagged - no access control decision
[ApiController]
public class PatientDataController : ControllerBase { ... }

// Fix - require authentication
[Authorize]
[ApiController]
public class PatientDataController : ControllerBase { ... }

// Fix - explicitly mark as public
[AllowAnonymous]
[ApiController]
public class HealthCheckController : ControllerBase { ... }
```

Severity is WARNING rather than ERROR because a global authorization policy in `Program.cs` may already cover the controller. The rule forces a conscious decision either way.

---

#### `csharp-hardcoded-connection-string`

**Severity**: ERROR | **CWE**: CWE-798 | **OWASP**: A2:2021 | **Confidence**: MEDIUM

Detects hardcoded credentials in `SqlConnection` and `NpgsqlConnection` strings. Credentials in source code are exposed in version control, build logs, and container images.

```csharp
// Flagged
var conn = new SqlConnection("Server=prod-db;Password=Sup3rS3cr3t!");

// Fix - environment variable
var conn = new SqlConnection(
    Environment.GetEnvironmentVariable("DB_CONNECTION_STRING"));

// Fix - AWS Secrets Manager
var secret = await client.GetSecretValueAsync(new GetSecretValueRequest {
    SecretId = "prod/db/connectionstring"
});
var conn = new SqlConnection(secret.SecretString);
```

Confidence is MEDIUM - test fixtures and example code will produce false positives. Findings warrant review before rejection.

---

#### `go-http-server-missing-timeout`

**Severity**: WARNING | **CWE**: CWE-400 | **OWASP**: A5:2021

Detects Go HTTP servers configured without read or write timeouts. A server with no timeouts is vulnerable to Slowloris-style denial of service where attackers hold connections open indefinitely.

`http.ListenAndServe()` cannot have timeouts set - the function signature does not support it. The fix always requires constructing `http.Server` directly.

```go
// Flagged
http.ListenAndServe(":8080", handler)

// Fix
srv := &http.Server{
    Addr:         ":8080",
    Handler:      handler,
    ReadTimeout:  5 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
}
srv.ListenAndServe()
```

---

## Usage

### Running the Pipeline

The workflow runs automatically on every pull request. No manual configuration required beyond adding the workflow file to `.github/workflows/`.

To run scans locally:

```bash
# Semgrep with community packs and custom rules
semgrep --config p/owasp-top-ten --config p/secrets --config ./rules/ .

# Individual tools
gosec ./...
staticcheck ./...
trivy fs .
```

### Dependabot Configuration

Add to `.github/dependabot.yml` to keep action SHAs and dependencies current:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"

  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot reads the version comments on SHA-pinned actions (`# v4.2.2`) and opens PRs when new versions are available. Immutability without manual maintenance.

---

## Adding to Your Repository

1. Copy `.github/workflows/security-scanning.yml` to your repo
2. Copy the `rules/` directory to your repo root
3. Add the Dependabot configuration above
4. Open a pull request - the pipeline runs automatically

The workflow requires no secrets or external services for the scanning jobs. The PR comment aggregation requires the default `GITHUB_TOKEN`, which is available in all GitHub Actions workflows without configuration.

---

## Related Articles

1. [Robust CI/CD Security on a Zero Dollar Budget](#) - The scanning workflow
2. [End-to-End Supply Chain Security with Open Source Tools](#) - Image signing, SBOM attestation, SHA pinning
3. [Writing Semgrep Rules That Actually Matter](#) - These custom rules

---

## License

MIT
