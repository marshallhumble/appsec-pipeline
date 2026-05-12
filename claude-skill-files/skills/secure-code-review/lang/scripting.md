# PowerShell & Bash — Security Patterns for Infra Scripts

Load alongside the relevant vulnerability reference file.
Covers infrastructure and operations scripts: deployment automation, AWS CLI wrappers,
secret rotation, provisioning, CI/CD pipeline steps.

---

## Command Injection

### Bash

```bash
# NEVER — variable expansion in eval or unquoted command substitution
eval "ls $user_input"
$(echo "$user_input")
bash -c "process $filename"

# NEVER — unquoted variables in command position
rm -rf $dir     # if dir contains spaces or metacharacters, this breaks badly
cp $src $dst

# ALWAYS — quote all variables; validate before use
filename="$1"
if [[ "$filename" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    convert -- "$filename" "output.jpg"   # -- prevents flag injection
else
    echo "Invalid filename" >&2; exit 1
fi

# ALWAYS — use arrays for commands with variable arguments
args=("$@")
/usr/bin/convert "${args[@]}" output.jpg
```

### PowerShell

```powershell
# NEVER — Invoke-Expression with user input
Invoke-Expression "Get-ChildItem $userInput"
iex "& $scriptPath $args"

# NEVER — string interpolation into Start-Process arguments
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $userCommand"

# ALWAYS — use parameter arrays, not string concatenation
$fileName = $args[0]
if ($fileName -match '^[\w\-\.]+$') {
    & /usr/bin/convert $fileName output.jpg   # & operator with validated arg
} else {
    Write-Error "Invalid filename"; exit 1
}

# ALWAYS — validate inputs before use in any system call
[ValidatePattern('^[a-zA-Z0-9_-]+$')]
param([string]$ResourceName)
```

---

## Secrets — Never in Scripts

```bash
# NEVER — hardcoded in script
DB_PASSWORD="hunter2"
aws s3 cp s3://bucket/data . --aws-secret-access-key="AKIAIOSFODNN7EXAMPLE/abc123"

# NEVER — echoed or printed to stdout/logs
echo "Connecting with password: $DB_PASSWORD"

# ALWAYS — load from environment or secrets manager at runtime
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD must be set}"

# ALWAYS — AWS Secrets Manager via CLI
SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "prod/db/password" \
    --query SecretString \
    --output text)
DB_PASSWORD=$(echo "$SECRET" | jq -r '.password')
unset SECRET   # clear the full JSON from memory after extraction
```

```powershell
# NEVER
$dbPassword = "hunter2"

# ALWAYS — environment variable (fail loud if missing)
$dbPassword = [System.Environment]::GetEnvironmentVariable("DB_PASSWORD")
if (-not $dbPassword) { throw "DB_PASSWORD must be set" }

# ALWAYS — AWS Secrets Manager via SDK or CLI
$secret = aws secretsmanager get-secret-value `
    --secret-id "prod/db/password" `
    --query SecretString `
    --output text | ConvertFrom-Json
$dbPassword = $secret.password
Remove-Variable secret   # clear after use
```

---

## AWS CLI — Least Privilege and Safe Patterns

```bash
# NEVER — wildcard permissions or long-lived root/admin keys in scripts
# These should never appear in a script: --aws-access-key-id, --aws-secret-access-key

# ALWAYS — use IAM roles; credentials come from instance metadata or environment
# EC2/ECS/Lambda: role attached to the compute resource provides credentials automatically
aws sts get-caller-identity   # verify which role is in use

# ALWAYS — scope S3 operations to specific prefixes
aws s3 sync ./artifacts s3://my-bucket/releases/v1.2.3/  # specific prefix
# Not: aws s3 sync ./artifacts s3://my-bucket/            # entire bucket

# ALWAYS — use --no-paginate carefully; paginate explicitly for large result sets
aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' \
    --output text --max-items 100

# ALWAYS — verify resource exists before destructive operations
if aws s3api head-object --bucket "$BUCKET" --key "$KEY" 2>/dev/null; then
    aws s3 rm "s3://$BUCKET/$KEY"
fi

# SSM Parameter Store for non-secret config, Secrets Manager for credentials
CONFIG=$(aws ssm get-parameter --name "/prod/app/config" --with-decryption \
    --query Parameter.Value --output text)
```

```powershell
# PowerShell — AWS Tools for PowerShell (AWS.Tools.*)
Import-Module AWS.Tools.SecretsManager

$secret = Get-SECSecretValue -SecretId "prod/db/password"
$creds  = $secret.SecretString | ConvertFrom-Json
# Use $creds.password, then clear
Remove-Variable creds
```

---

## Input Validation in Scripts

### Bash
```bash
# Validate all external inputs before use in any command or path
validate_resource_name() {
    local name="$1"
    if [[ ! "$name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$ ]]; then
        echo "ERROR: Invalid resource name: $name" >&2
        exit 1
    fi
}

# Use -- to separate flags from arguments (prevents flag injection)
git checkout -- "$branch"
grep -- "$pattern" "$file"
aws s3 cp -- "$source" "$dest"
```

### PowerShell
```powershell
# Parameter validation attributes
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')]
    [string]$ResourceName,

    [Parameter(Mandatory)]
    [ValidateSet('dev', 'staging', 'prod')]
    [string]$Environment
)

# Test-Path before file operations
if (-not (Test-Path $filePath -PathType Leaf)) {
    throw "File not found: $filePath"
}
```

---

## Error Handling — Fail Loud, Not Silent

```bash
# ALWAYS at the top of deployment/infra scripts
set -euo pipefail
# -e: exit on error
# -u: error on unset variable (prevents silent empty-string expansions)
# -o pipefail: pipeline failure propagates

# Trap for cleanup on error
trap 'echo "Error on line $LINENO" >&2; cleanup' ERR

cleanup() {
    # Remove temp files, release locks, notify on-call
    rm -f "$TMPFILE"
}
```

```powershell
# ALWAYS — set strict error behavior
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Try/catch for cleanup
try {
    # ... operations ...
} catch {
    Write-Error "Failed: $_"
    # cleanup
    exit 1
}
```

---

## Temporary Files

```bash
# NEVER — predictable temp file names (race condition / symlink attack)
TMP=/tmp/deploy_output.txt

# ALWAYS — mktemp creates a file with a random name in a secure directory
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT   # always clean up
```

```powershell
# ALWAYS — New-TemporaryFile creates a secure temp file
$tmpFile = New-TemporaryFile
try {
    # use $tmpFile.FullName
} finally {
    Remove-Item $tmpFile.FullName -ErrorAction SilentlyContinue
}
```

---

## Logging — Mask Sensitive Values

```bash
# NEVER — logs password or token to stdout/stderr/CI output
echo "Deploying with password: $DB_PASSWORD"
set -x   # prints all variable expansions including secrets

# ALWAYS — mask before any set -x tracing
{
    echo "Connecting to database..."
    # do NOT echo the password
} 2>&1

# In CI (GitHub Actions, AWS CodeBuild): add secrets to masked values
# GitHub Actions masks any value added with ::add-mask::
echo "::add-mask::$SECRET_VALUE"
```

```powershell
# NEVER
Write-Host "Password: $dbPassword"

# ALWAYS — use SecureString for sensitive values in memory
$securePassword = ConvertTo-SecureString $dbPassword -AsPlainText -Force
Remove-Variable dbPassword  # clear plaintext after conversion
```

---

## Script Hardening Checklist

- [ ] `set -euo pipefail` (bash) or `$ErrorActionPreference = "Stop"` (PowerShell) at top
- [ ] All variables quoted (`"$var"`, not `$var`) in bash
- [ ] All external inputs validated before use in any command or path
- [ ] No secrets hardcoded; loaded from secrets manager or environment at runtime
- [ ] Secrets never echoed, logged, or set -x traced
- [ ] Temp files created with `mktemp`; cleaned up on exit
- [ ] `--` used to separate flags from user-controlled arguments
- [ ] AWS operations use least-privilege IAM role, not long-lived keys
- [ ] Destructive operations verified before execution
