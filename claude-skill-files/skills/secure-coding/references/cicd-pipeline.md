# CI/CD Pipeline Security

CI/CD pipelines have elevated permissions — they build artifacts, push to registries,
and deploy to production. A compromised pipeline is a direct path to production.
Pipeline secrets (AWS credentials, deploy keys, signing certificates) are high-value
targets.

Covers: GitHub Actions, AWS CodeBuild/CodePipeline, and general principles.
For platform-specific secret loading, see `references/cloud-aws.md` or
`references/cloud-azure.md`.

---

## Secrets in Pipelines

### Never Put Secrets In

- Workflow/pipeline YAML files committed to the repo
- Environment variables set to literal values in pipeline config
- Build arguments (`--build-arg`) in Docker builds — visible in image history
- Log output — mask all secret values before any step that might echo them
- Artifacts — build outputs should never contain credentials

### Always Load Secrets From

- **GitHub Actions:** repository or organization secrets (Settings → Secrets)
  accessed via `${{ secrets.SECRET_NAME }}`
- **AWS CodeBuild:** environment variables backed by SSM Parameter Store or
  Secrets Manager (set in the project config, not the buildspec)
- **Azure Pipelines:** variable groups linked to Key Vault, or pipeline secrets

```yaml
# GitHub Actions — CORRECT
env:
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}

# GitHub Actions — NEVER
env:
  DB_PASSWORD: "hunter2"   # hardcoded
```

---

## OIDC-Based Role Assumption (No Long-Lived Keys)

The standard pattern for CI/CD accessing AWS or Azure is OIDC token federation.
The pipeline proves its identity to the cloud provider via a short-lived JWT;
the cloud provider issues temporary credentials. No long-lived access keys are
stored anywhere.

### GitHub Actions → AWS

```yaml
# .github/workflows/deploy.yml
permissions:
  id-token: write   # required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          aws-region: us-east-1
          # No access-key-id or secret-access-key — credentials are temporary
```

```json
// IAM trust policy on GitHubActionsDeployRole
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:ref:refs/heads/main"
    }
  }
}
```

Scope the `sub` condition to the specific repo and branch that should be able to
assume the role. Never use `StringLike` with a wildcard that permits other repos.

### GitHub Actions → Azure

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    # No client-secret — uses OIDC federation
```

### AWS CodeBuild → AWS Services

CodeBuild uses the IAM service role attached to the project. No credentials needed
in the buildspec — just call the AWS CLI or SDK and it picks up the role automatically.

```yaml
# buildspec.yml — CORRECT: no credentials
phases:
  build:
    commands:
      - aws s3 cp artifact.zip s3://my-bucket/releases/

# buildspec.yml — NEVER: hardcoded credentials
env:
  variables:
    AWS_ACCESS_KEY_ID: AKIA...        # hardcoded — reject this immediately
```

---

## Secret Masking in Logs

Even when secrets are loaded correctly, they can leak into logs through echoing,
debug output, or error messages.

```yaml
# GitHub Actions — mask a dynamically generated value
- name: Fetch and mask secret
  run: |
    SECRET=$(aws secretsmanager get-secret-value \
      --secret-id prod/api-key --query SecretString --output text)
    echo "::add-mask::$SECRET"   # masks this value in all subsequent log output
    echo "SECRET=$SECRET" >> $GITHUB_ENV

# Set -x in bash traces every command including variable expansions
# NEVER use set -x in a step that has access to secrets
```

```yaml
# AWS CodeBuild — mark parameter store values as secrets so they are masked
env:
  parameter-store:
    DB_PASSWORD: /prod/db/password   # value is masked in build logs automatically
  secrets-manager:
    API_KEY: prod/api-key            # value is masked in build logs automatically
```

---

## Third-Party Actions and Pipeline Steps

Every third-party GitHub Action runs in your pipeline with access to your secrets
and environment. A compromised action is a supply chain attack.

```yaml
# NEVER — mutable tag; a new commit to that tag can change behaviour silently
- uses: some-org/some-action@v2

# ALWAYS — pin to a specific commit SHA
- uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

Additional rules:
- Review the source code of any third-party action before adding it
- Prefer actions from GitHub's own org (`actions/*`) or well-known publishers
- Use `permissions:` to restrict what the GITHUB_TOKEN can do — default to
  minimal permissions and add only what the workflow needs
- Consider `zizmor` (GitHub Actions static analysis) in your toolchain

---

## Least Privilege for Pipeline Roles

Pipeline roles should have only the permissions needed for that specific job.
Deploy pipelines for different services should use different roles.

```
Build pipeline:     ECR push, S3 write to artifact bucket
Deploy to staging:  ECS update-service, read from artifact bucket
Deploy to prod:     ECS update-service (requires manual approval gate)
Infrastructure:     Terraform state bucket read/write, CloudFormation (scoped)
```

Never give a build pipeline the ability to deploy to production without a separate
approval step. A CI job triggered by a PR from a fork should not have write permissions.

```yaml
# GitHub Actions — restrict permissions per workflow
permissions:
  contents: read           # default: read only
  id-token: write          # only if OIDC needed
  packages: write          # only if pushing to GHCR
  # deployments: write     # add only if this workflow deploys
```

---

## Artifact Integrity

```bash
# Sign artifacts with sigstore/cosign (container images)
cosign sign --key cosign.key $IMAGE_DIGEST

# Verify before deployment
cosign verify --key cosign.pub $IMAGE

# Generate SLSA provenance (GitHub Actions)
# Use slsa-framework/slsa-github-generator action
# Produces verifiable build provenance attestation
```

---

## CI/CD Security Checklist

- [ ] No secrets hardcoded in pipeline YAML or buildspec files
- [ ] Long-lived access keys replaced with OIDC role assumption
- [ ] Pipeline roles follow least privilege; separate roles per environment
- [ ] Prod deployment requires manual approval gate
- [ ] Third-party actions pinned to commit SHA, not mutable tag
- [ ] `permissions:` block in GitHub Actions workflows set to minimum required
- [ ] Secrets masked in logs (`::add-mask::` or platform equivalent)
- [ ] `set -x` not used in scripts that handle secrets
- [ ] Fork PRs do not have access to repo secrets
- [ ] Dependency audit runs on every PR
- [ ] Container images signed and signature verified before deployment
