# Dependency & Supply Chain Security

Third-party code is the majority of most applications. A vulnerable dependency is
as exploitable as vulnerable code you wrote yourself — and you have less visibility
into it. Supply chain attacks (malicious packages, typosquatting, dependency
confusion) are an increasing vector.

---

## The Core Risks

**Known CVEs in dependencies:** A library version with a published CVE is directly
exploitable if the vulnerable code path is reachable. Attackers scan for these.

**Typosquatting:** `requets` instead of `requests`; `lodahs` instead of `lodash`.
Malicious packages with names similar to popular ones.

**Dependency confusion:** If your private package registry and the public registry
both have a package with the same name, some tools will pull the public (potentially
malicious) one. Affects npm, pip, NuGet, and cargo.

**Compromised maintainer accounts:** A legitimate package is taken over and a
malicious version published. Protestware (intentional sabotage by the author) is
also real.

**Transitive dependencies:** You audit your direct dependencies; you rarely audit
their dependencies, or their dependencies' dependencies. A vulnerability two levels
deep is still exploitable.

---

## Auditing Tools by Language

```bash
# C# / .NET
dotnet list package --vulnerable --include-transitive
# Retire.NET for client-side JS bundled in .NET projects
dotnet tool install -g retire.net && retire --path .

# Rust
cargo audit                     # RustSec advisory database
cargo deny check                # combines CVE check + license policy + duplicate detection

# Go
govulncheck ./...                # Go's official vulnerability scanner (uses Go vuln DB)

# Python
pip-audit                        # PyPA's official scanner
safety check -r requirements.txt # alternative

# JavaScript / TypeScript
npm audit --audit-level=moderate
npx audit-ci --moderate          # CI-friendly; exits non-zero on findings

# Container / cross-language
trivy fs .                       # scans lockfiles for all supported ecosystems
grype dir:.                      # alternative
```

Run these in CI on every PR, not just locally. A finding that blocks a PR is caught
before it ships; a finding in a scheduled scan may already be in production.

---

## Lock Files

Lock files record the exact resolved version of every dependency (direct and
transitive) at install time. They ensure reproducible builds and are essential for
security auditing.

**Always commit lock files:**
- `Cargo.lock` — Rust (commit for binaries; optional for libraries)
- `go.sum` — Go (always commit)
- `packages.lock.json` — .NET (enable with `RestorePackagesWithLockFile=true`)
- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` — Node.js
- `poetry.lock` / `Pipfile.lock` — Python

**Never use floating version ranges in production:**
- `^1.0.0`, `~1.0`, `>=1.0` can silently update to a compromised version
- Pin to exact versions in production; use Renovate or Dependabot to manage updates
  explicitly with a review step

---

## Dependency Confusion Prevention

If your team uses a private package registry (Artifactory, Azure Artifacts, AWS
CodeArtifact, GitHub Packages):

- **Scope all private packages** under a namespace that does not exist publicly
  (e.g., `@yourcompany/package-name` for npm; internal names for NuGet)
- **Configure the registry to prefer internal packages** over public ones for
  internal names
- **Use registry-specific lockfile features** — npm `overrides`, NuGet source
  mapping — to pin internal packages to the internal registry

```bash
# npm: .npmrc scoped to internal registry
@yourcompany:registry=https://your-registry.example.com/

# NuGet: packageSourceMapping in NuGet.Config
<packageSourceMapping>
  <packageSource key="nuget.org">
    <package pattern="*" />
  </packageSource>
  <packageSource key="internal">
    <package pattern="YourCompany.*" />
  </packageSource>
</packageSourceMapping>
```

---

## Reviewing New Dependencies

Before adding a dependency:

1. **Is it necessary?** Can you implement the needed functionality with a few lines
   of code, avoiding the dependency entirely?
2. **Is it maintained?** Last commit date, open issues, response to security reports.
3. **How many transitive dependencies does it add?** `npm why`, `cargo tree`,
   `go mod graph`. A single package that pulls in 50 others is higher risk.
4. **What permissions does it need?** A logging library that requests network access
   is suspicious.
5. **Is the publisher legitimate?** Check the package's history; typosquatting
   packages often have very recent creation dates and no prior releases.

---

## Automated Update Management

Manual dependency updates don't happen consistently. Use automation:

- **Dependabot** (GitHub) — creates PRs for vulnerable and outdated dependencies
- **Renovate** (self-hosted or cloud) — more configurable; supports grouping,
  scheduling, automerge for patch updates
- **Snyk** — combines SCA with fix PRs and a wider vulnerability database

Configure automerge for patch-level updates with passing tests. Require review for
minor and major updates. Never automerge if tests are failing.

---

## SBOM (Software Bill of Materials)

An SBOM is a machine-readable inventory of all components in your application.
Required by some customers, government contracts, and emerging regulation.

```bash
# Generate SBOM
# Rust
cargo cyclonedx                    # CycloneDX format

# .NET
dotnet CycloneDX <project>

# Go
cyclonedx-gomod mod -output bom.xml

# Node.js
npx @cyclonedx/cyclonedx-npm --output-format xml > bom.xml

# Container image
trivy image --format cyclonedx --output bom.json myimage:tag
syft myimage:tag -o cyclonedx-json > bom.json
```

---

## Supply Chain Review Checklist

- [ ] Lock files committed and up to date
- [ ] No floating version ranges (`^`, `~`, `>=`) in production dependencies
- [ ] Dependency audit tool runs in CI on every PR
- [ ] Private registry configured to prevent dependency confusion
- [ ] Renovate or Dependabot configured for automated update PRs
- [ ] New dependencies reviewed before adding (maintainer health, transitive deps, permissions)
- [ ] Container base images pinned to digest, not just tag
- [ ] SBOM generated and stored as build artifact
