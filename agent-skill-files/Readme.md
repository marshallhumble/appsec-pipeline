# AI Agent Security Configuration Files

Security-focused skills files and agent configuration for .NET/C#
development in a HIPAA healthcare environment. Drop the appropriate
file into your repository root based on which coding agent your
team uses.

## File Reference

| File | Agent | Location in repo |
|------|-------|-----------------|
| `CLAUDE.md` | Claude Code | Repository root |
| `.cursorrules` | Cursor | Repository root |
| `copilot-instructions.md` | GitHub Copilot | `.github/copilot-instructions.md` |
| `.windsurfrules` | Windsurf | Repository root |
| `AGENTS.md` | OpenAI Codex, generic agents | Repository root |

## Placement

```
your-repo/
├── .github/
│   └── copilot-instructions.md   ← GitHub Copilot
├── src/
├── AGENTS.md                      ← OpenAI Codex / generic
├── CLAUDE.md                      ← Claude Code
├── .cursorrules                   ← Cursor
└── .windsurfrules                 ← Windsurf
```

You can safely commit all files - agents only read the one they
recognize. Having all of them ensures coverage regardless of which
tool a developer uses.

## What These Files Do

Each file instructs the coding agent to:

1. Apply `[Authorize]` to all ASP.NET Core endpoints by default
2. Verify patient resource ownership server-side
3. Use Entity Framework LINQ - no raw SQL with string interpolation
4. Read secrets from IConfiguration / AWS Secrets Manager
5. Log events not data - no PHI in structured log fields
6. Return generic error messages to API clients
7. Avoid prohibited APIs: BinaryFormatter, MD5/SHA1, DES/3DES
8. Self-review generated code before returning it

## Important Limitations

These files reduce the rate of security violations in generated code.
They do not eliminate them. LLMs are non-deterministic and user
instructions can sometimes override agent configuration.

Your CI/CD security pipeline (Semgrep, SAST, dependency scanning)
remains the authoritative gate. These files are a shift-left control,
not a replacement for automated enforcement.

## Measuring Effectiveness

Run your Semgrep custom rules against 10 samples generated without
these files, then 10 with them. The delta in violation rate is your
baseline metric.

## Customization

Adapt the prohibited API list, naming conventions, and environment-
specific requirements to match your organization's standards. The
CLAUDE.md file is the most detailed and serves as the reference
version - use it as the template when customizing the others.

## Related

- Zero Budget AppSec series: CI/CD pipeline, custom Semgrep rules
- AI Secure Coding series: MCP attack surface, SBOM gaps,
  insecure output handling