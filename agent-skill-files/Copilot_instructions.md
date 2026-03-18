# GitHub Copilot Security Instructions

This repository is a HIPAA-regulated healthcare application in .NET/C#.
Apply the following security requirements to all code suggestions.

## Required Controls

**Authorization**: Every ASP.NET Core controller action must have
[Authorize] unless [AllowAnonymous] is explicitly applied. Always
verify that the requesting user owns the patient resource being accessed.
Never trust a client-supplied patient ID as authorization.

**Data access**: Use Entity Framework LINQ. Never build SQL queries
using string interpolation or concatenation. ExecuteSqlRaw requires
parameterized inputs.

**Secrets**: All connection strings and API keys via IConfiguration
binding to AWS Secrets Manager. Never hardcode credentials.

**Logging**: Log events not data. Never include patient IDs, SSNs,
diagnosis codes, PHI, emails, or credentials in log statements.

**Errors**: Return generic error messages to clients. Never surface
stack traces, SQL, or internal paths in API responses.

## Prohibited

- BinaryFormatter: use System.Text.Json
- MD5/SHA1 for security: use SHA256 minimum
- DES/3DES: use AES-256
- String interpolation in SQL
- Hardcoded secrets of any kind

## Verification

Before completing a suggestion, verify these controls are present.
If a requirement cannot be met, surface this rather than silently
omitting the control.