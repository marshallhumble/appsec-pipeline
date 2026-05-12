# Injection Prevention

Injection was the OWASP Top 10 number-one risk for 20 years. When an attacker's
input is interpreted as code or a command, their payload runs with the same
permissions as the application process.

Load `references/lang/<lang>.md` alongside this file for language-specific patterns.

---

## SQL Injection

**The rule:** Never concatenate user-supplied values into a SQL string.
Use parameterized queries or an ORM's query builder. Every language and every
major database driver supports parameterization.

**ORM escape hatches to audit:** Even ORMs have raw-query methods that bypass
parameterization. These are the most common source of SQL injection in codebases
that otherwise use an ORM:
- C#: `FromSqlRaw()`/`ExecuteSqlRaw()` with string interpolation; Dapper `Execute()` with format strings
- Rust: `sqlx::query(&format!(...))` skipping `.bind()`; diesel `sql()` helper with user-controlled content
- Go: `db.Raw()`/`db.Exec()` with string concatenation; `fmt.Sprintf` into any query string
- Python: `cursor.execute()` with `%` or `.format()`; Django `.raw()` with format strings
- PowerShell: `Invoke-Sqlcmd` with string interpolation; ADO.NET `SqlCommand` without parameters

**Additional defenses (layered):**
- Database user has minimum required privileges (read-only for read operations)
- `LIMIT` clauses prevent mass disclosure if injection occurs
- WAF as an additional layer — not a primary control

---

## Command Injection

**The rule:** Never pass user-controlled input to a shell or subprocess execution
function as part of a command string. Use the argument-array form with a fixed,
fully-qualified executable path.

**Dangerous patterns to audit in any language:**
- Passing a shell interpreter (`sh`, `bash`, `cmd.exe`, `powershell.exe`) with
  a user-controlled `-c` / `/c` argument
- String interpolation or concatenation into any command string
- Using the user-supplied value as the executable name itself

**What "safe" looks like:** The executable path is a hardcoded constant. Each
argument is a separate item, not part of a shell string. Shell expansion (`*`, `;`,
`&&`, pipes) cannot occur because no shell interpreter is invoked.

---

## LDAP Injection

Escape special LDAP filter characters before use: `\ * ( ) NUL`.
Use your library's parameterized filter API where available.
Never build LDAP filter strings via string concatenation.

---

## XPath / XML Injection

Use parameterized XPath where the library supports it.
Never build XPath expressions via string concatenation.
For XML parsing, disable external entity resolution (XXE) — see `references/deserialization.md`.

---

## Template Injection

Server-side template injection occurs when user input is rendered as the template
itself rather than as a variable inside a template. Never pass user-controlled
strings as the template source to a rendering engine. Always pass user data as
template variables with auto-escaping active.

---

## Taint Tracing (Manual Review Technique)

For any suspicious value, trace it from source to sink:
1. Where does the value originate? (user input, DB, external API, file, env var)
2. Does it pass through validation before use?
3. Does it reach a dangerous sink (query, exec, render) parameterized or concatenated?

A value is safe only if it is either: (a) validated against an allowlist before use,
or (b) passed as a bound parameter — never interpolated.
