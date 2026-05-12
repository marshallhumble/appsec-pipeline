# XSS & Output Encoding

Cross-site scripting (XSS) occurs when an attacker's input is rendered in a browser
as executable script rather than data. It is the most common class of web vulnerability
and enables session theft, credential harvesting, and full account takeover.

Load `references/lang/<lang>.md` for framework-specific encoding patterns and CSP headers.

---

## The Core Rule

**Every value from an untrusted source must be encoded for the context it will appear in.**

Context determines the correct encoding. The same value requires different treatment
depending on where it lands in the output:

| Output context | What can go wrong | Required defense |
|---------------|-------------------|-----------------|
| HTML body (`<p>VALUE</p>`) | `<script>` tags execute | HTML entity encoding |
| HTML attribute (`href="VALUE"`) | Event handlers, JS URLs | Attribute encoding + URL validation |
| JavaScript (`var x = "VALUE"`) | String breakout, code injection | JavaScript string encoding |
| CSS (`color: VALUE`) | Expression injection (IE legacy) | CSS encoding |
| URL parameter (`?q=VALUE`) | Parameter injection | `encodeURIComponent()` |
| URL itself (`href=VALUE`) | `javascript:` scheme | Scheme allowlist (`https:` only) |

Using the wrong encoding for the context — or encoding once for the wrong context —
does not prevent XSS.

---

## Framework Auto-Escaping

Modern templating engines HTML-encode variables by default. This is the primary
defense and should never be disabled for user-controlled content.

**The bypass patterns to audit:**

- **Go:** `html/template` auto-encodes; `text/template` does not — check imports
- **Rust (askama, tera, minijinja):** auto-encode by default; `|safe` filter bypasses it
- **C# Razor:** `@value` auto-encodes; `@Html.Raw(value)` does not — search for `Html.Raw`
- **Python Django:** `{{ value }}` auto-encodes; `{{ value|safe }}` and `mark_safe()` do not
- **Python Jinja2:** auto-encode when `autoescape=True`; `|safe` and `Markup()` bypass it
- **JavaScript React:** JSX auto-encodes; `dangerouslySetInnerHTML` does not
- **JavaScript (server-side templates):** varies by engine; Handlebars `{{{ }}}` is unescaped

Any use of a bypass (`Html.Raw`, `|safe`, `mark_safe`, `dangerouslySetInnerHTML`,
triple-brace) with user-controlled content is a finding. Check every occurrence.

---

## Stored vs Reflected vs DOM XSS

**Stored XSS:** Payload saved to the database; rendered when any user views it.
Highest impact — affects all users, persists indefinitely.

**Reflected XSS:** Payload in the request (URL param, form field); rendered in the
immediate response. Requires tricking the user into clicking a crafted link.

**DOM XSS:** Payload never touches the server; JavaScript reads it from the URL or
storage and writes it to the DOM unsafely. Server-side encoding does not help —
the JavaScript itself must encode before writing to the DOM.

DOM XSS sinks to audit in frontend code:
- `element.innerHTML = ...`
- `element.outerHTML = ...`
- `document.write(...)`
- `document.writeln(...)`
- `element.insertAdjacentHTML(...)`
- `eval(...)`, `new Function(...)`, `setTimeout("string")`, `setInterval("string")`
- `element.href = ...` (JavaScript URL injection)
- `element.src = ...` (script/iframe src injection)

DOM XSS sources (attacker-controlled values that reach sinks):
- `location.hash`, `location.search`, `location.href`
- `document.referrer`
- `window.name`
- `postMessage` data
- `localStorage`, `sessionStorage` (if populated from URL)

---

## Sanitization (When You Must Accept HTML)

If the feature genuinely requires accepting and rendering HTML from users (rich text
editor, markdown-to-HTML), sanitize with a well-tested allowlist library — never
attempt to strip tags with regex.

- **Browser (JS):** DOMPurify — `DOMPurify.sanitize(userHtml)`
- **Server-side (C#):** HtmlSanitizer NuGet package
- **Server-side (Python):** bleach — `bleach.clean(userHtml, tags=[...], attributes={...})`
- **Server-side (Go):** bluemonday — `p.Sanitize(userHtml)`
- **Server-side (Rust):** ammonia — `ammonia::clean(userHtml)`

Stripping `<script>` tags with regex is not sanitization. Event handlers (`onerror`,
`onload`), JavaScript URLs (`href="javascript:..."`), and CSS expressions can all
execute script without a `<script>` tag.

---

## Content Security Policy (CSP)

CSP is a defence-in-depth HTTP header that restricts what the browser will execute,
reducing the impact of any XSS that slips through.

**Minimum effective CSP:**
```
Content-Security-Policy:
  default-src 'self';
  script-src  'self';
  object-src  'none';
  base-uri    'self';
  upgrade-insecure-requests;
```

**What each directive does:**
- `default-src 'self'` — block all resources not from your own origin by default
- `script-src 'self'` — block inline scripts and scripts from other origins
- `object-src 'none'` — block Flash and plugins (common XSS vector)
- `base-uri 'self'` — prevent `<base>` tag injection hijacking relative URLs
- `upgrade-insecure-requests` — force HTTP resources to HTTPS

**Avoid in CSP:**
- `unsafe-inline` — allows inline `<script>` tags and event handlers; defeats most of CSP's value
- `unsafe-eval` — allows `eval()` and `new Function()`; required by some frameworks but weakens protection
- Wildcard sources (`*`, `https:`) — allow loading from any origin

**Report-only mode for rollout:**
```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```
Deploy in report-only first to find violations before blocking.

---

## URL Validation

Before using a user-supplied URL in an `href`, `src`, `action`, or redirect:

1. Parse with the platform's URL library
2. Verify the scheme is in an allowlist (`https:` only for external links;
   add `http:` only if genuinely needed)
3. Never allow `javascript:`, `data:`, `vbscript:`, or `blob:` in URL fields

```
NEVER: element.href = userUrl
NEVER: res.redirect(req.query.next)

CORRECT:
  const url = new URL(userUrl);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("Invalid URL scheme");
  element.href = url.toString();

CORRECT for redirects:
  const allowed = ["/dashboard", "/profile", "/settings"];
  const next = req.query.next;
  res.redirect(allowed.includes(next) ? next : "/dashboard");
```

---

## XSS Review Checklist

- [ ] All template engines using auto-escaping by default
- [ ] Every `Html.Raw`, `|safe`, `mark_safe`, `dangerouslySetInnerHTML`, `{{{ }}}` audited
- [ ] DOM XSS sinks (`innerHTML`, `document.write`, `eval`) checked for untrusted sources
- [ ] User-supplied HTML sanitized with allowlist library, not regex
- [ ] CSP header set on all responses
- [ ] User-supplied URLs validated for scheme before use in `href`/`src`/redirect
- [ ] `Content-Type` header set correctly on all responses (prevents MIME sniffing XSS)
- [ ] `X-Content-Type-Options: nosniff` header set
