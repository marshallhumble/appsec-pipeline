# CSRF & Request Integrity

Cross-site request forgery (CSRF) tricks an authenticated user's browser into making
a state-changing request to your application from a different origin. The browser
automatically includes the session cookie, so the request appears legitimate.

CSRF only affects state-changing operations (POST, PUT, PATCH, DELETE). Read-only
GET requests should have no side effects and are not a CSRF target — but they often
become one when developers put state changes on GET endpoints.

Load `references/lang/<lang>.md` for framework-specific CSRF middleware patterns.

---

## How CSRF Works

1. User is logged in to `bank.example.com` with a session cookie
2. User visits `evil.example.com` (in another tab)
3. Evil page contains: `<img src="https://bank.example.com/transfer?to=attacker&amount=1000">`
   or a hidden form that auto-submits
4. Browser sends the request to `bank.example.com` — with the session cookie
5. Bank processes the transfer because the cookie is valid

The attack requires no XSS and no credential theft. A valid session cookie is enough.

---

## Primary Defenses

Use one of these. They are not all required simultaneously — pick the one that fits
your architecture.

### 1. SameSite Cookie Attribute (Preferred for most apps)

Set `SameSite=Strict` or `SameSite=Lax` on the session cookie.

```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

- **`SameSite=Strict`:** Cookie never sent on cross-site requests. Strongest protection.
  Side effect: cookie not sent when user navigates to your site from an external link
  (e.g., clicking a link in email). Usually acceptable for API sessions.
- **`SameSite=Lax`:** Cookie sent on top-level navigations (link clicks) but not on
  sub-resource requests (images, iframes, fetch from other origin). Weaker but more
  user-friendly. Default in modern browsers if not specified.
- **`SameSite=None`:** Explicitly opts out; requires `Secure`. Required for cross-site
  embeds (iframes, third-party widgets). Leaves CSRF protection entirely to tokens.

`SameSite` alone is sufficient for most first-party web apps. It requires no changes
to form handling or JavaScript. Not sufficient when you need cross-site cookie delivery
(e.g., embedded iframes, OAuth flows, third-party integrations).

### 2. Synchronizer Token Pattern (CSRF Tokens)

Generate a random token per session (or per form), store it server-side, embed it in
every state-changing form and AJAX request, verify it on the server before processing.

```
Token requirements:
- At least 128 bits from a CSPRNG
- Unique per session (minimum); ideally per request
- Verified server-side via constant-time comparison
- Never transmitted in URL parameters (logged in access logs)
- Transmitted in: hidden form field, custom request header (X-CSRF-Token), or cookie
  read by JavaScript (readable because JS can access the same-origin cookie)
```

Used by: Django (`{% csrf_token %}`), Rails (`protect_from_forgery`),
ASP.NET Core (`[ValidateAntiForgeryToken]`), Spring Security.

### 3. Double Submit Cookie

Set a random token as a cookie AND require the same value in a request header or body
parameter. The server verifies they match. Works because attackers can read the URL
and headers they set, but cannot read `SameSite` cookies from your origin.

Weaker than synchronizer tokens if the attacker can set cookies (subdomain takeover,
cookie tossing). Use synchronizer tokens when possible.

### 4. Custom Request Header (for APIs)

Require a custom header (e.g., `X-Requested-With: XMLHttpRequest`). Cross-origin
requests cannot set custom headers without a CORS preflight, which the browser blocks
unless the server explicitly allows it.

Sufficient for API endpoints consumed only by your own JavaScript — not for
form-based endpoints where the browser submits without custom headers.

---

## CORS and CSRF Relationship

CORS restricts which origins can *read* cross-origin responses. It does not prevent
the browser from *sending* state-changing requests — a POST with a session cookie
will be sent even without CORS permission; the browser just won't let JavaScript read
the response.

Therefore: CORS does not protect against CSRF. Tight CORS configuration reduces the
attacker's ability to exfiltrate data, but a CSRF attack can succeed even when CORS
is locked down.

**Audit point:** `Access-Control-Allow-Origin: *` on endpoints that accept cookies or
Authorization headers is a misconfiguration — it exposes cross-origin reads. Use
specific origins with `Access-Control-Allow-Credentials: true` where needed.

---

## State-Changing GET Requests

GET requests must never have side effects. If a GET endpoint modifies data, deletes
records, sends email, or changes state in any way, it is CSRF-vulnerable regardless
of any token scheme — because tokens are typically not verified on GET requests.

Common examples of state-changing GETs to eliminate:
- `GET /users/{id}/delete`
- `GET /email/unsubscribe?token=...` (token here is for identity, not CSRF)
- `GET /cart/add?item=123`
- `GET /admin/approve?request=456`

Move all state changes to POST, PUT, PATCH, or DELETE.

---

## CSRF in APIs

REST APIs consumed by mobile apps or other backend services typically use bearer
tokens (JWT, API key) in the `Authorization` header rather than cookies. CSRF does
not apply to these — browsers do not automatically include `Authorization` headers
on cross-origin requests.

CSRF applies only when authentication depends on a cookie that the browser sends
automatically. If your API uses `Authorization: Bearer <token>` exclusively and
does not use session cookies, you do not need CSRF tokens.

If your API supports both cookie-based sessions (for browser clients) and bearer
tokens (for API clients), apply CSRF protection to the cookie-based paths only.

---

## CSRF Review Checklist

- [ ] Session cookie has `SameSite=Strict` or `SameSite=Lax`
- [ ] All state-changing endpoints use POST/PUT/PATCH/DELETE (no state-changing GETs)
- [ ] CSRF tokens verified on all state-changing form submissions (if using token pattern)
- [ ] CSRF middleware not disabled on any route that changes state
- [ ] CORS `Access-Control-Allow-Origin` not set to `*` on credentialed endpoints
- [ ] API endpoints using bearer tokens confirmed not relying on cookies for auth
- [ ] Logout endpoint protected (CSRF logout forces session termination)
