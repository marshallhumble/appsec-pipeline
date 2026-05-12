# Authorization & Access Control

**Core rule:** Authenticate first. Authorize second. Check for every resource,
every action, every request — server-side, always.

Load `references/lang/<lang>.md` for framework-specific patterns (policy-based auth,
middleware, decorators). Load `references/cloud-aws.md` or `references/cloud-azure.md`
for IAM and RBAC patterns.

---

## Access Control Models

**RBAC (Role-Based):** Users → roles → permissions. Simplest to implement and audit.
Right for most applications.

**ABAC (Attribute-Based):** Decisions based on user attributes, resource attributes,
and environment. More flexible, more complex. Use when RBAC cannot express the policy.

**DAC (Discretionary):** Resource owners grant access to others. Used for
user-generated content and file sharing.

Start with RBAC. Extend to ABAC only if needed.

---

## Insecure Direct Object Reference (IDOR)

IDOR occurs when a user accesses another user's resource by guessing or manipulating
an ID in a URL parameter, path variable, or request body.

**The check that must always be present:**
```
resource = load(id)
if resource.owner_id != current_user.id:
    return 404   # not 403 — don't confirm the resource exists
```

Return 404, not 403, when a user accesses a resource they don't own. Returning 403
confirms the resource exists, enabling enumeration attacks.

Using non-sequential UUIDs as IDs is defense-in-depth — it makes guessing harder.
It is not a substitute for the ownership check.

---

## Centralize Authorization Logic

Decentralized authorization (each handler checks its own permissions) fails when
one handler is missed. One missing check equals a vulnerability.

**Prefer:**
- Middleware or decorators that enforce authentication before any handler runs
- Policy/permission objects that encapsulate authorization logic for a resource type
- A central authorization service or library all endpoints call

The goal: it should be impossible to add a new endpoint without authorization
being applied by default.

---

## Privilege Escalation Patterns to Check

1. **Role-elevation via parameter:** Can a user send `role=admin` in a request body
   and have it accepted?
2. **Horizontal escalation (IDOR):** Can user A access user B's resources?
3. **Forced browsing:** Are admin-only routes enforced server-side, or just hidden
   from the navigation?
4. **Mass assignment:** Does a `PUT /users/{id}` accept a `role` or `isAdmin` field
   the user should not be able to set?
5. **Missing auth on new endpoints:** Are newly added endpoints automatically protected
   by the auth middleware, or do they default to public?

---

## Mass Assignment

Occurs when a framework binds all request fields to a model, including fields that
should not be user-settable (role, isAdmin, accountBalance, ownerId).

**Fix:** Use a dedicated input DTO/struct that only exposes safe fields. Never bind
directly from the request to a domain model or database entity. See
`references/lang/<lang>.md` for framework-specific patterns.

---

## Cloud IAM Principles

Apply least privilege to all cloud roles and policies. See `references/cloud-aws.md`
or `references/cloud-azure.md` for specifics. General rules:

- Services get their own IAM role with only the permissions they need
- No wildcard `*` on actions or resources in production policies
- No hardcoded long-lived access keys in code or environment — use instance roles,
  Managed Identity, or workload identity federation
- Regularly audit and rotate credentials; remove unused roles and users
- Separate roles for separate environments (dev/staging/prod never share credentials)
