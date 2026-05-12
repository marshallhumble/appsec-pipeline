# JavaScript & TypeScript — Security Patterns

Load alongside the relevant vulnerability reference file.
Covers Node.js backend (Express, Fastify, NestJS) and TypeScript equivalents.
Frontend-specific notes (DOM XSS, CSP) are at the end.

---

## SQL Injection

```typescript
// NEVER — string concatenation or template literals into queries
const result = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
const result = await db.query("SELECT * FROM users WHERE email = '" + email + "'");

// ALWAYS — pg (node-postgres) parameterized
const result = await pool.query(
    "SELECT * FROM users WHERE email = $1 AND active = $2",
    [email, true]
);

// ALWAYS — mysql2 parameterized
const [rows] = await connection.execute(
    "SELECT * FROM users WHERE email = ? AND active = ?",
    [email, true]
);

// ALWAYS — Prisma ORM (parameterized by construction)
const user = await prisma.user.findFirst({
    where: { email, active: true }
});

// ALWAYS — Prisma raw SQL must use tagged template (not string interpolation)
const users = await prisma.$queryRaw`
    SELECT * FROM users WHERE email = ${email}
`;
// NEVER with Prisma:
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);
```

**Escape hatches to avoid:**
- `pool.query("..." + variable)` — raw string bypasses parameterization
- Prisma `$queryRawUnsafe()` with any user-controlled value
- Knex `.raw("... " + variable)` — use `.raw("... ?", [variable])` instead
- TypeORM `query()` or `createQueryBuilder().where("field = " + value)`

---

## Command Injection

```typescript
import { execFile, spawn } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

// NEVER — exec() passes command to shell; user input can break out
import { exec } from "child_process";
exec(`convert ${filename} output.jpg`);           // shell injection
exec("grep " + userQuery + " /var/log/app.log");

// ALWAYS — execFile() with fixed binary path, arguments as array
await execFileAsync("/usr/bin/convert", [filename, "output.jpg"], {
    timeout: 10_000,
});

// ALWAYS — spawn() for streaming output
const proc = spawn("/bin/grep", ["--", userQuery, "/var/log/app.log"], {
    stdio: ["ignore", "pipe", "pipe"],
});
```

**Other dangerous sinks:**
- `eval(userInput)` — executes arbitrary JS
- `new Function(userInput)` — same as eval
- `vm.runInNewContext(userInput)` — sandbox escapes are well-documented
- `require(userInput)` — arbitrary module load
- `child_process.exec()` with any user-controlled content

---

## Secrets Management

```typescript
// NEVER — hardcoded in source
const apiKey = "sk-abc123";
const dbPassword = "hunter2";

// ACCEPTABLE — process.env (loaded from deployment environment or dotenv locally)
import "dotenv/config";  // local dev only; never commit .env

const dbPassword = process.env.DB_PASSWORD;
if (!dbPassword) throw new Error("DB_PASSWORD environment variable must be set");

// PREFERRED — AWS Secrets Manager
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({ region: "us-east-1" });
const response = await client.send(
    new GetSecretValueCommand({ SecretId: "prod/db/password" })
);
const secret = JSON.parse(response.SecretString!);
const dbPassword = secret.password;

// PREFERRED — Azure Key Vault
import { SecretClient } from "@azure/keyvault-secrets";
import { DefaultAzureCredential } from "@azure/identity";

const kvClient = new SecretClient(
    process.env.KEY_VAULT_URI!,
    new DefaultAzureCredential()
);
const secret = await kvClient.getSecret("db-password");
const dbPassword = secret.value!;
```

---

## Password Hashing

```typescript
import bcrypt from "bcrypt";
const ROUNDS = 12;

// Hash
const hashed = await bcrypt.hash(plainPassword, ROUNDS);

// Verify
const isValid = await bcrypt.compare(plainPassword, hashed);

// NEVER for passwords
import crypto from "crypto";
crypto.createHash("md5").update(password).digest("hex");   // fast hash — not for passwords
crypto.createHash("sha256").update(password).digest("hex");
```

---

## Symmetric Encryption (AES-256-GCM)

```typescript
import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";

function encrypt(plaintext: string, key: Buffer): string {
    const iv         = crypto.randomBytes(12);  // 96-bit nonce for GCM
    const cipher     = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted  = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag    = cipher.getAuthTag();
    // Store as: iv + authTag + ciphertext (all needed for decryption)
    return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

function decrypt(encoded: string, key: Buffer): string {
    const buf        = Buffer.from(encoded, "base64");
    const iv         = buf.subarray(0, 12);
    const authTag    = buf.subarray(12, 28);
    const ciphertext = buf.subarray(28);
    const decipher   = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    // Throws if tampered (authentication tag mismatch)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
```

---

## CSPRNG

```typescript
import crypto from "crypto";

// ALWAYS for tokens, session IDs, reset links, CSRF tokens
const token   = crypto.randomBytes(32).toString("hex");       // 256-bit hex
const tokenB64 = crypto.randomBytes(32).toString("base64url"); // URL-safe base64

// NEVER for security values
Math.random()                            // predictable
Math.floor(Math.random() * 1_000_000)   // predictable
```

---

## Constant-Time Comparison

```typescript
import crypto from "crypto";

// ALWAYS for token/hash comparison (prevents timing attacks)
const isValid = crypto.timingSafeEqual(
    Buffer.from(storedHash, "hex"),
    Buffer.from(computedHash, "hex")
);

// NEVER — short-circuits on first mismatch
const isValid = storedHash === submittedToken;
```

---

## Authentication & Authorization

```typescript
// JWT — always validate algorithm explicitly (prevents alg:none attack)
import jwt from "jsonwebtoken";

// Sign
const token = jwt.sign(
    { sub: userId },
    privateKey,
    { algorithm: "RS256", expiresIn: "15m", issuer: "api.example.com" }
);

// Verify — algorithms array is mandatory; never omit it
const payload = jwt.verify(token, publicKey, {
    algorithms: ["RS256"],   // explicit allowlist; rejects "none"
    issuer: "api.example.com",
    audience: "api.example.com",
}) as jwt.JwtPayload;

// Express auth middleware
function requireAuth(req: Request, res: Response, next: NextFunction) {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    try {
        const payload = jwt.verify(header.slice(7), publicKey, {
            algorithms: ["RS256"],
        }) as jwt.JwtPayload;
        res.locals.userId = payload.sub;
        next();
    } catch {
        res.status(401).json({ error: "Unauthorized" });
    }
}

// IDOR fix — always include ownership in the query
app.get("/documents/:id", requireAuth, async (req, res) => {
    const doc = await db.query(
        "SELECT * FROM documents WHERE id = $1 AND owner_id = $2",
        [req.params.id, res.locals.userId]
    );
    if (!doc.rows.length) return res.status(404).json({ error: "Not found" });
    res.json(doc.rows[0]);
});
```

---

## Mass Assignment

```typescript
// VULNERABLE — spreads entire req.body onto the update, including role/isAdmin
await User.findByIdAndUpdate(req.params.id, req.body);
await prisma.user.update({ where: { id }, data: req.body });

// CORRECT — destructure only safe fields
const { name, email, bio } = req.body as UpdateUserInput;
await prisma.user.update({
    where: { id, ownerId: res.locals.userId },
    data: { name, email, bio }
    // role, isAdmin never touched
});

// TypeScript: use a DTO type to make safe fields explicit
interface UpdateUserInput {
    name:  string;
    email: string;
    bio?:  string;
    // no role, no isAdmin
}
```

---

## Session Cookies (express-session)

```typescript
import session from "express-session";

app.use(session({
    secret:            process.env.SESSION_SECRET!,
    resave:            false,
    saveUninitialized: false,
    cookie: {
        httpOnly:  true,
        secure:    true,          // HTTPS only
        sameSite:  "strict",
        maxAge:    8 * 60 * 60 * 1000,  // 8 hours
    },
}));
```

---

## Security Headers (helmet)

```typescript
import helmet from "helmet";

// Applies: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
// X-XSS-Protection, and a default Content-Security-Policy
app.use(helmet());

// Custom CSP
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc:  ["'self'"],
            objectSrc:  ["'none'"],
            upgradeInsecureRequests: [],
        },
    })
);
```

---

## Rate Limiting (express-rate-limit)

```typescript
import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max:      10,
    message:  { error: "Too many login attempts; please try again later" },
    standardHeaders: true,
    legacyHeaders:   false,
});

app.post("/auth/login", loginLimiter, loginHandler);
```

---

## CSRF (csurf / double-submit cookie)

```typescript
// Express: use csurf middleware on state-changing routes
import csurf from "csurf";
const csrfProtection = csurf({ cookie: { httpOnly: true, sameSite: "strict" } });

app.post("/transfer", csrfProtection, transferHandler);

// OR: use SameSite=Strict on session cookie (see Session Cookies above)
// which makes CSRF tokens unnecessary for same-origin flows
```

---

## Frontend — DOM XSS

```typescript
// NEVER — sets innerHTML with user-controlled content
element.innerHTML = userContent;
document.write(userContent);

// ALWAYS — textContent for plain text (no HTML interpretation)
element.textContent = userContent;

// If you must render HTML: sanitize first with DOMPurify
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userContent);

// React — dangerouslySetInnerHTML requires sanitization
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
// Never:
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// NEVER — JavaScript URL injection
element.href = userUrl;           // attacker can use "javascript:alert(1)"
// ALWAYS — validate URL scheme before assignment
const url = new URL(userUrl);
if (url.protocol === "https:") element.href = url.toString();
```

---

## Logging — What Not to Log

```typescript
// DANGEROUS
logger.info(`Login: user=${username} password=${password}`);
logger.debug("Request body:", req.body);    // may contain tokens, card numbers

// SAFE
logger.info("Login attempt", { username, ip: req.ip });
// Never log: passwords, tokens, API keys, full request bodies, PII
```

---

## Dependency Auditing

```bash
npm audit --audit-level=moderate
npx audit-ci --moderate          # CI-friendly; exits non-zero on findings

# Semgrep with JS/TS rules
npx semgrep --config "p/javascript" .
npx semgrep --config "p/typescript" .

# Secret scanning
gitleaks detect --source=. --verbose
```
