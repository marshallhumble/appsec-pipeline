# Secrets Management & Cryptography

Load `references/lang/<lang>.md` for language-specific implementation patterns.
Load `references/cloud-aws.md` or `references/cloud-azure.md` for platform-specific
secrets management, KMS, and key rotation.

---

## Secrets Management

Secrets are machine credentials: API keys, database passwords, tokens, certificates,
connection strings, signing keys. They must never appear in source code, committed
config files, container image layers, or log output.

### Storage Hierarchy (Best to Worst)

1. **Managed secrets service:** AWS Secrets Manager, AWS SSM Parameter Store (SecureString),
   Azure Key Vault. Provides rotation, auditing, fine-grained access, automatic injection.
2. **Environment variables** injected at runtime by the platform (CI/CD, ECS task definition,
   Lambda environment, Kubernetes secrets). Not stored in code.
3. **`.env` file** in `.gitignore`. Acceptable for local dev only; never for any deployed
   environment.
4. **Encrypted secrets in version control** (SOPS, git-crypt). Acceptable with proper key
   management and a clear rotation process.
5. **Plaintext in any file committed to version control:** Never acceptable at any stage.

### Pre-commit Scanning
Add `gitleaks` or `truffleHog` as a pre-commit hook. Block commits containing
high-entropy strings or known secret patterns before they touch the repo.

If a secret is committed: rotate it immediately, then scrub it from history with
`git filter-repo` or BFG Repo Cleaner. Rotation before history scrub — the key
may already have been scraped.

---

## Password Hashing

Use a slow, memory-hard algorithm. Fast hashes (MD5, SHA-1, SHA-256) are designed
for speed; commodity hardware can brute-force them at billions of guesses per second.

**Algorithm preference:**
1. **Argon2id** — current best practice; PHC winner; memory-hard; resistant to
   both GPU and side-channel attacks
2. **bcrypt** (cost factor ≥ 12) — well-established; widely supported
3. **scrypt** — memory-hard; acceptable alternative
4. **PBKDF2** — acceptable only when FIPS 140 compliance is required; significantly
   weaker than the above for offline attack resistance

Never: MD5, SHA-1, SHA-256, SHA-512, unsalted hashes, or any home-grown scheme.

---

## Symmetric Encryption

Use **AES-256-GCM** for data at rest. GCM is authenticated encryption — it provides
confidentiality and integrity in one operation. Unauthenticated modes (ECB, CBC
without a separate HMAC) do not detect tampering.

**Key rules:**
- Never reuse a nonce with the same key (GCM catastrophically fails on nonce reuse)
- Generate nonces from a CSPRNG; 96 bits (12 bytes) for GCM
- Store the nonce alongside the ciphertext — it is not secret, only must be unique
- Alternatively: **ChaCha20-Poly1305** is a strong modern alternative to AES-GCM,
  preferred on platforms without hardware AES acceleration

---

## Asymmetric / Key Agreement

- **TLS:** minimum TLS 1.2; prefer TLS 1.3. Disable SSLv3, TLS 1.0, TLS 1.1.
  Prefer ECDHE cipher suites for forward secrecy.
- **Digital signatures:** Ed25519 or ECDSA P-256 for new code. RSA-2048 acceptable;
  prefer RSA-4096 for long-lived keys.
- **Key encapsulation:** use a well-tested library (libsodium, AWS KMS, Azure Key Vault
  managed HSM) rather than assembling primitives yourself.

Never implement your own cryptographic primitives.

---

## Cryptographically Secure Random Numbers (CSPRNG)

Use the platform's CSPRNG for all security-sensitive values: tokens, session IDs,
nonces, CSRF tokens, password reset links, API keys.

General-purpose random number generators (`Math.random()`, `System.Random`,
`math/rand`) are seeded predictably and must never be used for security values.
An attacker who can observe a few outputs can predict future outputs.

---

## Key Management Checklist

- [ ] Keys not hardcoded; loaded from secrets manager or environment
- [ ] Key rotation policy defined, documented, and tested
- [ ] Separate keys per environment (dev/staging/prod never share)
- [ ] Old keys retained only for decrypting legacy data, never for new encryption
- [ ] Key access is audited and alertable
- [ ] Exposed secrets are rotated before history scrub, within minutes of discovery
