# Rust — Security Patterns

Load alongside the relevant vulnerability reference file.

---

## SQL Injection

```rust
// NEVER — format! into query string
sqlx::query(&format!("SELECT * FROM users WHERE email = '{}'", email)).fetch_one(&pool).await?;

// ALWAYS — sqlx with .bind()
let user = sqlx::query_as::<_, User>(
    "SELECT * FROM users WHERE email = $1 AND active = $2"
)
.bind(&email)
.bind(true)
.fetch_optional(&pool)
.await?;

// ALWAYS — diesel query builder (parameterized by construction)
use schema::users::dsl::*;
let user = users
    .filter(email.eq(&user_email))
    .filter(active.eq(true))
    .first::<User>(&mut conn)?;
```

**Escape hatches to avoid:**
- `sqlx::query(&format!(...))` — skips bind parameters
- `diesel::sql()` helper with user-controlled string content
- `diesel::dsl::sql()` with interpolated values

---

## Command Injection

```rust
// NEVER — shell interpreter with user input
std::process::Command::new("sh")
    .arg("-c")
    .arg(format!("convert {} output.jpg", filename))
    .output()?;

// ALWAYS — fixed binary, separate arguments
std::process::Command::new("/usr/bin/convert")
    .arg(&filename)
    .arg("output.jpg")
    .stdout(Stdio::piped())
    .output()?;
```

---

## Secrets Management

```rust
// NEVER
let api_key = "sk-abc123";

// ACCEPTABLE — environment variable; wrap in Secret to prevent logging
use secrecy::{Secret, ExposeSecret};
let db_password = Secret::new(
    std::env::var("DB_PASSWORD").expect("DB_PASSWORD must be set")
);
// Only call .expose_secret() where the value is actually needed

// PREFERRED — AWS Secrets Manager via aws-sdk-secretsmanager
let config = aws_config::load_from_env().await;
let client = aws_sdk_secretsmanager::Client::new(&config);
let resp   = client.get_secret_value()
    .secret_id("prod/db/password")
    .send().await?;
let secret = Secret::new(resp.secret_string().unwrap_or_default().to_string());
```

**Always wrap secrets in `secrecy::Secret<T>`.** Its `Debug` and `Display` impls
print `[REDACTED]`, preventing accidental logging via `{:?}` or `{}`.

---

## Password Hashing

```rust
// PREFERRED — argon2 crate
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString, PasswordHash};

let salt   = SaltString::generate(&mut OsRng);
let argon2 = Argon2::default();  // Argon2id, recommended params
let hash   = argon2.hash_password(plain_password.as_bytes(), &salt)?.to_string();

// Verify
let parsed = PasswordHash::new(&hash)?;
let valid  = argon2.verify_password(plain_password.as_bytes(), &parsed).is_ok();

// ALTERNATIVE — bcrypt crate
let hash  = bcrypt::hash(plain_password, 12)?;
let valid = bcrypt::verify(plain_password, &hash)?;
```

---

## Symmetric Encryption (AES-256-GCM)

```rust
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore}
};

// Generate key — store in secrets manager, not in code
let key    = Aes256Gcm::generate_key(&mut OsRng);
let cipher = Aes256Gcm::new(&key);

// Encrypt — nonce must be unique per message with same key
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
let nonce      = Nonce::from_slice(&nonce_bytes);
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
// Store: nonce_bytes + ciphertext

// Decrypt — returns Err if tampered (authentication tag mismatch)
let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
```

---

## CSPRNG

```rust
use rand::{rngs::OsRng, RngCore};

// ALWAYS for security tokens
let mut token_bytes = [0u8; 32];
OsRng.fill_bytes(&mut token_bytes);
let token = hex::encode(token_bytes);

// NEVER for security values
use rand::Rng;
let token = rand::thread_rng().gen::<u64>(); // predictable under observation
```

---

## Constant-Time Comparison

```rust
// ALWAYS for token/hash comparison (prevents timing attacks)
use subtle::ConstantTimeEq;
let valid: bool = stored_hash.as_bytes()
    .ct_eq(computed_hash.as_bytes())
    .into();

// NEVER — short-circuits on first mismatch
let valid = stored_hash == submitted_token;
```

---

## Authentication & Authorization (axum)

```rust
// Middleware: authenticate all routes in the protected group
async fn require_auth(
    State(pool): State<PgPool>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token  = extract_bearer(&req).ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = validate_jwt(&token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(AuthUser { id: claims.sub });
    Ok(next.run(req).await)
}

let app = Router::new()
    .route("/documents/:id", get(get_document))
    .layer(middleware::from_fn_with_state(pool.clone(), require_auth));

// IDOR fix — always include ownership in the query
async fn get_document(
    Path(doc_id): Path<i64>,
    Extension(user): Extension<AuthUser>,
    State(pool): State<PgPool>,
) -> impl IntoResponse {
    sqlx::query_as::<_, Document>(
        "SELECT * FROM documents WHERE id = $1 AND owner_id = $2"
    )
    .bind(doc_id)
    .bind(user.id)
    .fetch_optional(&pool).await
    .map(|opt| opt.map_or(StatusCode::NOT_FOUND.into_response(),
                          |d| Json(d).into_response()))
}
```

---

## Mass Assignment

```rust
// VULNERABLE — deserializes full User struct including role
async fn update_user(Json(user): Json<User>) -> impl IntoResponse { ... }

// CORRECT — dedicated input type with only safe fields
#[derive(Deserialize)]
struct UpdateUserInput {
    name:  String,
    email: String,
    bio:   Option<String>,
    // no role, no is_admin, no owner_id
}
async fn update_user(
    Path(id): Path<i64>,
    Extension(user): Extension<AuthUser>,
    Json(input): Json<UpdateUserInput>,
) -> impl IntoResponse { ... }
```

---

## Session Cookies (tower-sessions)

```rust
let session_layer = SessionManagerLayer::new(store)
    .with_secure(true)
    .with_http_only(true)
    .with_same_site(SameSite::Strict)
    .with_expiry(Expiry::OnInactivity(Duration::hours(8)));
```

---

## Rate Limiting (tower-governor)

```rust
use tower_governor::{GovernorLayer, GovernorConfigBuilder};

let config = Arc::new(
    GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(10)
        .finish().unwrap()
);

let app = Router::new()
    .route("/auth/login", post(login))
    .layer(GovernorLayer { config });
```

---

## unsafe Blocks

Every `unsafe` block that handles untrusted input is a security boundary:
- Document the invariant being upheld above the block
- Review for: out-of-bounds access, integer overflow before indexing, pointer
  aliasing, uninitialized memory, lifetime violations
- Prefer safe abstractions; `unsafe` in hot paths processing external data warrants
  a dedicated security review

---

## Logging — What Not to Log

```rust
// DANGEROUS — Secret<T> prevents this, but plain String does not
println!("{:?}", config_with_api_key);   // logs key if not wrapped

// SAFE — secrecy::Secret prints [REDACTED] in Debug/Display
use secrecy::Secret;
let api_key = Secret::new(std::env::var("API_KEY")?);
println!("{:?}", api_key);  // prints: Secret([REDACTED])
```

---

## Dependency Auditing

```bash
cargo audit              # CVEs from RustSec advisory database
cargo outdated           # stale dependencies (informational)
cargo deny check         # license and advisory policy enforcement
```
