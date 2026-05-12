# Go — Security Patterns

Load alongside the relevant vulnerability reference file.

---

## SQL Injection

```go
// NEVER — string concatenation or fmt.Sprintf into query
db.QueryRow("SELECT * FROM users WHERE email = '" + email + "'")
db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email))

// ALWAYS — positional placeholder (PostgreSQL: $1, MySQL/SQLite: ?)
row := db.QueryRowContext(ctx,
    "SELECT id, email FROM users WHERE email = $1 AND active = $2",
    email, true)

// ALWAYS — GORM struct condition (parameterized)
db.Where(&User{Email: email, Active: true}).First(&user)
db.Where("email = ? AND active = ?", email, true).First(&user)

// ALWAYS — sqlc generated code is parameterized by construction
user, err := queries.GetUserByEmail(ctx, email)
```

**Escape hatches to avoid:**
- `db.Raw("... " + userInput)` — raw string is not parameterized
- `db.Exec(fmt.Sprintf(...))` — fmt.Sprintf bypasses placeholders
- GORM: `db.Where("email = '" + email + "'")` — raw string in Where

---

## Command Injection

```go
// NEVER — shell interpreter with user input
exec.Command("sh", "-c", "grep " + userQuery + " /var/log/app.log")
exec.Command("bash", "-c", fmt.Sprintf("convert %s output.jpg", filename))

// ALWAYS — fixed binary, arguments as separate values
cmd := exec.CommandContext(ctx, "/bin/grep", "--", userQuery, "/var/log/app.log")
cmd.Stdout = os.Stdout
err := cmd.Run()
```

---

## Secrets Management

```go
// NEVER
const dbPassword = "hunter2"

// ACCEPTABLE — environment variable
dbPassword := os.Getenv("DB_PASSWORD")
if dbPassword == "" {
    log.Fatal("DB_PASSWORD not set")
}

// PREFERRED — AWS Secrets Manager
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)
cfg, _    := config.LoadDefaultConfig(ctx)
client    := secretsmanager.NewFromConfig(cfg)
result, _ := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
    SecretId: aws.String("prod/db/password"),
})
dbPassword := aws.ToString(result.SecretString)
```

---

## Password Hashing

```go
import "golang.org/x/crypto/bcrypt"

// Hash — cost 12 minimum
hashed, err := bcrypt.GenerateFromPassword([]byte(plainPassword), 12)

// Verify — nil means valid
err = bcrypt.CompareHashAndPassword(hashed, []byte(plainPassword))
isValid := err == nil
```

---

## Symmetric Encryption (AES-256-GCM)

```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
)

// Key must come from a secrets manager, not be hardcoded
key := make([]byte, 32)
rand.Read(key)

block, _ := aes.NewCipher(key)
gcm, _   := cipher.NewGCM(block)

// Encrypt — prepend nonce to ciphertext for storage
nonce := make([]byte, gcm.NonceSize())
io.ReadFull(rand.Reader, nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

// Decrypt — returns error if tampered
nonce, ciphertext = ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
```

---

## CSPRNG

```go
import (
    "crypto/rand"
    "encoding/hex"
)

// ALWAYS for security tokens, session IDs, reset links
tokenBytes := make([]byte, 32)
rand.Read(tokenBytes)
token := hex.EncodeToString(tokenBytes)

// NEVER for security values
import "math/rand"
token := rand.Int63()  // predictable — seeded from system time
```

---

## Constant-Time Comparison

```go
import "crypto/subtle"

// ALWAYS for token/hash comparison
isValid := subtle.ConstantTimeCompare(
    []byte(storedHash),
    []byte(computedHash),
) == 1

// NEVER — short-circuits on first mismatch, leaks length/content via timing
isValid := storedHash == submittedToken
```

---

## Authentication & Authorization

```go
// Auth middleware applied to a route group
protected := r.Group("/api")
protected.Use(AuthMiddleware)

func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, err := validateJWT(r.Header.Get("Authorization"))
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// JWT verification — always validate signing method (prevents alg=none attacks)
import "github.com/golang-jwt/jwt/v5"

token, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) {
    if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return publicKey, nil
}, jwt.WithIssuer("api.example.com"), jwt.WithExpirationRequired())

// IDOR fix — always include ownership in the query
func getDocument(w http.ResponseWriter, r *http.Request) {
    docID  := chi.URLParam(r, "docID")
    userID := r.Context().Value(userIDKey).(int64)
    var doc Document
    result := db.Where("id = ? AND owner_id = ?", docID, userID).First(&doc)
    if errors.Is(result.Error, gorm.ErrRecordNotFound) {
        http.NotFound(w, r)  // 404, not 403
        return
    }
    json.NewEncoder(w).Encode(doc)
}
```

---

## Mass Assignment

```go
// VULNERABLE — decodes full request body into User including Role
var user User
json.NewDecoder(r.Body).Decode(&user)

// CORRECT — decode into struct with only safe fields
type UpdateUserInput struct {
    Name  string `json:"name"`
    Email string `json:"email"`
    Bio   string `json:"bio"`
    // Role, IsAdmin absent — cannot be set via this endpoint
}
var input UpdateUserInput
json.NewDecoder(r.Body).Decode(&input)
```

---

## Session Cookies (gorilla/sessions)

```go
store := sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
store.Options = &sessions.Options{
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
    MaxAge:   8 * 3600,
}
```

---

## Security Headers

```go
import "github.com/unrolled/secure"

sm := secure.New(secure.Options{
    STSSeconds:           31536000,
    STSIncludeSubdomains: true,
    FrameDeny:            true,
    ContentTypeNosniff:   true,
    ContentSecurityPolicy: "default-src 'self'",
    ReferrerPolicy:       "strict-origin-when-cross-origin",
})
mux.Use(sm.Handler)
```

---

## Rate Limiting (golang.org/x/time/rate)

```go
import "golang.org/x/time/rate"

// Per-IP limiters — use sync.Map keyed by IP in production
limiter := rate.NewLimiter(rate.Every(15*time.Minute/10), 10)

func RateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "Too many requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

---

## HTML Output

```go
// ALWAYS — html/template auto-encodes variables
import "html/template"
tmpl := template.Must(template.ParseFiles("page.html"))
tmpl.Execute(w, data)   // data.UserName etc. are encoded automatically

// NEVER for HTML output
import "text/template"  // no auto-encoding; XSS if user data is rendered
```

---

## Logging — What Not to Log

```go
// DANGEROUS
log.Printf("Login: user=%s password=%s", username, password)
log.Printf("Request body: %+v", requestStruct)  // may contain tokens

// SAFE
log.Printf("Login attempt: username=%s ip=%s", username, r.RemoteAddr)
// Never log: passwords, tokens, API keys, PII, full request bodies
```

---

## Dependency Auditing

```bash
govulncheck ./...        # Go's official vulnerability scanner
go list -m -json all | nancy  # alternative CVE check
trivy fs .               # broad filesystem scan
```
