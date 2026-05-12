# C# / ASP.NET Core — Security Patterns

Load alongside the relevant vulnerability reference file.

---

## SQL Injection

```csharp
// NEVER — string interpolation or concatenation
var cmd = new SqlCommand($"SELECT * FROM users WHERE email = '{email}'", conn);
db.Users.FromSqlRaw($"SELECT * FROM users WHERE email = '{email}'");

// ALWAYS — Dapper named parameters
var user = conn.QuerySingleOrDefault<User>(
    "SELECT * FROM users WHERE email = @Email AND active = @Active",
    new { Email = email, Active = true });

// ALWAYS — SqlCommand parameters
var cmd = new SqlCommand("SELECT * FROM users WHERE email = @Email", conn);
cmd.Parameters.AddWithValue("@Email", email);

// ALWAYS — EF Core LINQ (parameterized by construction)
var user = await db.Users
    .Where(u => u.Email == email && u.Active)
    .FirstOrDefaultAsync();

// ALLOWED — EF Core raw SQL with positional placeholder (not interpolated)
var users = db.Users.FromSqlRaw("SELECT * FROM users WHERE email = {0}", email);
```

**ORM escape hatches to avoid:**
- `FromSqlRaw($"...{variable}...")` — interpolation bypasses parameterization
- `ExecuteSqlRaw($"...{variable}...")` — same issue
- Dapper `Execute()` with a format string instead of a parameter object

---

## Command Injection

```csharp
// NEVER — UseShellExecute=true with user input
Process.Start("bash", $"-c \"convert {filename} output.jpg\"");
Process.Start(new ProcessStartInfo { FileName = "cmd.exe", Arguments = $"/c {userInput}", UseShellExecute = true });

// ALWAYS — fixed executable, ArgumentList, no shell
var psi = new ProcessStartInfo("/usr/bin/convert")
{
    UseShellExecute = false,
    RedirectStandardOutput = true,
    ArgumentList = { filename, "output.jpg" }
};
using var proc = Process.Start(psi)!;
await proc.WaitForExitAsync();
```

---

## Secrets Management

```csharp
// NEVER
var dbPassword = "hunter2";
var apiKey = builder.Configuration["ApiKey"];  // if appsettings.json is committed

// ACCEPTABLE — environment variable
var dbPassword = builder.Configuration["DB_PASSWORD"]
    ?? throw new InvalidOperationException("DB_PASSWORD not set");

// PREFERRED — AWS Secrets Manager
// Install: AWSSDK.SecretsManager
var client = new AmazonSecretsManagerClient();
var response = await client.GetSecretValueAsync(new GetSecretValueRequest
    { SecretId = "prod/db/password" });
var secret = JsonDocument.Parse(response.SecretString);

// PREFERRED — Azure Key Vault
builder.Configuration.AddAzureKeyVault(
    new Uri(builder.Configuration["KeyVaultUri"]!),
    new DefaultAzureCredential());
var dbPassword = builder.Configuration["db-password"];
```

---

## Password Hashing

```csharp
// PREFERRED — ASP.NET Core Identity IPasswordHasher<T> (uses Argon2id/PBKDF2)
var hasher = new PasswordHasher<string>();
string hashed = hasher.HashPassword(username, plainPassword);
var result = hasher.VerifyHashedPassword(username, hashed, plainPassword);
// result == PasswordVerificationResult.Success

// ALTERNATIVE — BCrypt.Net-Next
string hashed = BCrypt.Net.BCrypt.EnhancedHashPassword(plainPassword, 12);
bool valid   = BCrypt.Net.BCrypt.EnhancedVerify(plainPassword, hashed);

// NEVER for passwords
var hash = MD5.HashData(Encoding.UTF8.GetBytes(plainPassword));
var hash = SHA256.HashData(Encoding.UTF8.GetBytes(plainPassword));
```

---

## Symmetric Encryption (AES-256-GCM)

```csharp
using System.Security.Cryptography;

// Encrypt
byte[] key       = RandomNumberGenerator.GetBytes(32);  // store in secrets manager
byte[] nonce     = RandomNumberGenerator.GetBytes(12);  // unique per message
byte[] tag       = new byte[16];
byte[] plaintext = Encoding.UTF8.GetBytes(message);
byte[] ciphertext = new byte[plaintext.Length];

using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
aes.Encrypt(nonce, plaintext, ciphertext, tag);
// Store: nonce + tag + ciphertext

// Decrypt (throws AuthenticationTagMismatchException if tampered)
aes.Decrypt(nonce, ciphertext, tag, plaintext);
```

---

## CSPRNG

```csharp
// ALWAYS for security tokens, session IDs, reset links
byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
string token = Convert.ToBase64String(tokenBytes);
// or: Convert.ToHexString(tokenBytes).ToLower()

// NEVER for security values
var rng   = new Random();              // predictable
var token = rng.Next().ToString();
```

---

## Constant-Time Comparison

```csharp
// ALWAYS for token/hash comparison (prevents timing attacks)
bool isValid = CryptographicOperations.FixedTimeEquals(
    Convert.FromBase64String(storedHash),
    SHA256.HashData(Convert.FromBase64String(submittedToken))
);

// NEVER — string equality short-circuits on first mismatch
bool isValid = storedHash == submittedToken;
```

---

## Authentication & Authorization

```csharp
// JWT bearer — always validate algorithm, issuer, audience, expiry
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer           = true,
    ValidateAudience         = true,
    ValidateLifetime         = true,
    ValidateIssuerSigningKey = true,
    ValidIssuer              = "https://api.example.com",
    ValidAudience            = "https://api.example.com",
    IssuerSigningKey         = new RsaSecurityKey(rsa),
    // AlgorithmValidator is set by AddJwtBearer — never accept "none"
};

// Policy-based authorization (preferred — centralized, declarative)
builder.Services.AddAuthorization(opts =>
    opts.AddPolicy("OwnsDocument",
        p => p.Requirements.Add(new DocumentOwnerRequirement())));

app.MapGet("/documents/{id}", GetDocument)
   .RequireAuthorization("OwnsDocument");

// IDOR fix — always include ownership in the query
var doc = await db.Documents
    .FirstOrDefaultAsync(d => d.Id == docId &&
                               d.OwnerId == currentUserId);
return doc is null ? Results.NotFound() : Results.Ok(doc);
```

---

## Mass Assignment

```csharp
// VULNERABLE — model binding accepts Role, IsAdmin, etc.
[HttpPut("users/{id}")]
public async Task<IActionResult> Update(int id, User updatedUser) { ... }

// CORRECT — DTO exposes only safe fields
public record UpdateUserDto(string Name, string Email, string Bio);

[HttpPut("users/{id}")]
public async Task<IActionResult> Update(int id, UpdateUserDto dto)
{
    var user = await db.Users.FindAsync(id)
        ?? throw new NotFoundException();
    user.Name  = dto.Name;
    user.Email = dto.Email;
    user.Bio   = dto.Bio;
    // Role, IsAdmin never touched
    await db.SaveChangesAsync();
    return Ok();
}
```

---

## Session Cookies

```csharp
// AddCookie options
options.Cookie.HttpOnly     = true;
options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
options.Cookie.SameSite     = SameSiteMode.Strict;
options.ExpireTimeSpan      = TimeSpan.FromHours(8);
options.SlidingExpiration   = true;

// AddSession options
options.Cookie.HttpOnly     = true;
options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
options.Cookie.SameSite     = SameSiteMode.Strict;
options.IdleTimeout         = TimeSpan.FromHours(8);
```

---

## Security Headers

```csharp
// NWebsec or built-in middleware
app.UseHsts();                  // Strict-Transport-Security
app.UseXContentTypeOptions();   // X-Content-Type-Options: nosniff
app.UseXfo(o => o.Deny());      // X-Frame-Options: DENY
app.UseCsp(opts => opts
    .DefaultSources(s => s.Self())
    .ScriptSources(s => s.Self()));
```

---

## Rate Limiting (ASP.NET Core 8+)

```csharp
builder.Services.AddRateLimiter(opts =>
    opts.AddFixedWindowLimiter("login", o =>
    {
        o.PermitLimit = 10;
        o.Window      = TimeSpan.FromMinutes(15);
        o.QueueLimit  = 0;
    }));

app.MapPost("/auth/login", LoginHandler)
   .RequireRateLimiting("login");
```

---

## Logging — What Not to Log

```csharp
// DANGEROUS
_logger.LogInformation("Login: {User} {Password}", username, password);
_logger.LogDebug("Request body: {Body}", JsonSerializer.Serialize(body));

// SAFE
_logger.LogInformation("Login attempt: {User} from {IP}", username, ip);
// Never log: passwords, tokens, API keys, full request bodies, PII
```
