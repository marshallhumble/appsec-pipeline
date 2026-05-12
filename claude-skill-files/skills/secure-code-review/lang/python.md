# Python — Security Patterns

Load alongside the relevant vulnerability reference file.

---

## SQL Injection

```python
# NEVER — string formatting or concatenation
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
cursor.execute("SELECT * FROM users WHERE email = '%s'" % email)
cursor.execute("SELECT * FROM users WHERE email = " + email)

# ALWAYS — parameterized (psycopg2, sqlite3, mysql-connector)
cursor.execute("SELECT * FROM users WHERE email = %s AND active = %s", (email, True))
cursor.execute("SELECT * FROM users WHERE email = :email", {"email": email})

# ALWAYS — SQLAlchemy ORM (parameterized by construction)
users = session.query(User).filter(User.email == email, User.active == True).all()

# ALLOWED — SQLAlchemy text() with bound parameters
from sqlalchemy import text
users = session.execute(
    text("SELECT * FROM users WHERE email = :e"), {"e": email}
)
```

**Escape hatches to avoid:**
- `session.execute(text(f"... {variable} ..."))` — f-string bypasses binding
- Django `.raw("SELECT ... WHERE id = " + str(pk))`
- Django `cursor.execute("SELECT ... WHERE id = %s" % pk)`

---

## Command Injection

```python
import subprocess

# NEVER — shell=True with user input
subprocess.run(f"convert {filename} output.jpg", shell=True)
os.system(f"grep {user_query} /var/log/app.log")

# ALWAYS — array form, shell=False (default), fixed executable
subprocess.run(
    ["/usr/bin/convert", filename, "output.jpg"],
    shell=False,
    capture_output=True,
    timeout=30
)
```

---

## Secrets Management

```python
# NEVER
db_password = "hunter2"
api_key = "sk-abc123"

# ACCEPTABLE — environment variable
import os
db_password = os.environ["DB_PASSWORD"]  # raises KeyError if not set — fail loud

# PREFERRED — AWS Secrets Manager (boto3)
import boto3, json
client = boto3.client("secretsmanager", region_name="us-east-1")
secret = client.get_secret_value(SecretId="prod/db/password")
db_password = json.loads(secret["SecretString"])["password"]

# ALTERNATIVE — use python-dotenv for local dev only (.env in .gitignore)
from dotenv import load_dotenv
load_dotenv()
db_password = os.environ["DB_PASSWORD"]
```

---

## Password Hashing

```python
# PREFERRED — passlib with Argon2id
from passlib.hash import argon2
hashed  = argon2.hash(plain_password)
is_valid = argon2.verify(plain_password, hashed)

# ALTERNATIVE — bcrypt
import bcrypt
hashed   = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
is_valid = bcrypt.checkpw(password.encode(), hashed)

# NEVER for passwords
import hashlib
hashlib.md5(password.encode()).hexdigest()
hashlib.sha256(password.encode()).hexdigest()
```

---

## Symmetric Encryption (AES-256-GCM)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Key must come from a secrets manager
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# Encrypt — nonce must be unique per message with same key
nonce = os.urandom(12)  # 96-bit nonce for GCM
ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
# Store: nonce + ciphertext

# Decrypt — raises InvalidTag if tampered
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

---

## CSPRNG

```python
import secrets

# ALWAYS for security tokens, session IDs, reset links
token    = secrets.token_hex(32)       # 256-bit hex token
token_b64 = secrets.token_urlsafe(32)  # URL-safe base64

# NEVER for security values
import random
token = random.randint(0, 1000000)  # predictable
```

---

## Constant-Time Comparison

```python
import hmac

# ALWAYS — prevents timing attacks
is_valid = hmac.compare_digest(stored_hash, computed_hash)

# NEVER — short-circuits on first mismatch
is_valid = stored_hash == submitted_token
```

---

## Authentication & Authorization

```python
# Django — use built-in auth; apply @login_required everywhere needed
from django.contrib.auth.decorators import login_required, permission_required

@login_required
@permission_required("app.view_document", raise_exception=True)
def view_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    # owner= check prevents IDOR
    return JsonResponse(doc.to_dict())

# Flask — use Flask-Login and check ownership explicitly
from flask_login import login_required, current_user

@app.route("/documents/<int:doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first()
    if not doc:
        abort(404)  # not 403
    return jsonify(doc.to_dict())
```

---

## Session Cookies (Flask)

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SECURE    = True,
    SESSION_COOKIE_SAMESITE  = "Strict",
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
)
```

---

## Security Headers

```python
# Flask — flask-talisman
from flask_talisman import Talisman
Talisman(app, content_security_policy={"default-src": ["'self'"]})

# Django — settings.py
SECURE_HSTS_SECONDS          = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF  = True
X_FRAME_OPTIONS              = "DENY"
```

---

## Rate Limiting

```python
# Flask — flask-limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app)

@app.route("/auth/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def login(): ...

# Django — django-ratelimit
from ratelimit.decorators import ratelimit

@ratelimit(key="ip", rate="10/15m", method="POST", block=True)
def login(request): ...
```

---

## Logging — What Not to Log

```python
# DANGEROUS
logging.info(f"Login: user={username} password={password}")
logging.debug(f"Request body: {request.body}")

# SAFE
logging.info("Login attempt", extra={"username": username, "ip": request.remote_addr})
# Never log: passwords, tokens, API keys, PII, full request/response bodies
```

---

## Dependency Auditing

```bash
pip install pip-audit
pip-audit
# or
safety check -r requirements.txt
```
