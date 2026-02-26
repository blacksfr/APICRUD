# APICRUD — Hardened User Management API

> RESTful API for user management focused on enterprise-grade security and mitigation of OWASP Top 10 (2021) risks. Built with Node.js and MongoDB, applying strict validation, structured logging, and a modern defense-in-depth security stack.

---

## Overview

APICRUD is a security-focused backend project that implements a robust user management system. The design prioritizes defensive architecture, ensuring security controls are applied at every layer of the request lifecycle — from the first byte received to the last byte sent.

The API mitigates common modern vulnerabilities including:

- **Broken Object Level Authorization (BOLA / IDOR)** — ownership enforced on every user-scoped route
- **Mass Assignment** — immutable fields stripped automatically at the repository layer
- **Cross-Site Request Forgery (CSRF)** — double-submit cookie pattern with HMAC binding
- **Brute-Force & Credential Stuffing** — granular rate limiting per route and per IP (IPv6-normalized)
- **Injection Attacks** — Zod strict-mode schema validation rejects all unexpected or malformed input before it reaches the database

---

## Technology Stack

| Layer | Technology |
| :--- | :--- |
| Runtime | Node.js 20+ (ES Modules) |
| Framework | Express.js 5.x |
| Database | MongoDB (Native Driver — no ODM) |
| Password Hashing | Argon2id (PHC winner) |
| Schema Validation | Zod (strict mode) |
| Security Headers | Helmet (CSP, HSTS, COEP, CORP, etc.) |
| CSRF Protection | csrf-csrf (double-submit + HMAC) |
| Rate Limiting | express-rate-limit (IPv6-normalized) |
| Authentication | JWT HS512 (access + refresh token pair) |
| Encryption | AES-256-GCM (email at rest) |
| HMAC | SHA-256 (email lookup without decryption) |
| Logging | Pino (structured JSON, B2B pattern) |
| HTTP Logging | pino-http (request lifecycle) |
| Compression | compression (gzip) |
| HTTP Param Pollution | hpp |

---

## API Routes

### Public

| Method | Route | Description | Rate Limit |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1` | Health check — returns CSRF token | Global |
| `POST` | `/api/v1/auth/register` | Register new user | 3 req/h (prod) |
| `POST` | `/api/v1/auth/login` | Authenticate user | 5 req/15min (failed only) |
| `POST` | `/api/v1/auth/refresh` | Refresh token pair | 10 req/15min |

### Protected — requires `accessToken` cookie + `X-CSRF-Token` header

| Method | Route | Description | Rate Limit |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/logout` | Invalidate session and clear cookies | 10 req/min |
| `GET` | `/api/v1/users/me` | Get authenticated user by token | 50 req/min |
| `GET` | `/api/v1/users/:id` | Get user by ID (own only) | 50 req/min |
| `PATCH` | `/api/v1/users/:id` | Update user by ID (own only) | 50 req/min |
| `DELETE` | `/api/v1/users/:id` | Delete user by ID (own only) | 50 req/min |

> All state-changing routes (`POST`, `PATCH`, `DELETE`) require the `X-CSRF-Token` header with the token received from `GET /api/v1`.

---

## Authentication Flow

```
1. GET  /api/v1
        ← sets SID cookie (httpOnly)
        ← sets CSRF cookie (httpOnly)
        ← returns { csrfToken } in JSON body

2. POST /api/v1/auth/register  or  /api/v1/auth/login
        → X-CSRF-Token: <token from step 1>
        ← sets accessToken cookie  (signed, httpOnly, 1h)
        ← sets refreshToken cookie (signed, httpOnly, 30d, path=/api/v1/auth/refresh)
        ← returns { user, csrfToken }

3. Authenticated requests
        → accessToken cookie sent automatically by browser
        → X-CSRF-Token header sent by frontend
        ← 200 with data

4. POST /api/v1/auth/refresh  (when accessToken expires)
        → refreshToken cookie sent automatically (path-scoped)
        ← new accessToken + refreshToken pair
        ← new csrfToken

5. POST /api/v1/auth/logout
        ← clears all cookies (accessToken, refreshToken, SID, CSRF)
```

---

## Security Architecture

### Middleware Execution Order (Fail-Fast)

Every request passes through the following pipeline in order. A request is rejected at the earliest possible stage:

```
1.  HTTP Logger          → assigns requestId, logs request lifecycle
2.  Trust Proxy          → resolves real client IP behind load balancer
3.  Timeout (30s)        → starts request timer (anti-slowloris)
4.  Helmet               → sets all security response headers
5.  CORS                 → rejects unauthorized origins before any parsing
6.  Compression          → gzip response (before rate limit)
7.  Rate Limit (global)  → rejects abusive IPs before body parsing
8.  JSON Parser (1mb)    → parses body, enforces size limit
9.  Cookie Parser        → parses and verifies signed cookies
10. HPP                  → prevents HTTP parameter pollution
11. Ensure Session ID    → guarantees SID exists before CSRF check
12. CSRF Protection      → validates X-CSRF-Token on mutating requests
13. Timeout Handler      → responds 503 if timer expired
14. Routes               → business logic (with per-route rate limits + JWT auth)
15. 404 Handler          → catches unmatched routes
16. Error Handler        → centralized error classification and response
```

### CSRF Protection — Double-Submit with HMAC Binding

The standard double-submit pattern is hardened with HMAC binding using the session ID, preventing token forgery even if the attacker knows the CSRF secret:

```
Token = HMAC(COOKIE_SECRET, SID) + random(64 bytes)
```

- CSRF cookie is `httpOnly: true` — JavaScript cannot read it
- Token is delivered to the frontend via JSON on `GET /api/v1`
- Validation requires both the cookie (server-side) and the header (frontend-provided) to match
- Without the SID, a forged token will fail HMAC validation

### Email Security — Encrypt + HMAC

Emails are never stored in plaintext:

- **Stored as:** AES-256-GCM ciphertext (random IV per encryption)
- **Looked up via:** SHA-256 HMAC of the normalized email
- This allows existence checks (`findForLogin`, `exists`) without decrypting, and prevents email enumeration from a database breach

### Password Security — Argon2id

```
memoryCost:  65536 KB  (64MB — GPU-hostile)
timeCost:    3 iterations
parallelism: 1
```

- Constant-time comparison via `argon2.verify`
- Dummy comparison on missing user to prevent timing-based user enumeration
- Hash format validated with regex before `verify` to prevent hash confusion attacks

### JWT Configuration

```
Algorithm:     HS512
accessToken:   1h  — contains { id, username }
refreshToken:  30d — contains { id } only
```

- Tokens delivered via `signed` `httpOnly` cookies (not localStorage)
- `refreshToken` is path-scoped to `/api/v1/auth/refresh` — browser never sends it on other routes
- Session cookies cleared on logout, delete, and re-login

### BOLA / IDOR Prevention

Every user-scoped route performs an ownership check before any database operation:

```js
if (id !== req.user.id) return forbidden(res, '...');
```

A valid JWT for user A cannot access or modify user B's resources.

### Repository — Immutable Fields & Credential Redaction

The `BaseRepository` automatically:
- Strips `_id`, `isDeleted`, `createdAt`, `updatedAt`, `deletedAt` from all write operations (anti-mass-assignment)
- Excludes `password` from all read projections via `{ password: 0 }`
- Applies soft-delete (`isDeleted: true`) instead of hard-delete on all `deleteById` operations
- Validates and sanitizes all filter inputs before querying

---

## Structured Logging — B2B Pattern

All logs follow a consistent structured format using Pino:

```json
{
  "level": "info",
  "time": "2025-01-01T20:00:00.000Z",
  "event": "user_logged_in",
  "requestId": "fb56ba9f-21d4-4b22-a28c-fc19d915c29b",
  "userId": "699f824999f174a94a50d1db",
  "username": "example",
  "msg": "[UserController] Login successful"
}
```

Sensitive fields are automatically redacted at the logger level:

```
password, hashedPassword, token, accessToken, refreshToken,
authorization, cookie, email, emailHmac, req.headers.authorization,
req.headers.cookie, res.headers["set-cookie"]
```

Every error is classified with a semantic `event` key for observability tooling (Datadog, Grafana, etc.):

| Event | Level | Description |
| :--- | :--- | :--- |
| `user_registered` | info | Successful registration |
| `user_logged_in` | info | Successful login |
| `user_login_failed` | warn | Invalid credentials (with `reason` field) |
| `token_expired` | info | JWT access token expired |
| `token_invalid` | warn | Malformed or tampered JWT |
| `csrf_token_invalid` | warn | CSRF validation failed |
| `session_missing` | warn | SID cookie absent on protected route |
| `encryption_failure` | error | AES-256-GCM encryption error |
| `decryption_failure` | error | AES-256-GCM decryption error |
| `user_access_denied` | warn | BOLA attempt detected |
| `unhandled_error` | error | Unexpected server error |

---

## Environment Variables

Create a `.env` file in the project root. All variables are validated on startup — the server will refuse to start if any required variable is missing.

| Variable | Description | Minimum Length |
| :--- | :--- | :--- |
| `MONGO_DB_KEY` | MongoDB connection string | — |
| `DB_NAME` | Database name | — |
| `COOKIE_SECRET` | Secret for signing cookies and CSRF HMAC | 32 chars |
| `JWT_ACCESS_SECRET` | Access token signing secret | 32 chars |
| `JWT_REFRESH_SECRET` | Refresh token signing secret | 32 chars |
| `ENCRYPTION_SECRET` | AES-256-GCM key derivation secret | 32 chars |
| `NODE_ENV` | Environment mode | `development` / `production` / `test` |
| `PORT` | Server port (default: 3000) | — |

> Generate secrets with: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`

---

## Running the Project

```bash
# Install dependencies
npm install

# Development (loads .env automatically)
npm run dev

# Production
NODE_ENV=production node src/server.js
```

---

## Security Capabilities Summary

| Threat | Mitigation |
| :--- | :--- |
| Brute-force login | Rate limit: 5 failed attempts / 15min per IP |
| Credential stuffing | Argon2id (memory-hard), dummy compare on unknown user |
| CSRF | Double-submit + HMAC-bound session token |
| XSS cookie theft | `httpOnly` on all auth cookies |
| Cookie tampering | `signed: true` via cookie-parser |
| BOLA / IDOR | Ownership check on every user-scoped route |
| Mass assignment | Immutable field stripping in BaseRepository |
| Email enumeration | Constant-time dummy compare + HMAC lookup |
| Email breach | AES-256-GCM encryption at rest |
| Password breach | Argon2id (64MB memory cost) |
| Payload attacks | 1MB JSON limit + Zod strict validation |
| Slowloris / hanging | 30s request timeout |
| Clickjacking | `X-Frame-Options: DENY` via Helmet |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| Protocol downgrade | HSTS (1 year, preload) in production |
| Parameter pollution | hpp middleware |
| IPv6 rate limit bypass | `ipKeyGenerator` normalization |

---

*Documentation maintained for security auditing and AI-assisted review purposes.*
