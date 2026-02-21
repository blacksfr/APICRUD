# APICRUD — Hardened User Management API (Security-First)

RESTful API for user management focused on enterprise-grade security and mitigation of OWASP Top 10 (2021) risks. Built with Node.js and MongoDB, applying strict validation and a modern security stack.

## Overview
APICRUD is a security-focused backend project that implements a robust user management system. The design prioritizes defensive architecture, ensuring security controls are applied throughout the request lifecycle.

The API mitigates common modern vulnerabilities including:
* **Broken Object Level Authorization (BOLA / IDOR)**
* **Mass Assignment**
* **Cross-Site Request Forgery (CSRF)**

## Technology Stack
* **Runtime:** Node.js (ES Modules)
* **Framework:** Express.js 5.x
* **Database:** MongoDB (Native Driver)
* **Security & Validation:** * Argon2id (Winner of Password Hashing Competition)
    * Zod (Strict Mode) — Schema validation
    * Helmet & Lusca — Security headers & HSTS
    * CSRF Protection (Double-submit cookie pattern)
    * express-rate-limit — Brute-force mitigation
* **Testing:** Vitest & Supertest (Stateful security suite)



## Security Features

### CSRF Protection (Double-Submit Pattern)
Implemented using signed cookies with `HttpOnly` and `SameSite: Lax` flags. 
* State-changing requests (POST, PUT, DELETE) require a valid `X-CSRF-Token` header.
* The API remains stateless while ensuring that requests originate from trusted frontends.



### Argon2id Password Hashing
Unlike standard bcrypt, Argon2id provides:
* Resistance to GPU and ASIC brute-force attacks through memory hardness.
* Protection against side-channel attacks.
* Flexibility to support high-entropy passphrases without character limits.

### Infrastructure & DoS Hardening
* **Payload Limit:** Strict 1MB JSON limit to prevent memory exhaustion (Anti-DoS).
* **Request Timeouts:** Implemented via `connect-timeout` to mitigate slowloris and hanging request attacks.
* **MIME Sniffing Prevention:** `X-Content-Type-Options: nosniff` forced across all routes.

## Architecture & Design Patterns

The project follows a **Hardened Clean Architecture** approach:

### Shielded Routers
Middleware execution follows a "Fail-Fast" order:
1. **Rate Limiting** (Immediate rejection of abusers)
2. **Timeout** (Request lifecycle control)
3. **CSRF Validation** (Origin integrity)
4. **JWT Validation** (Identity verification)

### Sanitized Repositories
Implementation of the **Data Mapper** pattern with automatic sanitization. Sensitive fields, such as password hashes and internal roles, are stripped using private methods before data leaves the persistence layer.



## Environment Variables
Create a `.env` file in the project root. **Do not commit or share real secret values.**

| Variable | Description | Example |
| :--- | :--- | :--- |
| MONGO_DB_KEY | MongoDB connection string | `mongodb+srv://user:pass@cluster` |
| DB_NAME | Database name | `development-api-crud` |
| COOKIE_SECRET | Secret for signing CSRF cookies | `64-character hex string` |
| JWT_SECRET | Access token secret | `64-character hex string` |
| JWT_REFRESH_SECRET | Refresh token secret | `64-character hex string` |
| NODE_ENV | Environment mode | `development` / `production` |
| PORT | Server port | `3000` |

## Security Capabilities Demonstrated

* **Zero-Trust Validation:** No input is processed until it passes strict Zod validation (removing unexpected fields).
* **BOLA Prevention:** Ownership checks ensure users cannot access or modify resources belonging to others.
* **Anti-Brute Force:** Granular rate limiting applied specifically to authentication endpoints and global routes.
* **Secure Cookie Configuration:** All session-related cookies are signed and hardened to reduce XSS and session hijacking risks.

---
*Documentation for AI and Security Auditing purposes.*" adicione sobre informacoes que voce achar relevante sobre o projeto atual e mantenha a forma de escrevever em read me e coloque as rotas da api
Error
You have no quota
You said: "# APICRUD — Hardened User Management API
"# APICRUD — Hardened User Management API (Security-First)

RESTful API for user management focused on enterprise-grade security and mitigation of OWASP Top 10 (2021) risks. Built with Node.js and MongoDB, applying strict validation and a modern security stack.

## Overview
APICRUD is a security-focused backend project that implements a robust user management system. The design prioritizes defensive architecture, ensuring security controls are applied throughout the request lifecycle.

The API mitigates common modern vulnerabilities including:
* **Broken Object Level Authorization (BOLA / IDOR)**
* **Mass Assignment**
* **Cross-Site Request Forgery (CSRF)**

## Technology Stack
* **Runtime:** Node.js (ES Modules)
* **Framework:** Express.js 5.x
* **Database:** MongoDB (Native Driver)
* **Security & Validation:** * Argon2id (Winner of Password Hashing Competition)
    * Zod (Strict Mode) — Schema validation
    * Helmet & Lusca — Security headers & HSTS
    * CSRF Protection (Double-submit cookie pattern)
    * express-rate-limit — Brute-force mitigation
* **Testing:** Vitest & Supertest (Stateful security suite)



## Security Features

### CSRF Protection (Double-Submit Pattern)
Implemented using signed cookies with `HttpOnly` and `SameSite: Lax` flags. 
* State-changing requests (POST, PUT, DELETE) require a valid `X-CSRF-Token` header.
* The API remains stateless while ensuring that requests originate from trusted frontends.



### Argon2id Password Hashing
Unlike standard bcrypt, Argon2id provides:
* Resistance to GPU and ASIC brute-force attacks through memory hardness.
* Protection against side-channel attacks.
* Flexibility to support high-entropy passphrases without character limits.

### Infrastructure & DoS Hardening
* **Payload Limit:** Strict 1MB JSON limit to prevent memory exhaustion (Anti-DoS).
* **Request Timeouts:** Implemented via `connect-timeout` to mitigate slowloris and hanging request attacks.
* **MIME Sniffing Prevention:** `X-Content-Type-Options: nosniff` forced across all routes.

## Architecture & Design Patterns

The project follows a **Hardened Clean Architecture** approach:

### Shielded Routers
Middleware execution follows a "Fail-Fast" order:
1. **Rate Limiting** (Immediate rejection of abusers)
2. **Timeout** (Request lifecycle control)
3. **CSRF Validation** (Origin integrity)
4. **JWT Validation** (Identity verification)

### Sanitized Repositories
Implementation of the **Data Mapper** pattern with automatic sanitization. Sensitive fields, such as password hashes and internal roles, are stripped using private methods before data leaves the persistence layer.



## Environment Variables
Create a `.env` file in the project root. **Do not commit or share real secret values.**

| Variable | Description | Example |
| :--- | :--- | :--- |
| MONGO_DB_KEY | MongoDB connection string | `mongodb+srv://user:pass@cluster` |
| DB_NAME | Database name | `development-api-crud` |
| COOKIE_SECRET | Secret for signing CSRF cookies | `64-character hex string` |
| JWT_SECRET | Access token secret | `64-character hex string` |
| JWT_REFRESH_SECRET | Refresh token secret | `64-character hex string` |
| NODE_ENV | Environment mode | `development` / `production` |
| PORT | Server port | `3000` |

## Security Capabilities Demonstrated

* **Zero-Trust Validation:** No input is processed until it passes strict Zod validation (removing unexpected fields).
* **BOLA Prevention:** Ownership checks ensure users cannot access or modify resources belonging to others.
* **Anti-Brute Force:** Granular rate limiting applied specifically to authentication endpoints and global routes.
* **Secure Cookie Configuration:** All session-related cookies are signed and hardened to reduce XSS and session hijacking risks.

---
*Documentation for AI and Security Auditing purposes.*
