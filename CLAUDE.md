# Auth Server — Project Specification for Claude Code

## Overview

A lightweight, standalone OAuth2 authorisation server built with **Java and Quarkus**.
It handles user signup, email verification, login, password reset, and token introspection
for a web-based online game. There is no database — all persistent state lives in flat text
files, and all transient state lives in memory.

---

## Tech Stack

- **Language:** Java
- **Framework:** Quarkus
- **Templating:** Qute (via `quarkus-rest-qute`)
- **JWT:** Nimbus JOSE + JWT library
- **Password hashing:** jBCrypt
- **Email:** Quarkus Mailer (`quarkus-mailer`) over SMTP
- **REST + JSON:** `quarkus-rest-jackson`

---

## Authentication Flow

This server implements the **OAuth2 Authorization Code flow with PKCE** for browser-based clients.

```
1.  Browser redirects to  GET /authorize?client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256
2.  Server shows login form (Qute HTML template)
3.  User submits username + password via POST /authorize
4.  Server validates credentials, creates a short-lived auth code, redirects to redirect_uri?code=...
5.  Game frontend calls POST /token with code + code_verifier
6.  Server validates code + PKCE verifier, returns a signed JWT
7.  Browser stores JWT in memory / localStorage
8.  Every game API call sends:  Authorization: Bearer <jwt>
9.  Game server calls POST /introspect with the token
10. Auth server replies { "active": true, "userId": "alice123" }
         or            { "active": false }
```

Tokens are signed with **HS256** (shared secret). The game server always calls back to
`/introspect` rather than verifying the JWT signature locally, so RS256/public key
distribution is not needed.

---

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/authorize` | Display the login form |
| POST | `/authorize` | Process login, issue auth code, redirect |
| POST | `/token` | Exchange auth code + PKCE verifier for JWT |
| POST | `/introspect` | Validate a JWT → `{ active, userId }` |
| GET  | `/signup` | Display the signup form |
| POST | `/signup` | Create pending account, send verification email |
| GET  | `/verify-email?token=...` | Activate a pending account |
| GET  | `/forgot-password` | Display the forgot-password form |
| POST | `/forgot-password` | Send password reset link to email |
| GET  | `/reset-password?token=...` | Display the new-password form |
| POST | `/reset-password` | Save new BCrypt password hash |

---

## File Storage

### `users.txt`
One line per active (email-verified) user.

```
username:bcrypt_hash:userId:email
alice:$2a$12$xxxxx:alice123:alice@example.com
bob:$2a$12$yyyyy:bob456:bob@example.com
```

- `username` — the login name chosen at signup
- `bcrypt_hash` — BCrypt hash of the password (jBCrypt, cost factor 12)
- `userId` — alphanumeric identifier returned by `/introspect`
- `email` — used for verification and password reset emails

### `pending.txt`
One line per unverified signup. Entries are removed once the user clicks the
verification link, or can be cleaned up on startup if expired.

```
username:bcrypt_hash:userId:email:verifyToken:expiryEpochMs
```

---

## In-Memory Stores

All transient state is held in memory. If the server restarts, in-flight tokens
are lost — users simply log in or request a new link again.

| Store | Key | Value | TTL |
|-------|-----|-------|-----|
| Auth codes | random 32-byte hex string | `{ userId, codeChallenge }` | 60 seconds |
| Active JWTs | JWT `jti` claim (UUID) | `userId` | 15 minutes |
| Reset tokens | random 32-byte hex string | `{ userId, email }` | 15 minutes |
| Pending verifications | random 32-byte hex string | `{ username, bcryptHash, userId, email }` | 15 minutes |

---

## JWT Structure

- **Algorithm:** HS256
- **Expiry:** 15 minutes
- **Claims:**
  - `sub` — userId (alphanumeric)
  - `jti` — unique token ID (UUID, used as key in active JWT store)
  - `iat` — issued at
  - `exp` — expiry

The `jti` is stored in the active JWT map on issuance and removed on expiry.
`/introspect` checks both the signature and the presence of the `jti` in the map.

---

## Email

Sent via SMTP using Quarkus Mailer. Two email types:

1. **Account verification** — sent on signup, contains `GET /verify-email?token=<hex>`
2. **Password reset** — sent on forgot-password, contains `GET /reset-password?token=<hex>`

Both links expire after **15 minutes**.

### SMTP Configuration (`application.properties`)

```properties
auth.smtp.host=smtp.example.com
auth.smtp.port=587
auth.smtp.user=noreply@example.com
auth.smtp.password=secret
auth.smtp.from=noreply@mygame.com
auth.base-url=https://auth.mygame.com

quarkus.mailer.host=${auth.smtp.host}
quarkus.mailer.port=${auth.smtp.port}
quarkus.mailer.username=${auth.smtp.user}
quarkus.mailer.password=${auth.smtp.password}
quarkus.mailer.from=${auth.smtp.from}
quarkus.mailer.start-tls=REQUIRED
```

---

## Signup Flow

1. User fills in username, email, password on `GET /signup`
2. `POST /signup` validates input (username unique, email unique, password strength)
3. Server generates a random `userId` (alphanumeric), BCrypt-hashes the password
4. Entry written to `pending.txt` and stored in memory with a 15-minute expiry
5. Verification email sent with link to `GET /verify-email?token=<hex>`
6. User clicks link → entry moved from `pending.txt` / memory into `users.txt`
7. User can now log in

---

## Password Reset Flow

1. User visits `GET /forgot-password`, submits their email
2. If email matches a user in `users.txt`, a reset token is generated and stored in memory
3. Reset email sent with link to `GET /reset-password?token=<hex>`
4. User clicks link → shown a form to enter a new password
5. `POST /reset-password` validates token (exists + not expired), BCrypt-hashes new password
6. `users.txt` updated with new hash, reset token removed from memory

---

## HTML Templates (Qute)

| Template | Path | Purpose |
|----------|------|---------|
| `login.html` | `src/main/resources/templates/login.html` | Login form |
| `signup.html` | `src/main/resources/templates/signup.html` | Signup form |
| `forgot.html` | `src/main/resources/templates/forgot.html` | Forgot password form |
| `reset.html` | `src/main/resources/templates/reset.html` | New password form |
| `message.html` | `src/main/resources/templates/message.html` | Generic info/error page |

All forms use standard HTML POST. Keep styling minimal — plain HTML is fine.

---

## Source Structure

```
src/main/java/com/mygame/auth/
├── resource/
│   ├── AuthorizeResource.java       # GET+POST /authorize
│   ├── TokenResource.java           # POST /token
│   ├── IntrospectResource.java      # POST /introspect
│   ├── SignupResource.java          # GET+POST /signup, GET /verify-email
│   └── PasswordResetResource.java   # GET+POST /forgot-password, GET+POST /reset-password
├── service/
│   ├── UserStore.java               # Load/save users.txt and pending.txt
│   ├── TokenStore.java              # In-memory auth codes, JWTs, reset tokens
│   ├── JwtService.java              # Mint and verify HS256 JWTs
│   └── MailService.java             # Send verification and reset emails
└── model/
    ├── User.java                    # username, bcryptHash, userId, email
    └── PendingUser.java             # User + verifyToken + expiry
```

---

## Security Notes

- All passwords stored as BCrypt hashes (cost factor 12). Plaintext passwords never persisted.
- PKCE (S256) required on all authorization code requests — no plain code_challenge_method.
- Auth codes are single-use and expire after 60 seconds.
- Reset and verification tokens are cryptographically random (32 bytes, hex-encoded).
- `/introspect` should only be callable from trusted internal network (game server), not the public internet. Consider an IP allowlist or a shared secret header (`X-Introspect-Secret`) checked on every introspect request.
- `users.txt` and `pending.txt` must not be served statically — ensure Quarkus has no static file route covering them.
- HTTPS is assumed in production. Do not run this over plain HTTP.

---

## Maven Dependencies (`pom.xml`)

```xml
<dependencies>
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-rest-jackson</artifactId>
    </dependency>
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-rest-qute</artifactId>
    </dependency>
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-mailer</artifactId>
    </dependency>
    <dependency>
        <groupId>com.nimbusds</groupId>
        <artifactId>nimbus-jose-jwt</artifactId>
        <version>9.37.3</version>
    </dependency>
    <dependency>
        <groupId>org.mindrot</groupId>
        <artifactId>jbcrypt</artifactId>
        <version>0.4</version>
    </dependency>
</dependencies>
```
