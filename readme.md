# forge-auth

A lightweight authentication toolkit for Node.js: secure password hashing,
JWT access/refresh tokens, and Express middleware — as small, independent
building blocks. No database, no user model, no login routes, no opinions.
You stay in control of your app; this just handles the parts that are easy
to get wrong.

> Removes most authentication boilerplate while enforcing secure defaults —
> without turning into a full authentication platform.

---

## Table of Contents

1. [Why this exists](#why-this-exists)
2. [Installation](#installation)
3. [Environment setup (required)](#environment-setup-required)
4. [Quick start (all three modules together)](#quick-start-all-three-modules-together)
5. [Password module](#password-module)
6. [JWT module](#jwt-module)
7. [Middleware module](#middleware-module)
8. [Project structure](#project-structure)
9. [Local development](#local-development)
10. [Putting this project under version control](#putting-this-project-under-version-control)
11. [Roadmap](#roadmap)

---

## Why this exists

Authentication in Node.js is fragmented. Developers usually stitch together
`bcrypt`, `jsonwebtoken`, hand-rolled middleware, and advice from blog posts
— which leads to inconsistent implementations and avoidable security
mistakes (missing token expiry, plaintext refresh tokens, weak hashing
rounds, algorithm confusion attacks, and so on).

`forge-auth` gives you just the secure primitives, with safe defaults
already chosen for you, so you can wire up authentication in a few lines
instead of a few hundred.

## Installation

```bash
npm install forge-auth
```

If you plan to use the middleware module, you'll also need Express in your
project (it's an optional peer dependency — only required if you actually
use `authMiddleware` / `requireRole`):

```bash
npm install express
```

## Environment setup (required)

The JWT module needs two secret keys, read from environment variables.
**You must set these before creating or verifying any token.** The package
never generates or stores secrets for you — that's your app's
responsibility, same as any other auth library.

```
JWT_ACCESS_SECRET=<a random string, at least 32 characters>
JWT_REFRESH_SECRET=<a different random string, at least 32 characters>
```

Two separate secrets are required on purpose — it stops a leaked access
token secret from also being usable to forge refresh tokens.

**How to generate a strong secret** (run this twice, once for each
variable):

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Put the values in a `.env` file in your project root (and make sure `.env`
is in your `.gitignore` — never commit secrets):

```
# .env
JWT_ACCESS_SECRET=paste-your-generated-value-here
JWT_REFRESH_SECRET=paste-a-different-generated-value-here
```

Then load it at the top of your app's entry file, before anything else:

```javascript
import "dotenv/config"; // npm install dotenv
```

If a secret is missing or too short, the package will throw a clear error
the moment you try to use it — not a confusing crash somewhere else.

## Quick start (all three modules together)

A minimal Express app using all three modules — signup-style password
check, login that issues tokens, and a protected route:

```javascript
import express from "express";
import {
  hashPassword,
  verifyPassword,
  createAccessToken,
  createRefreshToken,
  authMiddleware,
  requireRole,
} from "forge-auth";

const app = express();
app.use(express.json());

// --- "Signup": hash a password before storing it yourself ---
app.post("/signup", async (req, res) => {
  const passwordHash = await hashPassword(req.body.password);
  // Save `passwordHash` to your own database here.
  res.json({ ok: true });
});

// --- "Login": verify password, then issue tokens ---
app.post("/login", async (req, res) => {
  // Look up the user + their stored hash from your own database.
  const user = { id: "123", passwordHash: "...", role: "user" };

  const isValid = await verifyPassword(req.body.password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const accessToken = createAccessToken({ id: user.id }, { role: user.role });
  const refreshToken = createRefreshToken({ id: user.id });

  res.json({ accessToken, refreshToken });
});

// --- A protected route: requires a valid access token ---
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ userId: req.user.sub });
});

// --- A protected + role-gated route ---
app.get("/admin", authMiddleware, requireRole("admin"), (req, res) => {
  res.json({ message: "Welcome, admin" });
});

app.listen(3000);
```

That's the whole flow. The sections below explain each function in detail.

---

## Password module

Secure password hashing using `bcrypt`, with the cost factor already chosen
for you (12 rounds — the current recommended minimum).

### `hashPassword(password)`

Turns a plain-text password into a secure hash you can safely store in your
database.

```javascript
import { hashPassword } from "forge-auth";

const hash = await hashPassword("the-users-plain-password");
// Save `hash` to your database — never save the plain password.
```

### `verifyPassword(password, hash)`

Checks a plain-text password against a stored hash (e.g. during login).
Returns `true` or `false` — it never throws just because the password is
wrong.

```javascript
import { verifyPassword } from "forge-auth";

const isCorrect = await verifyPassword("what-the-user-typed", storedHash);

if (!isCorrect) {
  // reject the login attempt
}
```

**Why not just use `bcrypt` directly?** You'd have to remember the right
cost factor yourself, and remember to always use `bcrypt.compare` instead of
`===` (a plain `===` comparison on hashes is vulnerable to timing attacks).
This module makes the safe choice the only choice.

---

## JWT module

Issues and verifies two kinds of tokens:

- **Access token** — short-lived (15 minutes). Sent with every request to
  prove who the user is.
- **Refresh token** — long-lived (7 days). Used only to get a new access
  token once the old one expires.

Each token type is signed with its own separate secret, and each token
embeds its own type (`"access"` or `"refresh"`) — so an access token can
never accidentally be accepted where a refresh token is expected, or vice
versa.

### `createAccessToken(user, extraClaims?)`

```javascript
import { createAccessToken } from "forge-auth";

// Basic — just embeds the user's id
const token = createAccessToken({ id: user.id });

// With extra data embedded in the token (e.g. for role-based routes)
const token = createAccessToken({ id: user.id }, { role: user.role });
```

⚠️ Anything you pass in `extraClaims` is **readable by anyone who has the
token** (JWTs are encoded, not encrypted). Only include non-sensitive data
like a role or plan tier — never passwords, emails you want to keep
private, or internal flags.

### `createRefreshToken(user)`

```javascript
import { createRefreshToken } from "forge-auth";

const refreshToken = createRefreshToken({ id: user.id });
// Send this to the client to store securely (e.g. an httpOnly cookie).
```

> ⚠️ **Choosing between `createRefreshToken` and `issueRefreshToken`:**
> This function signs a refresh token but does **not** track it — there's no
> way to rotate or revoke it later. If you want rotation, reuse detection,
> or logout support (see [Refresh Token Rotation](#refresh-token-rotation--reuse-detection)
> below), use `issueRefreshToken()` at login instead. Use plain
> `createRefreshToken()` only if you're intentionally handling revocation
> yourself, elsewhere.  

### `verifyAccessToken(token)`

Checks that an access token is valid, not expired, and really is an access
token (not a refresh token in disguise). Returns the decoded payload, or
throws an error you can catch.

```javascript
import { verifyAccessToken } from "forge-auth";

try {
  const payload = verifyAccessToken(token);
  console.log(payload.sub); // the user's id
} catch (err) {
  console.log(err.message); // e.g. "Token has expired"
}
```

### `verifyRefreshToken(token)`

Same idea, for refresh tokens — used when a client's access token has
expired and they want a new one without logging in again.

```javascript
import { verifyRefreshToken, createAccessToken } from "forge-auth";

const payload = verifyRefreshToken(oldRefreshToken);
const newAccessToken = createAccessToken({ id: payload.sub });
```

> Refresh token **rotation and revocation** (detecting a stolen/reused
> refresh token, invalidating old ones automatically) is a bigger feature
> planned for v0.2 — see [Roadmap](#roadmap). For now, this module only
> issues and checks tokens.

---

## Refresh Token Rotation & Reuse Detection

Plain refresh tokens (issued via `createRefreshToken`) are valid until they
expire — there's no way to tell a legitimate refresh apart from a stolen
token being replayed by an attacker. This module adds **rotation**
(every refresh invalidates the old token and issues a new one) and
**reuse detection** (if an already-used token is presented again, the
entire session is revoked immediately).

This is the difference between "authentication working" and
"authentication done right" — most tutorials stop at signing a JWT and
never implement this.

### How it works

- Every refresh token belongs to a **family** — a lineage created when you
  call `issueRefreshToken`, shared across every token that family gets
  rotated into.
- Rotating a token retires it (`status: "rotated"`) and issues a new one
  in the same family.
- If a `"rotated"` (already-used) token is presented again, that's a
  strong signal it leaked — **the whole family is revoked**, not just
  that one token. This forces re-login, even for the legitimate,
  currently-active token in that family.

### `issueRefreshToken(user)`

Use this **instead of** `createRefreshToken` at login if you want
rotation/revocation support. It signs the token and starts tracking it.

```javascript
import { issueRefreshToken } from "forge-auth";

const refreshToken = await issueRefreshToken({ id: user.id });
```

### `rotateRefreshToken(token)`

Exchanges a valid, active refresh token for a new access+refresh pair.
Throws if the token is invalid, expired, revoked, unrecognized, or
**reused** (in which case the session is revoked as a side effect).

```javascript
import { rotateRefreshToken } from "forge-auth";

try {
  const { accessToken, refreshToken } = await rotateRefreshToken(oldToken);
  // Send both back to the client.
} catch (err) {
  // Any failure here (including reuse detection) means: force re-login.
  console.log(err.message);
}
```

### `revokeSession(token)`

Logs out one session — e.g. "log out this device." Safe to call even if
the token is already gone (no-op, doesn't throw).

```javascript
import { revokeSession } from "forge-auth";

await revokeSession(refreshTokenFromCookie);
```

### `revokeAllSessions(userId)`

Logs out **every** session for a user — "log out everywhere," or an
incident-response action if an account is suspected compromised.

```javascript
import { revokeAllSessions } from "forge-auth";

await revokeAllSessions(user.id);
```

### Storage

By default, all of the above use a shared **in-memory store** — fine for
single-process apps, development, and testing, but state is lost on
restart and isn't shared across multiple server instances.

```javascript
import { createRefreshToken, rotateRefreshToken } from "forge-auth"; // wrong import, illustrative only — use issueRefreshToken
```

If you need an isolated store (e.g. per-test, or a multi-tenant scope),
create one explicitly and pass it to any refresh function:

```javascript
import { createRefreshStore, issueRefreshToken, rotateRefreshToken } from "forge-auth";

const store = createRefreshStore();

const token = await issueRefreshToken({ id: user.id }, { store });
const rotated = await rotateRefreshToken(token, { store });
```

> A persistent adapter interface (Redis, PostgreSQL, MongoDB) is planned
> for **v1.0** — any custom store just needs to implement the
> `RefreshTokenStore` type exported from this package, so switching later
> won't require changing how you call `rotateRefreshToken`, `revokeSession`,
> etc.

## Middleware module

Ready-to-use Express middleware — no setup function needed, just plug it
in.

### `authMiddleware`

Reads the `Authorization: Bearer <token>` header, verifies it, and attaches
the result to `req.user`. If the token is missing, malformed, invalid, or
expired, it responds with `401` automatically — your route handler code
never runs in that case.

```javascript
import { authMiddleware } from "forge-auth";

app.use(authMiddleware); // protect every route below this line

// or, protect just one route:
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ userId: req.user.sub });
});
```

### `requireRole(role)`

Use **after** `authMiddleware` on routes that should only be accessible to
users with a specific role. The role must have been embedded when the token
was created (see `createAccessToken`'s `extraClaims` example above).

```javascript
import { authMiddleware, requireRole } from "forge-auth";

app.get(
  "/admin",
  authMiddleware,
  requireRole("admin"),
  (req, res) => {
    res.json({ message: "Only admins see this" });
  }
);
```

- If the user isn't authenticated at all → `401 Not authenticated`
- If the user is authenticated but has the wrong role → `403 Insufficient permissions`

---

## Project structure

```
src/
├── index.ts              # Public API — the only file consumers import from
├── password/
│   ├── hash.ts             # hashPassword()
│   ├── verify.ts           # verifyPassword()
│   └── index.ts             # barrel export
├── jwt/
│   ├── config.ts            # secret validation, expiry settings
│   ├── sign.ts               # createAccessToken(), createRefreshToken()
│   ├── verify.ts              # verifyAccessToken(), verifyRefreshToken()
│   └── index.ts                # barrel export
├── refresh/
│   ├── types.ts              # RefreshTokenStore interface, record shape
│   ├── store.ts                # InMemoryRefreshStore, createRefreshStore()
│   ├── hash.ts                   # SHA-256 hashing for token storage/lookup
│   ├── issue.ts                    # issueRefreshToken()
│   ├── rotate.ts                     # rotateRefreshToken()
│   ├── revoke.ts                      # revokeSession(), revokeAllSessions()
│   └── index.ts                        # barrel export
├── middleware/
│   ├── express.ts               # adds `req.user` typing
│   ├── authenticate.ts           # authMiddleware
│   ├── requireRole.ts             # requireRole()
│   └── index.ts                    # barrel export
└── types/
    └── index.ts                     # shared TypeScript types

tests/                    # one test file per module, using vitest
```

## Local development

```bash
# 1. Install dependencies
npm install

# 2. Set up your local secrets (see "Environment setup" above)
cp .env.example .env   # then fill in real values

# 3. Run tests
npm run test

# 4. Type-check without building
npm run typecheck

# 5. Build the package (outputs to dist/, both CJS and ESM + types)
npm run build
```

All current modules are covered by tests — 24 tests across password
hashing, JWT signing/verification, and Express middleware.

## Putting this project under version control

If you haven't already:

```bash
git init
git add .
git commit -m "chore: initial project scaffold"

# then push to your own remote, e.g. GitHub
git remote add origin <your-repo-url>
git branch -M main
git push -u origin main
```

Doing this early means the project's history lives independently of any
single chat session or machine — always keep your own repo as the source of
truth.

<!-- ## Roadmap

- [x] **v0.1** — Password hashing (bcrypt) + JWT helpers + Express middleware
- [ ] **v0.2** — Refresh token rotation with reuse detection
- [ ] **v0.3** — RBAC / declarative permissions middleware
- [ ] **v1.0** — Storage adapters (Redis, PostgreSQL, MongoDB) + broader
      framework support (Fastify, NestJS, Hono) -->

## Roadmap

- [x] **v0.1** — Password hashing (bcrypt) + JWT helpers + Express middleware
- [x] **v0.2** — Dependencies upgraded to the latest versions
- [x] **v0.2.1** — Refresh token rotation with reuse detection (in-memory store)
- [ ] **v0.3** — RBAC / declarative permissions middleware
- [ ] **v1.0** — Storage adapters (Redis, PostgreSQL, MongoDB) + broader
      framework support (Fastify, NestJS, Hono)

## License

MIT