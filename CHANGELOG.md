# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.1] - 2026-09-14

### Added
- Refresh token rotation with reuse detection (`refresh/` module):
  - `issueRefreshToken(user)` — tracked refresh token issuance
  - `rotateRefreshToken(token)` — rotate + detect reused/stolen tokens
  - `revokeSession(token)` — single-session logout
  - `revokeAllSessions(userId)` — logout everywhere
  - `createRefreshStore()` — isolated in-memory store factory
  - `RefreshTokenStore` type — implement this for custom storage adapters
- `jti` (JWT ID) claim added to refresh tokens, preventing token
  collisions when issued within the same second.

### Fixed
- (internal, pre-release) Refresh tokens issued in rapid succession for
  the same user could be byte-identical due to deterministic HS256
  signing + second-level `iat` precision, silently corrupting
  hash-based rotation/reuse-detection lookups. Fixed via `jti`.

### Note on versioning
Refresh rotation was originally planned as the "v0.2" roadmap feature,
but landed here in v0.2.1 instead — see the v0.2 entry below for why.

## [0.2.0] - 2026-08-05

### Changed
- Dependencies upgraded to their latest versions (`bcrypt` ^6.0.0,
  `jsonwebtoken` ^9.0.3, `vitest` ^4.1.10, and related dev dependencies).

### Note
No new features or API changes in this release — dependency maintenance
only. The version number was bumped as part of this update, which is why
the refresh-token-rotation feature (originally planned as "v0.2" in the
project roadmap) shipped afterward as v0.2.1 instead.

## [0.1.0] - Initial release

### Added
- Password hashing/verification (`hashPassword`, `verifyPassword`) — bcrypt, cost factor 12.
- JWT access/refresh token issuance and verification, with separate
  secrets per token type and a `type` claim to prevent token-confusion attacks.
- Express middleware: `authMiddleware`, `requireRole(role)`.