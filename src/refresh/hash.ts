// src/refresh/hash.ts
import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Hashes a refresh token for storage/lookup.
 *
 * Uses SHA-256 rather than bcrypt: refresh tokens are already
 * high-entropy random values (signed JWTs), not human-chosen passwords,
 * so bcrypt's deliberate slowness and per-call random salt would only
 * add latency while breaking hash-based lookup (bcrypt never produces
 * the same output twice for the same input).
 *
 * @throws {TypeError} If token is not a non-empty string.
 */
export function hashRefreshToken(token: string): string {
  if (typeof token !== "string" || token.length === 0) {
    throw new TypeError("hashRefreshToken: token must be a non-empty string");
  }

  return createHash("sha256").update(token).digest("hex");
}

/**
 * Checks a raw refresh token against a stored hash using a constant-time
 * comparison — protects against timing attacks the same way
 * `verifyPassword` does via bcrypt.compare, just with a manual
 * constant-time check since SHA-256 has no built-in compare function.
 *
 * @throws {TypeError} If token or hash is not a non-empty string.
 */
export function verifyRefreshTokenHash(token: string, hash: string): boolean {
  if (typeof token !== "string" || token.length === 0) {
    throw new TypeError(
      "verifyRefreshTokenHash: token must be a non-empty string"
    );
  }

  if (typeof hash !== "string" || hash.length === 0) {
    throw new TypeError(
      "verifyRefreshTokenHash: hash must be a non-empty string"
    );
  }

  const computed = createHash("sha256").update(token).digest();
  const stored = Buffer.from(hash, "hex");

  // Different lengths would make timingSafeEqual throw rather than
  // return false — guard explicitly so a malformed hash fails safely.
  if (computed.length !== stored.length) {
    return false;
  }

  return timingSafeEqual(computed, stored);
}