// src/refresh/revoke.ts
import { hashRefreshToken } from "./hash.js";
import { defaultRefreshStore } from "./store.js";
import type { RefreshTokenStore } from "./types.js";

/**
 * Revokes the session a specific refresh token belongs to — i.e. "log out
 * this device". Also revokes any other token in the same rotation family
 * (e.g. if this token had already been rotated forward), so a stale
 * token can't be used to keep the session alive.
 *
 * Silently succeeds if the token is unrecognized or already revoked —
 * logout should never fail loudly just because the token was already
 * gone (double logout, expired session, etc.).
 *
 * @example
 * await revokeSession(refreshTokenFromCookie);
 */
export async function revokeSession(
  token: string,
  options: { store?: RefreshTokenStore } = {}
): Promise<void> {
  const store = options.store ?? defaultRefreshStore;

  const record = await store.findByHash(hashRefreshToken(token));
  if (!record) {
    return;
  }

  await store.revokeFamily(record.familyId);
}

/**
 * Revokes every refresh session for a user — i.e. "log out everywhere".
 * Use this for a user-initiated "log out all devices" action, or as an
 * incident response if an account is suspected compromised.
 *
 * @example
 * await revokeAllSessions(user.id);
 */
export async function revokeAllSessions(
  userId: string,
  options: { store?: RefreshTokenStore } = {}
): Promise<void> {
  const store = options.store ?? defaultRefreshStore;
  await store.revokeAllForUser(userId);
}