// src/refresh/issue.ts
import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { createRefreshToken } from "../jwt/sign.js";
import { hashRefreshToken } from "./hash.js";
import { defaultRefreshStore } from "./store.js";
import type { AuthUser } from "../types/index.js";
import type { RefreshTokenStore } from "./types.js";

/**
 * Issues a new, tracked refresh token — the start of a rotation "family".
 * Use this at login instead of the untracked `createRefreshToken()` if you
 * want rotation and reuse detection (see `rotateRefreshToken`).
 *
 * @param user - Must have at least an `id` field.
 * @param options.store - Custom store (defaults to the shared in-memory store).
 *
 * @example
 * const refreshToken = await issueRefreshToken({ id: user.id });
 */
export async function issueRefreshToken(
  user: AuthUser,
  options: { store?: RefreshTokenStore } = {},
): Promise<string> {
  const store = options.store ?? defaultRefreshStore;
  const token = createRefreshToken(user);

  // Extract the real expiry from the signed token rather than
  // recomputing it, so the store record always matches the JWT's
  // actual `exp` claim even if REFRESH_TOKEN_EXPIRY ever changes.
  const decoded = jwt.decode(token) as { exp?: number } | null;
  const expiresAt = decoded?.exp ? decoded.exp * 1000 : Date.now();

  await store.save({
    tokenHash: hashRefreshToken(token),
    familyId: randomUUID(),
    userId: user.id,
    status: "active",
    createdAt: Date.now(),
    expiresAt,
  });

  return token;
}
