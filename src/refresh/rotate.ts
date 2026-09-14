// src/refresh/rotate.ts
import jwt from "jsonwebtoken";
import { verifyRefreshToken } from "../jwt/verify.js";
import { createAccessToken, createRefreshToken } from "../jwt/sign.js";
import { hashRefreshToken } from "./hash.js";
import { defaultRefreshStore } from "./store.js";
import type { RefreshTokenStore } from "./types.js";

export interface RotatedTokens {
  accessToken: string;
  refreshToken: string;
}

/**
 * Exchanges a valid, active refresh token for a new access+refresh pair.
 *
 * Reuse detection: if the given token was already rotated (or revoked)
 * before, presenting it again strongly suggests it was stolen — the
 * entire token family is revoked immediately, forcing re-login.
 *
 * @throws {Error} If the token is invalid/expired (from verifyRefreshToken),
 *   unrecognized by the store, expired per the store record, already
 *   revoked, or reused (triggers family revocation).
 *
 * @example
 * const { accessToken, refreshToken } = await rotateRefreshToken(oldToken);
 */
export async function rotateRefreshToken(
  token: string,
  options: { store?: RefreshTokenStore } = {}
): Promise<RotatedTokens> {
  const store = options.store ?? defaultRefreshStore;

  // Signature, expiry, and type("refresh") checks — reuses existing
  // battle-tested verification rather than re-implementing it.
  const payload = verifyRefreshToken(token);

  const tokenHash = hashRefreshToken(token);
  const record = await store.findByHash(tokenHash);

  if (!record) {
    throw new Error("Refresh token not recognized");
  }

  // Independent expiry check against the store record itself — defense
  // in depth. In practice this mirrors the JWT's own exp claim today
  // (see issue.ts), but the store should never blindly trust that a
  // valid JWT signature also means its tracked record hasn't expired,
  // since future storage adapters (v1.0) may set TTLs independently.
  if (record.expiresAt <= Date.now()) {
    await store.updateStatus(tokenHash, "revoked");
    throw new Error("Refresh token has expired");
  }

  if (record.status === "revoked") {
    throw new Error("Refresh token has been revoked");
  }

  if (record.status === "rotated") {
    // This exact token was already exchanged once before. Being
    // presented again means it leaked (e.g. stolen + replayed) —
    // the whole family is compromised, not just this one token.
    await store.revokeFamily(record.familyId);
    throw new Error("Refresh token reuse detected — session revoked");
  }

  // Legitimate rotation: retire this token, issue a new one in the
  // same family so the lineage (and reuse detection) continues.
  await store.updateStatus(tokenHash, "rotated");

  const newRefreshToken = createRefreshToken({ id: payload.sub });
  const decoded = jwt.decode(newRefreshToken) as { exp?: number } | null;
  const expiresAt = decoded?.exp ? decoded.exp * 1000 : Date.now();

  await store.save({
    tokenHash: hashRefreshToken(newRefreshToken),
    familyId: record.familyId,
    userId: record.userId,
    status: "active",
    createdAt: Date.now(),
    expiresAt,
  });

  return {
    accessToken: createAccessToken({ id: payload.sub }),
    refreshToken: newRefreshToken,
  };
}