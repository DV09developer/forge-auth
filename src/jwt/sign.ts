import jwt from "jsonwebtoken";
import type { AuthUser } from "../types/index.js";
import {
  getAccessTokenSecret,
  getRefreshTokenSecret,
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY,
} from "./config.js";
import { randomUUID } from "crypto";

const ISSUER = "forge-auth";

/**
 * Creates a short-lived access token for the given user.
 *
 * Only `user.id` is embedded (as the standard `sub` claim). Other user
 * fields are intentionally NOT included — JWT payloads are base64-encoded,
 * not encrypted, so anything embedded is readable by anyone holding the
 * token.
 *
 * @param user - Must have at least an `id` field.
 * @returns A signed JWT string, valid for 15 minutes.
 * @throws {Error} If `JWT_ACCESS_SECRET` is missing or too short.
 *
 * @example
 * const token = createAccessToken({ id: user.id });
 */
export function createAccessToken(
  user: AuthUser,
  extraClaims: Record<string, unknown> = {}
): string {
  const secret = getAccessTokenSecret();

  return jwt.sign({ ...extraClaims, sub: user.id, type: "access" }, secret, {
    algorithm: "HS256",
    expiresIn: ACCESS_TOKEN_EXPIRY,
    issuer: ISSUER,
  });
}

/**
 * Creates a long-lived refresh token for the given user.
 *
 * Refresh tokens should be stored securely by the consumer (e.g. httpOnly
 * cookie) and exchanged for new access tokens via `verifyRefreshToken`.
 * Rotation and reuse detection are handled in the refresh module (v0.2) —
 * this function only issues the token.
 *
 * @param user - Must have at least an `id` field.
 * @returns A signed JWT string, valid for 7 days.
 * @throws {Error} If `JWT_REFRESH_SECRET` is missing or too short.
 *
 * @example
 * const token = createRefreshToken({ id: user.id });
 */
export function createRefreshToken(user: AuthUser): string {
  const secret = getRefreshTokenSecret();

  return jwt.sign({ sub: user.id, type: "refresh", jti: randomUUID() }, secret, {
    algorithm: "HS256",
    expiresIn: REFRESH_TOKEN_EXPIRY,
    issuer: ISSUER,
  });
}