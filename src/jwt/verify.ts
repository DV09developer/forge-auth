import jwt from "jsonwebtoken";
import type { TokenPayload } from "../types/index.js";
import { getAccessTokenSecret, getRefreshTokenSecret } from "./config.js";

const ISSUER = "simple-auth";

/**
 * Verifies a raw JWT and returns its decoded payload, using the given
 * secret. Pins the algorithm to HS256 to prevent algorithm confusion
 * attacks, and checks the issuer claim.
 */
function verifyToken(token: string, secret: string): TokenPayload {
  if (typeof token !== "string" || token.length === 0) {
    throw new TypeError("token must be a non-empty string");
  }

  try {
    const decoded = jwt.verify(token, secret, {
      algorithms: ["HS256"],
      issuer: ISSUER,
    });

    // jwt.verify can technically return a string; our tokens are always
    // signed with an object payload, so this should never happen in
    // practice, but we guard for type safety.
    if (typeof decoded === "string") {
      throw new Error("Malformed token payload");
    }

    return decoded as TokenPayload;
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw new Error("Token has expired");
    }
    if (err instanceof jwt.JsonWebTokenError) {
      throw new Error(`Invalid token: ${err.message}`);
    }
    throw err;
  }
}

/**
 * Verifies an access token and returns its decoded payload.
 * Rejects tokens whose `type` claim is not `"access"` (e.g. a refresh
 * token presented in its place), even if the signature is valid.
 *
 * @throws {Error} If the token is invalid, expired, or not an access token.
 *
 * @example
 * const payload = verifyAccessToken(token);
 * console.log(payload.sub); // user id
 */
export function verifyAccessToken(token: string): TokenPayload {
  const secret = getAccessTokenSecret();
  const payload = verifyToken(token, secret);

  if (payload.type !== "access") {
    throw new Error("Token is not an access token");
  }

  return payload;
}

/**
 * Verifies a refresh token and returns its decoded payload.
 * Rejects tokens whose `type` claim is not `"refresh"`.
 *
 * @throws {Error} If the token is invalid, expired, or not a refresh token.
 *
 * @example
 * const payload = verifyRefreshToken(refreshToken);
 */
export function verifyRefreshToken(token: string): TokenPayload {
  const secret = getRefreshTokenSecret();
  const payload = verifyToken(token, secret);

  if (payload.type !== "refresh") {
    throw new Error("Token is not a refresh token");
  }

  return payload;
}