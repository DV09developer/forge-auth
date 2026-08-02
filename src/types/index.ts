// Shared types used across modules (password, jwt, middleware).
// Populated as each module is built.

/**
 * Minimal user shape required to issue a token.
 * Only `id` is required — this toolkit has no user model, so consumers
 * may attach any additional fields relevant to their app (e.g. `role`).
 */
export interface AuthUser {
  id: string;
  [key: string]: unknown;
}

/**
 * The type of JWT — embedded in the payload itself so a refresh token
 * can never be mistakenly accepted where an access token is expected,
 * and vice versa (prevents token confusion attacks).
 */
export type TokenType = "access" | "refresh";

/**
 * Decoded shape of tokens issued by this library.
 * `sub` (subject) follows the standard JWT claim convention for user id.
 */
export interface TokenPayload {
  sub: string;
  type: TokenType;
  [key: string]: unknown;
}