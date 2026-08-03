/**
 * Minimum acceptable length for JWT secrets, in characters.
 * Shorter secrets are meaningfully easier to brute-force.
 */
const MIN_SECRET_LENGTH = 32;

/** Access tokens are short-lived — limits damage if one is leaked. */
export const ACCESS_TOKEN_EXPIRY = "15m";

/** Refresh tokens are long-lived but rotated/revocable (see v0.2). */
export const REFRESH_TOKEN_EXPIRY = "7d";

/**
 * Reads and validates a JWT secret from an environment variable.
 * Throws immediately with a clear message if missing or too weak, rather
 * than allowing a silently insecure token to be issued.
 */
function readSecret(envVar: string): string {
  const secret = process.env[envVar];

  if (!secret) {
    throw new Error(
      `forge-auth: missing required environment variable "${envVar}". ` +
        `Set it to a random string of at least ${MIN_SECRET_LENGTH} characters.`
    );
  }

  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `forge-auth: "${envVar}" is too short (${secret.length} chars). ` +
        `Use at least ${MIN_SECRET_LENGTH} characters to resist brute-force attacks.`
    );
  }

  return secret;
}

/** Retrieves and validates the access token secret. */
export function getAccessTokenSecret(): string {
  return readSecret("JWT_ACCESS_SECRET");
}

/** Retrieves and validates the refresh token secret. */
export function getRefreshTokenSecret(): string {
  return readSecret("JWT_REFRESH_SECRET");
}