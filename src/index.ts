// forge-auth — public API
// Only what is exported from this file is visible to consumers of the package.
// Internal helpers in `utils/` are intentionally NOT re-exported here.

// --- Password module (v0.1) ---
export { hashPassword, verifyPassword } from "./password/index.js";

// --- JWT module (v0.1) ---
export {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "./jwt/index.js";

// --- Middleware module (v0.1) ---
export { authMiddleware, requireRole } from "./middleware/index.js";

// --- Refresh token rotation module (v0.2.1) ---
export {
  issueRefreshToken,
  rotateRefreshToken,
  revokeSession,
  revokeAllSessions,
  createRefreshStore,
} from "./refresh/index.js";
export type {
  RotatedTokens,
  RefreshTokenStore,
  RefreshTokenRecord,
  RefreshTokenStatus,
} from "./refresh/index.js";

// --- Shared types ---
export type * from "./types/index.js";