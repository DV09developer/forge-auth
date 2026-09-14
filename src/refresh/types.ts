// src/refresh/types.ts

/**
 * Lifecycle state of a stored refresh token.
 * - "active": currently valid, has not been rotated or revoked.
 * - "rotated": exchanged for a new token; presenting it again is a reuse attack.
 * - "revoked": manually invalidated (logout) or auto-revoked (reuse detected).
 */
export type RefreshTokenStatus = "active" | "rotated" | "revoked";

/**
 * A stored record for one issued refresh token.
 * The raw token is never stored — only its hash (see refresh/hash.ts),
 * mirroring the password module's "never store the plaintext" principle.
 */
export interface RefreshTokenRecord {
  /** Hash of the refresh token string (lookup key). */
  tokenHash: string;
  /** Groups all rotations of a single login session together. */
  familyId: string;
  /** The user this token belongs to. */
  userId: string;
  status: RefreshTokenStatus;
  /** Unix ms timestamp when this record was created. */
  createdAt: number;
  /** Unix ms timestamp when this token expires. */
  expiresAt: number;
}

/**
 * Storage contract for refresh token records. The in-memory implementation
 * (v0.2.1) and any future Redis/Postgres/Mongo adapter (v1.0) both
 * implement this same interface — consumers and internal logic never
 * depend on the storage mechanism directly.
 */
export interface RefreshTokenStore {
  save(record: RefreshTokenRecord): Promise<void>;
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  updateStatus(tokenHash: string, status: RefreshTokenStatus): Promise<void>;
  /** Revokes every record sharing a familyId — used on reuse detection. */
  revokeFamily(familyId: string): Promise<void>;
  /** Revokes every record for a user — used for "log out everywhere". */
  revokeAllForUser(userId: string): Promise<void>;
}