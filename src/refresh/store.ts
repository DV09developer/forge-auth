// src/refresh/store.ts
import type {
  RefreshTokenRecord,
  RefreshTokenStatus,
  RefreshTokenStore,
} from "./types.js";

/**
 * Default in-memory implementation of RefreshTokenStore.
 *
 * ⚠️ Not suitable for multi-process/serverless deployments — state is
 * lost on restart and not shared across instances. Fine for single-process
 * apps, development, and testing. A persistent adapter (Redis/Postgres/
 * Mongo) is planned for v1.0.
 */
export class InMemoryRefreshStore implements RefreshTokenStore {
  private records = new Map<string, RefreshTokenRecord>();

  async save(record: RefreshTokenRecord): Promise<void> {
    this.records.set(record.tokenHash, record);
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    return this.records.get(tokenHash) ?? null;
  }

  async updateStatus(
    tokenHash: string,
    status: RefreshTokenStatus
  ): Promise<void> {
    const record = this.records.get(tokenHash);
    if (record) {
      record.status = status;
    }
  }

  async revokeFamily(familyId: string): Promise<void> {
    for (const record of this.records.values()) {
      if (record.familyId === familyId) {
        record.status = "revoked";
      }
    }
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const record of this.records.values()) {
      if (record.userId === userId) {
        record.status = "revoked";
      }
    }
  }
}

/**
 * Creates a new, isolated in-memory store.
 *
 * Use this in tests (one fresh store per test = no cross-test state
 * leakage) or in apps that intentionally want a separate store scope
 * (e.g. multi-tenant setups keeping tenants isolated in-process).
 *
 * @example
 * // In a test file:
 * const store = createRefreshStore();
 * const token = await rotateRefreshToken(oldToken, { store });
 */
export function createRefreshStore(): RefreshTokenStore {
  return new InMemoryRefreshStore();
}

/**
 * Shared default store instance used by rotateRefreshToken() and friends
 * when no custom store is supplied via the optional `{ store }` parameter.
 * This is what keeps the common-case API boilerplate-free:
 * `rotateRefreshToken(token)` — no setup required.
 *
 * Advanced consumers (or v1.0 persistent adapters) can override this per
 * call without any breaking change to the function signature.
 */
export const defaultRefreshStore: RefreshTokenStore = createRefreshStore();