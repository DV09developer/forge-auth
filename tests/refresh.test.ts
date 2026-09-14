// tests/refresh.test.ts
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { issueRefreshToken } from "../src/refresh/issue.js";
import { rotateRefreshToken } from "../src/refresh/rotate.js";
import { revokeSession, revokeAllSessions } from "../src/refresh/revoke.js";
import { createRefreshStore } from "../src/refresh/store.js";
import type { RefreshTokenStore } from "../src/refresh/types.js";

const TEST_ACCESS_SECRET = "e".repeat(32);
const TEST_REFRESH_SECRET = "f".repeat(32);

let originalAccessSecret: string | undefined;
let originalRefreshSecret: string | undefined;

beforeAll(() => {
  originalAccessSecret = process.env.JWT_ACCESS_SECRET;
  originalRefreshSecret = process.env.JWT_REFRESH_SECRET;
  process.env.JWT_ACCESS_SECRET = TEST_ACCESS_SECRET;
  process.env.JWT_REFRESH_SECRET = TEST_REFRESH_SECRET;
});

afterAll(() => {
  process.env.JWT_ACCESS_SECRET = originalAccessSecret;
  process.env.JWT_REFRESH_SECRET = originalRefreshSecret;
});

// Fresh, isolated store per test — see Step 2's createRefreshStore().
let store: RefreshTokenStore;
beforeEach(() => {
  store = createRefreshStore();
});

describe("rotateRefreshToken — happy path", () => {
  it("returns a new access + refresh token pair", async () => {
    const initial = await issueRefreshToken({ id: "user-1" }, { store });
    const result = await rotateRefreshToken(initial, { store });

    expect(result.accessToken).toEqual(expect.any(String));
    expect(result.refreshToken).toEqual(expect.any(String));
    expect(result.refreshToken).not.toBe(initial);
  });

  it("allows the newly rotated token to be rotated again", async () => {
    const initial = await issueRefreshToken({ id: "user-1" }, { store });
    const first = await rotateRefreshToken(initial, { store });
    const second = await rotateRefreshToken(first.refreshToken, { store });

    expect(second.refreshToken).not.toBe(first.refreshToken);
  });
});

describe("rotateRefreshToken — reuse detection", () => {
  it("throws when a rotated (already-used) token is presented again", async () => {
    const initial = await issueRefreshToken({ id: "user-1" }, { store });
    await rotateRefreshToken(initial, { store }); // first, legitimate use

    // Same token used again — simulates a stolen/replayed token.
    await expect(rotateRefreshToken(initial, { store })).rejects.toThrow(
      /reuse detected/i
    );
  });

  it("revokes the entire family on reuse, invalidating the newer token too", async () => {
    const initial = await issueRefreshToken({ id: "user-1" }, { store });
    const rotated = await rotateRefreshToken(initial, { store });

    // Trigger reuse detection.
    await expect(rotateRefreshToken(initial, { store })).rejects.toThrow();

    // The legitimately-rotated token should now ALSO be dead, since the
    // whole family was revoked — this is the actual security guarantee.
    await expect(
      rotateRefreshToken(rotated.refreshToken, { store })
    ).rejects.toThrow(/revoked/i);
  });
});

describe("rotateRefreshToken — invalid inputs", () => {
  it("throws for a well-formed but unrecognized refresh token", async () => {
    // Signed correctly, but never stored via issueRefreshToken —
    // simulates a token the store has no record of.
    const { createRefreshToken } = await import("../src/jwt/sign.js");
    const untracked = createRefreshToken({ id: "user-1" });

    await expect(rotateRefreshToken(untracked, { store })).rejects.toThrow(
      /not recognized/i
    );
  });

  it("throws for a garbage token string", async () => {
    await expect(
      rotateRefreshToken("not-a-real-token", { store })
    ).rejects.toThrow();
  });
});

describe("revokeSession", () => {
  it("prevents further rotation of a revoked session", async () => {
    const token = await issueRefreshToken({ id: "user-2" }, { store });
    await revokeSession(token, { store });

    await expect(rotateRefreshToken(token, { store })).rejects.toThrow(
      /revoked/i
    );
  });

  it("does not throw for an unrecognized token (safe no-op)", async () => {
    await expect(
      revokeSession("unrecognized-token", { store })
    ).resolves.not.toThrow();
  });
});

describe("revokeAllSessions", () => {
  it("revokes every session for a user, but not other users' sessions", async () => {
    const tokenA = await issueRefreshToken({ id: "user-3" }, { store });
    const tokenB = await issueRefreshToken({ id: "user-3" }, { store }); // 2nd device
    const otherUserToken = await issueRefreshToken({ id: "user-4" }, { store });

    await revokeAllSessions("user-3", { store });

    await expect(rotateRefreshToken(tokenA, { store })).rejects.toThrow();
    await expect(rotateRefreshToken(tokenB, { store })).rejects.toThrow();

    // user-4's session must be untouched.
    await expect(
      rotateRefreshToken(otherUserToken, { store })
    ).resolves.toBeDefined();
  });
});

// tests/refresh.test.ts (add this describe block)

describe("rotateRefreshToken — expiry", () => {
  it("throws when the store record has expired, even if not yet revoked/rotated", async () => {
    const token = await issueRefreshToken({ id: "user-5" }, { store });

    // Manually age the record past expiry, simulating time passing
    // without needing to wait 7 real days or mock global Date.now().
    const { hashRefreshToken } = await import("../src/refresh/hash.js");
    const record = await store.findByHash(hashRefreshToken(token));
    if (record) {
      record.expiresAt = Date.now() - 1000; // 1 second in the past
    }

    await expect(rotateRefreshToken(token, { store })).rejects.toThrow(
      /expired/i
    );
  });

  it("marks an expired token's record as revoked as a side effect", async () => {
    const token = await issueRefreshToken({ id: "user-5" }, { store });
    const { hashRefreshToken } = await import("../src/refresh/hash.js");
    const hash = hashRefreshToken(token);

    const record = await store.findByHash(hash);
    if (record) {
      record.expiresAt = Date.now() - 1000;
    }

    await expect(rotateRefreshToken(token, { store })).rejects.toThrow();

    const updated = await store.findByHash(hash);
    expect(updated?.status).toBe("revoked");
  });
});