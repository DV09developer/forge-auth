import { describe, it, expect, beforeAll, afterAll } from "vitest";
import jwt from "jsonwebtoken";
import {
  createAccessToken,
  createRefreshToken,
} from "../src/jwt/sign.js";
import {
  verifyAccessToken,
  verifyRefreshToken,
} from "../src/jwt/verify.js";

const TEST_ACCESS_SECRET = "a".repeat(32);
const TEST_REFRESH_SECRET = "b".repeat(32);

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

describe("access tokens", () => {
  it("round-trips: sign then verify returns correct payload", () => {
    const token = createAccessToken({ id: "user-123" });
    const payload = verifyAccessToken(token);

    expect(payload.sub).toBe("user-123");
    expect(payload.type).toBe("access");
  });

  it("rejects a refresh token presented as an access token", () => {
    // Refresh tokens are signed with a different secret than access tokens,
    // so this fails signature verification first — the type-claim check is
    // a second, independent layer of defense in case secrets were ever
    // shared by mistake.
    const refreshToken = createRefreshToken({ id: "user-123" });
    expect(() => verifyAccessToken(refreshToken)).toThrow(/Invalid token/);
  });

  it("rejects an expired access token", () => {
    const expiredToken = jwt.sign(
      { sub: "user-123", type: "access" },
      TEST_ACCESS_SECRET,
      { algorithm: "HS256", expiresIn: "-1s", issuer: "forge-auth" }
    );

    expect(() => verifyAccessToken(expiredToken)).toThrow("Token has expired");
  });

  it("rejects a tampered token", () => {
    const token = createAccessToken({ id: "user-123" });
    const tampered = token.slice(0, -1) + (token.at(-1) === "a" ? "b" : "a");

    expect(() => verifyAccessToken(tampered)).toThrow(/Invalid token/);
  });
});

describe("refresh tokens", () => {
  it("round-trips: sign then verify returns correct payload", () => {
    const token = createRefreshToken({ id: "user-456" });
    const payload = verifyRefreshToken(token);

    expect(payload.sub).toBe("user-456");
    expect(payload.type).toBe("refresh");
  });

  it("rejects an access token presented as a refresh token", () => {
    // Same reasoning as above: different secret means this fails at
    // signature verification, before the type-claim check would run.
    const accessToken = createAccessToken({ id: "user-456" });
    expect(() => verifyRefreshToken(accessToken)).toThrow(/Invalid token/);
  });

  it("rejects a same-secret token with the wrong type claim", () => {
    // Directly tests the type-claim check in isolation: craft a token
    // signed with the correct refresh secret, but with type "access" —
    // this is the scenario the type check specifically guards against.
    const badToken = jwt.sign(
      { sub: "user-456", type: "access" },
      TEST_REFRESH_SECRET,
      { algorithm: "HS256", expiresIn: "7d", issuer: "forge-auth" }
    );
    expect(() => verifyRefreshToken(badToken)).toThrow(
      "Token is not a refresh token"
    );
  });
});

describe("secret validation", () => {
  it("throws a clear error when JWT_ACCESS_SECRET is missing", () => {
    const saved = process.env.JWT_ACCESS_SECRET;
    delete process.env.JWT_ACCESS_SECRET;

    expect(() => createAccessToken({ id: "user-789" })).toThrow(
      /missing required environment variable "JWT_ACCESS_SECRET"/
    );

    process.env.JWT_ACCESS_SECRET = saved;
  });

  it("throws a clear error when JWT_ACCESS_SECRET is too short", () => {
    const saved = process.env.JWT_ACCESS_SECRET;
    process.env.JWT_ACCESS_SECRET = "too-short";

    expect(() => createAccessToken({ id: "user-789" })).toThrow(
      /too short/
    );

    process.env.JWT_ACCESS_SECRET = saved;
  });
});