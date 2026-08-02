import { describe, it, expect } from "vitest";
import { hashPassword } from "../src/password/hash.js";
import { verifyPassword } from "../src/password/verify.js";

describe("hashPassword", () => {
  it("produces a bcrypt-formatted hash", async () => {
    const hash = await hashPassword("correct horse battery staple");
    // bcrypt hashes start with $2b$ (or $2a$/$2y$) followed by cost factor
    expect(hash).toMatch(/^\$2[aby]\$\d{2}\$/);
  });

  it("produces different hashes for the same password (salting)", async () => {
    const hash1 = await hashPassword("same-password");
    const hash2 = await hashPassword("same-password");
    expect(hash1).not.toBe(hash2);
  });

  it("throws TypeError for empty password", async () => {
    await expect(hashPassword("")).rejects.toThrow(TypeError);
  });

  it("throws TypeError for non-string password", async () => {
    // @ts-expect-error intentionally testing invalid input at runtime
    await expect(hashPassword(12345)).rejects.toThrow(TypeError);
  });
});

describe("verifyPassword", () => {
  it("returns true for the correct password", async () => {
    const hash = await hashPassword("my-secret-password");
    const result = await verifyPassword("my-secret-password", hash);
    expect(result).toBe(true);
  });

  it("returns false for an incorrect password", async () => {
    const hash = await hashPassword("my-secret-password");
    const result = await verifyPassword("wrong-password", hash);
    expect(result).toBe(false);
  });

  it("throws TypeError for empty password", async () => {
    const hash = await hashPassword("some-password");
    await expect(verifyPassword("", hash)).rejects.toThrow(TypeError);
  });

  it("throws TypeError for empty hash", async () => {
    await expect(verifyPassword("some-password", "")).rejects.toThrow(TypeError);
  });

  // Note: timing-attack resistance is provided by bcrypt.compare internally
  // and isn't meaningfully testable in a unit test (timing noise). Covered
  // by using bcrypt.compare rather than manual string comparison in verify.ts.
});