import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { authMiddleware } from "../src/middleware/authenticate.js";
import { requireRole } from "../src/middleware/requireRole.js";
import { createAccessToken } from "../src/jwt/sign.js";

const TEST_ACCESS_SECRET = "c".repeat(32);
const TEST_REFRESH_SECRET = "d".repeat(32);

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

/** Builds a minimal mock Express Response with spy-able status/json chain. */
function mockResponse() {
  const res: Partial<Response> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as Response;
}

describe("authMiddleware", () => {
  it("responds 401 when Authorization header is missing", () => {
    const req = { headers: {} } as Request;
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: "Missing or malformed Authorization header",
    });
    expect(next).not.toHaveBeenCalled();
  });

  it("responds 401 when Authorization header has no Bearer prefix", () => {
    const req = { headers: { authorization: "Basic abc123" } } as Request;
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("sets req.user and calls next() for a valid token", () => {
    const token = createAccessToken({ id: "user-123" });
    const req = { headers: { authorization: `Bearer ${token}` } } as Request;
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req, res, next);

    expect(req.user).toBeDefined();
    expect(req.user?.sub).toBe("user-123");
    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("responds 401 with an error message for an invalid token", () => {
    const req = {
      headers: { authorization: "Bearer not-a-real-token" },
    } as Request;
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.any(String) })
    );
    expect(next).not.toHaveBeenCalled();
  });
});

describe("requireRole", () => {
  it("responds 401 when req.user is not set (not authenticated)", () => {
    const req = {} as Request;
    const res = mockResponse();
    const next = vi.fn();

    requireRole("admin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: "Not authenticated" });
    expect(next).not.toHaveBeenCalled();
  });

  it("responds 403 when the user's role does not match", () => {
    const req = { user: { sub: "user-123", type: "access", role: "user" } } as Request;
    const res = mockResponse();
    const next = vi.fn();

    requireRole("admin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: "Insufficient permissions" });
    expect(next).not.toHaveBeenCalled();
  });

  it("calls next() when the user's role matches", () => {
    const req = { user: { sub: "user-123", type: "access", role: "admin" } } as Request;
    const res = mockResponse();
    const next = vi.fn();

    requireRole("admin")(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });
});
