import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../jwt/verify.js";
import "./express.js";

const BEARER_PREFIX = "Bearer ";

/**
 * Express middleware that authenticates a request using a bearer access
 * token from the `Authorization` header. On success, attaches the decoded
 * payload to `req.user` and calls `next()`. On failure, responds with 401
 * and a JSON error body — it never throws or falls through to Express's
 * default error handler.
 *
 * @example
 * app.use(authMiddleware);
 *
 * app.get("/profile", (req, res) => {
 *   res.json({ userId: req.user.sub });
 * });
 */
export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const header = req.headers.authorization;

  if (!header || !header.startsWith(BEARER_PREFIX)) {
    res.status(401).json({ error: "Missing or malformed Authorization header" });
    return;
  }

  const token = header.slice(BEARER_PREFIX.length).trim();

  if (token.length === 0) {
    res.status(401).json({ error: "Missing or malformed Authorization header" });
    return;
  }

  try {
    req.user = verifyAccessToken(token);
    next();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Invalid token";
    res.status(401).json({ error: message });
  }
}