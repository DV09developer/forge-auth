import type { Request, Response, NextFunction } from "express";

/**
 * Express middleware factory that restricts a route to users with a
 * specific role. Must run after `authMiddleware` (which populates
 * `req.user`). The role must have been embedded at token creation time
 * via `createAccessToken(user, { role })`.
 *
 * Responds 401 if the request isn't authenticated at all, or 403 if it's
 * authenticated but lacks the required role.
 *
 * For declarative multi-permission checks beyond a single role, see the
 * planned RBAC module (v0.3) — this middleware intentionally stays narrow.
 *
 * @param role - The role required to access the route.
 *
 * @example
 * app.get("/admin", authMiddleware, requireRole("admin"), controller);
 */
export function requireRole(role: string) {
  return function (req: Request, res: Response, next: NextFunction): void {
    if (!req.user) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }

    if (req.user.role !== role) {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }

    next();
  };
}
