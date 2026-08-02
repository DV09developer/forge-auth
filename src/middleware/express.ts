import type { TokenPayload } from "../types/index.js";

/**
 * Augments Express's Request type so `req.user` is available and typed
 * after `authMiddleware` runs. `undefined` before authentication (or on
 * routes that don't use the middleware) — do not assume it always exists.
 */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

export {};
