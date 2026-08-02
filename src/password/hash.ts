import bcrypt from "bcrypt";

/**
 * Cost factor for bcrypt hashing.
 * 12 is the current OWASP-recommended minimum — high enough to resist
 * brute-force attacks, low enough to avoid excessive server load.
 * Not exposed as a parameter: consumers shouldn't need to choose this.
 */
const SALT_ROUNDS = 12;

/**
 * Hashes a plaintext password using bcrypt with a secure default cost factor.
 *
 * @param password - The plaintext password to hash. Must be a non-empty string.
 * @returns A bcrypt hash string (includes algorithm, cost factor, and salt).
 * @throws {TypeError} If password is not a non-empty string.
 *
 * @example
 * const hash = await hashPassword("correct horse battery staple");
 */
export async function hashPassword(password: string): Promise<string> {
  if (typeof password !== "string" || password.length === 0) {
    throw new TypeError("hashPassword: password must be a non-empty string");
  }

  return bcrypt.hash(password, SALT_ROUNDS);
}