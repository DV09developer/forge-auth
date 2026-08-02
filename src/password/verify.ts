import bcrypt from "bcrypt";

/**
 * Verifies a plaintext password against a bcrypt hash.
 *
 * Uses bcrypt's constant-time comparison internally, which protects against
 * timing attacks (an attacker measuring response time to infer whether
 * partial guesses are correct). Never compare hashes with `===`.
 *
 * @param password - The plaintext password to check.
 * @param hash - The bcrypt hash to check against (from `hashPassword`).
 * @returns `true` if the password matches the hash, `false` otherwise.
 * @throws {TypeError} If password or hash is not a non-empty string.
 *
 * @example
 * const isValid = await verifyPassword("user-input", storedHash);
 * if (!isValid) {
 *   // reject login
 * }
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  if (typeof password !== "string" || password.length === 0) {
    throw new TypeError("verifyPassword: password must be a non-empty string");
  }

  if (typeof hash !== "string" || hash.length === 0) {
    throw new TypeError("verifyPassword: hash must be a non-empty string");
  }

  return bcrypt.compare(password, hash);
}