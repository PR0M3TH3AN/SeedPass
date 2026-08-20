import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Parity cases run real KDFs — PBKDF2 at 100k iterations per password
    // case, Argon2id for the KDF fixtures. The 5s default is unrealistic for
    // these, especially in the jsdom run or on a loaded machine.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
