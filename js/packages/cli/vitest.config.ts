import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // These tests exercise real KDFs: profile creation and unlock each run
    // PBKDF2 at 200k iterations (and Argon2id where configured), which
    // comfortably exceeds the 5s default once several files run in parallel.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
