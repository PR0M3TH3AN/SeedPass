import { defineConfig } from "vitest/config";
import process from "node:process";

/**
 * The agent's transport is a Unix domain socket at a filesystem path, and its
 * access control IS the socket's 0600 mode. Node on Windows wants a named
 * pipe (`\\\\.\\pipe\\name`) for `server.listen(path)`, so a path like
 * `C:\...\agent.sock` fails with EACCES before a single assertion runs —
 * these four files die in beforeAll.
 *
 * Excluded here rather than skipped test by test, because the reason is one
 * fact about the platform and not a property of any individual test: the
 * session daemon does not run on Windows today. That is a real gap in a
 * product about to ship TypeScript as its only implementation, and it is
 * recorded in TODO.md — supporting it needs a named-pipe transport AND a
 * Windows answer to what 0600 on the socket was buying, which is a security
 * design question rather than a path substitution.
 */
const AGENT_TESTS = [
  "test/agentSecurity.test.ts",
  "test/tokens.test.ts",
  "test/highRisk.test.ts",
  "test/profiles.test.ts",
];

export default defineConfig({
  test: {
    // These tests exercise real KDFs: profile creation and unlock each run
    // PBKDF2 at 200k iterations (and Argon2id where configured), which
    // comfortably exceeds the 5s default once several files run in parallel.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    ...(process.platform === "win32" ? { exclude: ["**/node_modules/**", ...AGENT_TESTS] } : {}),
  },
});
