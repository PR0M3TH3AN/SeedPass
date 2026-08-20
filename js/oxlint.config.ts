import { defineConfig } from "oxlint";

/**
 * Lint gate for the TypeScript port.
 *
 * WHAT THIS IS AND IS NOT
 *
 * The rules under tools/oxlint/anti-slop are vendored from
 * github.com/dmmulroy/anti-slop, which offers fifteen. TWO are enabled. The
 * rest were measured against this codebase and rejected, and the reasons are
 * worth keeping because "why is this off" is the question a future reader
 * will actually have:
 *
 *   no-conditional-empty-object-spread -- 77 hits, all of them correct.
 *     `...(x !== undefined && { key: x })` is the idiom REQUIRED by
 *     exactOptionalPropertyTypes, which tsconfig.base.json turns on. The rule
 *     would fight the compiler settings.
 *
 *   no-unsafe-dictionary-type (123 hits) and no-runtime-typeof (53) -- these
 *     are overwhelmingly the agent's socket protocol: `Record<string,
 *     unknown>` for an untrusted message, then explicit `typeof x !==
 *     "string"` checks per field. That IS boundary validation, which is what
 *     both rules ask for. Typing the wire message more precisely would be
 *     false confidence at the one place honesty about untrusted input matters
 *     most.
 *
 *   no-module-mocking, no-reflect-get, no-reflect-apply -- zero hits. The
 *     suite already uses real dependency seams: real daemons, real sockets,
 *     real temp directories. Nothing to enforce.
 *
 *   require-safety-comment-for-type-assertion -- 220 hits. Plausible for this
 *     codebase, which comments heavily already, but not until the number
 *     comes down. Revisit.
 *
 * The two that are on both point at the same thing: an assertion that
 * fabricates certainty the code never established. That is the failure mode
 * this vault cannot afford, because a wrong belief about a decrypted record's
 * shape is a wrong belief about someone's secrets.
 */
export default defineConfig({
  ignorePatterns: [
    "**/dist/**",
    "**/node_modules/**",
    "packages/test-vectors/fixtures/**",
    // The vendored rules are third-party source we do not police.
    "tools/oxlint/anti-slop/**",
  ],
  jsPlugins: [
    { name: "anti-slop", specifier: "./tools/oxlint/anti-slop/index.ts" },
  ],
  rules: {
    // `x as unknown as T` launders an unproven claim into a certainty. Either
    // the precise type survives, or the value is parsed at its boundary.
    "anti-slop/no-chained-type-assertions": "error",
    // Widening a known value and asserting it back is the same move spread
    // across two statements.
    "anti-slop/no-widen-then-assert": "error",
  },
  overrides: [
    {
      // Tests may construct deliberately malformed values -- that is what a
      // test of a validator IS. Policing them would push toward testing only
      // shapes the type system already permits, which is the opposite of the
      // point.
      files: ["**/test/**", "**/*.test.ts"],
      rules: {
        "anti-slop/no-chained-type-assertions": "off",
        "anti-slop/no-widen-then-assert": "off",
      },
    },
  ],
});
