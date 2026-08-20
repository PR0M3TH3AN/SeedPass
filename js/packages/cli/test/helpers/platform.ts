/**
 * Platform guards for tests, with the reason attached to each.
 *
 * These exist so a skip is a stated decision rather than a quiet gap. The
 * JavaScript suite first ran on Windows and macOS on 2026-08-20 and produced
 * seventeen failures. Most were real bugs and got fixed — a Windows path
 * containment check that refused everything, a command parser that ate
 * backslashes, tests naming `/bin/true` and `cat`. What is left behind these
 * constants are the cases where the property under test does not exist on
 * that platform at all.
 *
 * Use as `it.skipIf(NO_POSIX_PERMISSIONS)("...", ...)`.
 */

import process from "node:process";

export const IS_WINDOWS = process.platform === "win32";

/**
 * POSIX mode bits — every `0600` assertion.
 *
 * Windows has no such thing: `chmod` toggles a read-only flag and `stat`
 * reports 0o666 whatever you asked for, so these assertions cannot hold.
 * Skipped rather than relaxed, because the property is real and a weakened
 * assertion would answer it falsely.
 *
 * Skipping does NOT answer the underlying question, which is tracked in
 * TODO.md: on Windows these files inherit directory ACLs instead of carrying
 * an explicit owner-only mode, and the vault index, the semantic index and
 * the recovery-drill key all hold secrets. Verifying that the inherited ACL
 * is user-scoped, and asserting THAT on Windows, is the real fix.
 */
export const NO_POSIX_PERMISSIONS = IS_WINDOWS;

/**
 * A working system clipboard.
 *
 * The Windows CI runner is headless and has none, so clipboardSink writes
 * nowhere and reads back empty. Nothing about the code is wrong; there is no
 * clipboard to put a secret on.
 */
export const NO_CLIPBOARD = IS_WINDOWS;
