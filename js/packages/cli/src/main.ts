import process from "node:process";
import { buildProgram } from "./program.js";

// Replaced at bundle time; falls back for source runs (tsx / vitest).
declare const __SEEDPASS_VERSION__: string | undefined;
const version = typeof __SEEDPASS_VERSION__ === "string" ? __SEEDPASS_VERSION__ : "0.0.0-dev";

const program = buildProgram();
program.version(version, "-v, --version", "print the seedpass-js version");
try {
  await program.parseAsync(process.argv);
} catch (e) {
  const err = e as { exitCode?: number; code?: string; message?: string };

  // exitOverride() makes commander throw for everything it would otherwise
  // exit on — including displaying help or the version, and its own usage
  // errors, which it has already written to stderr. Re-reporting those as
  // "error: ..." is wrong twice over: a bare `seedpass-js` printed the help
  // and then claimed to have failed with "(outputHelp)". Honour commander's
  // exit code, but let it own the message.
  if (typeof err.code === "string" && err.code.startsWith("commander.")) {
    process.exit(typeof err.exitCode === "number" ? err.exitCode : 0);
  }

  // Anything else is ours, and the message is the useful part.
  process.stderr.write(`error: ${err.message ?? String(e)}\n`);
  process.exit(typeof err.exitCode === "number" && err.exitCode !== 0 ? err.exitCode : 1);
}
