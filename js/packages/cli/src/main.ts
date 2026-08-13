import process from "node:process";
import { buildProgram } from "./program.js";

const program = buildProgram();
try {
  await program.parseAsync(process.argv);
} catch (e) {
  // commander's exitOverride throws for --help/--version too; those carry
  // exitCode 0 and must not be reported as errors.
  const err = e as { exitCode?: number; code?: string; message?: string };
  if (err.code === "commander.helpDisplayed" || err.code === "commander.version") {
    process.exit(0);
  }
  process.stderr.write(`error: ${err.message ?? String(e)}\n`);
  process.exit(typeof err.exitCode === "number" && err.exitCode !== 0 ? err.exitCode : 1);
}
