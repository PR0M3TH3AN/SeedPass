export { buildProgram, type ProgramIo } from "./program.js";
export { openVault, saveVault, type OpenedVault } from "./vaultFile.js";
export { resolveEntry, entryMetadata, refFor, parseRef, REF_PREFIX } from "./refs.js";
export { materializeSecret } from "./secrets.js";
export { execSink, stdinSink, clipboardSink, EXEC_ENV_VAR } from "./sinks.js";
export { capabilities } from "./capabilities.js";
