export { buildProgram, type ProgramIo } from "./program.js";
export { openVault, saveVault, type OpenedVault } from "./vaultFile.js";
export { resolveEntry, entryMetadata, refFor, parseRef, REF_PREFIX } from "./refs.js";
export { materializeSecret } from "./secrets.js";
export { execSink, stdinSink, clipboardSink, EXEC_ENV_VAR } from "./sinks.js";
export { capabilities } from "./capabilities.js";
export { AppDir, resolveAppDir, INDEX_FILENAME, CONFIG_FILENAME } from "./appDir.js";
export { loadConfig, saveConfig, defaultConfig, DEFAULT_RELAYS } from "./configFile.js";
export { AgentDaemon, AgentClient, agentSocketPath } from "./agent.js";
export { ApiServer, HttpError, resolveBind } from "./api/server.js";
export { registerRoutes, UNPORTED_PREFIXES, type ApiContext } from "./api/routes.js";
export { buildContext, serveApi } from "./api/serve.js";
export {
  setFactor,
  tagForFactor,
  verifyFactor,
  factorConfigured,
  readPartition,
  writePartition,
  partitionPath,
} from "./highRisk.js";
export {
  issueApproval,
  listApprovals,
  revokeApproval,
  consumeApproval,
  approvalRequired,
  VALID_APPROVAL_ACTIONS,
  type ApprovalRecord,
} from "./approvals.js";
