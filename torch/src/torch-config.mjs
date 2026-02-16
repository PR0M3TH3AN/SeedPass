import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_RELAYS,
  DEFAULT_TTL,
  DEFAULT_NAMESPACE,
  DEFAULT_QUERY_TIMEOUT_MS,
  DEFAULT_PUBLISH_TIMEOUT_MS,
  DEFAULT_MIN_SUCCESSFUL_PUBLISHES,
  DEFAULT_MIN_ACTIVE_RELAY_POOL,
} from './constants.mjs';

const DEFAULT_CONFIG_PATH = 'torch-config.json';

let cachedConfig = null;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 120_000;

function parsePositiveInteger(value) {
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.floor(value);
}

function parseRelayList(value) {
  if (!Array.isArray(value)) return null;
  const parsed = value.map((relay) => String(relay).trim()).filter(Boolean);
  return parsed.length > 0 ? parsed : null;
}

function assertValidRelayUrl(relay, sourceLabel) {
  let parsed;
  try {
    parsed = new URL(relay);
  } catch {
    throw new Error(`Invalid relay URL in ${sourceLabel}: "${relay}" (must be an absolute ws:// or wss:// URL)`);
  }
  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    throw new Error(`Invalid relay URL in ${sourceLabel}: "${relay}" (protocol must be ws:// or wss://)`);
  }
}

function assertTimeoutInRange(value, sourceLabel) {
  if (!Number.isInteger(value) || value < MIN_TIMEOUT_MS || value > MAX_TIMEOUT_MS) {
    throw new Error(
      `Invalid ${sourceLabel}: ${value} (must be an integer between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS} ms)`,
    );
  }
}

function assertPositiveCount(value, sourceLabel) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`Invalid ${sourceLabel}: ${value} (must be a positive integer)`);
  }
}

function normalizeCadence(value, fallback) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === 'daily' || normalized === 'weekly' || normalized === 'all' ? normalized : fallback;
}

function normalizeStatus(value, fallback) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === 'active' || normalized === 'all' ? normalized : fallback;
}

function parseRoster(value) {
  if (!Array.isArray(value)) return null;
  const parsed = value.map((item) => String(item).trim()).filter(Boolean);
  return parsed.length > 0 ? parsed : null;
}

export function getTorchConfigPath() {
  const explicitPath = (process.env.TORCH_CONFIG_PATH || '').trim();
  if (explicitPath) return path.resolve(process.cwd(), explicitPath);

  const localPath = path.resolve(process.cwd(), DEFAULT_CONFIG_PATH);
  if (fs.existsSync(localPath)) return localPath;

  const parentPath = path.resolve(process.cwd(), '..', DEFAULT_CONFIG_PATH);
  if (fs.existsSync(parentPath)) return parentPath;

  return localPath;
}

export function parseTorchConfig(raw, configPath = null) {
  const nostrLock = raw.nostrLock || {};
  const dashboard = raw.dashboard || {};
  const scheduler = raw.scheduler || {};
  const firstPromptByCadence = scheduler.firstPromptByCadence || {};
  const paused = scheduler.paused || {};

  return {
    configPath,
    raw,
    nostrLock: {
      namespace: typeof nostrLock.namespace === 'string' ? nostrLock.namespace.trim() : null,
      relays: Array.isArray(nostrLock.relays)
        ? nostrLock.relays.map((relay) => String(relay).trim()).filter(Boolean)
        : null,
      relayFallbacks: parseRelayList(nostrLock.relayFallbacks),
      ttlSeconds: Number.isFinite(nostrLock.ttlSeconds) && nostrLock.ttlSeconds > 0
        ? Math.floor(nostrLock.ttlSeconds)
        : null,
      queryTimeoutMs: parsePositiveInteger(nostrLock.queryTimeoutMs),
      publishTimeoutMs: parsePositiveInteger(nostrLock.publishTimeoutMs),
      minSuccessfulRelayPublishes: parsePositiveInteger(nostrLock.minSuccessfulRelayPublishes),
      minActiveRelayPool: parsePositiveInteger(nostrLock.minActiveRelayPool),
      dailyRoster: parseRoster(nostrLock.dailyRoster),
      weeklyRoster: parseRoster(nostrLock.weeklyRoster),
    },
    dashboard: {
      defaultCadenceView: normalizeCadence(dashboard.defaultCadenceView, 'daily'),
      defaultStatusView: normalizeStatus(dashboard.defaultStatusView, 'active'),
      relays: Array.isArray(dashboard.relays)
        ? dashboard.relays.map((relay) => String(relay).trim()).filter(Boolean)
        : null,
      namespace: typeof dashboard.namespace === 'string' ? dashboard.namespace.trim() : null,
      hashtag: typeof dashboard.hashtag === 'string' ? dashboard.hashtag.trim() : null,
    },
    scheduler: {
      firstPromptByCadence: {
        daily: typeof firstPromptByCadence.daily === 'string' ? firstPromptByCadence.daily.trim() : null,
        weekly: typeof firstPromptByCadence.weekly === 'string' ? firstPromptByCadence.weekly.trim() : null,
      },
      paused: {
        daily: parseRoster(paused.daily) || [],
        weekly: parseRoster(paused.weekly) || [],
      },
    },
  };
}

/** @internal */
export function _resetTorchConfigCache() {
  cachedConfig = null;
}

export function loadTorchConfig(fileSystem = fs) {
  if (cachedConfig) return cachedConfig;

  const configPath = getTorchConfigPath();
  let raw = {};

  if (fileSystem.existsSync(configPath)) {
    try {
      raw = JSON.parse(fileSystem.readFileSync(configPath, 'utf8'));
    } catch (err) {
      throw new Error(`Failed to parse ${configPath}: ${err.message}`, { cause: err });
    }
  }

  cachedConfig = parseTorchConfig(raw, configPath);
  validateLockBackendConfig(cachedConfig);
  return cachedConfig;
}

function validateLockBackendConfig(config) {
  const relays = config.nostrLock.relays || [];
  const relayFallbacks = config.nostrLock.relayFallbacks || [];

  for (const relay of relays) {
    assertValidRelayUrl(relay, 'nostrLock.relays');
  }
  for (const relay of relayFallbacks) {
    assertValidRelayUrl(relay, 'nostrLock.relayFallbacks');
  }

  if (config.nostrLock.queryTimeoutMs !== null) {
    assertTimeoutInRange(config.nostrLock.queryTimeoutMs, 'nostrLock.queryTimeoutMs');
  }
  if (config.nostrLock.publishTimeoutMs !== null) {
    assertTimeoutInRange(config.nostrLock.publishTimeoutMs, 'nostrLock.publishTimeoutMs');
  }
  if (config.nostrLock.minSuccessfulRelayPublishes !== null) {
    assertPositiveCount(config.nostrLock.minSuccessfulRelayPublishes, 'nostrLock.minSuccessfulRelayPublishes');
  }
  if (config.nostrLock.minActiveRelayPool !== null) {
    assertPositiveCount(config.nostrLock.minActiveRelayPool, 'nostrLock.minActiveRelayPool');
  }
}

function parseEnvRelayList(envValue, envName) {
  const relays = envValue.split(',').map((r) => r.trim()).filter(Boolean);
  for (const relay of relays) {
    assertValidRelayUrl(relay, envName);
  }
  return relays;
}

function parseEnvInteger(envValue, envName) {
  const parsed = parseInt(envValue, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid ${envName}: "${envValue}" (must be an integer)`);
  }
  return parsed;
}

export function getRelays() {
  const config = loadTorchConfig();
  const envRelays = process.env.NOSTR_LOCK_RELAYS;
  if (envRelays) {
    return parseEnvRelayList(envRelays, 'NOSTR_LOCK_RELAYS');
  }
  if (config.nostrLock.relays?.length) {
    return config.nostrLock.relays;
  }
  for (const relay of DEFAULT_RELAYS) {
    assertValidRelayUrl(relay, 'DEFAULT_RELAYS');
  }
  return DEFAULT_RELAYS;
}

export function getRelayFallbacks() {
  const config = loadTorchConfig();
  const envRelays = process.env.NOSTR_LOCK_RELAY_FALLBACKS;
  if (envRelays) {
    return parseEnvRelayList(envRelays, 'NOSTR_LOCK_RELAY_FALLBACKS');
  }
  return config.nostrLock.relayFallbacks || [];
}

export function getNamespace() {
  const config = loadTorchConfig();
  const namespace = (process.env.NOSTR_LOCK_NAMESPACE || config.nostrLock.namespace || DEFAULT_NAMESPACE).trim();
  return namespace || DEFAULT_NAMESPACE;
}

export function getTtl() {
  const config = loadTorchConfig();
  const envTtl = process.env.NOSTR_LOCK_TTL;
  if (envTtl) {
    const parsed = parseInt(envTtl, 10);
    if (!Number.isNaN(parsed) && parsed > 0) return parsed;
  }
  if (config.nostrLock.ttlSeconds) {
    return config.nostrLock.ttlSeconds;
  }
  return DEFAULT_TTL;
}

export function getQueryTimeoutMs() {
  const config = loadTorchConfig();
  const envValue = process.env.NOSTR_LOCK_QUERY_TIMEOUT_MS;
  if (envValue) {
    const parsed = parseEnvInteger(envValue, 'NOSTR_LOCK_QUERY_TIMEOUT_MS');
    assertTimeoutInRange(parsed, 'NOSTR_LOCK_QUERY_TIMEOUT_MS');
    return parsed;
  }
  const value = config.nostrLock.queryTimeoutMs || DEFAULT_QUERY_TIMEOUT_MS;
  assertTimeoutInRange(value, 'effective query timeout');
  return value;
}

export function getPublishTimeoutMs() {
  const config = loadTorchConfig();
  const envValue = process.env.NOSTR_LOCK_PUBLISH_TIMEOUT_MS;
  if (envValue) {
    const parsed = parseEnvInteger(envValue, 'NOSTR_LOCK_PUBLISH_TIMEOUT_MS');
    assertTimeoutInRange(parsed, 'NOSTR_LOCK_PUBLISH_TIMEOUT_MS');
    return parsed;
  }
  const value = config.nostrLock.publishTimeoutMs || DEFAULT_PUBLISH_TIMEOUT_MS;
  assertTimeoutInRange(value, 'effective publish timeout');
  return value;
}

export function getMinSuccessfulRelayPublishes() {
  const config = loadTorchConfig();
  const envValue = process.env.NOSTR_LOCK_MIN_SUCCESSFUL_PUBLISHES;
  if (envValue) {
    const parsed = parseEnvInteger(envValue, 'NOSTR_LOCK_MIN_SUCCESSFUL_PUBLISHES');
    assertPositiveCount(parsed, 'NOSTR_LOCK_MIN_SUCCESSFUL_PUBLISHES');
    return parsed;
  }
  const value = config.nostrLock.minSuccessfulRelayPublishes || DEFAULT_MIN_SUCCESSFUL_PUBLISHES;
  assertPositiveCount(value, 'effective min successful relay publishes');
  return value;
}

export function getMinActiveRelayPool() {
  const config = loadTorchConfig();
  const envValue = process.env.NOSTR_LOCK_MIN_ACTIVE_RELAY_POOL;
  if (envValue) {
    const parsed = parseEnvInteger(envValue, 'NOSTR_LOCK_MIN_ACTIVE_RELAY_POOL');
    assertPositiveCount(parsed, 'NOSTR_LOCK_MIN_ACTIVE_RELAY_POOL');
    return parsed;
  }
  const value = config.nostrLock.minActiveRelayPool || DEFAULT_MIN_ACTIVE_RELAY_POOL;
  assertPositiveCount(value, 'effective min active relay pool');
  return value;
}

export function getHashtag() {
  const config = loadTorchConfig();
  const envValue = process.env.NOSTR_LOCK_HASHTAG;
  if (envValue) {
    return envValue.trim();
  }
  if (config.dashboard.hashtag) {
    return config.dashboard.hashtag;
  }
  const namespace = getNamespace();
  return `${namespace}-agent-lock`;
}
