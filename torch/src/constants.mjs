export const DEFAULT_DASHBOARD_PORT = 4173;
export const RACE_CHECK_DELAY_MS = 1500;
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
];
export const DEFAULT_TTL = 7200;
export const DEFAULT_NAMESPACE = 'torch';
export const DEFAULT_QUERY_TIMEOUT_MS = 30_000;
export const DEFAULT_PUBLISH_TIMEOUT_MS = 15_000;
export const DEFAULT_MIN_SUCCESSFUL_PUBLISHES = 1;
export const DEFAULT_MIN_ACTIVE_RELAY_POOL = 1;
export const VALID_CADENCES = new Set(['daily', 'weekly']);
export const KIND_APP_DATA = 30078;
