import {
  loadTorchConfig,
  getRelays,
  getNamespace,
} from './torch-config.mjs';
import { getRoster } from './roster.mjs';
import { queryLocks } from './lock-ops.mjs';
import { todayDateStr } from './utils.mjs';

export async function cmdCheck(cadence) {
  const relays = getRelays();
  const namespace = getNamespace();
  const dateStr = todayDateStr();
  const config = loadTorchConfig();
  const pausedAgents = (cadence === 'daily' ? config.scheduler.paused.daily : config.scheduler.paused.weekly) || [];

  console.error(`Checking locks: namespace=${namespace}, cadence=${cadence}, date=${dateStr}`);
  console.error(`Relays: ${relays.join(', ')}`);
  if (pausedAgents.length > 0) {
    console.error(`Paused agents: ${pausedAgents.join(', ')}`);
  }

  const locks = await queryLocks(relays, cadence, dateStr, namespace);
  const lockedAgents = [...new Set(locks.map((l) => l.agent).filter(Boolean))];
  const roster = getRoster(cadence);

  const excludedAgents = [...new Set([...lockedAgents, ...pausedAgents])];
  const unknownLockedAgents = lockedAgents.filter((agent) => !roster.includes(agent));
  const available = roster.filter((a) => !excludedAgents.includes(a));

  const result = {
    namespace,
    cadence,
    date: dateStr,
    locked: lockedAgents.sort(),
    paused: pausedAgents.sort(),
    excluded: excludedAgents.sort(),
    available: available.sort(),
    lockCount: locks.length,
    unknownLockedAgents: unknownLockedAgents.sort(),
    locks: locks.map((l) => ({
      agent: l.agent,
      eventId: l.eventId,
      createdAt: l.createdAtIso,
      expiresAt: l.expiresAtIso,
      platform: l.platform,
    })),
  };

  console.log(JSON.stringify(result, null, 2));
  return result;
}
