import {
  getRelays,
  getNamespace,
} from './torch-config.mjs';
import { getRoster } from './roster.mjs';
import { queryLocks } from './lock-ops.mjs';
import { todayDateStr, nowUnix } from './utils.mjs';

export async function cmdList(cadence) {
  const relays = await getRelays();
  const namespace = await getNamespace();
  const dateStr = todayDateStr();
  const cadences = cadence ? [cadence] : ['daily', 'weekly'];

  console.error(`Listing active locks: namespace=${namespace}, cadences=${cadences.join(', ')}`);

  const results = await Promise.all(
    cadences.map(async (c) => {
      const locks = await queryLocks(relays, c, dateStr, namespace);
      return { c, locks };
    }),
  );

  for (const { c, locks } of results) {
    console.log(`\n${'='.repeat(72)}`);
    console.log(`Active ${namespace} ${c} locks (${dateStr})`);
    console.log('='.repeat(72));

    if (locks.length === 0) {
      console.log('  (no active locks)');
      continue;
    }

    const sorted = locks.sort((a, b) => a.createdAt - b.createdAt);
    for (const lock of sorted) {
      const age = nowUnix() - lock.createdAt;
      const ageMin = Math.round(age / 60);
      const remaining = lock.expiresAt ? lock.expiresAt - nowUnix() : null;
      const remainMin = remaining ? Math.round(remaining / 60) : '?';

      console.log(
        `  ${(lock.agent ?? 'unknown').padEnd(30)} ` +
          `age: ${String(ageMin).padStart(4)}m  ` +
          `ttl: ${String(remainMin).padStart(4)}m  ` +
          `platform: ${lock.platform ?? '?'}  ` +
          `event: ${lock.eventId?.slice(0, 12)}...`,
      );
    }

    const roster = await getRoster(c);
    const lockedAgents = new Set(locks.map((l) => l.agent).filter(Boolean));
    const unknownLockedAgents = [...lockedAgents].filter((agent) => !roster.includes(agent));
    const available = roster.filter((a) => !lockedAgents.has(a));

    if (unknownLockedAgents.length > 0) {
      console.log(`  Warning: lock events found with non-roster agent names: ${unknownLockedAgents.join(', ')}`);
    }

    console.log(`\n  Locked: ${lockedAgents.size}/${roster.length}`);
    console.log(`  Available: ${available.join(', ') || '(none)'}`);
  }
}
