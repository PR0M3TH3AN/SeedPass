import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import {
  getRelays,
  getNamespace,
  getTtl,
} from './torch-config.mjs';
import {
  RACE_CHECK_DELAY_MS,
  KIND_APP_DATA,
} from './constants.mjs';
import { getRoster } from './roster.mjs';
import { queryLocks, publishLock } from './lock-ops.mjs';
import { todayDateStr, nowUnix } from './utils.mjs';
import { ExitError } from './errors.mjs';

export async function cmdLock(agent, cadence, dryRun = false) {
  const relays = getRelays();
  const namespace = getNamespace();
  const dateStr = todayDateStr();
  const ttl = getTtl();
  const now = nowUnix();
  const expiresAt = now + ttl;

  console.error(`Locking: namespace=${namespace}, agent=${agent}, cadence=${cadence}, date=${dateStr}`);
  console.error(`TTL: ${ttl}s, expires: ${new Date(expiresAt * 1000).toISOString()}`);
  console.error(`Relays: ${relays.join(', ')}`);

  const roster = getRoster(cadence);
  if (!roster.includes(agent)) {
    console.error(`ERROR: agent "${agent}" is not in the ${cadence} roster`);
    console.error(`Allowed ${cadence} agents: ${roster.join(', ')}`);
    throw new ExitError(1, 'Agent not in roster');
  }

  console.error('Step 1: Checking for existing locks...');
  const existingLocks = await queryLocks(relays, cadence, dateStr, namespace);
  const conflicting = existingLocks.filter((l) => l.agent === agent);

  if (conflicting.length > 0) {
    const earliest = conflicting.sort((a, b) => a.createdAt - b.createdAt)[0];
    console.error(
      `LOCK DENIED: ${agent} already locked by event ${earliest.eventId} ` +
        `(created ${earliest.createdAtIso}, platform: ${earliest.platform})`,
    );
    console.log('LOCK_STATUS=denied');
    console.log('LOCK_REASON=already_locked');
    console.log(`LOCK_EXISTING_EVENT=${earliest.eventId}`);
    throw new ExitError(3, 'Lock denied');
  }

  console.error('Step 2: Generating ephemeral keypair...');
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  console.error(`  Ephemeral pubkey: ${pk.slice(0, 16)}...`);

  console.error('Step 3: Building lock event...');
  const event = finalizeEvent(
    {
      kind: KIND_APP_DATA,
      created_at: now,
      tags: [
        ['d', `${namespace}-lock/${cadence}/${agent}/${dateStr}`],
        ['t', `${namespace}-agent-lock`],
        ['t', `${namespace}-lock-${cadence}`],
        ['t', `${namespace}-lock-${cadence}-${dateStr}`],
        ['expiration', String(expiresAt)],
      ],
      content: JSON.stringify({
        agent,
        cadence,
        status: 'started',
        namespace,
        date: dateStr,
        platform: process.env.AGENT_PLATFORM || 'unknown',
        lockedAt: new Date(now * 1000).toISOString(),
        expiresAt: new Date(expiresAt * 1000).toISOString(),
      }),
    },
    sk,
  );

  console.error(`  Event ID: ${event.id}`);

  if (dryRun) {
    console.error('Step 4: [DRY RUN] Skipping publish — event built but not sent');
    console.error('RACE CHECK: won (dry run — no real contention possible)');
  } else {
    console.error('Step 4: Publishing to relays...');
    await publishLock(relays, event);

    console.error('Step 5: Race check...');
    await new Promise((resolve) => setTimeout(resolve, RACE_CHECK_DELAY_MS));

    const postLocks = await queryLocks(relays, cadence, dateStr, namespace);
    const racingLocks = postLocks
      .filter((l) => l.agent === agent)
      .sort((a, b) => a.createdAt - b.createdAt);

    if (racingLocks.length > 1 && racingLocks[0].eventId !== event.id) {
      const winner = racingLocks[0];
      console.error(
        `RACE CHECK: lost (earlier lock by event ${winner.eventId}, created ${winner.createdAtIso})`,
      );
      console.log('LOCK_STATUS=race_lost');
      console.log('LOCK_REASON=earlier_claim_exists');
      console.log(`LOCK_WINNER_EVENT=${winner.eventId}`);
      throw new ExitError(3, 'Race check lost');
    }

    console.error('RACE CHECK: won');
  }

  console.log('LOCK_STATUS=ok');
  console.log(`LOCK_EVENT_ID=${event.id}`);
  console.log(`LOCK_PUBKEY=${pk}`);
  console.log(`LOCK_AGENT=${agent}`);
  console.log(`LOCK_CADENCE=${cadence}`);
  console.log(`LOCK_DATE=${dateStr}`);
  console.log(`LOCK_EXPIRES=${expiresAt}`);
  console.log(`LOCK_EXPIRES_ISO=${new Date(expiresAt * 1000).toISOString()}`);
  return { status: 'ok', eventId: event.id };
}
