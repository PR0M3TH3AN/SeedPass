import WebSocket from 'ws';
import { useWebSocketImplementation } from 'nostr-tools/relay';
import { SimplePool } from 'nostr-tools/pool';
import { generateSecretKey, finalizeEvent } from 'nostr-tools/pure';
import fs from 'node:fs';
import path from 'node:path';
import { ensureDir } from '../../src/utils.mjs';

useWebSocketImplementation(WebSocket);

const RELAY_URL = process.env.RELAY_URL;
const CLIENTS = parseInt(process.env.CLIENTS || '10', 10);
const DURATION_SEC = parseInt(process.env.DURATION_SEC || '10', 10);
const RATE_EPS = parseInt(process.env.RATE_EPS || '5', 10);
const MIX = parseFloat(process.env.MIX || '0.1'); // 10% metadata
const DRY_RUN = process.env.DRY_RUN !== '0'; // Default to true for safety

const KIND_TEXT = 1;
const KIND_METADATA = 30078; // App Data as proxy for metadata

console.log('Load Test Configuration:');
console.log(`  RELAY_URL: ${RELAY_URL || '(none)'}`);
console.log(`  CLIENTS: ${CLIENTS}`);
console.log(`  DURATION_SEC: ${DURATION_SEC}`);
console.log(`  RATE_EPS: ${RATE_EPS}`);
console.log(`  MIX: ${MIX}`);
console.log(`  DRY_RUN: ${DRY_RUN}`);

if (!RELAY_URL && !DRY_RUN) {
  console.error('ERROR: RELAY_URL is required unless DRY_RUN=1');
  process.exit(1);
}

const stats = {
  totalAttempts: 0,
  success: 0,
  failed: 0,
  latencySum: 0,
  latencyMin: Infinity,
  latencyMax: 0,
  errors: {},
  startTime: Date.now(),
  endTime: 0
};

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function generateEvent(sk) {
  const isMetadata = Math.random() < MIX;
  const kind = isMetadata ? KIND_METADATA : KIND_TEXT;
  const content = isMetadata
    ? JSON.stringify({ type: 'video-metadata', title: 'Load Test Video', duration: 120, tags: ['test', 'load'] })
    : `Load test view event ${Date.now()}`;

  const tags = [['t', 'load-test']];
  if (isMetadata) {
    tags.push(['d', `load-test-${Date.now()}-${Math.random()}`]);
  }

  return finalizeEvent({
    kind,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content,
  }, sk);
}

async function main() {
  const reportDir = 'reports/load-test';
  ensureDir(reportDir);

  if (DRY_RUN) {
    console.log('Starting DRY RUN...');
    const start = Date.now();
    let eventsGenerated = 0;
    // Simple simulation loop
    while (Date.now() - start < DURATION_SEC * 1000) {
      eventsGenerated++;
      if (eventsGenerated % RATE_EPS === 0) await sleep(1000);
    }
    stats.totalAttempts = eventsGenerated;
    stats.success = eventsGenerated;
    stats.endTime = Date.now();
    stats.latencySum = eventsGenerated * 10; // Fake 10ms latency
    stats.latencyMin = 5;
    stats.latencyMax = 15;

    writeReport(reportDir);
    return;
  }

  const pool = new SimplePool();
  const sks = Array.from({ length: CLIENTS }, () => generateSecretKey());

  console.log(`Starting load test against ${RELAY_URL} for ${DURATION_SEC}s...`);

  const start = Date.now();
  const end = start + DURATION_SEC * 1000;

  const interval = 1000 / RATE_EPS;

  return new Promise((resolve) => {
    const timer = setInterval(async () => {
        if (Date.now() >= end) {
          clearInterval(timer);
          pool.close([RELAY_URL]);
          stats.endTime = Date.now();
          writeReport(reportDir);
          resolve();
          return;
        }

        const clientIdx = Math.floor(Math.random() * CLIENTS);
        const sk = sks[clientIdx];
        const event = generateEvent(sk);

        stats.totalAttempts++;
        const sendStart = Date.now();

        try {
          await Promise.any(pool.publish([RELAY_URL], event));
          const latency = Date.now() - sendStart;
          stats.success++;
          stats.latencySum += latency;
          stats.latencyMin = Math.min(stats.latencyMin, latency);
          stats.latencyMax = Math.max(stats.latencyMax, latency);
        } catch (err) {
          stats.failed++;
          const msg = err.message || String(err);
          stats.errors[msg] = (stats.errors[msg] || 0) + 1;
        }
      }, interval);
  });
}

function writeReport(dir) {
  const duration = (stats.endTime - stats.startTime) / 1000;
  const throughput = stats.success / duration;
  const avgLatency = stats.success > 0 ? stats.latencySum / stats.success : 0;

  const report = {
    config: {
      relayUrl: RELAY_URL,
      clients: CLIENTS,
      durationSec: DURATION_SEC,
      rateEps: RATE_EPS,
      mix: MIX,
      dryRun: DRY_RUN
    },
    results: {
      totalAttempts: stats.totalAttempts,
      success: stats.success,
      failed: stats.failed,
      throughputEps: throughput,
      latency: {
        min: stats.latencyMin === Infinity ? 0 : stats.latencyMin,
        max: stats.latencyMax,
        avg: avgLatency
      },
      errors: stats.errors
    },
    timestamp: new Date().toISOString()
  };

  const dateStr = new Date().toISOString().slice(0, 10);
  const jsonPath = path.join(dir, `load-report-${dateStr}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  console.log(`JSON report written to ${jsonPath}`);

  const mdPath = path.join(dir, `load-test-report-${dateStr}.md`);
  const mdContent = `
# Load Test Report - ${dateStr}

## Configuration
- **Relay**: ${RELAY_URL || '(dry run)'}
- **Clients**: ${CLIENTS}
- **Duration**: ${DURATION_SEC}s
- **Rate**: ${RATE_EPS} eps
- **Mix**: ${MIX}
- **Dry Run**: ${DRY_RUN}

## Results
- **Total Attempts**: ${stats.totalAttempts}
- **Success**: ${stats.success}
- **Failed**: ${stats.failed}
- **Throughput**: ${throughput.toFixed(2)} events/sec
- **Latency (Avg)**: ${avgLatency.toFixed(2)} ms
- **Latency (Min/Max)**: ${stats.latencyMin === Infinity ? 0 : stats.latencyMin} / ${stats.latencyMax} ms

## Errors
\`\`\`json
${JSON.stringify(stats.errors, null, 2)}
\`\`\`
`;
  fs.writeFileSync(mdPath, mdContent.trim());
  console.log(`Markdown report written to ${mdPath}`);
}

main().catch(console.error);
