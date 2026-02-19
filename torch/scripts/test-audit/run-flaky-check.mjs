import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const RUNS = 5;
const results = {};

// Parse arguments to separate our flags from test runner args
const args = process.argv.slice(2);
let outputDir = 'reports/test-audit';
const testArgs = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--output-dir') {
    outputDir = args[i + 1];
    i++; // Skip next arg
  } else {
    testArgs.push(args[i]);
  }
}

async function runTests(i) {
  console.log(`Run ${i + 1}/${RUNS}...`);
  return new Promise((resolve) => {
    // Pass strictly the test args to the child process
    const child = spawn('node', ['--test', ...testArgs], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';

    child.stdout.on('data', (d) => stdout += d.toString());

    child.on('close', (code) => {
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.startsWith('not ok ') && !line.includes('# skip') && !line.includes('# todo')) {
          const name = line.substring(line.indexOf('-') + 1).trim();
          if (!results[name]) results[name] = { pass: 0, fail: 0 };
          results[name].fail++;
        } else if (line.startsWith('ok ') && !line.includes('# skip') && !line.includes('# todo')) {
          const name = line.substring(line.indexOf('-') + 1).trim();
          if (!results[name]) results[name] = { pass: 0, fail: 0 };
          results[name].pass++;
        }
      }
      resolve();
    });
  });
}

async function main() {
  for (let i = 0; i < RUNS; i++) {
    await runTests(i);
  }

  // Ensure output directory exists
  mkdirSync(outputDir, { recursive: true });

  const outputPath = join(outputDir, 'flakiness-matrix.json');
  writeFileSync(outputPath, JSON.stringify(results, null, 2));
  console.log(`Flakiness matrix written to ${outputPath}.`);
}

main();
