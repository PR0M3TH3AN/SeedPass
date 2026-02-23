import { rollbackPrompt } from './services/governance/index.js';
import { ExitError } from './errors.mjs';

export async function cmdRollback(target, strategy) {
  if (!target) {
    console.error('Usage: torch-lock rollback --target <path> [--strategy <hash|latest>]');
    throw new ExitError(1, 'Missing target');
  }

  const effectiveStrategy = strategy || 'latest';

  try {
    const result = await rollbackPrompt(target, effectiveStrategy);
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    console.error(`Rollback failed: ${e.message}`);
    throw new ExitError(1, 'Rollback failed');
  }
}
