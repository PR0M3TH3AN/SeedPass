import fs from 'node:fs/promises';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const PROPOSALS_DIR = path.resolve(process.cwd(), 'src/proposals');
const HISTORY_DIR = path.resolve(process.cwd(), '.torch/prompt-history');
const ALLOWED_TARGET_DIRS = [
  path.resolve(process.cwd(), 'src/prompts/daily'),
  path.resolve(process.cwd(), 'src/prompts/weekly'),
];

async function ensureDirs() {
  await fs.mkdir(PROPOSALS_DIR, { recursive: true });
  await fs.mkdir(HISTORY_DIR, { recursive: true });
}

export async function listProposals() {
  await ensureDirs();
  const entries = await fs.readdir(PROPOSALS_DIR, { withFileTypes: true });
  const proposals = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      const metaPath = path.join(PROPOSALS_DIR, entry.name, 'meta.json');
      try {
        const metaContent = await fs.readFile(metaPath, 'utf8');
        const meta = JSON.parse(metaContent);
        proposals.push({
          id: entry.name,
          ...meta
        });
      } catch (e) {
        // Ignore invalid proposals
      }
    }
  }
  return proposals;
}

export async function getProposal(id) {
  const dir = path.join(PROPOSALS_DIR, id);
  const metaPath = path.join(dir, 'meta.json');
  const newPath = path.join(dir, 'new.md');
  const diffPath = path.join(dir, 'change.diff');

  try {
    const meta = JSON.parse(await fs.readFile(metaPath, 'utf8'));
    const newContent = await fs.readFile(newPath, 'utf8');
    let diff = '';
    try {
      diff = await fs.readFile(diffPath, 'utf8');
    } catch {
      // Ignore missing diff
    }

    return {
      id,
      meta,
      newContent,
      diff,
      dir
    };
  } catch (e) {
    throw new Error(`Proposal ${id} not found or invalid: ${e.message}`, { cause: e });
  }
}

export async function createProposal({ agent, target, newContent, reason }) {
  await ensureDirs();

  // Validate target path is allowed
  const absoluteTarget = path.resolve(process.cwd(), target);
  const isAllowed = ALLOWED_TARGET_DIRS.some(allowed => absoluteTarget.startsWith(allowed));

  if (!isAllowed) {
    throw new Error(`Target ${target} is not in an allowed directory (src/prompts/daily or src/prompts/weekly).`);
  }

  // Generate ID
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const id = `${timestamp}_${agent}`;
  const dir = path.join(PROPOSALS_DIR, id);

  await fs.mkdir(dir, { recursive: true });

  // Write content
  await fs.writeFile(path.join(dir, 'new.md'), newContent);

  // Generate Diff if target exists
  let diff = '';
  try {
    // Check if target exists
    await fs.access(absoluteTarget);

    // Create a temporary file for the diff logic to work cleanly
    // But direct path is fine.
    const newFile = path.join(dir, 'new.md');
    const diffCmd = `git diff --no-index --color=never "${absoluteTarget}" "${newFile}"`;
    try {
      execSync(diffCmd, { stdio: 'pipe' }); // Will throw if exit code 1 (diff found)
    } catch (e) {
      if (e.status === 1 && e.stdout) {
        diff = e.stdout.toString();
      } else if (e.status !== 1) {
          // Some other error
          console.error('Diff generation failed:', e.message);
      }
    }
  } catch (err) {
    diff = '(New File)';
  }

  await fs.writeFile(path.join(dir, 'change.diff'), diff);

  const meta = {
    id,
    author: agent,
    target,
    reason,
    timestamp: new Date().toISOString(),
    status: 'pending'
  };

  await fs.writeFile(path.join(dir, 'meta.json'), JSON.stringify(meta, null, 2));

  return { id, diff };
}

export async function validateProposal(id) {
  const { meta, newContent } = await getProposal(id);

  // 1. Allowlist check (redundant but safe)
  const absoluteTarget = path.resolve(process.cwd(), meta.target);
  const isAllowed = ALLOWED_TARGET_DIRS.some(allowed => absoluteTarget.startsWith(allowed));
  if (!isAllowed) {
    return { valid: false, reason: 'Target not in allowed directories.' };
  }

  // 2. Invariant checks
  // Check for required headers based on common prompt structure
  const requiredPatterns = [
    /Shared contract \(required\):/i,
    /Required startup \+ artifacts \+ memory \+ issue capture/i,
  ];

  for (const pattern of requiredPatterns) {
    if (!pattern.test(newContent)) {
       return { valid: false, reason: `Missing required header pattern: ${pattern}` };
    }
  }

  return { valid: true };
}

export async function applyProposal(id) {
  const proposal = await getProposal(id);
  const { meta, newContent, dir } = proposal;

  if (meta.status !== 'pending') {
    throw new Error(`Proposal is ${meta.status}, cannot apply.`);
  }

  const validation = await validateProposal(id);
  if (!validation.valid) {
    // Mark as rejected if validation fails?
    // Or just throw? The governance agent should decide.
    // We throw here to prevent accidental application.
    throw new Error(`Validation failed: ${validation.reason}`);
  }

  const absoluteTarget = path.resolve(process.cwd(), meta.target);

  // Archive old
  try {
    const oldContent = await fs.readFile(absoluteTarget, 'utf8');
    const hash = createHash('sha256').update(oldContent).digest('hex');

    // We store archives in .torch/prompt-history/<target_path>/<hash>.md
    // Note: meta.target is relative path like 'src/prompts/daily/agent.md'
    // We want to keep that structure.
    const archiveDir = path.join(HISTORY_DIR, path.dirname(meta.target));
    await fs.mkdir(archiveDir, { recursive: true });

    // Add timestamp to filename for easier sorting later?
    // Or just rely on hash and store metadata elsewhere?
    // User requested <path>/<hash>.md.
    const archivePath = path.join(archiveDir, `${path.basename(meta.target, '.md')}_${hash}.md`);
    await fs.writeFile(archivePath, oldContent);
  } catch (e) {
    // If file didn't exist, nothing to archive
  }

  // Apply new
  await fs.mkdir(path.dirname(absoluteTarget), { recursive: true });
  await fs.writeFile(absoluteTarget, newContent);

  // Update meta
  meta.status = 'applied';
  meta.appliedAt = new Date().toISOString();
  await fs.writeFile(path.join(dir, 'meta.json'), JSON.stringify(meta, null, 2));

  // Git Commit (optional)
  try {
    // We use execSync for git operations
    // Ensure we are in repo root? cwd is repo root.
    execSync(`git add "${meta.target}"`);
    const commitMsg = `feat(prompts): apply proposal ${id} by ${meta.author}`;
    execSync(`git commit -m "${commitMsg}"`);
    meta.gitCommit = execSync('git rev-parse HEAD').toString().trim();
    await fs.writeFile(path.join(dir, 'meta.json'), JSON.stringify(meta, null, 2));
  } catch (gitErr) {
    console.warn('Git commit failed (ignoring):', gitErr.message);
  }

  return { success: true };
}

export async function rejectProposal(id, reason) {
  const proposal = await getProposal(id);
  const { meta, dir } = proposal;

  meta.status = 'rejected';
  meta.rejectionReason = reason;
  meta.rejectedAt = new Date().toISOString();

  await fs.writeFile(path.join(dir, 'meta.json'), JSON.stringify(meta, null, 2));
  return { success: true };
}

export async function rollbackPrompt(target, hashOrStrategy = 'latest') {
  // target is relative path e.g. src/prompts/daily/agent.md
  const archiveDir = path.join(HISTORY_DIR, path.dirname(target));
  const absoluteTarget = path.resolve(process.cwd(), target);

  let sourceContent = null;
  let sourceName = null;

  try {
    // Try Local Archive first
    if (hashOrStrategy === 'latest') {
       // Find latest file in archiveDir
       // Our naming is <agent>_<hash>.md.
       // We can rely on file mtime.
       const files = await fs.readdir(archiveDir);
       const targetBase = path.basename(target, '.md');
       const prefix = targetBase + '_';
       const candidates = files.filter(f => f.startsWith(prefix));

       if (candidates.length > 0) {
           const stats = await Promise.all(candidates.map(async f => ({
               name: f,
               ...await fs.stat(path.join(archiveDir, f))
           })));
           const latest = stats.sort((a, b) => b.mtimeMs - a.mtimeMs)[0];
           sourceName = latest.name;
           sourceContent = await fs.readFile(path.join(archiveDir, sourceName), 'utf8');
       }
    } else {
        // Try to find file containing hash
        const files = await fs.readdir(archiveDir);
        const match = files.find(f => f.includes(hashOrStrategy));
        if (match) {
            sourceName = match;
            sourceContent = await fs.readFile(path.join(archiveDir, match), 'utf8');
        }
    }
  } catch (e) {
      // Archive lookup failed
  }

  if (sourceContent) {
      await fs.writeFile(absoluteTarget, sourceContent);
      return { success: true, source: 'archive', restored: sourceName };
  }

  // Fallback to Git
  try {
      const commit = hashOrStrategy === 'latest' ? 'HEAD' : hashOrStrategy;
      // Use git show instead of checkout to avoid detaching head if we just want content
      // But user said "git checkout" implying revert state.
      // Actually `git checkout <commit> -- <path>` overwrites the file in working tree.
      execSync(`git checkout "${commit}" -- "${target}"`);
      return { success: true, source: 'git', restored: commit };
  } catch (e) {
      throw new Error(`Rollback failed: Local archive not found and git failed (${e.message})`, { cause: e });
  }
}
