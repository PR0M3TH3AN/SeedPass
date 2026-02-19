import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { DEFAULT_RELAYS } from './constants.mjs';
import { ensureDir } from './utils.mjs';

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Source paths (in the package)
const SRC_PROMPTS_DIR = path.join(PKG_ROOT, 'src', 'prompts');

// Files to treat as "Static" (always overwrite on update, with transformations)
const STATIC_FILES = [
  'META_PROMPTS.md',
  'scheduler-flow.md',
  'daily-scheduler.md',
  'weekly-scheduler.md',
];

// Directories containing "Evolving" files (copy if missing, preserve if present)
const EVOLVING_DIRS = ['daily', 'weekly'];

// New constants for full application install
const APP_DIRS = ['src', 'bin', 'dashboard', 'landing', 'assets', 'scripts'];
const APP_FILES = ['package.json', 'build.mjs', 'README.md', 'torch-config.example.json', 'TORCH.md'];

function getPaths(root, installDirName) {
    const torchDir = path.resolve(root, installDirName);
    return {
        root,
        torchDir,
        promptsDir: path.join(torchDir, 'prompts'),
        roster: path.join(torchDir, 'roster.json'),
    };
}

function copyDir(src, dest) {
    if (fs.existsSync(src)) {
        fs.cpSync(src, dest, { recursive: true });
    }
}

function transformContent(content, installDirName) {
  // Replace source paths with user paths
  // We assume the user is running from root, so 'src/prompts/daily/' becomes 'torch/prompts/daily/'
  // If installDirName is different, we should use that.
  // Note: These replacements are somewhat fragile regexes.
  // We'll replace 'src/' with 'installDirName/' essentially?
  // The original code replaced 'src/prompts/' with 'torch/prompts/'.

  // If installDirName is '.', we want 'prompts/daily/'.
  // If installDirName is 'torch', we want 'torch/prompts/daily/'.

  const prefix = installDirName === '.' ? '' : `${installDirName}/`;

  return content
    .replace(/src\/prompts\/daily\//g, `${prefix}prompts/daily/`)
    .replace(/src\/prompts\/weekly\//g, `${prefix}prompts/weekly/`)
    .replace(/src\/prompts\/roster\.json/g, `${prefix}roster.json`)
    .replace(/src\/prompts\/scheduler-flow\.md/g, `${prefix}scheduler-flow.md`)
    .replace(/TORCH\.md/g, `${prefix}TORCH.md`);
}

function copyFile(src, dest, transform = false, overwrite = true, installDirName = 'torch') {
  if (fs.existsSync(dest) && !overwrite) {
    return false; // Skipped
  }
  if (!fs.existsSync(src)) return false;

  const content = fs.readFileSync(src, 'utf8');
  const finalContent = transform ? transformContent(content, installDirName) : content;
  fs.writeFileSync(dest, finalContent, 'utf8');
  return true; // Copied/Overwritten
}

function syncAppDirectories(torchDir, verb = 'Copied') {
  console.log(`${verb === 'Copied' ? 'Copying' : 'Updating'} application directories...`);
  for (const dir of APP_DIRS) {
    const src = path.join(PKG_ROOT, dir);
    const dest = path.join(torchDir, dir);
    if (fs.existsSync(src)) {
      copyDir(src, dest);
      console.log(`  ${verb} ${dir}/`);
    }
  }
}

function syncAppFiles(torchDir, installDir, verb = 'Copied') {
  console.log(`${verb === 'Copied' ? 'Copying' : 'Updating'} application files...`);
  for (const file of APP_FILES) {
    const src = path.join(PKG_ROOT, file);
    const dest = path.join(torchDir, file);
    if (fs.existsSync(src)) {
      if (installDir === '.' && file === 'package.json') {
        if (verb === 'Copied' && fs.existsSync(dest)) {
          console.warn('  Skipping package.json to avoid overwriting host package.json (installing to root).');
          continue;
        }
        if (verb === 'Updated') {
          console.log('  Skipping package.json update (installed in root).');
          continue;
        }
      }

      fs.copyFileSync(src, dest);
      console.log(`  ${verb} ${file}`);
    }
  }
}

async function interactiveInit(cwd) {
  const rl = readline.createInterface({ input, output });
  const currentDirName = path.basename(cwd);

  console.log('\n🔥 TORCH Initialization 🔥\n');

  try {
    // 1. Install Directory
    let defaultDir = 'torch';
    if (currentDirName === 'torch') {
      defaultDir = '.';
    }

    const dirAnswer = await rl.question(`Install directory (default: ${defaultDir}): `);
    const installDir = dirAnswer.trim() || defaultDir;

    // 2. Namespace
    const randomSuffix = crypto.randomBytes(4).toString('hex');
    const defaultNamespace = `torch-${randomSuffix}`;
    const namespaceAnswer = await rl.question(`Nostr Namespace (default: ${defaultNamespace}): `);
    const namespace = namespaceAnswer.trim() || defaultNamespace;

    // 3. Relays
    console.log(`\nDefault Relays:\n  ${DEFAULT_RELAYS.join('\n  ')}`);
    const relaysAnswer = await rl.question('Enter relays (comma-separated) or press Enter to use defaults: ');
    let relays = DEFAULT_RELAYS;
    if (relaysAnswer.trim()) {
      relays = relaysAnswer.split(',').map(r => r.trim()).filter(Boolean);
    }

    return { installDir, namespace, relays };
  } finally {
    rl.close();
  }
}

function validateInstallDir(dir) {
  if (dir === '.') return;

  // Strict validation to prevent command injection
  // Only allow alphanumeric, hyphens, underscores, slashes, and periods.
  if (!/^[a-zA-Z0-9_\-./]+$/.test(dir)) {
    throw new Error(`Invalid directory name: "${dir}". Only alphanumeric characters, hyphens, underscores, slashes, and periods are allowed.`);
  }
}

async function resolveConfiguration(cwd, mockAnswers) {
  let config;
  if (mockAnswers) {
    config = mockAnswers;
  } else {
    config = await interactiveInit(cwd);
  }

  validateInstallDir(config.installDir);
  return config;
}

function ensureInstallDirectory(paths, force, installDir) {
  if (fs.existsSync(paths.torchDir) && !force) {
     const entries = fs.readdirSync(paths.torchDir);
     if (entries.length > 0 && installDir !== '.') {
         throw new Error(`Directory ${paths.torchDir} already exists and is not empty. Use --force to overwrite.`);
     }
  }
  ensureDir(paths.torchDir);
  ensureDir(paths.promptsDir);

  // Ensure governance directories
  // We assume standard structure src/proposals and .torch/prompt-history
  // even if installed in a subdirectory, these are usually repo-level.
  // But if installed in 'torch', maybe they should be in 'torch/src/proposals'?
  // For now, we follow the pattern that prompts are managed where the scheduler expects them.
  // If we are in this repo, it's src/prompts.
  // If torch is initializing a new repo, it might put prompts in installDir/prompts.
  // However, governance service currently hardcodes 'src/proposals'.
  // So we ensure 'src/proposals' relative to root.
  ensureDir(path.join(paths.root, 'src', 'proposals'));
  ensureDir(path.join(paths.root, '.torch', 'prompt-history'));
}

function installAppAssets(torchDir, installDir) {
  // 1. Copy App Directories
  syncAppDirectories(torchDir, 'Copied');

  // 2. Copy App Files
  syncAppFiles(torchDir, installDir, 'Copied');
}

function installTorchAssets(paths, installDir) {
  // 3. Copy Roster
  const srcRoster = path.join(SRC_PROMPTS_DIR, 'roster.json');
  if (fs.existsSync(srcRoster)) {
    copyFile(srcRoster, paths.roster, false, true, installDir);
    console.log(`Created ${path.relative(paths.root, paths.roster)}`);
  }

  // 4. Copy Static Files
  for (const file of STATIC_FILES) {
    const src = path.join(SRC_PROMPTS_DIR, file);
    const dest = path.join(paths.torchDir, file);
    if (fs.existsSync(src)) {
      copyFile(src, dest, true, true, installDir);
      console.log(`Created ${path.relative(paths.root, dest)}`);
    }
  }

  // 5. Copy Prompts
  for (const dir of EVOLVING_DIRS) {
    const srcDir = path.join(SRC_PROMPTS_DIR, dir);
    const destDir = path.join(paths.promptsDir, dir);
    ensureDir(destDir);

    if (fs.existsSync(srcDir)) {
      const files = fs.readdirSync(srcDir);
      for (const file of files) {
        const srcFile = path.join(srcDir, file);
        const destFile = path.join(destDir, file);
        copyFile(srcFile, destFile, false, true, installDir);
      }
      console.log(`Created ${files.length} files in ${path.relative(paths.root, destDir)}/`);
    }
  }
}

function configureTorch(cwd, paths, installDir, namespace, relays) {
  // 6. Create/Update torch-config.json
  const configPath = path.join(paths.root, 'torch-config.json');

  let configData = {};

  // Try to load existing or example
  if (fs.existsSync(configPath)) {
      try {
          configData = JSON.parse(fs.readFileSync(configPath, 'utf8'));
          console.log(`Updating existing ${path.relative(cwd, configPath)}...`);
      } catch (e) {
          console.warn(`Could not parse existing config: ${e.message}`);
      }
  } else {
      const exampleConfigPath = path.join(PKG_ROOT, 'torch-config.example.json');
      if (fs.existsSync(exampleConfigPath)) {
          configData = JSON.parse(fs.readFileSync(exampleConfigPath, 'utf8'));
      }
  }

  // Apply user choices
  if (!configData.nostrLock) configData.nostrLock = {};
  configData.nostrLock.namespace = namespace;
  configData.nostrLock.relays = relays;

  // Configure memory policy with correct paths
  if (!configData.scheduler) configData.scheduler = {};
  // Always ensure memory policy exists and points to the correct scripts
  // We use the installDir to construct the path
  const scriptPrefix = installDir === '.' ? '' : `${installDir}/`;

  if (!configData.scheduler.memoryPolicyByCadence) {
    configData.scheduler.memoryPolicyByCadence = {};
  }

  // Populate or update daily/weekly memory policy
  // We force update the command paths to match the install directory,
  // while preserving other settings if they exist.
  ['daily', 'weekly'].forEach(cadence => {
    if (!configData.scheduler.memoryPolicyByCadence[cadence]) {
      configData.scheduler.memoryPolicyByCadence[cadence] = {
        mode: "required",
        retrieveSuccessMarkers: ["MEMORY_RETRIEVED"],
        storeSuccessMarkers: ["MEMORY_STORED"],
        retrieveArtifacts: [`.scheduler-memory/latest/${cadence}/retrieve.ok`],
        storeArtifacts: [`.scheduler-memory/latest/${cadence}/store.ok`]
      };
    }

    // Always ensure commands point to the correct script location
    const policy = configData.scheduler.memoryPolicyByCadence[cadence];
    policy.retrieveCommand = `node ${scriptPrefix}scripts/memory/retrieve.mjs`;
    policy.storeCommand = `node ${scriptPrefix}scripts/memory/store.mjs`;
  });

  fs.writeFileSync(configPath, JSON.stringify(configData, null, 2), 'utf8');
  console.log(`Saved configuration to ${path.relative(cwd, configPath)}`);
}

function injectHostScriptsIfNeeded(paths, installDir) {
  // 7. Inject Scripts into Host Package.json
  // If we are NOT installing to '.', the host package.json is in paths.root
  if (installDir !== '.') {
      injectScriptsIntoHost(paths.root, installDir);
  }
}

export async function cmdInit(force = false, cwd = process.cwd(), mockAnswers = null) {
  const config = await resolveConfiguration(cwd, mockAnswers);
  const { installDir, namespace, relays } = config;

  const paths = getPaths(cwd, installDir);
  console.log(`\nInitializing torch in ${paths.torchDir}...`);

  ensureInstallDirectory(paths, force, installDir);

  installAppAssets(paths.torchDir, installDir);
  installTorchAssets(paths, installDir);
  configureTorch(cwd, paths, installDir, namespace, relays);
  injectHostScriptsIfNeeded(paths, installDir);

  console.log('\nInitialization complete.');
  console.log('You can now customize the files in ' + path.relative(cwd, paths.torchDir) + '/');
}

function injectScriptsIntoHost(hostRoot, installDirName) {
    const hostPkgPath = path.join(hostRoot, 'package.json');
    if (!fs.existsSync(hostPkgPath)) {
        console.warn('No package.json found in host root. Skipping script injection.');
        return;
    }

    try {
        const pkg = JSON.parse(fs.readFileSync(hostPkgPath, 'utf8'));
        if (!pkg.scripts) pkg.scripts = {};

        const scriptsToAdd = {
            'torch:dashboard': `npm run --prefix ${installDirName} dashboard:serve`,
            'torch:check': `npm run --prefix ${installDirName} lock:check:daily`, // Default to daily check
            'torch:lock': `npm run --prefix ${installDirName} lock:lock`,
            'torch:health': `npm run --prefix ${installDirName} lock:health`,
            'torch:memory:list': `node ${installDirName === '.' ? '' : installDirName + '/'}bin/torch-lock.mjs list-memories`,
            'torch:memory:inspect': `node ${installDirName === '.' ? '' : installDirName + '/'}bin/torch-lock.mjs inspect-memory`,
        };

        let modified = false;
        for (const [key, cmd] of Object.entries(scriptsToAdd)) {
            if (!pkg.scripts[key]) {
                pkg.scripts[key] = cmd;
                console.log(`  Added script: "${key}"`);
                modified = true;
            } else {
                console.log(`  Script "${key}" already exists, skipping.`);
            }
        }

        if (modified) {
            fs.writeFileSync(hostPkgPath, JSON.stringify(pkg, null, 2), 'utf8');
            console.log('Updated package.json with convenience scripts.');
        }

    } catch (e) {
        console.error(`Failed to inject scripts: ${e.message}`);
    }
}

export function cmdUpdate(force = false, cwd = process.cwd()) {
  // Update logic needs to know WHERE torch is installed.
  // We can look for torch directory? Or assume 'torch'?
  // For now, let's look for 'torch' directory first, then fallback to '.' if we detect torch files?
  // Or just default to 'torch' and let user move files if they changed it?
  // Realistically, 'update' should probably take an argument for the dir, or we just default to 'torch'.

  // If the user installed to 'custom-dir', cmdUpdate will fail unless we auto-detect.
  // Auto-detection strategy: check if 'torch' exists. If not, check if 'package.json' has 'torch-lock' name?

  let installDirName = 'torch';
  if (!fs.existsSync(path.join(cwd, 'torch')) && fs.existsSync(path.join(cwd, 'package.json'))) {
      // Check if current dir is the torch dir
      try {
          const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'));
          if (pkg.name === 'torch-lock') {
              installDirName = '.';
          }
      } catch (e) {
          // Ignore error if package.json is missing or invalid
      }
  }

  const paths = getPaths(cwd, installDirName);
  console.log(`Updating torch configuration in ${paths.torchDir}...`);

  if (!fs.existsSync(paths.torchDir)) {
    throw new Error(`${paths.torchDir} not found. Run 'torch-lock init' first.`);
  }

  // 1. Backup
  const backupName = `backup_${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const backupRoot = path.join(paths.torchDir, '_backups');
  const thisBackupDir = path.join(backupRoot, backupName);

  ensureDir(thisBackupDir);
  console.log(`Creating backup at ${path.relative(paths.root, thisBackupDir)}...`);

  // We backup EVERYTHING in torchDir except _backups and node_modules
  const entries = fs.readdirSync(paths.torchDir);
  for (const entry of entries) {
      if (entry === '_backups' || entry === 'node_modules' || entry === '.git') continue;

      const srcPath = path.join(paths.torchDir, entry);
      const destPath = path.join(thisBackupDir, entry);
      fs.cpSync(srcPath, destPath, { recursive: true });
  }

  // 2. Update App Directories (Overwrite)
  syncAppDirectories(paths.torchDir, 'Updated');

  // 3. Update App Files (Overwrite)
  syncAppFiles(paths.torchDir, installDirName, 'Updated');

  // 4. Update Static Files (Always Overwrite)
  console.log('Updating static files...');
  for (const file of STATIC_FILES) {
    const src = path.join(SRC_PROMPTS_DIR, file);
    const dest = path.join(paths.torchDir, file);
    if (fs.existsSync(src)) {
      copyFile(src, dest, true, true, installDirName);
      console.log(`  Updated ${file}`);
    }
  }

  // 5. Update Roster (Preserve unless force)
  const srcRoster = path.join(SRC_PROMPTS_DIR, 'roster.json');
  if (fs.existsSync(srcRoster)) {
    if (force) {
      copyFile(srcRoster, paths.roster, false, true, installDirName);
      console.log('  Overwrote roster.json (forced)');
    } else {
      console.log('  Skipped roster.json (preserved)');
    }
  }

  // 6. Update Prompts (Copy missing, preserve existing unless force)
  console.log('Updating prompts...');
  for (const dir of EVOLVING_DIRS) {
    const srcDir = path.join(SRC_PROMPTS_DIR, dir);
    const destDir = path.join(paths.promptsDir, dir);
    ensureDir(destDir);

    if (fs.existsSync(srcDir)) {
      const files = fs.readdirSync(srcDir);
      let added = 0;
      let updated = 0;
      let skipped = 0;

      for (const file of files) {
        const srcFile = path.join(srcDir, file);
        const destFile = path.join(destDir, file);

        if (force) {
            copyFile(srcFile, destFile, false, true, installDirName);
            updated++;
        } else {
            if (!fs.existsSync(destFile)) {
                copyFile(srcFile, destFile, false, true, installDirName);
                added++;
            } else {
                skipped++;
            }
        }
      }
      console.log(`  ${dir}/: ${added} added, ${updated} updated, ${skipped} preserved`);
    }
  }

  console.log('\nUpdate complete.');
}
