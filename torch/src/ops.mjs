import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { DEFAULT_RELAYS } from './constants.mjs';

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
const APP_FILES = ['package.json', 'build.mjs', 'README.md', 'torch-config.example.json'];

function getPaths(root, installDirName) {
    const torchDir = path.resolve(root, installDirName);
    return {
        root,
        torchDir,
        promptsDir: path.join(torchDir, 'prompts'),
        roster: path.join(torchDir, 'roster.json'),
    };
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
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
    .replace(/src\/prompts\/scheduler-flow\.md/g, `${prefix}scheduler-flow.md`);
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

export async function cmdInit(force = false, cwd = process.cwd(), mockAnswers = null) {
  // Use interactive mode to get configuration unless mock answers are provided
  let config;
  if (mockAnswers) {
    config = mockAnswers;
  } else {
    config = await interactiveInit(cwd);
  }
  const { installDir, namespace, relays } = config;

  const paths = getPaths(cwd, installDir);
  console.log(`\nInitializing torch in ${paths.torchDir}...`);

  // Check if directory exists and is not empty (unless force is used or we are installing to .)
  if (fs.existsSync(paths.torchDir) && !force) {
     const entries = fs.readdirSync(paths.torchDir);
     if (entries.length > 0 && installDir !== '.') {
         // If installing to current dir, we might expect some files, but warn anyway?
         // Simpler: just throw if strictly not empty and not forced.
         // But usually we don't want to fail if just re-running init.
         console.warn(`Warning: ${paths.torchDir} already exists.`);
     }
  }

  ensureDir(paths.torchDir);
  ensureDir(paths.promptsDir);

  // 1. Copy App Directories
  console.log('Copying application directories...');
  for (const dir of APP_DIRS) {
      const src = path.join(PKG_ROOT, dir);
      const dest = path.join(paths.torchDir, dir);
      // If installing to '.', src/bin maps to ./bin, which is fine.
      if (fs.existsSync(src)) {
          copyDir(src, dest);
          console.log(`  Copied ${dir}/`);
      }
  }

  // 2. Copy App Files
  console.log('Copying application files...');
  for (const file of APP_FILES) {
      const src = path.join(PKG_ROOT, file);
      const dest = path.join(paths.torchDir, file);
      if (fs.existsSync(src)) {
          // Careful not to overwrite critical files if they exist in root?
          // e.g. package.json.
          // If installing to '.', we definitely don't want to overwrite package.json unless it's the torch one?
          // But torch is "vendored", so it has its own package.json.
          // If installing to '.', we are overwriting the USER's package.json?
          // That is dangerous.

          if (installDir === '.' && file === 'package.json' && fs.existsSync(dest)) {
              console.warn('  Skipping package.json to avoid overwriting host package.json (installing to root).');
              continue;
          }

          fs.copyFileSync(src, dest);
          console.log(`  Copied ${file}`);
      }
  }

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

  fs.writeFileSync(configPath, JSON.stringify(configData, null, 2), 'utf8');
  console.log(`Saved configuration to ${path.relative(cwd, configPath)}`);

  // 7. Inject Scripts into Host Package.json
  // If we are NOT installing to '.', the host package.json is in paths.root
  if (installDir !== '.') {
      injectScriptsIntoHost(paths.root, installDir);
  }

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
  console.log('Updating application directories...');
  for (const dir of APP_DIRS) {
      const src = path.join(PKG_ROOT, dir);
      const dest = path.join(paths.torchDir, dir);
      if (fs.existsSync(src)) {
          copyDir(src, dest);
          console.log(`  Updated ${dir}/`);
      }
  }

  // 3. Update App Files (Overwrite)
  console.log('Updating application files...');
  for (const file of APP_FILES) {
      const src = path.join(PKG_ROOT, file);
      const dest = path.join(paths.torchDir, file);
      if (fs.existsSync(src)) {
          if (installDirName === '.' && file === 'package.json') {
             console.log('  Skipping package.json update (installed in root).');
             continue;
          }
          fs.copyFileSync(src, dest);
          console.log(`  Updated ${file}`);
      }
  }

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
