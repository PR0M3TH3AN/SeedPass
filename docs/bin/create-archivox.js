#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function main() {
  const args = process.argv.slice(2);
  const install = args.includes('--install');
  const targetArg = args.find(a => !a.startsWith('-')) || '.';
  const targetDir = path.resolve(process.cwd(), targetArg);

  const templateDir = path.join(__dirname, '..', 'starter');
  copyDir(templateDir, targetDir);

  const pkgPath = path.join(targetDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const version = require('../package.json').version;
    if (pkg.dependencies && pkg.dependencies.archivox)
      pkg.dependencies.archivox = `^${version}`;
    pkg.name = path.basename(targetDir);
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
  }

  if (install) {
    execSync('npm install', { cwd: targetDir, stdio: 'inherit' });
  }

  console.log(`Archivox starter created at ${targetDir}`);
}

main();
