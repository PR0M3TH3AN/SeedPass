import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DIST_DIR = path.join(__dirname, 'dist');
const LANDING_SRC = path.join(__dirname, 'landing');
const DASHBOARD_SRC = path.join(__dirname, 'dashboard');
const DOCS_SRC = path.join(__dirname, 'src', 'docs');
const CONSTANTS_SRC = path.join(__dirname, 'src', 'constants.mjs');
const PROMPTS_SRC = path.join(__dirname, 'src', 'prompts', 'META_PROMPTS.md');
const CONFIG_SRC = path.join(__dirname, 'torch-config.json');
const ASSETS_SRC = path.join(__dirname, 'assets');

// Ensure clean slate
if (fs.existsSync(DIST_DIR)) {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(DIST_DIR);

// 1. Copy landing/index.html -> dist/index.html
const landingHtml = fs.readFileSync(path.join(LANDING_SRC, 'index.html'), 'utf8');
let distHtml = landingHtml;

// Patch relative paths for root deployment
// Remove ../ prefix for these specific paths since they are now relative to root (dist/)
distHtml = distHtml.replace(/"\.\.\/dashboard\/styles\.css"/g, '"dashboard/styles.css"');
distHtml = distHtml.replace(/"\.\.\/dashboard\/"/g, '"dashboard/"'); // Link to dashboard
distHtml = distHtml.replace(/'\.\.\/src\/docs\/TORCH\.md'/g, "'src/docs/TORCH.md'");
distHtml = distHtml.replace(/"\.\.\/assets\//g, '"assets/');

fs.writeFileSync(path.join(DIST_DIR, 'index.html'), distHtml);

// 2. Copy dashboard/ -> dist/dashboard/
const distDashboard = path.join(DIST_DIR, 'dashboard');
fs.mkdirSync(distDashboard, { recursive: true });
fs.cpSync(DASHBOARD_SRC, distDashboard, { recursive: true });

// 3. Copy src/docs/ -> dist/src/docs/
const distDocs = path.join(DIST_DIR, 'src', 'docs');
fs.mkdirSync(distDocs, { recursive: true });
fs.cpSync(DOCS_SRC, distDocs, { recursive: true });

// 3.5. Copy src/constants.mjs -> dist/src/constants.mjs
fs.copyFileSync(CONSTANTS_SRC, path.join(DIST_DIR, 'src', 'constants.mjs'));

// 4. Copy src/prompts/META_PROMPTS.md -> dist/src/prompts/META_PROMPTS.md
const distPromptsDir = path.join(DIST_DIR, 'src', 'prompts');
fs.mkdirSync(distPromptsDir, { recursive: true });
if (fs.existsSync(PROMPTS_SRC)) {
  fs.copyFileSync(PROMPTS_SRC, path.join(distPromptsDir, 'META_PROMPTS.md'));
}

// 5. Copy torch-config.json -> dist/torch-config.json (optional config)
if (fs.existsSync(CONFIG_SRC)) {
  fs.copyFileSync(CONFIG_SRC, path.join(DIST_DIR, 'torch-config.json'));
}

// 6. Copy assets/ -> dist/assets/
const distAssets = path.join(DIST_DIR, 'assets');
if (fs.existsSync(ASSETS_SRC)) {
  fs.mkdirSync(distAssets, { recursive: true });
  fs.cpSync(ASSETS_SRC, distAssets, { recursive: true });
}

console.log('Build complete! Output directory: dist/');
