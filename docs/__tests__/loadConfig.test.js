const fs = require('fs');
const path = require('path');
const loadConfig = require('../src/config/loadConfig');

test('loads configuration and merges defaults', () => {
  const dir = fs.mkdtempSync(path.join(__dirname, 'cfg-'));
  const file = path.join(dir, 'config.yaml');
  fs.writeFileSync(file, 'site:\n  title: Test Site\n');
  const cfg = loadConfig(file);
  expect(cfg.site.title).toBe('Test Site');
  expect(cfg.navigation.search).toBe(true);
  fs.rmSync(dir, { recursive: true, force: true });
});
