jest.mock('@11ty/eleventy', () => {
  const fs = require('fs');
  const path = require('path');
  return class Eleventy {
    constructor(input, output) {
      this.input = input;
      this.output = output;
    }
    setConfig() {}
    async write() {
      const walk = d => {
        const entries = fs.readdirSync(d, { withFileTypes: true });
        let files = [];
        for (const e of entries) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) files = files.concat(walk(p));
          else if (p.endsWith('.md')) files.push(p);
        }
        return files;
      };
      for (const file of walk(this.input)) {
        const rel = path.relative(this.input, file).replace(/\.md$/, '.html');
        const dest = path.join(this.output, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, '<header></header><aside class="sidebar"></aside>');
      }
    }
  };
});

const fs = require('fs');
const path = require('path');
const os = require('os');
const { generate } = require('../src/generator');

function getPaths(tree) {
  const paths = [];
  for (const node of tree) {
    if (node.path) paths.push(node.path);
    if (node.children) paths.push(...getPaths(node.children));
  }
  return paths;
}

test('markdown files render with layout and appear in nav/search', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'df-test-'));
  const contentDir = path.join(tmp, 'content');
  const outputDir = path.join(tmp, '_site');
  fs.mkdirSync(path.join(contentDir, 'guide'), { recursive: true });
  fs.writeFileSync(path.join(contentDir, 'index.md'), '# Home\nWelcome');
  fs.writeFileSync(path.join(contentDir, 'guide', 'install.md'), '# Install\nSteps');
  const configPath = path.join(tmp, 'config.yaml');
  fs.writeFileSync(configPath, 'site:\n  title: Test\n');

  await generate({ contentDir, outputDir, configPath });

  const indexHtml = fs.readFileSync(path.join(outputDir, 'index.html'), 'utf8');
  const installHtml = fs.readFileSync(path.join(outputDir, 'guide', 'install.html'), 'utf8');
  expect(indexHtml).toContain('<header');
  expect(indexHtml).toContain('<aside class="sidebar"');
  expect(installHtml).toContain('<header');
  expect(installHtml).toContain('<aside class="sidebar"');

  const nav = JSON.parse(fs.readFileSync(path.join(outputDir, 'navigation.json'), 'utf8'));
  const navPaths = getPaths(nav);
  expect(navPaths).toContain('/index.html');
  expect(navPaths).toContain('/guide/install.html');

  const search = JSON.parse(fs.readFileSync(path.join(outputDir, 'search-index.json'), 'utf8'));
  const docs = search.docs.map(d => d.id);
  expect(docs).toContain('index.html');
  expect(docs).toContain('guide/install.html');
  const installDoc = search.docs.find(d => d.id === 'guide/install.html');
  expect(installDoc.body).toContain('Steps');

  fs.rmSync(tmp, { recursive: true, force: true });
});
