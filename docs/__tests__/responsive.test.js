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
        fs.writeFileSync(
          dest,
          `<!DOCTYPE html><html><head><link rel="stylesheet" href="/assets/theme.css"></head><body><header><button id="sidebar-toggle" class="sidebar-toggle">☰</button></header><div class="container"><aside class="sidebar"></aside><main></main></div><script src="/assets/theme.js"></script></body></html>`
        );
      }
    }
  };
});

const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const puppeteer = require('puppeteer');
const { generate } = require('../src/generator');

jest.setTimeout(30000);

let server;
let browser;
let port;
let tmp;

beforeAll(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'df-responsive-'));
  const contentDir = path.join(tmp, 'content');
  const outputDir = path.join(tmp, '_site');
  fs.mkdirSync(contentDir, { recursive: true });
  fs.writeFileSync(path.join(contentDir, 'index.md'), '# Home\n');
  await generate({ contentDir, outputDir });
  fs.cpSync(path.join(__dirname, '../assets'), path.join(outputDir, 'assets'), { recursive: true });

  server = http.createServer((req, res) => {
    let filePath = path.join(outputDir, req.url === '/' ? 'index.html' : req.url);
    if (req.url.startsWith('/assets')) {
      filePath = path.join(outputDir, req.url);
    }
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      const ext = path.extname(filePath).slice(1);
      const type = { html: 'text/html', js: 'text/javascript', css: 'text/css' }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type });
      res.end(data);
    });
  });
  await new Promise(resolve => {
    server.listen(0, () => {
      port = server.address().port;
      resolve();
    });
  });

  browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
});

afterAll(async () => {
  if (browser) await browser.close();
  if (server) server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('sidebar opens on small screens', async () => {
  const page = await browser.newPage();
  await page.setViewport({ width: 500, height: 800 });
  await page.goto(`http://localhost:${port}/`);
  await page.waitForSelector('#sidebar-toggle');
  await page.click('#sidebar-toggle');
  await new Promise(r => setTimeout(r, 300));
  const bodyClass = await page.evaluate(() => document.body.classList.contains('sidebar-open'));
  const sidebarLeft = await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar')).left);
  expect(bodyClass).toBe(true);
  expect(sidebarLeft).toBe('0px');
});

test('clicking outside closes sidebar on small screens', async () => {
  const page = await browser.newPage();
  await page.setViewport({ width: 500, height: 800 });
  await page.goto(`http://localhost:${port}/`);
  await page.waitForSelector('#sidebar-toggle');
  await page.click('#sidebar-toggle');
  await new Promise(r => setTimeout(r, 300));
  await page.click('main');
  await new Promise(r => setTimeout(r, 300));
  const bodyClass = await page.evaluate(() => document.body.classList.contains('sidebar-open'));
  expect(bodyClass).toBe(false);
});

test('sidebar toggles on large screens', async () => {
  const page = await browser.newPage();
  await page.setViewport({ width: 1024, height: 800 });
  await page.goto(`http://localhost:${port}/`);
  await page.waitForSelector('#sidebar-toggle');
  await new Promise(r => setTimeout(r, 300));
  let sidebarWidth = await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar')).width);
  expect(sidebarWidth).toBe('240px');
  await page.click('#sidebar-toggle');
  await new Promise(r => setTimeout(r, 300));
  sidebarWidth = await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar')).width);
  expect(sidebarWidth).toBe('0px');
});
