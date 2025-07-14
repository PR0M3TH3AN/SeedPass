// Generator entry point for Archivox
const fs = require('fs');
const path = require('path');
const matter = require('gray-matter');
const lunr = require('lunr');
const marked = require('marked');
const { lexer } = marked;
const loadConfig = require('../config/loadConfig');
const loadPlugins = require('../config/loadPlugins');

function formatName(name) {
  return name
    .replace(/^\d+[-_]?/, '')
    .replace(/\.md$/, '');
}

async function readDirRecursive(dir) {
  const entries = await fs.promises.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const res = path.resolve(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await readDirRecursive(res));
    } else {
      files.push(res);
    }
  }
  return files;
}

function buildNav(pages) {
  const tree = {};
  for (const page of pages) {
    const rel = page.file.replace(/\\/g, '/');
    if (rel === 'index.md') {
      if (!tree.children) tree.children = [];
      tree.children.push({
        name: 'index.md',
        children: [],
        page: page.data,
        path: `/${rel.replace(/\.md$/, '.html')}`,
        order: page.data.order || 0
      });
      continue;
    }
    const parts = rel.split('/');
    let node = tree;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isLast = i === parts.length - 1;
      const isIndex = isLast && part === 'index.md';
      if (isIndex) {
        node.page = page.data;
        node.path = `/${rel.replace(/\.md$/, '.html')}`;
        node.order = page.data.order || 0;
        break;
      }
      if (!node.children) node.children = [];
      let child = node.children.find(c => c.name === part);
      if (!child) {
        child = { name: part, children: [] };
        node.children.push(child);
      }
      node = child;
      if (isLast) {
        node.page = page.data;
        node.path = `/${rel.replace(/\.md$/, '.html')}`;
        node.order = page.data.order || 0;
      }
    }
  }

  function finalize(node, isRoot = false) {
    if (node.page && node.page.title) {
      node.displayName = node.page.title;
    } else if (node.name) {
      node.displayName = formatName(node.name);
    }
    if (node.children) {
      node.children.forEach(c => finalize(c));
      node.children.sort((a, b) => {
        const orderDiff = (a.order || 0) - (b.order || 0);
        if (orderDiff !== 0) return orderDiff;
        return (a.displayName || '').localeCompare(b.displayName || '');
      });
      node.isSection = node.children.length > 0;
    } else {
      node.isSection = false;
    }
    if (isRoot && node.children) {
      const idx = node.children.findIndex(c => c.name === 'index.md');
      if (idx > 0) {
        const [first] = node.children.splice(idx, 1);
        node.children.unshift(first);
      }
    }
  }

  finalize(tree, true);
  return tree.children || [];
}

async function generate({ contentDir = 'content', outputDir = '_site', configPath } = {}) {
  const config = loadConfig(configPath);
  const plugins = loadPlugins(config);

  async function runHook(name, data) {
    for (const plugin of plugins) {
      if (typeof plugin[name] === 'function') {
        const res = await plugin[name](data);
        if (res !== undefined) data = res;
      }
    }
    return data;
  }
  if (!fs.existsSync(contentDir)) {
    console.error(`Content directory not found: ${contentDir}`);
    return;
  }

  const files = await readDirRecursive(contentDir);
  const pages = [];
  const assets = [];
  const searchDocs = [];

  for (const file of files) {
    const rel = path.relative(contentDir, file);
    if (file.endsWith('.md')) {
      const srcStat = await fs.promises.stat(file);
      const outPath = path.join(outputDir, rel.replace(/\.md$/, '.html'));
      if (fs.existsSync(outPath)) {
        const outStat = await fs.promises.stat(outPath);
        if (srcStat.mtimeMs <= outStat.mtimeMs) {
          continue; // skip unchanged
        }
      }
      let raw = await fs.promises.readFile(file, 'utf8');
      const mdObj = await runHook('onParseMarkdown', { file: rel, content: raw });
      if (mdObj && mdObj.content) raw = mdObj.content;
      const parsed = matter(raw);
      const tokens = lexer(parsed.content || '');
      const firstHeading = tokens.find(t => t.type === 'heading');
      const title = parsed.data.title || (firstHeading ? firstHeading.text : path.basename(rel, '.md'));
      const headings = tokens.filter(t => t.type === 'heading').map(t => t.text).join(' ');
      const htmlBody = require('marked').parse(parsed.content || '');
      const bodyText = htmlBody.replace(/<[^>]+>/g, ' ');
      pages.push({ file: rel, data: { ...parsed.data, title } });
      searchDocs.push({ id: rel.replace(/\.md$/, '.html'), url: '/' + rel.replace(/\.md$/, '.html'), title, headings, body: bodyText });
    } else {
      assets.push(rel);
    }
  }

  const nav = buildNav(pages);
  await fs.promises.mkdir(outputDir, { recursive: true });
  await fs.promises.writeFile(path.join(outputDir, 'navigation.json'), JSON.stringify(nav, null, 2));
  await fs.promises.writeFile(path.join(outputDir, 'config.json'), JSON.stringify(config, null, 2));

  const searchIndex = lunr(function() {
    this.ref('id');
    this.field('title');
    this.field('headings');
    this.field('body');
    searchDocs.forEach(d => this.add(d));
  });
  await fs.promises.writeFile(
    path.join(outputDir, 'search-index.json'),
    JSON.stringify({ index: searchIndex.toJSON(), docs: searchDocs }, null, 2)
  );

  const nunjucks = require('nunjucks');
  const env = new nunjucks.Environment(
    new nunjucks.FileSystemLoader('templates')
  );
  env.addGlobal('navigation', nav);
  env.addGlobal('config', config);

  for (const page of pages) {
    const outPath = path.join(outputDir, page.file.replace(/\.md$/, '.html'));
    await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
    const srcPath = path.join(contentDir, page.file);
    const raw = await fs.promises.readFile(srcPath, 'utf8');
    const { content, data } = matter(raw);
    const body = require('marked').parse(content);

    const pageContext = {
      title: data.title || page.data.title,
      content: body,
      page: { url: '/' + page.file.replace(/\.md$/, '.html') }
    };

    let html = env.render('layout.njk', pageContext);
    const result = await runHook('onPageRendered', { file: page.file, html });
    if (result && result.html) html = result.html;
    await fs.promises.writeFile(outPath, html);
  }


  for (const asset of assets) {
    const srcPath = path.join(contentDir, asset);
    const destPath = path.join(outputDir, asset);
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
    try {
      const sharp = require('sharp');
      if (/(png|jpg|jpeg)/i.test(path.extname(asset))) {
        await sharp(srcPath).toFile(destPath);
        continue;
      }
    } catch (e) {
      // sharp not installed, fallback
    }
    await fs.promises.copyFile(srcPath, destPath);
  }

  // Copy the main assets directory (theme, js, etc.)
  // Always resolve assets relative to the Archivox package so it works
  // regardless of the current working directory or config location.
  const mainAssetsSrc = path.resolve(__dirname, '../../assets');
  const mainAssetsDest = path.join(outputDir, 'assets');

  if (fs.existsSync(mainAssetsSrc)) {
    console.log(`Copying main assets from ${mainAssetsSrc} to ${mainAssetsDest}`);
    // Use fs.promises.cp for modern Node.js, it's like `cp -R`
    await fs.promises.cp(mainAssetsSrc, mainAssetsDest, { recursive: true });
  }
}

module.exports = { generate, buildNav };

if (require.main === module) {
  generate().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
