const fs = require('fs');
const path = require('path');
const loadPlugins = require('../src/config/loadPlugins');

test('plugin hook modifies data', async () => {
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'plugins-'));
  const pluginFile = path.join(dir, 'test.plugin.js');
  fs.writeFileSync(
    pluginFile,
    "module.exports = { onParseMarkdown: ({ content }) => ({ content: content + '!!' }) };\n"
  );

  const plugins = loadPlugins({ pluginsDir: dir, plugins: ['test.plugin'] });
  let data = { content: 'hello' };
  for (const plugin of plugins) {
    if (typeof plugin.onParseMarkdown === 'function') {
      const res = await plugin.onParseMarkdown(data);
      if (res !== undefined) data = res;
    }
  }
  expect(data.content).toBe('hello!!');
  fs.rmSync(dir, { recursive: true, force: true });
});
