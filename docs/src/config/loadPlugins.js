const path = require('path');
const fs = require('fs');

function loadPlugins(config) {
  const dir = path.resolve(process.cwd(), config.pluginsDir || 'plugins');
  const names = Array.isArray(config.plugins) ? config.plugins : [];
  const plugins = [];
  for (const name of names) {
    const file = path.join(dir, name.endsWith('.js') ? name : `${name}.js`);
    if (fs.existsSync(file)) {
      try {
        const mod = require(file);
        plugins.push(mod);
      } catch (e) {
        console.error(`Failed to load plugin ${name}:`, e);
      }
    } else {
      console.warn(`Plugin not found: ${file}`);
    }
  }
  return plugins;
}

module.exports = loadPlugins;
