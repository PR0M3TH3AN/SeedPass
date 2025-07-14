const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key])
    ) {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else if (source[key] !== undefined) {
      target[key] = source[key];
    }
  }
  return target;
}

function loadConfig(configPath = path.join(process.cwd(), 'config.yaml')) {
  let raw = {};
  if (fs.existsSync(configPath)) {
    try {
      raw = yaml.load(fs.readFileSync(configPath, 'utf8')) || {};
    } catch (e) {
      console.error(`Failed to parse ${configPath}: ${e.message}`);
      process.exit(1);
    }
  }

  const defaults = {
    site: {
      title: 'Archivox',
      description: '',
      logo: '',
      favicon: ''
    },
    navigation: {
      search: true
    },
    footer: {},
    theme: {
      name: 'minimal',
      darkMode: false
    },
    features: {},
    pluginsDir: 'plugins',
    plugins: []
  };

  const config = deepMerge(defaults, raw);

  const errors = [];
  if (
    !config.site ||
    typeof config.site.title !== 'string' ||
    !config.site.title.trim()
  ) {
    errors.push('site.title is required in config.yaml');
  }

  if (errors.length) {
    errors.forEach(err => console.error(`Config error: ${err}`));
    process.exit(1);
  }

  return config;
}

module.exports = loadConfig;
