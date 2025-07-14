#!/usr/bin/env node
const path = require('path');
const { generate } = require('./src/generator');

(async () => {
  try {
    const contentDir = path.join(__dirname, 'docs', 'content');
    const configPath = path.join(__dirname, 'docs', 'config.yaml');
    const outputDir = path.join(__dirname, '_site');
    await generate({ contentDir, outputDir, configPath });
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
})();
