# Archivox

Archivox is a lightweight static site generator aimed at producing documentation sites similar to "Read the Docs". Write your content in Markdown, run the generator, and deploy the static files anywhere.

[![Build Status](https://github.com/PR0M3TH3AN/Archivox/actions/workflows/ci.yml/badge.svg)](https://github.com/PR0M3TH3AN/Archivox/actions/workflows/ci.yml)

## Features
- Markdown based pages with automatic navigation
- Responsive layout with sidebar and search powered by Lunr.js
- Simple configuration through `config.yaml`
- Extensible via plugins and custom templates

## Getting Started
Install the dependencies and start the development server:

```bash
npm install
npm run dev
```

The site will be available at `http://localhost:8080`. Edit files inside the `content/` directory to update pages.

To create a new project from the starter template you can run:

```bash
npx create-archivox my-docs --install
```

## Building
When you are ready to publish your documentation run:

```bash
npm run build
```

The generated site is placed in the `_site/` folder.

## Customization
- **`config.yaml`** – change the site title, theme options and other settings.
- **`plugins/`** – add JavaScript files exporting hook functions such as `onPageRendered` to extend the build process.
- **`templates/`** – modify or replace the Nunjucks templates for full control over the HTML.

## Hosting
Upload the contents of `_site/` to any static host. For Netlify you can use the provided `netlify.toml`:

```toml
[build]
  command = "npm run build"
  publish = "_site"
```

## Documentation
See the files under the `docs/` directory for a full guide to Archivox including an integration tutorial for existing projects.

Archivox is released under the MIT License.
