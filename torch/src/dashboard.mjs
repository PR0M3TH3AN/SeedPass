import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { DEFAULT_DASHBOARD_PORT } from './constants.mjs';

export async function cmdDashboard(port = DEFAULT_DASHBOARD_PORT) {
  // Resolve package root relative to this file (src/dashboard.mjs)
  // this file is in <root>/src/dashboard.mjs, so '..' goes to <root>
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

  const server = http.createServer(async (req, res) => {
    // URL parsing
    const url = new URL(req.url, `http://${req.headers.host}`);
    let pathname = url.pathname;

    // Redirect / to /dashboard/
    if (pathname === '/' || pathname === '/dashboard') {
      res.writeHead(302, { 'Location': '/dashboard/' });
      res.end();
      return;
    }

    async function statSafe(p) {
      try {
        return await fsp.stat(p);
      } catch {
        return null;
      }
    }

    // Special case: /torch-config.json
    // Priority: User's CWD > Package default
    if (pathname === '/torch-config.json') {
      const userConfigPath = path.resolve(process.cwd(), 'torch-config.json');
      if (await statSafe(userConfigPath)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        fs.createReadStream(userConfigPath).pipe(res);
        return;
      }
      // If not found in CWD, fall through to serve from packageRoot (if it exists there)
      // or return empty object if missing?
      // Falling through means it looks for packageRoot/torch-config.json
    }

    // Security check: prevent directory traversal
    const safePath = path.normalize(pathname).replace(new RegExp('^(\\.\\.[\\/\\\\])+'), '');
    let filePath = path.join(packageRoot, safePath);

    // If directory, try index.html
    let fileStat = await statSafe(filePath);
    if (fileStat && fileStat.isDirectory()) {
       filePath = path.join(filePath, 'index.html');
       fileStat = await statSafe(filePath);
    }

    // Check if file exists and is a file
    if (!fileStat || !fileStat.isFile()) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }

    // MIME types
    const extname = path.extname(filePath);
    let contentType = 'text/plain';
    switch (extname) {
      case '.html': contentType = 'text/html'; break;
      case '.js': contentType = 'text/javascript'; break;
      case '.mjs': contentType = 'text/javascript'; break;
      case '.css': contentType = 'text/css'; break;
      case '.json': contentType = 'application/json'; break;
      case '.png': contentType = 'image/png'; break;
      case '.jpg': contentType = 'image/jpeg'; break;
      case '.svg': contentType = 'image/svg+xml'; break;
      case '.ico': contentType = 'image/x-icon'; break;
      case '.md': contentType = 'text/markdown'; break;
    }

    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });

  server.listen(port, () => {
    console.log(`Dashboard running at http://localhost:${port}/dashboard/`);
    console.log(`Serving files from ${packageRoot}`);
    console.log(`Using configuration from ${process.cwd()}`);
  });

  // Keep process alive
  return new Promise(() => {});
}
