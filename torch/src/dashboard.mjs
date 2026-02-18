import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEFAULT_DASHBOARD_PORT } from './constants.mjs';
import { getDashboardAuth, parseTorchConfig } from './torch-config.mjs';

function timingSafeCompare(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still do a comparison to avoid some timing leaks, though length leak is hard to avoid entirely
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

export async function cmdDashboard(port = DEFAULT_DASHBOARD_PORT, host = '127.0.0.1') {
  // Resolve package root relative to this file (src/dashboard.mjs)
  // this file is in <root>/src/dashboard.mjs, so '..' goes to <root>
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const auth = await getDashboardAuth();

  const server = http.createServer(async (req, res) => {
    try {
    // Basic Auth check
    if (auth) {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="TORCH Dashboard"' });
        res.end('Authentication required');
        return;
      }
      const parts = authHeader.split(' ');
      const type = parts[0];
      const credentials = parts[1];
      let isValid = false;
      if (type === 'Basic' && credentials) {
        try {
          const decoded = Buffer.from(credentials, 'base64').toString();
          isValid = timingSafeCompare(decoded, auth);
        } catch {
          isValid = false;
        }
      }

      if (!isValid) {
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="TORCH Dashboard"' });
        res.end('Invalid credentials');
        return;
      }
    }

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
    // Priority: Env Var > User's CWD > Package default
    if (pathname === '/torch-config.json') {
      let configContent = null;

      if (process.env.TORCH_CONFIG_PATH) {
        const envPath = path.resolve(process.cwd(), process.env.TORCH_CONFIG_PATH);
        try {
          configContent = await fsp.readFile(envPath, 'utf8');
        } catch {
          // Explicitly provided config path not found, do not fall back
        }
      } else {
        const userConfigPath = path.resolve(process.cwd(), 'torch-config.json');
        try {
          configContent = await fsp.readFile(userConfigPath, 'utf8');
        } catch {
          // Try package default
          const packageConfigPath = path.join(packageRoot, 'torch-config.json');
          try {
            configContent = await fsp.readFile(packageConfigPath, 'utf8');
          } catch {
            // Not found in either location
          }
        }
      }

      if (configContent) {
        try {
          const rawConfig = JSON.parse(configContent);
          const safeConfig = parseTorchConfig(rawConfig);

          // Security: Sanitize sensitive fields
          if (safeConfig.dashboard) {
            delete safeConfig.dashboard.auth;
          }
          delete safeConfig.configPath;

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(safeConfig, null, 2));
          return;
        } catch (err) {
          console.error('Error parsing torch-config.json:', err);
          res.writeHead(500);
          res.end('Internal Server Error');
          return;
        }
      } else {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
    }

    // Security check: prevent directory traversal
    const safePath = path.normalize(pathname).replace(new RegExp('^(\\.\\.[\\/\\\\])+'), '');
    let filePath = path.join(packageRoot, safePath);

    // Security check: restrict access to allowed paths
    const allowedPaths = [
      path.join(packageRoot, 'dashboard'),
      path.join(packageRoot, 'assets'),
      path.join(packageRoot, 'src', 'docs'),
      path.join(packageRoot, 'src', 'constants.mjs'),
      path.join(packageRoot, 'torch-config.json')
    ];

    const isAllowed = allowedPaths.some(allowedPath => {
      const rel = path.relative(allowedPath, filePath);
      return !rel.startsWith('..') && !path.isAbsolute(rel);
    });

    if (!isAllowed) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

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
    } catch (err) {
      console.error('Dashboard Server Error:', err);
      if (!res.headersSent) {
        res.writeHead(500);
        res.end('Internal Server Error');
      }
    }
  });

  return new Promise((resolve, reject) => {
    server.listen(port, host, () => {
      const listenUrl = `http://${host === '0.0.0.0' ? 'localhost' : host}:${port}/dashboard/`;
      console.log(`Dashboard running at ${listenUrl}`);
      if (auth) {
        console.log('Authentication: enabled (Basic Auth)');
      } else {
        console.warn('Authentication: DISABLED (Dashboard is public)');
      }
      console.log(`Serving files from ${packageRoot}`);
      console.log(`Using configuration from ${process.cwd()}`);
      resolve(server);
    });
    server.on('error', reject);
  });
}
