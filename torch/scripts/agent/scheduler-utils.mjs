import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';

const ALLOWED_ENV_KEYS = new Set([
  'PATH', 'Path', // Windows compatibility
  'HOME', 'USER', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ',
  'NODE_ENV', 'NODE_OPTIONS', 'NODE_PATH',
  'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'SystemRoot', 'windir', 'ComSpec', 'PATHEXT',
  'TMPDIR', 'TEMP', 'TMP',
  'EDITOR', 'VISUAL',
  // CI variables
  'CI', 'GITHUB_ACTIONS', 'GITHUB_REF', 'GITHUB_HEAD_REF', 'GITHUB_BASE_REF', 'GITHUB_EVENT_NAME', 'GITHUB_SHA',
]);

export function getSafeEnv() {
  const safeEnv = {};
  for (const key in process.env) {
    if (ALLOWED_ENV_KEYS.has(key) ||
        key.startsWith('npm_') ||
        key.startsWith('NOSTR_') ||
        key.startsWith('TORCH_') ||
        key.startsWith('SCHEDULER_') ||
        key.startsWith('AGENT_') ||
        key.startsWith('JULES_') ||
        key.startsWith('CODEX_') ||
        key.startsWith('CLAUDE_') ||
        key.startsWith('ANTHROPIC_') ||
        key.startsWith('GOOSE_')) {
      safeEnv[key] = process.env[key];
    }
  }
  return safeEnv;
}

/**
 * Spawns a child process with a sanitized environment by default.
 * @param {string} command
 * @param {string[]} args
 * @param {object} options
 * @param {object} [options.env] - Additional environment variables to merge.
 * @param {boolean} [options.inheritProcessEnv=false] - If true, use full process.env. If false (default), use sanitized env.
 */
export async function runCommand(command, args = [], options = {}) {
  const baseEnv = options.inheritProcessEnv ? process.env : getSafeEnv();
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env: { ...baseEnv, ...(options.env || {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    const OUTPUT_LIMIT = 20000; // 20KB
    let stdoutWritten = 0;
    let stderrWritten = 0;
    let stdoutTruncated = false;
    let stderrTruncated = false;

    child.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;

      if (stdoutWritten < OUTPUT_LIMIT) {
        const remaining = OUTPUT_LIMIT - stdoutWritten;
        if (text.length <= remaining) {
          process.stdout.write(text);
          stdoutWritten += text.length;
        } else {
          process.stdout.write(text.slice(0, remaining));
          stdoutWritten += remaining;
        }
      } else if (!stdoutTruncated) {
        process.stdout.write('\n...[stdout truncated]...\n');
        stdoutTruncated = true;
      }
    });

    child.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      stderr += text;

      if (stderrWritten < OUTPUT_LIMIT) {
        const remaining = OUTPUT_LIMIT - stderrWritten;
        if (text.length <= remaining) {
          process.stderr.write(text);
          stderrWritten += text.length;
        } else {
          process.stderr.write(text.slice(0, remaining));
          stderrWritten += remaining;
        }
      } else if (!stderrTruncated) {
        process.stderr.write('\n...[stderr truncated]...\n');
        stderrTruncated = true;
      }
    });

    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

export function parseJsonFromOutput(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return null;
  const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i];
    if (!line.startsWith('{') && !line.startsWith('[')) continue;
    try {
      return JSON.parse(line);
    } catch {
      // Keep scanning from the end.
    }
  }
  return null;
}

export function parseJsonEventsFromOutput(text) {
  const events = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        events.push(parsed);
      }
    } catch {
      // Ignore non-JSON lines.
    }
  }
  return events;
}

export async function readJson(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

export function normalizeStringList(value, fallback = []) {
  if (!Array.isArray(value)) return fallback;
  return value.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
}

export function parseNonNegativeInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (Number.isFinite(parsed) && parsed >= 0) {
    return parsed;
  }
  return fallback;
}

export function parseBooleanFlag(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

export function redactSensitive(text) {
  if (!text) return '';
  return String(text)
    .replace(/\b(BEARER\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/\b(token|api[_-]?key|secret(?:[_-]?key)?|password|passwd|authorization)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(/\b(sk|pk|ghp|xoxb|xoxp)_[A-Za-z0-9_-]+\b/g, '[REDACTED]');
}

export function excerptText(text, maxChars = 600) {
  const clean = redactSensitive(String(text || '').trim());
  if (!clean) return '';
  if (clean.length <= maxChars) return clean;
  return `${clean.slice(0, maxChars)}…`;
}

export function formatDurationMs(ms) {
  if (!Number.isFinite(ms) || ms < 0) return 'unknown';
  const minutes = Math.round(ms / 60000);
  return `${minutes} minute(s)`;
}

export function getRunDateKey(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

export function toYamlScalar(value) {
  const str = String(value ?? '');
  return `'${str.replace(/'/g, "''")}'`;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
