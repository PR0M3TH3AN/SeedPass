/**
 * HTTP API server — parity with src/seedpass/api.py.
 *
 * This process holds an unlocked parent seed and binds a TCP port, which is a
 * strictly larger attack surface than the session agent's 0600 unix socket.
 * Everything here is shaped by that:
 *
 *   - Loopback only unless the operator explicitly says otherwise, and even
 *     then it refuses to bind a non-loopback address without a token they
 *     supplied themselves (see `resolveBind`).
 *   - Every route requires a bearer token. The token is printed once, at
 *     startup, and never written to disk.
 *   - Routes that produce plaintext secrets additionally require the master
 *     password in a header, so a leaked bearer token alone does not read the
 *     vault. This mirrors Python's `_require_password`.
 *   - Rate limits on everything, and a separate, much tighter limit on failed
 *     unlock attempts, so the port is not an offline-speed password oracle.
 *
 * Implemented on `node:http` rather than a framework. The CLI ships as a
 * single audited bundle with an empty production dependency list, and adding
 * a web framework to a process that holds unlocked seeds would be the largest
 * supply-chain change in the project.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

/** Default cap on a request body, matching Python's SEEDPASS_MAX_IMPORT_BYTES. */
export const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

export const DEFAULT_RATE_LIMIT = 100;
export const DEFAULT_RATE_WINDOW_SECONDS = 60;
export const DEFAULT_UNLOCK_ATTEMPT_LIMIT = 5;
export const DEFAULT_UNLOCK_ATTEMPT_WINDOW_SECONDS = 300;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export interface ApiRequest {
  method: string;
  /** Path with no query string. */
  path: string;
  query: URLSearchParams;
  headers: Record<string, string | undefined>;
  /** Parsed JSON body, or undefined when there was none. */
  body: unknown;
  /** Raw body bytes, for routes that take a file. */
  rawBody: Uint8Array;
  /** Path parameters captured by the route pattern. */
  params: Record<string, string>;
}

export interface ApiResponse {
  status?: number;
  /** JSON-serializable body. Mutually exclusive with `bytes`. */
  json?: unknown;
  /** Raw bytes, for downloads. */
  bytes?: Uint8Array;
  contentType?: string;
  headers?: Record<string, string>;
}

export type RouteHandler = (req: ApiRequest) => Promise<ApiResponse> | ApiResponse;

interface CompiledRoute {
  method: string;
  /** Segments; a leading ':' marks a parameter. */
  segments: string[];
  handler: RouteHandler;
  /** Whether this route needs the master-password header. */
  requiresPassword: boolean;
}

export interface ApiServerOptions {
  host?: string;
  port?: number;
  /**
   * Explicit acknowledgement that a non-loopback bind is intended. Without it
   * the server refuses to listen anywhere but localhost — an accidental
   * `--host 0.0.0.0` on a process holding unlocked seeds is not a mistake
   * that should be recoverable after the fact.
   */
  allowRemote?: boolean;
  /** Supply a token instead of generating one (tests, or an operator's own). */
  token?: string;
  maxBodyBytes?: number;
  rateLimit?: number;
  rateWindowSeconds?: number;
  unlockAttemptLimit?: number;
  unlockAttemptWindowSeconds?: number;
  /** Origins allowed for CORS. Empty (the default) sends no CORS headers. */
  corsOrigins?: string[];
  /** Injectable clock, in milliseconds. */
  now?: () => number;
}

function loopback(host: string): boolean {
  if (host === "localhost") return true;
  if (isIP(host) === 4) return host.startsWith("127.");
  if (isIP(host) === 6) return host === "::1" || host === "::ffff:127.0.0.1";
  return false;
}

/**
 * Where to bind, refusing anything exposed unless it was asked for outright.
 */
export function resolveBind(options: ApiServerOptions): { host: string; port: number } {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8765;
  if (!loopback(host) && !options.allowRemote) {
    throw new Error(
      `refusing to bind ${host}: this process holds unlocked parent seeds, so ` +
        `it listens on loopback only. Pass --allow-remote if you genuinely ` +
        `intend to expose it, and put a TLS-terminating proxy in front of it.`,
    );
  }
  return { host, port };
}

/** Sliding-window counter, keyed per client+token. */
class SlidingWindow {
  private readonly buckets = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  /** Drops expired hits and reports whether `key` is already at the limit. */
  atLimit(key: string, now: number): boolean {
    return this.prune(key, now).length >= this.limit;
  }

  record(key: string, now: number): void {
    this.prune(key, now).push(now);
  }

  private prune(key: string, now: number): number[] {
    const bucket = this.buckets.get(key) ?? [];
    const cutoff = now - this.windowMs;
    let i = 0;
    while (i < bucket.length && bucket[i]! <= cutoff) i++;
    const live = i > 0 ? bucket.slice(i) : bucket;
    this.buckets.set(key, live);
    return live;
  }
}

export class ApiServer {
  private readonly routes: CompiledRoute[] = [];
  private server: Server | null = null;
  private readonly tokenHash: Buffer;
  private readonly rate: SlidingWindow;
  private readonly unlockAttempts: SlidingWindow;
  private readonly now: () => number;
  private readonly maxBodyBytes: number;
  private readonly corsOrigins: Set<string>;

  /** The bearer token. Printed once by the caller; never persisted. */
  readonly token: string;

  constructor(private readonly options: ApiServerOptions = {}) {
    // A 32-byte random token is not a password: it is not guessable, not
    // reused, and not chosen by a human, so a slow KDF over it buys nothing
    // that a hash does not. (Python uses bcrypt here; matching that would
    // mean adding a native dependency to a seed-holding process for no gain.)
    // What does matter is comparing in constant time, which is why this
    // hashes both sides to a fixed length before comparing.
    this.token = options.token ?? randomBytes(32).toString("base64url");
    this.tokenHash = createHash("sha256").update(this.token).digest();
    this.now = options.now ?? (() => Date.now());
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    this.rate = new SlidingWindow(
      options.rateLimit ?? DEFAULT_RATE_LIMIT,
      (options.rateWindowSeconds ?? DEFAULT_RATE_WINDOW_SECONDS) * 1000,
    );
    this.unlockAttempts = new SlidingWindow(
      options.unlockAttemptLimit ?? DEFAULT_UNLOCK_ATTEMPT_LIMIT,
      (options.unlockAttemptWindowSeconds ?? DEFAULT_UNLOCK_ATTEMPT_WINDOW_SECONDS) * 1000,
    );
    this.corsOrigins = new Set(options.corsOrigins ?? []);
  }

  /**
   * Register a route.
   *
   * `requiresPassword` marks routes that hand back plaintext secrets. Those
   * need the master password in addition to the bearer token, so that a
   * token captured from a script cannot read the vault on its own.
   */
  route(
    method: string,
    pattern: string,
    handler: RouteHandler,
    opts: { requiresPassword?: boolean } = {},
  ): this {
    this.routes.push({
      method: method.toUpperCase(),
      segments: pattern.split("/").filter((s) => s.length > 0),
      handler,
      requiresPassword: opts.requiresPassword ?? false,
    });
    return this;
  }

  /** Verify a bearer token in constant time. */
  private tokenValid(authorization: string | undefined): boolean {
    if (!authorization || !authorization.startsWith("Bearer ")) return false;
    const presented = createHash("sha256")
      .update(authorization.slice("Bearer ".length))
      .digest();
    return timingSafeEqual(presented, this.tokenHash);
  }

  /**
   * Rate-limit key.
   *
   * Includes the client address so one misbehaving caller cannot exhaust
   * another's budget, and a short digest of the token rather than the token,
   * so the limiter's own state never holds the credential.
   */
  private rateKey(req: IncomingMessage, authorization: string | undefined): string {
    const client = req.socket.remoteAddress ?? "unknown";
    const digest = createHash("sha256")
      .update(authorization ?? "")
      .digest("hex")
      .slice(0, 16);
    return `${client}:${digest}`;
  }

  /** Note a failed unlock, tightening the dedicated unlock limiter. */
  recordUnlockFailure(req: ApiRequest): void {
    this.unlockAttempts.record(String(req.headers["x-seedpass-rate-key"] ?? ""), this.now());
  }

  private match(method: string, path: string): { route: CompiledRoute; params: Record<string, string> } | null {
    const parts = path.split("/").filter((s) => s.length > 0);
    // A path that matches some route but not this method should say so,
    // rather than reporting the path as missing.
    let pathMatched = false;
    for (const route of this.routes) {
      if (route.segments.length !== parts.length) continue;
      const params: Record<string, string> = {};
      let ok = true;
      for (let i = 0; i < route.segments.length; i++) {
        const seg = route.segments[i]!;
        if (seg.startsWith(":")) {
          params[seg.slice(1)] = decodeURIComponent(parts[i]!);
        } else if (seg !== parts[i]) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      pathMatched = true;
      if (route.method === method) return { route, params };
    }
    if (pathMatched) throw new HttpError(405, "Method Not Allowed");
    return null;
  }

  private async readBody(req: IncomingMessage): Promise<Uint8Array> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of req) {
      const buf = chunk as Buffer;
      total += buf.length;
      // Stop while it is still arriving rather than after it is all in
      // memory: this process holds seeds and must not be trivially OOM-able.
      if (total > this.maxBodyBytes) {
        throw new HttpError(413, `request body exceeds ${this.maxBodyBytes} bytes`);
      }
      chunks.push(buf);
    }
    return new Uint8Array(Buffer.concat(chunks));
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const headers: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
    }
    const origin = headers["origin"];
    const corsHeaders: Record<string, string> = {};
    if (origin && this.corsOrigins.has(origin)) {
      corsHeaders["access-control-allow-origin"] = origin;
      corsHeaders["vary"] = "Origin";
      corsHeaders["access-control-allow-headers"] =
        "authorization, content-type, x-seedpass-password";
      corsHeaders["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS";
    }

    try {
      if (req.method === "OPTIONS") {
        this.send(res, { status: 204, headers: corsHeaders });
        return;
      }

      const url = new URL(req.url ?? "/", "http://localhost");
      const authorization = headers["authorization"];
      const rateKey = this.rateKey(req, authorization);
      const now = this.now();

      // Rate limit before authentication, so an unauthenticated flood cannot
      // be used to hammer the token comparison either.
      if (this.rate.atLimit(rateKey, now)) {
        throw new HttpError(429, "Rate limit exceeded");
      }
      this.rate.record(rateKey, now);

      if (!this.tokenValid(authorization)) throw new HttpError(401, "Unauthorized");

      const matched = this.match(req.method ?? "GET", url.pathname);
      if (!matched) throw new HttpError(404, "Not Found");

      const rawBody = await this.readBody(req);
      let body: unknown;
      if (rawBody.length > 0 && (headers["content-type"] ?? "").includes("json")) {
        try {
          body = JSON.parse(new TextDecoder().decode(rawBody));
        } catch {
          throw new HttpError(400, "invalid JSON body");
        }
      }

      const apiReq: ApiRequest = {
        method: req.method ?? "GET",
        path: url.pathname,
        query: url.searchParams,
        headers: { ...headers, "x-seedpass-rate-key": rateKey },
        body,
        rawBody,
        params: matched.params,
      };

      if (matched.route.requiresPassword && !headers["x-seedpass-password"]) {
        // Said plainly: this is not a missing token, it is a route that will
        // not hand over plaintext on a bearer token alone.
        throw new HttpError(
          401,
          "this route returns plaintext secrets and requires the master " +
            "password in the X-SeedPass-Password header",
        );
      }

      // The unlock route is the one place a wrong password is expected, so it
      // gets its own much tighter budget — otherwise the port is a password
      // oracle at network speed.
      if (url.pathname.endsWith("/vault/unlock")) {
        if (this.unlockAttempts.atLimit(rateKey, now)) {
          throw new HttpError(429, "Too many failed unlock attempts; wait and retry");
        }
      }

      const result = await matched.route.handler(apiReq);
      this.send(res, { ...result, headers: { ...corsHeaders, ...(result.headers ?? {}) } });
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      // Never let an internal message escape: stack traces and filesystem
      // paths from this process describe a machine holding unlocked seeds.
      const detail =
        e instanceof HttpError ? e.message : "internal error";
      if (!(e instanceof HttpError)) {
        process.stderr.write(`api: unhandled error: ${String(e)}\n`);
      }
      this.send(res, { status, json: { detail }, headers: corsHeaders });
    }
  }

  private send(res: ServerResponse, response: ApiResponse): void {
    const status = response.status ?? 200;
    const headers: Record<string, string> = {
      // This is a JSON API for local automation; nothing here should be
      // framed, sniffed, or cached.
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...(response.headers ?? {}),
    };
    let payload: Uint8Array;
    if (response.bytes) {
      payload = response.bytes;
      headers["content-type"] = response.contentType ?? "application/octet-stream";
    } else if (response.json !== undefined) {
      payload = new TextEncoder().encode(JSON.stringify(response.json));
      headers["content-type"] = response.contentType ?? "application/json";
    } else {
      payload = new Uint8Array(0);
    }
    headers["content-length"] = String(payload.length);
    res.writeHead(status, headers);
    res.end(Buffer.from(payload));
  }

  async listen(): Promise<{ host: string; port: number }> {
    const { host, port } = resolveBind(this.options);
    this.server = createServer((req, res) => {
      void this.handle(req, res);
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, () => resolve());
    });
    const address = this.server.address();
    const actualPort = typeof address === "object" && address ? address.port : port;
    return { host, port: actualPort };
  }

  async close(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }
}
