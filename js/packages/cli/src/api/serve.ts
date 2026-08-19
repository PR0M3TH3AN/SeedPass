/**
 * Wire the API server to a profile and run it until interrupted.
 *
 * Kept separate from the route handlers so tests can build a server against a
 * context they control, without a process that installs signal handlers and
 * never returns.
 */

import { AppDir } from "../appDir.js";
import type { ProgramIo } from "../program.js";
import { ApiServer } from "./server.js";
import { registerRoutes, type ApiContext } from "./routes.js";

export interface ServeApiOptions {
  app: AppDir;
  fingerprint: string;
  /** Seed to start with, or null to start locked. */
  mnemonic: string | null;
  host: string;
  port: number;
  allowRemote?: boolean;
  corsOrigins?: string[];
  io: ProgramIo;
}

/**
 * Build the context that routes operate through.
 *
 * `unlock` and `verifyPassword` both go through AppDir's parent-seed
 * decryption, which is the only thing that can actually answer "is this the
 * master password" — there is no separate password verifier to disagree with.
 */
export function buildContext(options: {
  app: AppDir;
  fingerprint: string;
  mnemonic: string | null;
  requestShutdown?: () => void;
  now?: () => number;
}): ApiContext {
  const ctx: ApiContext = {
    appDir: options.app,
    fingerprint: options.fingerprint,
    mnemonic: options.mnemonic,
    notifications: [],
    now: options.now ?? (() => Date.now()),
    requestShutdown: options.requestShutdown ?? (() => {}),
    verifyPassword: async (password: string) => {
      try {
        await options.app.decryptParentSeed(ctx.fingerprint, password);
        return true;
      } catch {
        return false;
      }
    },
    unlock: async (password: string) => {
      const started = Date.now();
      // Throws on a wrong password; the caller turns that into a 401 and
      // records the attempt against the tighter unlock budget.
      ctx.mnemonic = await options.app.decryptParentSeed(ctx.fingerprint, password);
      return (Date.now() - started) / 1000;
    },
  };
  return ctx;
}

export async function serveApi(options: ServeApiOptions): Promise<void> {
  let shuttingDown = false;
  const server = new ApiServer({
    host: options.host,
    port: options.port,
    ...(options.allowRemote !== undefined && { allowRemote: options.allowRemote }),
    ...(options.corsOrigins !== undefined && { corsOrigins: options.corsOrigins }),
  });

  const ctx = buildContext({
    app: options.app,
    fingerprint: options.fingerprint,
    mnemonic: options.mnemonic,
    requestShutdown: () => {
      if (shuttingDown) return;
      shuttingDown = true;
      // Let the response for POST /shutdown finish before the socket closes.
      setTimeout(() => {
        void stop();
      }, 50).unref();
    },
  });

  registerRoutes(server, ctx);
  const bound = await server.listen();

  const stop = async (): Promise<void> => {
    // Drop the seed before releasing the port, not after: the window between
    // the two is a window where the process is still holding an unlocked seed
    // with no way to say so.
    ctx.mnemonic = null;
    await server.close();
  };

  // The token goes to stdout exactly once and is never written to disk. An
  // operator who loses it restarts the server.
  options.io.out(
    JSON.stringify({
      listening: `http://${bound.host}:${bound.port}`,
      fingerprint: options.fingerprint,
      locked: ctx.mnemonic === null,
      token: server.token,
    }),
  );
  options.io.err(
    "This process holds an unlocked parent seed and is listening on a port. " +
      "The token above is shown once. Stop it with Ctrl-C or POST /api/v1/shutdown.",
  );

  await new Promise<void>((resolve) => {
    const onSignal = (): void => {
      void stop().then(resolve);
    };
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    const poll = setInterval(() => {
      if (shuttingDown) {
        clearInterval(poll);
        resolve();
      }
    }, 100);
    poll.unref();
  });
}
