/**
 * Relay transport: a small pool over the platform WebSocket (global in
 * Node >= 22 and all target browsers — no dependency).
 *
 * Publishes to every relay and aggregates fetches across them, deduping by
 * event id and dropping events whose id or signature fails verification.
 * Parity reference for behavior: src/nostr/connection.py + snapshot.py
 * (timeouts, per-chunk retry with backoff).
 */

import {
  eventMatchesFilter,
  eventMessage,
  isWellFormedEvent,
  parseRelayMessage,
  reqMessage,
  verifyEvent,
  type Filter,
  type NostrEvent,
} from "./events.js";

export interface PublishResult {
  relay: string;
  ok: boolean;
  message: string;
}

export interface RelayPoolOptions {
  /** Per-operation timeout in milliseconds. */
  timeoutMs?: number;
}

interface Conn {
  url: string;
  socket: WebSocket;
  ready: Promise<void>;
}

let subCounter = 0;

export class RelayPool {
  private readonly timeoutMs: number;
  private conns: Conn[] | null = null;

  constructor(
    public readonly urls: string[],
    options: RelayPoolOptions = {},
  ) {
    if (urls.length === 0) throw new Error("no relays configured");
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  private async connect(): Promise<Conn[]> {
    if (this.conns) return this.conns;
    const attempts = this.urls.map((url) => {
      const socket = new WebSocket(url);
      const ready = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`connect timeout: ${url}`)),
          this.timeoutMs,
        );
        socket.addEventListener("open", () => {
          clearTimeout(timer);
          resolve();
        });
        socket.addEventListener("error", () => {
          clearTimeout(timer);
          reject(new Error(`connect failed: ${url}`));
        });
      });
      return { url, socket, ready };
    });
    const settled = await Promise.allSettled(attempts.map((c) => c.ready));
    const alive = attempts.filter((_, i) => settled[i]!.status === "fulfilled");
    for (let i = 0; i < attempts.length; i++) {
      if (settled[i]!.status === "rejected") {
        try {
          attempts[i]!.socket.close();
        } catch {
          // already dead
        }
      }
    }
    if (alive.length === 0) {
      throw new Error(`could not connect to any relay: ${this.urls.join(", ")}`);
    }
    this.conns = alive;
    return alive;
  }

  /** Publish an event to every connected relay; resolves with per-relay OKs. */
  async publish(event: NostrEvent): Promise<PublishResult[]> {
    const conns = await this.connect();
    const msg = eventMessage(event);
    return Promise.all(
      conns.map(
        (conn) =>
          new Promise<PublishResult>((resolve) => {
            const timer = setTimeout(() => {
              cleanup();
              resolve({ relay: conn.url, ok: false, message: "timeout waiting for OK" });
            }, this.timeoutMs);
            const onMessage = (raw: MessageEvent) => {
              try {
                const parsed = parseRelayMessage(String(raw.data));
                if (parsed.type === "OK" && parsed.eventId === event.id) {
                  cleanup();
                  resolve({ relay: conn.url, ok: parsed.accepted, message: parsed.message });
                }
              } catch {
                // ignore unrelated frames
              }
            };
            const cleanup = () => {
              clearTimeout(timer);
              conn.socket.removeEventListener("message", onMessage);
            };
            conn.socket.addEventListener("message", onMessage);
            conn.socket.send(msg);
          }),
      ),
    );
  }

  /**
   * Fetch events matching the filters from every relay until EOSE (or
   * timeout), deduped by id; invalid ids/signatures are dropped.
   */
  async fetch(...filters: Filter[]): Promise<NostrEvent[]> {
    const conns = await this.connect();
    const byId = new Map<string, NostrEvent>();
    await Promise.all(
      conns.map(
        (conn) =>
          new Promise<void>((resolve) => {
            const subId = `sp-${++subCounter}-${Math.floor(Math.random() * 1e6)}`;
            const timer = setTimeout(() => finish(), this.timeoutMs);
            const onMessage = (raw: MessageEvent) => {
              try {
                const parsed = parseRelayMessage(String(raw.data));
                if (parsed.type === "EVENT" && parsed.subscriptionId === subId) {
                  const ev = parsed.event;
                  // A relay is asked for a filter; it is not obliged to obey
                  // one. Accept an event only if it is well formed, actually
                  // satisfies a filter we sent (author, kind, id, time, tags)
                  // and carries a valid signature over its own id.
                  if (
                    !byId.has(ev.id) &&
                    isWellFormedEvent(ev) &&
                    filters.some((f) => eventMatchesFilter(ev, f)) &&
                    verifyEvent(ev)
                  ) {
                    byId.set(ev.id, ev);
                  }
                } else if (
                  (parsed.type === "EOSE" || parsed.type === "CLOSED") &&
                  parsed.subscriptionId === subId
                ) {
                  finish();
                }
              } catch {
                // ignore malformed frames
              }
            };
            const finish = () => {
              clearTimeout(timer);
              conn.socket.removeEventListener("message", onMessage);
              try {
                conn.socket.send(JSON.stringify(["CLOSE", subId]));
              } catch {
                // socket may be gone
              }
              resolve();
            };
            conn.socket.addEventListener("message", onMessage);
            conn.socket.send(reqMessage(subId, ...filters));
          }),
      ),
    );
    return [...byId.values()];
  }

  async close(): Promise<void> {
    for (const conn of this.conns ?? []) {
      try {
        conn.socket.close();
      } catch {
        // already closed
      }
    }
    this.conns = null;
  }
}
