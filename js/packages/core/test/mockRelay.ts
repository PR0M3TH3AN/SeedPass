/**
 * In-process NIP-01 relay for tests: stores events, answers REQ with
 * matching EVENTs + EOSE, acks EVENT with OK. Test-only (uses `ws`).
 */

import { WebSocketServer, type WebSocket as WsSocket } from "ws";
import type { AddressInfo } from "node:net";
import type { Filter, NostrEvent } from "@seedpass/core";

function matches(event: NostrEvent, filter: Filter): boolean {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.since !== undefined && event.created_at < filter.since) return false;
  if (filter.until !== undefined && event.created_at > filter.until) return false;
  for (const tagName of ["#d", "#e"] as const) {
    const wanted = filter[tagName];
    if (wanted) {
      const values = event.tags.filter((t) => t[0] === tagName[1]).map((t) => t[1]);
      if (!wanted.some((w) => values.includes(w))) return false;
    }
  }
  return true;
}

export class MockRelay {
  readonly events: NostrEvent[] = [];
  private server: WebSocketServer | null = null;
  url = "";

  async start(): Promise<string> {
    this.server = new WebSocketServer({ port: 0 });
    await new Promise<void>((resolve) => this.server!.once("listening", resolve));
    const { port } = this.server.address() as AddressInfo;
    this.url = `ws://127.0.0.1:${port}`;
    this.server.on("connection", (socket: WsSocket) => {
      socket.on("message", (raw) => {
        let msg: unknown[];
        try {
          msg = JSON.parse(String(raw)) as unknown[];
        } catch {
          return;
        }
        if (msg[0] === "EVENT") {
          const event = msg[1] as NostrEvent;
          this.events.push(event);
          socket.send(JSON.stringify(["OK", event.id, true, ""]));
        } else if (msg[0] === "REQ") {
          const subId = String(msg[1]);
          const filters = msg.slice(2) as Filter[];
          let sent = 0;
          for (const event of this.events) {
            if (filters.some((f) => matches(event, f))) {
              const limit = Math.min(...filters.map((f) => f.limit ?? Infinity));
              if (sent >= limit) break;
              socket.send(JSON.stringify(["EVENT", subId, event]));
              sent++;
            }
          }
          socket.send(JSON.stringify(["EOSE", subId]));
        }
        // CLOSE is a no-op for the mock
      });
    });
    return this.url;
  }

  async stop(): Promise<void> {
    for (const client of this.server?.clients ?? []) client.terminate();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
    this.server = null;
  }
}
