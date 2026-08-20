/**
 * Scoped-token enforcement tests: a token-holding process with NO mnemonic
 * anywhere in its environment gets exactly what its scopes grant — reads,
 * sink deliveries for permitted kinds/labels, nothing else — with every
 * decision landing in the tamper-evident audit log.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile, appendFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import { generateFingerprint } from "@seedpass/core";
import {
  buildProgram,
  AgentDaemon,
  AgentClient,
  agentSocketPath,
  type ProgramIo,
} from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "token-test-pw";

let appDir: string;
let daemon: AgentDaemon;
let token: string;

async function run(
  env: Record<string, string | undefined>,
  ...argv: string[]
): Promise<{ stdout: string; error?: unknown }> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const out: string[] = [];
  const io: ProgramIo = { out: (l: string) => out.push(l), err: () => {} };
  let error: unknown;
  try {
    await buildProgram(io).parseAsync(["node", "seedpass-js", "--app-dir", appDir, ...argv]);
  } catch (e) {
    error = e;
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return { stdout: out.join("\n"), error };
}

const asOwner = { SEEDPASS_MNEMONIC: MNEMONIC };
const asTokenHolder = (t: string) => ({
  SEEDPASS_MNEMONIC: undefined,
  SEEDPASS_TOKEN: t,
});

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-tokens-"));
  process.env["SEEDPASS_AGENT_SOCK"] = join(appDir, "agent.sock");
  daemon = new AgentDaemon(agentSocketPath(appDir), 900, appDir);
  await daemon.start();

  await run({ ...asOwner, SEEDPASS_PASSWORD: PASSWORD }, "fingerprint", "add");
  await run(asOwner, "entry", "add", "key-value", "api-token", "k", "sinkable-secret");
  await run(asOwner, "entry", "add", "key-value", "internal-db", "k", "off-limits");
  await run(asOwner, "entry", "add", "password", "site-login", "--length", "16");
  await run({ SEEDPASS_MNEMONIC: undefined, SEEDPASS_PASSWORD: PASSWORD }, "vault", "unlock");
});

afterAll(async () => {
  await daemon.stop();
  delete process.env["SEEDPASS_AGENT_SOCK"];
});

describe("token issuance", () => {
  it("issues a scoped token, printed exactly once", async () => {
    const r = await run(
      {},
      "agent", "token-issue",
      "--name", "deploy-bot",
      "--scope", "read", "use",
      "--kind", "key_value",
      "--label-regex", "^api-",
      "--ttl", "600",
      "--uses", "2",
    );
    const issued = JSON.parse(r.stdout);
    token = issued.token;
    expect(token.length).toBeGreaterThan(20);
    expect(issued.record.scopes).toEqual(["read", "use"]);
    expect(issued.record).not.toHaveProperty("secret_hash");

    const list = JSON.parse((await run({}, "agent", "token-list")).stdout);
    expect(list[0].name).toBe("deploy-bot");
    expect(JSON.stringify(list)).not.toContain(token);
  });
});

/**
 * `label_regex` is a search, not a full match — in both implementations.
 * Python enforces it with `re.search` (cli/agent.py), so anchoring on the TS
 * side would mean the same token grants different access depending on which
 * implementation holds it, and would silently narrow every token already
 * issued. These tests pin the semantics so the surprise stays documented
 * rather than becoming an accidental behavior change later.
 */
describe("the kind restriction on a token", () => {
  /**
   * `--kind` is half of a token's reach; `--label-regex` is the other half.
   * The header of this file claimed both were covered and only the label side
   * was — removing the kind check entirely left every test here green, which
   * means a token scoped to one kind could read every other kind's secrets
   * and nothing would have said so.
   */
  it("hides other kinds from listings and refuses their secrets", async () => {
    await run(asOwner, "entry", "add", "key-value", "kv-only", "k", "kv-secret");
    await run(asOwner, "entry", "add", "password", "pw-only");

    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "kv-scoped",
        "--scope", "read",
        "--kind", "key_value",
        "--label-regex", "only",
        "--ttl", "600",
      )).stdout,
    );

    // The label pattern matches BOTH entries, so anything visible here is the
    // kind check's doing and not the label's.
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    expect(rows.map((x) => x.label)).toEqual(["kv-only"]);

    // And listing is not the only door: the secret itself must be refused,
    // not merely omitted from the index the token can see.
    const pwRow = JSON.parse(
      (await run(asOwner, "entry", "list")).stdout,
    ) as { id: string | number; label: string }[];
    const pwId = String(pwRow.find((r) => r.label === "pw-only")!.id);
    const denied = await run(
      asTokenHolder(issued.token),
      "entry", "get", pwId, "--secret",
    );
    expect(denied.error).toBeDefined();
    expect(denied.stdout).not.toContain("pw-only");
  });
});

describe("label_regex matches anywhere, matching Python's re.search", () => {
  it("an unanchored pattern reaches labels that merely contain it", async () => {
    await run(asOwner, "entry", "add", "key-value", "not-prod-db", "k", "adjacent-secret");
    await run(asOwner, "entry", "add", "key-value", "prod", "k", "intended-secret");

    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "substring-demo",
        "--scope", "read",
        "--kind", "key_value",
        "--label-regex", "prod",
        "--ttl", "600",
      )).stdout,
    );
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    // The point of the test: BOTH are visible, not just the exact match.
    expect(rows.map((x) => x.label).sort()).toEqual(["not-prod-db", "prod"]);
  });

  it("anchoring the pattern is how an operator gets an exact match", async () => {
    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "anchored-demo",
        "--scope", "read",
        "--kind", "key_value",
        "--label-regex", "^prod$",
        "--ttl", "600",
      )).stdout,
    );
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    expect(rows.map((x) => x.label)).toEqual(["prod"]);
  });

  it("reports the semantics in capabilities so automation can scope correctly", async () => {
    const caps = JSON.parse((await run({}, "capabilities")).stdout);
    expect(caps.tokens.label_regex_semantics).toContain("search");
    expect(caps.tokens.label_regex_semantics).toContain("^...$");
    // The exec allowlist's containment is likewise narrower than it reads:
    // it names a binary, not what that binary may be asked to do.
    expect(caps.tokens.exec_allowlist_semantics).toContain("command word only");
  });

  it("an uncompilable pattern denies rather than throwing", async () => {
    const issued = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "bad-regex",
        "--scope", "read",
        "--label-regex", "([unclosed",
        "--ttl", "600",
      )).stdout,
    );
    const rows = JSON.parse(
      (await run(asTokenHolder(issued.token), "entry", "list")).stdout,
    ) as { label: string }[];
    expect(rows).toEqual([]);
  });
});

describe("token-mode access (no mnemonic anywhere)", () => {
  it("lists only the entries the token may act on, with no secret values", async () => {
    const r = await run(asTokenHolder(token), "entry", "list");
    const rows = JSON.parse(r.stdout) as { label: string }[];
    // Scoped to kind key_value and labels matching ^api-, so the password
    // entry and the non-matching key_value are not even disclosed.
    expect(rows.map((x) => x.label)).toEqual(["api-token"]);
    expect(r.stdout).not.toContain("sinkable-secret");
    expect(r.stdout).not.toContain("off-limits");
  });

  it("delivers a permitted secret to a sink", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-tok-sink-"));
    const capture = join(dir, "captured.txt");
    const script = join(dir, "cap.sh");
    await writeFile(script, `#!/bin/sh\nprintf '%s' "$SEEDPASS_SECRET" > "${capture}"\n`, {
      mode: 0o755,
    });
    const r = await run(asTokenHolder(token), "use", "api-token", "--exec", script);
    expect(JSON.parse(r.stdout).exitCode).toBe(0);
    expect(await readFile(capture, "utf8")).toBe("sinkable-secret");
    expect(r.stdout).not.toContain("sinkable-secret");
  });

  it("denies reveal (scope), wrong kind, and non-matching label", async () => {
    const reveal = await run(asTokenHolder(token), "entry", "reveal", "api-token");
    expect(String((reveal.error as Error).message)).toContain("scope 'reveal' not granted");

    // Entries outside the token's constraints are not resolvable at all —
    // the agent never returned them, so their existence is not disclosed.
    const wrongKind = await run(asTokenHolder(token), "use", "site-login", "--stdin-to", "cat");
    expect(String((wrongKind.error as Error).message)).toContain("no entry matches");

    const wrongLabel = await run(asTokenHolder(token), "use", "internal-db", "--stdin-to", "cat");
    expect(String((wrongLabel.error as Error).message)).toContain("no entry matches");

    // Addressing a forbidden entry by id still fails, in the agent
    const byId = await run(asTokenHolder(token), "use", "sp://entry/2", "--stdin-to", "cat");
    expect(String((byId.error as Error).message)).toMatch(/no entry|denied/);
  });

  it("exhausts after the allotted uses", async () => {
    // Use #2 of 2 (use #1 was the sink delivery above; denials don't consume)
    const second = await run(asTokenHolder(token), "use", "api-token", "--stdin-to", "cat");
    expect(second.error).toBeUndefined();
    const third = await run(asTokenHolder(token), "use", "api-token", "--stdin-to", "cat");
    expect(String((third.error as Error).message)).toContain("token exhausted");
  });

  it("revocation cuts off reads too", async () => {
    const list = JSON.parse((await run({}, "agent", "token-list")).stdout);
    await run({}, "agent", "token-revoke", list[0].id);
    const denied = await run(asTokenHolder(token), "entry", "list");
    expect(String((denied.error as Error).message)).toContain("token revoked");
  });

  it("token mode cannot provision or modify", async () => {
    const r = await run(asTokenHolder(token), "entry", "add", "key-value", "x", "k", "v");
    expect(r.error).toBeTruthy();
  });
});

describe("audit chain", () => {
  it("recorded the whole story and verifies", async () => {
    const r = await run(asOwner, "agent", "audit-verify");
    const summary = JSON.parse(r.stdout);
    expect(summary.verified).toBe(true);
    expect(summary.records).toBeGreaterThanOrEqual(6);

    const tail = JSON.parse((await run(asOwner, "agent", "audit-tail", "-n", "50")).stdout) as {
      event: string;
      details: Record<string, unknown>;
    }[];
    const events = tail.map((r) => r.event);
    expect(events).toContain("token_issued");
    expect(events).toContain("secret_delivered");
    expect(events).toContain("access_denied");
    expect(events).toContain("token_revoked");
    const denial = tail.find((r) => r.event === "access_denied")!;
    expect(String(denial.details["reason"])).toBeTruthy();
    // Secrets never appear in the audit log
    expect(JSON.stringify(tail)).not.toContain("sinkable-secret");
  });

  it("detects tampering", async () => {
    const path = join(appDir, FINGERPRINT, "audit.log");
    await appendFile(path, JSON.stringify({ timestamp: "x", event: "forged", details: {}, sig: "00" }) + "\n");
    const r = await run(asOwner, "agent", "audit-verify");
    expect(String((r.error as Error).message)).toContain("audit chain broken");
  });
});

describe("the exec allowlist", () => {
  /**
   * Mutation testing found this control had NO test at all: the clipboard
   * check could be inverted, weakened, or removed entirely and the suite
   * stayed green.
   *
   * It matters because the clipboard is readable by every process in the
   * session. A token restricted to `cat` that may still reach the clipboard
   * is not restricted to anything — the holder just copies the secret out.
   * The allowlist would look enforced and contain nothing.
   */
  let restricted: string;
  let unrestricted: string;

  beforeAll(async () => {
    restricted = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "restricted",
        "--scope", "read", "use",
        "--kind", "key_value",
        "--ttl", "600",
        "--uses", "20",
        "--exec-allowlist", "cat",
      )).stdout,
    ).token;
    unrestricted = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "unrestricted",
        "--scope", "read", "use",
        "--kind", "key_value",
        "--ttl", "600",
        "--uses", "20",
      )).stdout,
    ).token;
  });

  it("refuses the clipboard to a command-restricted token", async () => {
    const r = await run(asTokenHolder(restricted), "use", "api-token", "--clipboard");
    expect(String((r.error as Error).message)).toContain("clipboard not permitted");
    expect(r.stdout).not.toContain("sinkable-secret");
  });

  it("permits the clipboard to a token with no allowlist", async () => {
    // The restriction has to be conditional on there BEING an allowlist,
    // otherwise it is just a blanket clipboard ban wearing a disguise, and
    // the test above would pass for the wrong reason.
    const r = await run(asTokenHolder(unrestricted), "use", "api-token", "--clipboard");
    // Clipboard tooling is absent in CI; either it worked or it failed for a
    // clipboard reason — what matters is that it was not refused by policy.
    const message = r.error ? String((r.error as Error).message) : "";
    expect(message).not.toContain("clipboard not permitted");
  });

  it("permits an allowlisted command and refuses one outside the list", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-allow-"));
    const capture = join(dir, "out.txt");
    const script = join(dir, "notcat.sh");
    await writeFile(script, `#!/bin/sh\nprintf '%s' "$SEEDPASS_SECRET" > "${capture}"\n`, {
      mode: 0o755,
    });

    // `cat` is allowlisted, so the delivery is permitted.
    const allowed = await run(asTokenHolder(restricted), "use", "api-token", "--exec", "cat");
    expect(allowed.error).toBeUndefined();

    // The script is not, however harmless it looks.
    const denied = await run(asTokenHolder(restricted), "use", "api-token", "--exec", script);
    expect(String((denied.error as Error).message)).toContain("not permitted by this token");
    expect(existsSync(capture)).toBe(false);
  });
});

describe("the audit log distinguishes what the response deliberately does not", () => {
  /**
   * A denial and a missing entry return the SAME message on purpose, so the
   * response cannot be used to enumerate which ids exist. The audit log is
   * where the difference is supposed to be recorded — that is the whole
   * reason two reason strings exist.
   *
   * Mutation testing found the two could be swapped with every test passing,
   * because nothing read the log. An audit trail that records the wrong
   * reason is worse than one that records nothing: it is evidence, and it
   * would be wrong.
   */
  it("records why access was denied, even though the caller is not told", async () => {
    // Straight to the daemon, by id. The CLI resolves references against the
    // entries the token may already see, so it refuses locally and the
    // request never arrives — which is correct behaviour and useless for
    // testing what the DAEMON records.
    //
    // Entry 9999 does not exist; entry 2 (a password) exists but is outside
    // this token's key_value/^api- constraints. The caller cannot tell them
    // apart, and the operator must be able to.
    // A fresh token: the shared one is revoked by an earlier test in this
    // file, and a revoked token is refused at the token check — long before
    // the entry-resolution step whose reasons this is about.
    const fresh = JSON.parse(
      (await run(
        {},
        "agent", "token-issue",
        "--name", "audit-reasons",
        "--scope", "read", "reveal",
        "--kind", "key_value",
        "--label-regex", "^api-",
        "--ttl", "600",
        "--uses", "10",
      )).stdout,
    ).token as string;

    const client = new AgentClient(agentSocketPath(appDir));
    await expect(
      client.secret({ fingerprint: FINGERPRINT, id: "9999", token: fresh }),
    ).rejects.toThrow();
    await expect(
      client.secret({ fingerprint: FINGERPRINT, id: "2", token: fresh }),
    ).rejects.toThrow();

    // Both refusals must read the same to the caller, or the response itself
    // becomes the enumeration oracle the audit split exists to avoid.
    const [a, b] = await Promise.all([
      client.secret({ fingerprint: FINGERPRINT, id: "9999", token: fresh }).catch((e) => String(e.message)),
      client.secret({ fingerprint: FINGERPRINT, id: "2", token: fresh }).catch((e) => String(e.message)),
    ]);
    expect(String(a).replace("9999", "ID")).toBe(String(b).replace("2", "ID"));

    const log = await readFile(join(appDir, FINGERPRINT, "audit.log"), "utf8");
    const denials = log
      .split("\n")
      .filter((line) => line.includes("access_denied"))
      // The reason lives under `details`, alongside the action and entry id.
      .map(
        (line) =>
          JSON.parse(line) as { details?: { reason?: string; entry_id?: string } },
      );

    const reasonFor = (entryId: string): string =>
      String(
        denials.filter((d) => d.details?.entry_id === entryId).at(-1)?.details?.reason ??
          "",
      );

    // Asserting that both reasons merely APPEAR is not enough: swapping them
    // leaves both present and the log confidently wrong. The pairing is the
    // property — which id got which reason.
    expect(reasonFor("9999")).toContain("no such entry");
    expect(reasonFor("2")).toContain("outside token constraints");
  });
});
