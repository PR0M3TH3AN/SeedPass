/**
 * The retrieval index, checked against the Python implementation.
 *
 * Two properties matter, and they pull in different directions:
 *
 *   1. It must rank identically to Python, so a query answered on one
 *      implementation is answered the same way on the other. Fixtures below
 *      are that implementation's actual output.
 *   2. It must never write a secret. The records file is plaintext on disk,
 *      so anything indexed is readable by whatever can read the profile
 *      directory without the master password. Python used to index a
 *      key_value entry's `value`; the fixture proves it no longer does, and
 *      the TS side is asserted against the same rule.
 */

import { describe, expect, it } from "vitest";
import {
  buildSemanticRecords,
  searchSemanticRecords,
  semanticStatus,
  tokenize,
  SEMANTIC_MODEL_ID,
  type SemanticRecord,
} from "@seedpass/core";
import { semanticFixture } from "@seedpass/test-vectors";

// Imported through the fixture package rather than read from disk, so the
// suite also runs under the jsdom environment, where there is no filesystem.
const fx = semanticFixture;

describe("record building matches Python", () => {
  it("produces the same records, in the same order, with the same tokens", () => {
    expect(buildSemanticRecords(fx.entries)).toEqual(fx.records);
  });

  it("indexes entry 0, and skips only what genuinely has nothing to index", () => {
    const ids = buildSemanticRecords(fx.entries).map((r) => r.entry_id);
    // Entry 0 is the FIRST entry any profile creates. Both implementations
    // used to test `id <= 0` and silently dropped it, so every user's first
    // entry was permanently unfindable with nothing to indicate why.
    expect(ids).toContain(0);
    expect(ids).not.toContain(7); // 'seed' is not an indexed kind
    expect(ids).not.toContain(8); // no text at all
    expect(ids).toContain(9); // a link's relation and note are indexable text
  });

  it("still skips an entry with no id, which is what the old test meant", () => {
    // The fixture carries one entry with no `id` key. Dropping it is correct;
    // dropping id 0 alongside it was the bug.
    const withoutId = fx.entries.filter((e) => e["id"] === undefined);
    expect(withoutId).toHaveLength(1);
    expect(buildSemanticRecords(withoutId)).toEqual([]);
  });

  it("finds the first entry a profile ever created", () => {
    const hits = searchSemanticRecords(buildSemanticRecords(fx.entries), "first entry");
    expect(hits.map((h) => h.entry_id)).toContain(0);
  });
});

describe("no secret reaches the index", () => {
  it("omits a key_value entry's value while keeping its key name", () => {
    const records = buildSemanticRecords(fx.entries);
    const serialized = JSON.stringify(records);
    // The fixture entry carries this value; it must not survive indexing.
    expect(serialized).not.toContain("SECRET-MUST-NOT-APPEAR");
    // Tokenized fragments leak it just as well as the whole string.
    for (const fragment of ["secret", "appear"]) {
      expect(serialized.toLowerCase()).not.toContain(fragment);
    }
    // Still findable by the things that are not the secret.
    const kv = records.find((r) => r.entry_id === 2)!;
    expect(kv.text).toContain("DEPLOY_TOKEN");
    expect(kv.text).toContain("ci pipeline");
  });

  it("indexes only the public half of a nostr entry", () => {
    const nostr = buildSemanticRecords(fx.entries).find((r) => r.entry_id === 6)!;
    expect(nostr.text).toContain("npub1example");
    expect(nostr.text).not.toContain("nsec");
  });
});

describe("search matches Python", () => {
  for (const [query, expected] of Object.entries(fx.queries)) {
    it(`ranks "${query}" identically`, () => {
      const got = searchSemanticRecords(fx.records, query, { k: 10 });
      expect(got).toEqual(expected);
    });
  }

  it("filters by kind", () => {
    const got = searchSemanticRecords(fx.records, "ops", { k: 10, kind: "ssh" });
    expect(got.map((h) => h.entry_id)).toEqual(fx.kind_filtered.map((h) => h.entry_id));
  });

  it("returns nothing for an empty query rather than everything", () => {
    // An empty query has no tokens, so nothing overlaps it. Returning the
    // whole vault would be the dangerous reading of "matches everything".
    expect(searchSemanticRecords(fx.records, "")).toEqual([]);
    expect(searchSemanticRecords(fx.records, "   ")).toEqual([]);
  });

  it("honours k, keeping the highest scores", () => {
    const all = searchSemanticRecords(fx.records, "bank account", { k: 10 });
    const one = searchSemanticRecords(fx.records, "bank account", { k: 1 });
    expect(one).toHaveLength(1);
    expect(one[0]).toEqual(all[0]);
  });

  it("breaks score ties by entry id, so the order is stable", () => {
    const records: SemanticRecord[] = [
      { entry_id: 9, kind: "document", label: "b", text: "alpha", tokens: ["alpha"] },
      { entry_id: 2, kind: "document", label: "a", text: "alpha", tokens: ["alpha"] },
    ];
    expect(searchSemanticRecords(records, "alpha").map((h) => h.entry_id)).toEqual([2, 9]);
  });
});

describe("tokenizing", () => {
  it("lowercases and splits on non-word characters", () => {
    // Underscore is a word character, so `Login_2FA` is one token rather than
    // two — verified against Python's [a-z0-9_]+ rather than assumed.
    expect([...tokenize("Bank.Example/Login_2FA")].sort()).toEqual([
      "bank",
      "example",
      "login_2fa",
    ]);
  });

  it("is empty for whitespace", () => {
    expect(tokenize("   ").size).toBe(0);
  });
});

describe("status", () => {
  it("reports the model id that marks a post-fix index", () => {
    // A v1 index was built by code that wrote secrets, so the id has to
    // distinguish them.
    expect(semanticStatus({ built: true, enabled: true }, 3).model_id).toBe(SEMANTIC_MODEL_ID);
    expect(SEMANTIC_MODEL_ID).toBe("seedpass-token-overlap-v2");
  });
});
