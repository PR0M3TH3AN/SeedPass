/**
 * TypeScript side of scripts/differential_fuzz.py.
 *
 * Reads a JSON array of requests, returns a JSON array of results in the same
 * order. Errors are returned as `ERROR:<Name>` strings rather than thrown, so
 * that "both implementations refuse this input" counts as agreement — a
 * divergence where one accepts and the other refuses is exactly the kind of
 * bug this is looking for.
 */

import { readFileSync } from "node:fs";
import {
  canonicalJson,
  entryEventHash,
  mergeIndexPayloads,
  generatePassword,
  passwordPolicyFromRecord,
  Bip85,
  appendIndex0Event,
  compactIndex0Payload,
  recoverSecret,
  buildSemanticRecords,
  searchSemanticRecords,
} from "./src/index.js";

type Request = Record<string, any>;

function attempt(fn: () => unknown): unknown {
  try {
    return fn();
  } catch (e) {
    // Mirrors the Python side's `ERROR:<ExceptionName>`. Python raises
    // ValueError where TS throws Error, so the names are normalized to the
    // one distinction that matters: refused vs accepted.
    void e;
    return "ERROR:Refused";
  }
}

const requests = JSON.parse(readFileSync(process.argv[2]!, "utf8")) as Request[];
const results: unknown[] = [];

for (const request of requests) {
  switch (request["op"]) {
    case "noop":
      results.push(null);
      break;

    case "canonical":
      results.push(attempt(() => canonicalJson(request["value"])));
      break;

    case "entryHash":
      results.push(attempt(() => entryEventHash(request["entry"])));
      break;

    case "password":
      results.push(
        attempt(() =>
          generatePassword(Bip85.fromMnemonic(request["mnemonic"]), {
            length: request["length"],
            index: request["index"],
            genVersion: request["genVersion"],
            policy: passwordPolicyFromRecord(request["policy"]),
          }),
        ),
      );
      break;

    case "merge":
      results.push(
        attempt(() =>
          mergeIndexPayloads(request["current"], request["incoming"], request["sourceTag"]),
        ),
      );
      break;

    case "index0":
      results.push(
        attempt(() => {
          let payload: unknown = { schema_version: 4, entries: request["entries"] };
          for (const spec of request["events"] as Request[]) {
            payload = appendIndex0Event(payload, {
              eventType: spec["event_type"],
              subjectType: spec["subject_type"],
              subjectId: spec["subject_id"],
              subjectKind: spec["subject_kind"],
              modifiedTs: spec["modified_ts"],
              fingerprintDir: request["fingerprintDir"],
              tags: spec["tags"],
              summary: spec["summary"],
            });
          }
          return compactIndex0Payload(payload, { fingerprintDir: request["fingerprintDir"] });
        }),
      );
      break;

    case "recover":
      results.push(attempt(() => recoverSecret(request["shares"])));
      break;

    case "semantic":
      results.push(
        attempt(() => {
          const records = buildSemanticRecords(request["entries"]);
          return {
            records,
            hits: searchSemanticRecords(records, request["query"], { k: 10 }),
          };
        }),
      );
      break;

    default:
      results.push(`ERROR:UnknownOp:${String(request["op"])}`);
  }
}

process.stdout.write(JSON.stringify(results));
