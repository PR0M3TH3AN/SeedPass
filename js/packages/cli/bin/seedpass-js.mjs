#!/usr/bin/env node
// Thin launcher: runs the TypeScript CLI via tsx until a build step exists.
import { pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const entry = pathToFileURL(join(here, "..", "src", "main.ts")).href;

const { register } = await import("tsx/esm/api");
register();
await import(entry);
