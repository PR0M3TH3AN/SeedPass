import { register } from "tsx/esm/api";
register();
const { MockRelay } = await import(
  "/home/user/Documents/GitHub/SeedPass/js/packages/core/test/mockRelay.ts"
);
const relay = new MockRelay();
const url = await relay.start();
console.log(url);
process.on("SIGTERM", () => relay.stop().then(() => process.exit(0)));
await new Promise(() => {});
