import { hexToBytes, bytesToHex } from "./src/util/bytes.js";
const cases = ["1z", "-1", "+1", " 1", "0x", "1 ", "gg", "1\n", "aA", "1e", "Infinity".slice(0,2), "e5", "1_", ".5", "0b"];
for (const c of cases) {
  try { console.log(JSON.stringify(c), "->", bytesToHex(hexToBytes(c))); }
  catch (e) { console.log(JSON.stringify(c), "-> THROW", (e as Error).message); }
}
// bech32 roundtrip malleability
import { hexToBech32 } from "./src/derive/nostr.js";
console.log("npub from 'zz'*32:", (()=>{try{return hexToBech32("zz".repeat(32) as string, "npub")}catch(e){return "throw "+(e as Error).message}})());
