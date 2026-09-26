// node tests/js/audit_cli.mjs CHAIN.json  -> {"valid":..., "problems":[...], ...}
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
createRequire(import.meta.url)("../../site/verify.js");
const r = await globalThis.JurisVerify.auditChain(JSON.parse(readFileSync(process.argv[2], "utf8")));
console.log(JSON.stringify(r));
