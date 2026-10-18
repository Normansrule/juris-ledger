// node tests/js/canonical_cli.mjs VECTORS.json -> [hex or null, ...] using site/verify.js
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
require("../../site/verify.js");
const { canonical } = globalThis.JurisVerify;
const vec = JSON.parse(readFileSync(process.argv[2], "utf8"));
const hex = s => Buffer.from(s, "utf8").toString("hex");
console.log(JSON.stringify(vec.cases.map(c => { try { return hex(canonical(JSON.parse(c.value))); } catch (e) { return null; } })));
