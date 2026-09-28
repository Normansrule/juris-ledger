import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
createRequire(import.meta.url)("../../site/verify.js");
const threshold = +(process.argv[3] || 1000000);
console.log(JSON.stringify(globalThis.JurisVerify.reviewFlags(JSON.parse(readFileSync(process.argv[2], "utf8")), threshold)));
