import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
createRequire(import.meta.url)("../../site/verify.js");
console.log(JSON.stringify(globalThis.JurisVerify.expenditure(JSON.parse(readFileSync(process.argv[2], "utf8")))));
