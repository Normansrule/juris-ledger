// node tests/js/verify_cli.mjs EVIDENCE.json VALIDATORS.json  -> prints the report as JSON
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
require("../../site/verify.js");
const [ev, vals] = process.argv.slice(2);
const bundle = JSON.parse(readFileSync(ev, "utf8"));
const v = JSON.parse(readFileSync(vals, "utf8"));
const report = await globalThis.JurisVerify.verifyBundle(bundle, Array.isArray(v) ? v : v.validators);
console.log(JSON.stringify({ valid: report.valid, problems: report.problems, fully_signed: report.fully_signed,
  prose_matches: report.prose_matches, title: report.title, n: report.timeline.length }));
