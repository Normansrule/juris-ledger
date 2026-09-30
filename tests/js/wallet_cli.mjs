// node tests/js/wallet_cli.mjs sign SEED CHAIN KIND NONCE PAYLOAD_JSON   -> signed tx JSON
// node tests/js/wallet_cli.mjs seal SEED PASSPHRASE                        -> keystore JSON
// node tests/js/wallet_cli.mjs open KEYSTORE_FILE PASSPHRASE               -> {"address": ...}
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
require("../../site/verify.js"); require("../../site/wallet.js");
const W = globalThis.JurisWallet, [cmd, ...a] = process.argv.slice(2);
if (cmd === "sign") { const k = await W.fromSeed(a[0]); console.log(JSON.stringify(await W.sign(k, a[1], a[2], +a[3], JSON.parse(a[4])))); }
else if (cmd === "seal") { console.log(JSON.stringify(await W.seal(await W.fromSeed(a[0]), a[1]))); }
else if (cmd === "open") { const k = await W.open(JSON.parse(readFileSync(a[0], "utf8")), a[1]); console.log(JSON.stringify({ address: k.address })); }
