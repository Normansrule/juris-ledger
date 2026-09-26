/* JurisLedger evidence verifier, in the browser.
 *
 * The same checks as `jurisledger verify EVIDENCE.json VALIDATORS.json`, re-implemented
 * with the Web Cryptography API so a lawyer, clerk or arbitrator can verify a file
 * without installing anything and without the file leaving their machine:
 *
 *   - every transaction's Ed25519 signature, over the exact bytes the ledger signs
 *   - every block header's commit certificate: > 2/3 of the validators YOU supply
 *   - every transaction's Merkle path from its id to the header's tx_root
 *   - that every party signed the same text fingerprint (following key changes)
 *   - that the enclosed text, if any, is the text that was signed
 *
 * Byte-for-byte compatible with jurisledger/crypto.py (canonical JSON, SHA-256,
 * RFC 6962 leaf/node prefixes) and tx.py / block.py (signing prefixes).
 * Works in browsers with WebCrypto Ed25519 (Chrome 137+, Firefox 129+, Safari 17+)
 * and in Node 20+.  Exposes globalThis.JurisVerify.
 */
(function (root) {
  "use strict";
  const subtle = root.crypto && root.crypto.subtle;
  const enc = new TextEncoder();
  const FORMAT = "jurisledger/evidence/v1";

  // ---- canonical JSON: sorted keys, no whitespace, integers only ---------- //
  function canonical(v) {
    if (v === null) return "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "number") {
      if (!Number.isInteger(v)) throw new Error("floats are not allowed in canonical data");
      return String(v);
    }
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  }

  const hexToBytes = h => { if (typeof h !== "string" || h.length % 2) throw new Error("bad hex"); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) { const x = parseInt(h.substr(2 * i, 2), 16); if (Number.isNaN(x)) throw new Error("bad hex"); b[i] = x; } return b; };
  const bytesToHex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, "0")).join("");
  const concat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
  const sha256 = async bytes => new Uint8Array(await subtle.digest("SHA-256", bytes));
  const sha256hex = async bytes => bytesToHex(await sha256(bytes));

  async function supported() {
    try { await subtle.importKey("raw", new Uint8Array(32).fill(1), { name: "Ed25519" }, false, ["verify"]); return true; }
    catch (e) { return false; }
  }

  const keyCache = new Map();
  async function edVerify(pubHex, message, sigHex) {
    try {
      let key = keyCache.get(pubHex);
      if (!key) { key = await subtle.importKey("raw", hexToBytes(pubHex), { name: "Ed25519" }, false, ["verify"]); keyCache.set(pubHex, key); }
      return await subtle.verify({ name: "Ed25519" }, key, hexToBytes(sigHex), message);
    } catch (e) { return false; }
  }

  // ---- the ledger's objects ------------------------------------------------ //
  const txBody = t => ({ chain_id: t.chain_id, kind: t.kind, sender: t.sender, nonce: t.nonce, payload: t.payload });
  const txSigningBytes = t => enc.encode("jurisledger/tx/v1:" + canonical(txBody(t)));
  const txid = async t => sha256hex(txSigningBytes(t));
  const headerHash = async h => sha256hex(enc.encode(canonical(h)));
  const voteMessage = (chainId, height, round, blockHash) =>
    enc.encode("jurisledger/vote/v1:" + canonical({ chain_id: chainId, height, round, block_hash: blockHash }));
  const quorum = n => Math.floor(2 * n / 3) + 1;

  async function merkleOk(itemHex, proof, rootHex) {
    let acc = await sha256(concat(new Uint8Array([0]), hexToBytes(itemHex)));
    for (const [side, sib] of proof) {
      const s = hexToBytes(sib);
      acc = await sha256(side === "L" ? concat(new Uint8Array([1]), s, acc) : concat(new Uint8Array([1]), acc, s));
    }
    return bytesToHex(acc) === rootHex;
  }

  async function inclusionOk(id, inc, validators) {
    const h = inc.header, hash = await headerHash(h);
    const round = inc.commit_round !== undefined && inc.commit_round !== null ? inc.commit_round : h.round;
    const msg = voteMessage(h.chain_id, h.height, round, hash);
    let good = 0;
    for (const [v, sig] of Object.entries(inc.votes || {})) if (validators.includes(v) && await edVerify(v, msg, sig)) good++;
    return { quorum: good >= quorum(validators.length), votes: good, merkle: await merkleOk(id, inc.proof, h.tx_root) };
  }

  const relates = (t, id, cid) => {
    const p = t.payload || {};
    if (id === cid || p.contract_id === cid || p.contract === cid) return true;
    return t.kind === "CONTRACT_CREATE" && (p.references || []).some(r => r.kind === "contract" && r.id === cid);
  };
  const keyChange = t => t.kind === "KEY_ROTATE" ? [t.sender, t.payload.new_key]
    : t.kind === "RECOVERY_FINALIZE" ? [t.payload.subject, t.payload.new_key] : null;

  // ---- the verdict ---------------------------------------------------------- //
  async function verifyBundle(bundle, validators, onProgress) {
    const problems = [], timeline = [];
    const cid = bundle.contract_id;
    if (bundle.format !== FORMAT) problems.push("unknown bundle format");
    if (!Array.isArray(validators) || !validators.length) problems.push("no validator keys supplied");
    const items = bundle.items || [];
    let create = null, done = 0, total = items.length + (bundle.key_changes || []).length;
    for (let i = 0; i < items.length; i++) {
      const it = items[i], t = it.tx, id = await txid(t);
      const sigOk = await edVerify(t.sender, txSigningBytes(t), t.signature);
      const inc = await inclusionOk(id, it.inclusion, validators || []);
      const net = t.chain_id === bundle.chain_id && it.inclusion.header.chain_id === bundle.chain_id;
      if (!net) problems.push(`item ${i}: belongs to another network`);
      if (!sigOk) problems.push(`item ${i}: transaction signature is invalid`);
      if (!inc.quorum) problems.push(`item ${i}: block ${it.inclusion.header.height} has ${inc.votes} valid validator signatures, ${quorum((validators || []).length)} needed`);
      if (!inc.merkle) problems.push(`item ${i}: the transaction is not under its block's Merkle root`);
      if (!relates(t, id, cid)) problems.push(`item ${i}: unrelated to this contract`);
      if (id === cid && t.kind === "CONTRACT_CREATE") create = t;
      timeline.push({ height: it.inclusion.header.height, time: it.inclusion.header.timestamp || 0, kind: t.kind, by: t.sender, txid: id,
        ok: sigOk && inc.quorum && inc.merkle && net, votes: inc.votes, detail: t.payload });
      if (onProgress) await onProgress(++done, total, timeline[timeline.length - 1]);
    }
    const successor = {};
    for (let i = 0; i < (bundle.key_changes || []).length; i++) {
      const it = bundle.key_changes[i], t = it.tx, id = await txid(t), ch = keyChange(t);
      const ok = ch && await edVerify(t.sender, txSigningBytes(t), t.signature) && (await inclusionOk(id, it.inclusion, validators)).quorum
        && (await inclusionOk(id, it.inclusion, validators)).merkle;
      if (!ok) problems.push(`key change ${i}: not a proven, final key change`); else successor[ch[0]] = ch[1];
      if (onProgress) await onProgress(++done, total, null);
    }
    const current = k => { for (let hops = 0; successor[k] && hops < 100; hops++) k = successor[k]; return k; };
    const report = { contract_id: cid, timeline: timeline.sort((a, b) => a.height - b.height), problems, labels: bundle.labels || {} };
    if (!create) problems.push("the file does not contain the contract's creating transaction");
    else {
      const p = create.payload, parties = new Set(p.parties.map(current));
      const signed = new Set(parties.has(current(create.sender)) ? [current(create.sender)] : []);
      for (const it of items) {
        const t = it.tx;
        if (t.kind === "CONTRACT_SIGN" && t.payload.contract_id === cid && t.payload.prose_hash === p.prose_hash && parties.has(current(t.sender)))
          signed.add(current(t.sender));
      }
      Object.assign(report, { title: p.title, parties: p.parties, signed_by: [...signed], prose_hash: p.prose_hash,
        fully_signed: signed.size === parties.size, references: p.references || [] });
      if (typeof bundle.prose === "string") {
        report.prose_matches = (await sha256hex(enc.encode(bundle.prose))) === p.prose_hash;
        if (!report.prose_matches) problems.push("the enclosed text is NOT the text the parties signed");
      }
    }
    report.valid = problems.length === 0;
    return report;
  }

  root.JurisVerify = { canonical, txid, headerHash, verifyBundle, supported, sha256hex, quorum };
})(typeof globalThis !== "undefined" ? globalThis : this);
