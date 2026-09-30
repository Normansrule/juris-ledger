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


  // ---- whole-ledger structural audit ---------------------------------------- //
  async function merkleRoot(ids) {
    if (!ids.length) return sha256hex(enc.encode("jurisledger-empty-merkle"));
    let level = [];
    for (const id of ids) level.push(await sha256(concat(new Uint8Array([0]), hexToBytes(id))));
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2)
        next.push(i + 1 < level.length ? await sha256(concat(new Uint8Array([1]), level[i], level[i + 1])) : level[i]);
      level = next;
    }
    return bytesToHex(level[0]);
  }

  /* Checks everything that can be checked without re-running the state machine:
   * the hash chain, heights, timestamps, Merkle roots, every transaction signature,
   * and every commit certificate against the genesis validators.  Balances, nonces
   * and contract rules are NOT re-executed here -- that is `jurisledger audit`.     */
  async function auditChain(exported, onBlock) {
    const g = exported.genesis, validators = g.validators, problems = [];
    let prevHash = await sha256hex(enc.encode(canonical(g))), prevHeight = 0, prevTime = 0;
    if (exported.snapshot) {
      const h = exported.snapshot.header, hash = await headerHash(h);
      const round = exported.snapshot.commit_round ?? h.round, msg = voteMessage(g.chain_id, h.height, round, hash);
      let good = 0;
      for (const [v, sig] of Object.entries(exported.snapshot.votes || {})) if (validators.includes(v) && await edVerify(v, msg, sig)) good++;
      if (good < quorum(validators.length)) problems.push(`snapshot at block ${h.height}: ${good} valid validator signatures, ${quorum(validators.length)} needed`);
      prevHash = hash; prevHeight = h.height; prevTime = h.timestamp || 0;
    }
    const blocks = exported.blocks || [];
    let txCount = 0;
    for (let i = 0; i < blocks.length; i++) {
      const b = blocks[i], h = b.header, hash = await headerHash(h), issues = [];
      if (h.chain_id !== g.chain_id) issues.push("belongs to another network");
      if (h.height !== prevHeight + 1) issues.push(`height ${h.height} follows ${prevHeight}`);
      if (h.prev_hash !== prevHash) issues.push("does not link to the previous block (history was altered)");
      if ((h.timestamp || 0) < prevTime) issues.push("time runs backwards");
      const ids = [];
      let badSigs = 0;
      for (const t of b.txs) { ids.push(await txid(t)); if (!(await edVerify(t.sender, txSigningBytes(t), t.signature))) badSigs++; }
      if (badSigs) issues.push(`${badSigs} transaction signature${badSigs > 1 ? "s are" : " is"} invalid`);
      if ((await merkleRoot(ids)) !== h.tx_root) issues.push("transactions do not match the block's Merkle root");
      const round = b.commit_round ?? h.round, msg = voteMessage(h.chain_id, h.height, round, hash);
      let good = 0;
      for (const [v, sig] of Object.entries(b.votes || {})) if (validators.includes(v) && await edVerify(v, msg, sig)) good++;
      if (good < quorum(validators.length)) issues.push(`${good} valid validator signatures, ${quorum(validators.length)} needed`);
      issues.forEach(x => problems.push(`block ${h.height}: ${x}`));
      txCount += b.txs.length;
      if (onBlock) await onBlock({ index: i, total: blocks.length, block: b, hash, ids, votes: good, ok: issues.length === 0, issues });
      prevHash = hash; prevHeight = h.height; prevTime = h.timestamp || 0;
    }
    return { valid: problems.length === 0, problems, blocks: blocks.length, transactions: txCount,
             base_height: exported.snapshot ? exported.snapshot.header.height : 0, chain_id: g.chain_id };
  }

  // ---- national accounts, expenditure side, from a chain export ------------- //
  // Mirrors jurisledger/stats.py so the explorer's numbers match `jurisledger gdp`.
  function accountsOf(exported) {
    const acc = {};
    for (const a of exported.genesis.accounts || []) acc[a.address] = { name: a.name, role: a.role, sector: a.sector || "" };
    for (const i of exported.genesis.issuers || []) acc[i.address] = { name: i.name, role: "issuer", sector: "" };
    for (const b of exported.blocks || []) for (const t of b.txs) {
      if (t.kind === "REGISTER" && !acc[t.sender]) acc[t.sender] = { name: t.payload.name, role: t.payload.role, sector: t.payload.sector || "" };
      if (t.kind === "KEY_ROTATE" && acc[t.sender]) acc[t.payload.new_key] = { ...acc[t.sender] };
    }
    return acc;
  }
  const GOODS = new Set(["FINAL_CONSUMPTION", "INTERMEDIATE", "INVESTMENT", "GOVERNMENT_PURCHASE", "EXPORT"]);
  function expenditure(exported, acc) {
    acc = acc || accountsOf(exported);
    const r = { C: 0, I: 0, G: 0, X: 0, M: 0, payments: 0 };
    for (const b of exported.blocks || []) for (const t of b.txs) {
      if (t.kind !== "PAYMENT") continue;
      const p = t.payload, amt = p.amount, payer = acc[t.sender] || {}, payee = acc[p.to] || {};
      r.payments++;
      if (p.purpose === "FINAL_CONSUMPTION") r.C += amt;
      else if (p.purpose === "INVESTMENT") r.I += amt;
      else if (p.purpose === "GOVERNMENT_PURCHASE") r.G += amt;
      else if (p.purpose === "EXPORT") r.X += amt;
      else if (p.purpose === "WAGES" && payer.role === "government") r.G += amt;
      if (GOODS.has(p.purpose) && payee.role === "foreign") r.M += amt;
    }
    r.gdp = r.C + r.I + r.G + r.X - r.M;
    return r;
  }

  // ---- review flags: the four detectors of jurisledger/fraud.py ------------- //
  // Same thresholds and rules, so a statistics office's command-line run and a
  // journalist's browser see the same leads.  A flag is a lead, never a verdict.
  function payments(exported) {
    const out = [];
    for (const b of exported.blocks || []) for (const t of b.txs) if (t.kind === "PAYMENT") out.push({ h: b.header.height, t });
    return out;
  }
  const NON_TRADE = new Set(["WAGES", "TAX", "TRANSFER"]);

  function structuring(exported, threshold = 1000000, band = 0.10, minCount = 3, window = 5) {
    const low = Math.floor(threshold * (1 - band)), hits = new Map();
    for (const { h, t } of payments(exported)) {
      const a = t.payload.amount;
      if (a >= low && a < threshold) { if (!hits.has(t.sender)) hits.set(t.sender, []); hits.get(t.sender).push([h, a]); }
    }
    const flags = [];
    for (const [sender, items] of hits) {
      items.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
      let best = [];
      for (let i = 0; i < items.length; i++) { const run = items.slice(i).filter(x => x[0] - items[i][0] <= window); if (run.length > best.length) best = run; }
      if (best.length >= minCount) flags.push({ detector: "structuring", account: sender, count: best.length,
        total: best.reduce((s, x) => s + x[1], 0), blocks: [best[0][0], best[best.length - 1][0]] });
    }
    return flags;
  }

  function circularFlows(exported, maxLen = 5, tolerance = 0.10, window = 6) {
    const edges = new Map();
    for (const { h, t } of payments(exported)) {
      const p = t.payload;
      if (NON_TRADE.has(p.purpose) || p.amount < 1) continue;
      if (!edges.has(t.sender)) edges.set(t.sender, []);
      edges.get(t.sender).push({ to: p.to, amt: p.amount, h, id: t.signature });
    }
    const found = new Map();
    function walk(origin, node, path, amounts, heights, ids) {
      for (const e of edges.get(node) || []) {
        if (amounts.length && !((1 - tolerance) * amounts[0] <= e.amt && e.amt <= (1 + tolerance) * amounts[0])) continue;
        if (heights.length && !(heights[heights.length - 1] <= e.h && e.h <= heights[0] + window)) continue;
        if (e.to === origin && path.length >= 2) {
          const key = [...ids, e.id].sort().join("|");
          if (!found.has(key)) found.set(key, { detector: "circular_flow", accounts: [...path], hops: path.length,
            amounts: [...amounts, e.amt], total: amounts.reduce((s, x) => s + x, 0) + e.amt, blocks: [heights[0], e.h], signatures: [...ids, e.id] });
        } else if (!path.includes(e.to) && path.length < maxLen) {
          walk(origin, e.to, [...path, e.to], [...amounts, e.amt], [...heights, e.h], [...ids, e.id]);
        }
      }
    }
    for (const origin of edges.keys()) walk(origin, origin, [origin], [], [], []);
    const unique = new Map();
    for (const f of found.values()) { const k = [...f.accounts].sort().join("|"); if (!unique.has(k) || f.blocks[0] < unique.get(k).blocks[0]) unique.set(k, f); }
    return [...unique.values()].sort((a, b) => b.total - a.total);
  }

  const BENFORD = [1, 2, 3, 4, 5, 6, 7, 8, 9].map(d => Math.log10(1 + 1 / d));
  function benford(exported, minPayments = 60, critical = 20.09) {
    const by = new Map();
    for (const { t } of payments(exported)) { if (NON_TRADE.has(t.payload.purpose)) continue; if (!by.has(t.sender)) by.set(t.sender, []); by.get(t.sender).push(t.payload.amount); }
    const flags = [];
    for (const [sender, amounts] of by) {
      const n = amounts.length; if (n < minPayments) continue;
      const counts = new Array(9).fill(0); for (const a of amounts) counts[+String(a)[0] - 1]++;
      const chi2 = counts.reduce((s, c, i) => s + (c - n * BENFORD[i]) ** 2 / (n * BENFORD[i]), 0);
      if (chi2 > critical) flags.push({ detector: "benford", account: sender, payments: n, chi2: Math.round(chi2 * 10) / 10, critical });
    }
    return flags;
  }

  function duplicatePledges(exported) {
    const lenders = new Map();
    for (const { t } of payments(exported)) {
      const p = t.payload; if (p.purpose !== "FINANCIAL" || !("invoice" in p)) continue;
      const k = p.invoice + "|" + p.to; if (!lenders.has(k)) lenders.set(k, new Set()); lenders.get(k).add(t.sender);
    }
    return [...lenders].filter(([, ls]) => ls.size > 1).map(([k, ls]) => ({ detector: "duplicate_invoice_financing",
      invoice: k.split("|")[0], borrower: k.split("|")[1], lenders: [...ls].sort() }));
  }

  function reviewFlags(exported, threshold = 1000000) {
    return [...structuring(exported, threshold), ...circularFlows(exported), ...benford(exported), ...duplicatePledges(exported)];
  }

  async function verifyTx(t) { return edVerify(t.sender, txSigningBytes(t), t.signature); }

  root.JurisVerify = { canonical, txSigningBytes, verifyTx, bytesToHex, hexToBytes, txid, headerHash, verifyBundle, auditChain, merkleRoot, accountsOf, expenditure, reviewFlags, circularFlows, structuring, benford, duplicatePledges, supported, sha256hex, quorum };
})(typeof globalThis !== "undefined" ? globalThis : this);
