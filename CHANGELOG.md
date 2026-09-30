# Changelog

## 0.19.0 — the wallet, and signing away from the network
- `site/wallet.html` and `site/wallet.js`: create or open a key in the browser (WebCrypto Ed25519), look up the account through the API, write a payment, sign it, and download the signed transaction; an envelope seals as you sign. Nothing leaves the page.
- `jurisledger submit SIGNED.json HOST:PORT`: send a transaction signed elsewhere; refuses a broken signature before touching the network, refuses a wrong transaction number, and waits for finality. Tested live against a four-validator cluster, including a refused replay.
- Keystores gain `pbkdf2-sha256` (600,000 iterations) beside scrypt so browsers can seal and open them; key-derivation cost parameters are bounded when opening. Browser signatures are byte-identical to Python's; sealed key files open on both sides (tested).
- `/api/account/...` now returns the account's name, role and next transaction number.
- 160 tests.

## 0.18.0 — live data: an API and a dashboard
- `api.py` and `jurisledger api`: a read-only JSON API over the index (status, GDP by range, per-block metrics, top accounts, account history, contract timeline). SQLite read-only mode, GET only, bound parameters, capped results, per-client token-bucket rate limiting, loopback by default, private-network preflight so the public site can read a local API. `--follow HOST:PORT` keeps indexing a live validator over pinned TLS.
- `site/dashboard.html`: KPIs and four hand-drawn animated charts with hover details — activity, where the money went (imports below the line), GDP accumulating, and consensus health — fed live by the API, by `metrics.csv`, or by a bundled 60-block sample run on the two-phase network with one validator offline (its turns show as extra rounds).
- 157 tests.

## 0.17.0 — 3D views, sealed keys, spam quotas, a data index
- **3D.** `site/ledger3d.js`, a dependency-free 3D renderer, adds two views to the explorer: *the chain* (every block a box on a rising spiral, sized by its transactions, linked to its parent, with the validators orbiting and amber vote lines showing who signed the selected block) and *money flows* (every account a sphere grouped by role, every trading pair an arc weighted by volume; a review flag lights its ring in red). Drag, zoom, click a block.
- **Security.** Encrypted key files (`keystore.py`: scrypt + AES-256-GCM, address bound as associated data) for `keygen --encrypt`, `wallet new --encrypt` and `init --encrypt`; validators read `JURISLEDGER_PASSPHRASE` or prompt. Plain key files are created mode 600 and flagged if readable by others. A per-account, per-block transaction quota (`max_tx_per_block`) set by validator vote; excess transactions wait instead of being dropped; institutions exempt.
- **Data tracking.** `index.py` and `jurisledger index | query | metrics`: an incremental SQLite index built only from audited blocks, refusing a different history, crash-safe per sync. About 35,000 transactions per second to build; GDP for any block range in about 0.1 ms. `docs/DATA.md`.
- 153 tests.

## 0.16.0 — fraud leads in the explorer
- `verify.js` gained the four detectors of `fraud.py` (circular flows, structuring, Benford first digits, one invoice financed by several lenders) with identical thresholds; a test injects all four kinds of fraud and requires the browser and Python to flag exactly the same accounts, totals and counts.
- The explorer shows a *Review flags* panel: each ring drawn as a diagram with curved edges and amounts, each other lead as a plain sentence; clicking a flag lights up its blocks and jumps to the first.
- 144 tests.

## 0.15.0 — a self-verifying public register
- `jurisledger register` and `jurisledger demo` now render the public register in the site's shared visual system (from a source checkout; otherwise the built-in styles).
- Every contract in the register carries its own evidence file and a *Verify this contract in your browser* button backed by `site/verify.js`: signatures, certificates and Merkle paths are checked locally against the genesis validators embedded in the page. Embedded data is escaped so no string in it can close its script element.
- 143 tests.

## 0.14.0 — arbitration, visualized
- Explainer step 8, "Settle a dispute": a lease with three instalments on a block timeline. Advance time, pay or miss, open a dispute (the obligation turns *disputed*, not *overdue*), and issue an award with sliders that physically cannot exceed the original debt or bring a due date forward. Two cheat buttons show the validators' refusals. Evidence verification moves to step 9.

## 0.13.0 — the explorer
- `site/explorer.html`: drop a `chain.json` (or open the bundled demo republic) and every block is checked in the browser as it animates into a strip — links, heights, timestamps, Merkle roots, every transaction signature and every commit certificate; snapshot-based exports are understood. Then browse blocks, read transactions as plain sentences, filter them, follow one account across the chain, and see GDP by expenditure up to any block. "Alter one old payment" shows exactly which block breaks and why.
- `verify.js` gained `auditChain`, `merkleRoot`, `accountsOf` and `expenditure`; tests require the structural audit to reject exactly what `Chain.load` rejects on four kinds of tampering and GDP to match `stats.gdp` to the cent.
- Shared styles moved to `site/style.css`.
- 142 tests.

## 0.12.0 — prove it in the browser
- `site/verify.js`: the evidence-file verifier re-implemented with WebCrypto (Ed25519, SHA-256), byte-for-byte compatible canonical JSON, Merkle paths, commit certificates and key-change following.
- Explainer step 8, "Prove it to a court": drop an evidence file and validators, watch each transaction verify, then try four ways to cheat (edit an amount, swap the text, strip signatures, trust the wrong validators) — each fails for its own reason. A real sample from the demo ledger is included.
- `tests/test_site_verifier.py` runs the JavaScript verifier under Node and requires it to agree with the Python verifier on genuine and tampered files, including key rotation. CI installs Node 22.
- 140 tests.

## 0.11.0 — the explainer
- `site/index.html`: a self-contained interactive explainer that walks the life of one transaction in seven steps — finality stepper, the partition attack against both voting protocols, a contract whose fingerprint reacts to edits, k-of-n identity with a corrupt issuer, 32-bit range-proof decomposition that refuses negatives, GDP against off-ledger cash, and a fraud ring with a detector. No external scripts, fonts or requests; dark mode and reduced motion respected.
- GitHub Pages workflow publishes it; README redesigned around it with an animated banner.

## 0.10.0 — deployment and governance
- `jurisledger init`: prepares a multi-machine network — shared genesis and peers, one folder per machine holding only its own key and a `start.sh`, issuer and treasury keys kept aside. `docs/DEPLOY.md` covers operations and a two-machine exercise.
- `VALIDATOR_VOTE` with `SET_POLICY`: the identity threshold, unverified payment cap and recovery delay change only by validator quorum, effective at once and recorded forever.
- 137 tests.

## 0.9.0 — snapshots, encrypted notes, a wallet
- Certified state snapshots: `Chain.make_snapshot` / `Chain.from_snapshot`, `jurisledger snapshot`; the certificate is checked against trusted validators and the state against the certified `state_root`; the access log is verified against its digest. A chain started from a snapshot keeps accepting blocks and exports normally.
- Confidential payments carry the recipient's opening encrypted (ECIES over the account's Ed25519 key, AES-256-GCM); `ConfidentialWallet.scan` recovers incoming payments from the chain.
- `jurisledger wallet new|register|balance|pay`: a command-line wallet against a running validator. Nodes answer `account` queries.
- Per-source connection rate limiting on validators.
- 135 tests.

## 0.8.0 — confidential payments
- `ec.py`: Ed25519 point arithmetic. `privacy.py` moved from the 2048-bit MODP group to the curve (about ten times faster) and gained bit-decomposition range proofs (32 bits, ~11 kB, ~0.25 s).
- `SHIELD`, `CONFIDENTIAL_PAYMENT`, `UNSHIELD`: hidden balances as commitments; payments carry range proofs on the amount and on the remaining balance; commitments outside the prime-order subgroup are refused; confidential use requires a verified identity when the network has an identity policy. `ConfidentialWallet` tracks openings and builds proofs. `stats.committed_totals` sums commitments by purpose.
- Fixed during development: the subgroup check reduced the group order modulo itself and would have accepted small-order points; caught by a test.
- Fix: `jurisledger demo --out DIR` failed when DIR already held a store from an earlier run.
- New experiment `confidential` (11 claims). Totals: 11 experiments, 101 claims, 131 tests.

## 0.7.0 — encrypted, authenticated transport
- Every connection is TLS 1.3. Each validator's certificate is self-signed with its own Ed25519 validator key and verified by pinning against the genesis, so no certificate authority is needed. Peers authenticate by signing a per-connection challenge; only authenticated peers may send consensus or block-sync frames, and only under their own index. Inbound connections are capped. `Client(..., expect_address=)` pins the validator it talks to.
- 126 tests.

## 0.6.1
- Fix: `jurisledger cluster` failed when re-run in the same directory — new keys and genesis were generated but stores from the previous run were reused, so validators crashed on start with "prev_hash does not match". Stale stores and logs are now removed, and a validator refuses to start on a store whose founding record does not match its genesis, with a message saying what to do.
- The cluster reports which validators exited if no block appears.
- New client commands `jurisledger status HOST:PORT` and `jurisledger export HOST:PORT`.

## 0.6.0 — real processes, real sockets, real time
- `net.py`: validators as separate processes over TCP; length-prefixed signed JSON frames; transaction gossip; block catch-up with certificate re-verification; resume from the on-disk store; `Client` for wallets and tools. `cluster.py` and `jurisledger cluster` run four processes, pay, kill one, restart it and check it rejoins. `jurisledger node`, `jurisledger keygen`; key files with the raw Ed25519 seed.
- Block headers carry a proposer timestamp endorsed by every vote; validators refuse headers more than five minutes from their clock; the chain rejects time running backwards.
- Idle proposers wait two seconds before proposing an empty block.
- 122 tests.

## 0.5.0 — security, usability and viability for public-sector use
- **Security.** `ledgernet.py`: the real chain runs on signed two-phase consensus; certificates record their voting round; equivocation evidence is per voting round; finality announcements are verified, never trusted. All earlier claims re-run on it. Identity from *k* independent issuers (`ATTEST`, `ATTEST_REVOKE`, issuer governance), capped unverified accounts, verified contract parties. `KEY_ROTATE` and issuer-assisted recovery with an owner veto window; contracts, obligations and evidence files follow key changes.
- **Usability.** `jurisledger demo`, `audit`, `verify`, `register`, `bench`; a self-contained browsable public register; plain-language verdicts and error messages; readable labels in evidence files.
- **Viability.** `storage.py` durable block store that re-audits on open and survives torn writes; honest benchmark; `docs/GOVERNMENT.md` blueprint.
- New experiments `identity` (11 claims) and `integration` (9 claims). Totals: 10 experiments, 90 claims, 119 tests.

## 0.4.0
- `bft.py`: message-level consensus laboratory. Single-phase voting forks under a delaying adversary with four honest validators; Tendermint-style two-phase voting with locks survives the same adversary and 1,000 random schedules with a lying validator. Two colluders of four fork it, and are provably guilty.
- New experiment `asynchrony` (8 claims) and `tests/test_bft.py`. Totals: 8 experiments, 70 claims, 109 tests.

## 0.3.0
- Arbitration: `DISPUTE_OPEN`, `DISPUTE_FILE`, `DISPUTE_WITHDRAW`, `DISPUTE_AWARD`; awards can only reduce, postpone or waive disputed obligations. `DISPUTED` and `WAIVED` compliance states. Experiment `disputes`.

## 0.2.0
- Machine-readable payment obligations, `legal.compliance`, offline-verifiable evidence files. Experiment `legal`. Project renamed from its working titles to JurisLedger.

## 0.1.0
- Ledger, quorum certificates, Ricardian contracts with access receipts, national accounts from the ledger, fraud detectors, Pedersen commitments, adversarial experiments.
