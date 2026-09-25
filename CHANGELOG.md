# Changelog

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
