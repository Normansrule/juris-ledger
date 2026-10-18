# Security findings register — audit of v0.25.0, remediation in v0.26.0

**Source.** An external audit of v0.25.0 (archive commit `07f0f2f`) reported 30 findings: 4 critical,
18 high-priority, 8 other. Only the audit's *summary* was available to us, not its full report,
findings register or reproduction scripts. Every finding the summary describes was reproduced
independently, turned into an automated regression, fixed and re-verified. Findings the summary
does not describe cannot be identified, so they are listed as **BLOCKED BY MISSING EVIDENCE** and
not claimed as fixed.

**Statuses** (as the audit requires): FIXED AND VERIFIED · TESTED AND NOT DEFECTIVE ·
DEFERRED WITH TECHNICAL JUSTIFICATION · BLOCKED BY MISSING EVIDENCE.

**Evidence.** `python tools/audit_repro.py [TREE]` runs every reproduction against any source tree.
Same script, both trees:

| ID | Reproduction | v0.25.0 | v0.26.0 |
|---|---|---|---|
| F01 | malformed transaction to a validator's port | VULNERABLE (event loop died: `KeyError: 'kind'`) | SAFE |
| F02 | restarted validator signs a conflicting precommit | VULNERABLE (two valid conflicting signatures) | SAFE (`DoubleSignRefused`) |
| F03 | cross-network key change completes signatures | VULNERABLE (`fully_signed` with a party unsigned) | SAFE |
| F04 | forged snapshot names its own certifiers | VULNERABLE (loaded with +777,777) | SAFE (`UntrustedSnapshot`) |
| H1 | note-less confidential payment | VULNERABLE (recipient's opening invalid) | SAFE (protocol 2) |
| H2 | rejected confidential payment | VULNERABLE (wallet 250, ledger 300) | SAFE |
| H3 | recovery after revocation | VULNERABLE (account moved) | SAFE (protocol 2) |
| H4 | damaged vault journal | VULNERABLE (receipt spent twice) | SAFE (`VaultJournalCorrupt`) |
| H5 | key file with scrypt r = 2^20 | VULNERABLE (derivation attempted: 4 TiB) | SAFE (refused before derivation) |
| H6 | privacy release noise | VULNERABLE (identical noise every call) | SAFE |
| H7 | damaged middle block record | VULNERABLE (file cut to 1 of 5 records) | SAFE (`CorruptStore`, 5 kept) |
| H8 | paid obligation on a pruned copy | VULNERABLE (reported OVERDUE) | SAFE (`HistoryPruned`) |
| H9 | second award raises a reduced debt | VULNERABLE (100 → 900) | SAFE (protocol 2) |
| H10 | integer beyond 2^53 | VULNERABLE (Python signs 2^64, browser sees …552000) | SAFE (both refuse) |
| H11 | API next_nonce on a snapshot-based index | VULNERABLE (API 2, ledger 4) | SAFE |
| H12 | hostile API strings in the dashboard (Chromium) | VULNERABLE (script ran 10 times) | SAFE (0; and CSP blocks raw injection) |
| H13 | dashboard past 5,000 rows, then a new block (Chromium) | VULNERABLE (never refreshed) | SAFE (pages, refreshes) |

H12 and H13 are reproduced by `tests/test_browser_security.py`; set `JURISLEDGER_SITE` to another
tree's `site/` to run them against it.

---

## Critical

### F01 — validator denial of service from one malformed transaction — FIXED AND VERIFIED
- **Cause.** `Transaction.from_dict` trusted its input; the validator's event loop had no per-message fault boundary.
- **Changed.** `jurisledger/tx.py` (strict parser, `MalformedTransaction`, `signature_valid` never raises), `jurisledger/net.py` (fault boundary, frame must be an object, 1 MiB limit for unauthenticated connections, bounded future-height buffer), `jurisledger/consensus.py` (mempool capped at 20,000, stale nonces refused).
- **Tests.** `tests/test_audit_v26.py::test_F01_*` (7 malformed shapes, live TLS validator with garbage client and authenticated-peer frames, bounds).
- **Remaining risk.** Volumetric flooding of the listening socket is a network-layer problem.

### F02 — double-signing after restart — FIXED AND VERIFIED
- **Cause.** Nothing recorded what a validator had signed; a new process started from round 0 with no lock.
- **Changed.** New `jurisledger/signguard.py` (durable journal `store/sign_state.json`, strictly increasing height/round/step, same-value re-sign only, fsync before release, restores the precommit lock), `jurisledger/ledgernet.py` (signing goes through the guard; a refused signature is silence), `jurisledger/net.py` (resume at the journal's round with its lock).
- **Tests.** `test_F02_*`, including a negative control showing unguarded instances really equivocate, and the live cluster crash/restart tests.
- **Remaining risk.** One key on two machines with two journals can still double-sign: operators must never run a key twice (`docs/DEPLOY.md`). A damaged journal stops the validator by design; `signguard.on_corrupt_journal` is the single place to change that policy.

### F03 — key changes from other networks manufactured signatures — FIXED AND VERIFIED
- **Cause.** Key-change records were checked for signatures and inclusion, not for their network; parties were resolved to keys and then compared as a set, so two parties could collapse into one key.
- **Changed.** `jurisledger/legal.py` and `site/verify.js`, identically: key changes only from the bundle's `chain_id`; signatures counted per party, valid only while that party held the signing key; two parties resolving to one key is a problem and never "fully signed"; only proven, own-network, validly signed items count. The report adds `unsigned`.
- **Tests.** `test_F03_*` (Python and the browser verifier on the auditor's scenario, rotation-then-sign still accepted), `tests/test_site_verifier.py`.
- **Remaining risk.** None known. Evidence bundles still cannot prove that nothing was *omitted* (documented since 0.6).

### F04 — self-authorised snapshot — FIXED AND VERIFIED
- **Cause.** When genesis validators did not certify a stored snapshot, `BlockStore` trusted the `certified_by` list inside the snapshot file.
- **Changed.** `jurisledger/storage.py`: anchors only from outside the snapshot — genesis validators, operator `--trust-validators FILE`, `anchor.json` signed by the validator's own key, or a full archive replay from genesis; otherwise `UntrustedSnapshot`. `certified_by` is still written (no change to stored format) but never trusted. `jurisledger audit` prints the founding record's fingerprint and says that without `--genesis` it proves self-consistency only; `--genesis FILE` checks it. `jurisledger demo` writes `genesis.json`.
- **Tests.** `test_F04_*` (forgery refused, genuine pruned store and archive anchor still open, signed anchor accepted only from the expected key and unedited, audit fingerprint and `--genesis`).
- **Remaining risk.** Whoever controls the machine can also replace the program. A store copied between machines needs `--trust-validators` or its archive.

## High priority

### H1 — confidential note ownership — FIXED AND VERIFIED (protocol 2) · DEFERRED WITH TECHNICAL JUSTIFICATION (protocol-1 ledgers)
- **Cause.** The ledger credited every incoming commitment to the recipient's balance, so anyone could change the point the recipient must open.
- **Changed.** Redesign, not a null check: on `protocol_version: 2` ledgers, incoming hidden payments wait in an inbox; the recipient signs `CONFIDENTIAL_CLAIM` to accept (its wallet can open the note) or refuse (the commitment returns to the payer, who always can). `jurisledger/state.py`, `jurisledger/tx.py`, `jurisledger/contracts.py` (`scan` stages claims). `jurisledger init` writes protocol 2.
- **Why protocol 1 is deferred.** Changing v1 rules would change the state roots of every existing v1 ledger and invalidate its history — the audit forbids that. The version is part of the state root only when it is not 1, so v1 roots are byte-identical (tested). Migration = a new ledger at protocol 2, or a future explicitly voted activation height.
- **Tests.** `test_H1_*` (the auditor's 100-unit scenario: v1 reproduces, v2 refuses and the recipient withdraws all 100; genuine payment credited only when claimed; v1 roots unchanged; claims refused on v1).

### H2 — confidential wallet changed before finality — FIXED AND VERIFIED
- **Changed.** `ConfidentialWallet` keeps a confirmed opening (proven by finalised blocks) and a projected one; `sync(chain)` confirms included transactions and rolls back any that can never be included (nonce used, or the next block would reject it) together with everything queued after; `matches_ledger(chain)` checks the opening against the ledger.
- **Tests.** `test_H2_rejected_transaction_is_rolled_back`.

### H3 — recovery after revocation — FIXED AND VERIFIED (protocol 2) · DEFERRED (protocol 1, same justification as H1)
- **Changed.** At finalisation, only issuers still accredited and still attesting count; a revocation also withdraws that issuer's request and lapses the approval.
- **Tests.** `test_H3_*` (v1 negative control, v2 refusal).

### H4 — damaged vault journal let a receipt be reused — FIXED AND VERIFIED
- **Changed.** `jurisledger/vault.py`: journal lines are hash-chained (`prev`); a damaged complete line, or one that does not follow its predecessor, raises `VaultJournalCorrupt` and the custodian releases nothing; only a torn last line (no newline) is cut; receipt counts are monotone.
- **Tests.** `test_H4_*` (damaged middle line, deleted middle line, torn last line).
- **Remaining risk.** Deleting the *last* lines of a journal is undetectable from the journal alone: back journals up off-machine.

### H5 — scrypt r and p unbounded — FIXED AND VERIFIED
- **Changed.** `jurisledger/keystore.py`: every parameter type-checked and bounded before any derivation: N a power of two in 2^14..2^20, r 1..32, p 1..4, 128·N·r ≤ 256 MiB, PBKDF2 100,000..10,000,000, salt 16–64 bytes, nonce 12 bytes, known KDF and cipher only.
- **Tests.** `test_H5_*` (10 hostile files refused with derivation never called; default files still open).

### H6 — privacy release: predictable noise, deterministic suppression — FIXED AND VERIFIED
- **Changed.** `jurisledger/stats.py`: noise from the operating system's generator by default; integer (two-sided geometric) noise; suppression decided on a noisy count; budget split by sequential composition. A `seed` is documented as reproducible and **not private**. The experiment's claim now reads that thin sectors are suppressed far more often (57% vs 6%), not always — the honest cost of a real guarantee.
- **Tests.** `test_H6_*`.
- **Remaining risk.** No formal proof of this implementation; the privacy unit is a firm.

### H7 — damaged middle record truncated later history — FIXED AND VERIFIED
- **Changed.** `jurisledger/storage.py`: `CorruptStore`; nothing is truncated except a final line without a newline.
- **Tests.** `test_H7_*`.

### H8 — pruned history silently omitted — FIXED AND VERIFIED
- **Changed.** `Chain.iter_txs` raises `HistoryPruned` for a range that starts inside pruned history; callers that accept partial history pass `partial_ok=True` explicitly.
- **Tests.** `test_H8_pruned_history_raises_instead_of_reporting_overdue`.

### H9 — consecutive awards worsened terms — FIXED AND VERIFIED (protocol 2) · DEFERRED (protocol 1, same justification as H1)
- **Changed.** Limits apply to the effective terms after earlier awards; earlier relief persists; a waiver cannot be reinstated.
- **Tests.** `test_H9_*` (amount, due date and waiver: v1 negative controls, v2 refusals; improvements still allowed).

### H10 — Python and JavaScript canonicalisation differed — FIXED AND VERIFIED
- **Changed.** One written contract, [`docs/CANONICAL.md`](CANONICAL.md): integers within ±(2^53−1), keys sorted by code point, no lone surrogates, no normalisation. Two levels in Python: hashing stays byte-identical for all history (so no identifier, root or evidence changes), while signing, network parsing and protocol-2 state admission enforce the contract. `site/verify.js` sorts by code point and refuses what it cannot reproduce. Found by the fuzzer during remediation: a first version that made hashing itself strict would have broken replay of protocol-1 history.
- **Tests.** `tests/vectors/canonical.json` (12 vectors) run against both implementations; `test_H10_*`.

### H11 — API nonce calculation — FIXED AND VERIFIED
- **Changed.** `jurisledger/api.py`: `next_nonce` = last nonce used + 1, or `null` when an index that starts from a snapshot cannot know; the wallet page says so instead of guessing.
- **Tests.** `test_H11_*`.

### H12 — dashboard script injection — FIXED AND VERIFIED
- **Changed.** New `site/safe.js` (`html` tagged template escapes every interpolation). Every dynamic `innerHTML` in all four pages converted — including the explorer and the evidence verifier, which render *valid* but attacker-written ledger strings. A Content Security Policy from script hashes (`tools/csp.py`). Typed validation of API responses. The wallet now shows the address an API resolved a name to and makes the user confirm it.
- **Tests.** Static rule over every page (`test_H12_no_page_assigns_unescaped_markup`), live Chromium against a hostile API (0 executions; 10 on v0.25.0), CSP present, current and enforced on every page while each page still works.

### H13 — stale data near the 5,000-row limit — FIXED AND VERIFIED
- **Changed.** The dashboard pages through `/api/metrics` up to the status height, refreshes whenever the height changes, labels incomplete answers, and shows a trust line ("display data from an API, not verified in this browser").
- **Tests.** `test_H13_*` in Chromium (5,003 rows, then 5,004).

### H14–H18 — BLOCKED BY MISSING EVIDENCE
The summary names 13 high-priority defects (H1–H13 above, where the audit's own grouping is
unknown; some of them may be among its "other" findings). Up to five more high-priority findings
are not described. They need the audit's full report or findings register.

## Other findings

| ID | Finding | Status | Change and test |
|---|---|---|---|
| O1 | README onboarding too long | FIXED AND VERIFIED | Four-command "Start here" block and a security status box at the top |
| O2 | Version labels inconsistent | FIXED AND VERIFIED | README said 0.23; all labels now come from one version and `test_readme_states_the_package_version` fails on drift |
| O3 | Mobile layouts | FIXED AND VERIFIED | Phone-width rules in `site/style.css`; `test_pages_do_not_scroll_sideways_on_a_phone` (375 px, four pages; v0.25.0: 437 px and 441 px); accessibility audit re-run: 0 problems |
| O4 | Intermittent cluster re-run test | FIXED AND VERIFIED | Cause found: copies were compared by *latest* state root, so a block finalised between two exports looked like disagreement. `cluster.same_history` compares the block at the highest common height; `test_cluster_comparison_tolerates_a_block_finalised_between_exports`; the re-run test passed 5 of 5 consecutive runs |
| O5–O8 | Not described in the summary | BLOCKED BY MISSING EVIDENCE | — |

## Found during remediation (not in the audit summary)

| ID | Finding | Status |
|---|---|---|
| S1 | `pyproject.toml` allowed `cryptography>=41`; that floor has 20 published advisories (pip-audit) | FIXED AND VERIFIED: floor raised to 50.0.0 (no advisories); CI scans the runtime closure |
| S2 | The web wallet silently replaced a typed name with whatever address the API returned | FIXED AND VERIFIED: the address is shown and must be confirmed |
| S3 | The explorer and evidence verifier rendered attacker-chosen ledger strings as markup | FIXED AND VERIFIED (H12 static rule and CSP) |
| S4 | Mempool and future-height buffers were unbounded | FIXED AND VERIFIED (F01 bounds) |
| S5 | `jurisledger audit` reported VERIFIED for an export with an attacker's own genesis | FIXED AND VERIFIED: fingerprint printed, `--genesis` check (F04) |

## Independent review of the 0.26 fixes

A separate reviewer, who had not seen the remediation being written, tried to bypass each fix and
compared protocol-1 behaviour between v0.25.0 and v0.26.0 on a 34-block history covering every
transaction kind (same accept/reject decision for every transaction, same state root for every
block). It confirmed seven issues in the first version of these fixes; all are fixed here.

| ID | Finding | Status | Change and test |
|---|---|---|---|
| R1 | F01 bypass: an authenticated peer's signed proposal with a string timestamp raised `TypeError` from `tick()` / buffered-message replay, outside the fault boundary | FIXED AND VERIFIED | header types checked on parse; any failure to validate a proposal means "invalid"; the fault boundary covers every protocol step; a wrongly typed payload is an `InvalidTx`. `test_R1_*` |
| R2 | An idle proposer timed out its own round while waiting for work, signing nil prevote and precommit before proposing — an **honest double-sign, present in v0.25.0**; in the first 0.26 build the journal refused it, costing a round | FIXED AND VERIFIED | no timeouts while the proposer is deliberately waiting. `test_R2_an_idle_proposer_never_times_out_its_own_round` |
| R3 | F02 bypass: if writing the journal failed, memory had already advanced, so a retry released the signature with nothing on disk | FIXED AND VERIFIED | disk first, then memory. `test_R3_*` |
| R4 | H4 bypass: deleting a line and stripping `prev` from the next made it look like a pre-0.26 line; the chain was unkeyed, so it could be recomputed | FIXED AND VERIFIED | HMAC chain keyed from the custodian's own key; unchained lines are refused unless the operator migrates once (`migrate_legacy=True`). `test_R4_*` |
| R5 | H1 follow-on: a refused payment returned to the payer, whose wallet did not know | FIXED AND VERIFIED | the wallet remembers its payments' openings and credits refunds. `test_R5_*` |
| R6 | H1 follow-on: anyone could fill a recipient's inbox | FIXED AND VERIFIED (per payer) · DEFERRED (many payers) | at most 8 unclaimed payments per payer per recipient; many colluding accounts can still fill 256 slots, which identity attestations (required for confidential balances under an identity policy) and the per-block quota bound. Also: unregistered senders can no longer fill the mempool. `test_R6_*` |
| R7 | H10 gap: `JSON.parse` reads the text `3.0` as an integer, Python as a float, so the verifiers disagreed about the same file | FIXED AND VERIFIED | `JurisVerify.parseJSON` refuses non-integer and unsafe number text before parsing; pages and harnesses use it. `test_R7_*` |

Reported as plausible and **not** fixed (each a design limit, recorded in the threat model):

- **Retired genesis validators.** A store's snapshot is tried against the genesis validators first; if a quorum of *retired* genesis keys were stolen, they could certify a forged snapshot. This is the long-range attack class the threat model already lists as unaddressed. DEFERRED WITH TECHNICAL JUSTIFICATION: the standard defences (checkpoints, key-retirement proofs) are protocol work beyond this release.
- **Future-message buffer** is bounded by count (64 heights × 512), not bytes; a Byzantine validator with 32 MiB frames could use a lot of memory. DEFERRED: a byte budget needs frame sizes threaded through the transport.
- **Mempool clean-up** is quadratic in the worst case (also in v0.25.0). DEFERRED: performance, not safety.

## Regression results (v0.26.0, 18 October 2026)

| Gate | Result |
|---|---|
| `python -m pytest` (unit, live multi-process TLS validators, Chromium security tests) | **279 passed**, 0 failed (v0.25.0: 189) |
| `tests/test_audit_v26.py` + `tests/test_browser_security.py` | every audit and review reproduction, as a regression |
| `tools/audit_repro.py` | v0.25.0: 15 of 15 VULNERABLE · v0.26.0: 15 of 15 SAFE |
| `tests/test_browser_security.py` with `JURISLEDGER_SITE` = v0.25.0 | fails as expected (10 script executions; no refresh past 5,000 rows) |
| Cluster re-run test, five consecutive runs (ten cluster launches) | 5 of 5 passed |
| `jurisledger fuzz --runs 50 --steps 500` (25,000 hostile transactions, 8 invariants) | no violation |
| `jurisledger all` | 127 of 127 claims PASS |
| `tools/a11y_audit.py` (WCAG 2.1 AA, light and dark) | 0 problems |
| `tools/csp.py --check` | 4 of 4 pages current |
| `pip-audit` on the runtime closure (`cryptography` 50.0.1, `cffi`, `pycparser`) | no known vulnerabilities |
| Protocol-1 compatibility (independent reviewer, 34-block v0.25.0 history) | identical accept/reject decisions and state roots |

## Production-readiness decision

**Not ready for production, real money, sensitive contracts, production signing keys or legal-evidence decisions.**
Passing these tests does not mean there are no vulnerabilities. Before any such use:

1. Independent review of the consensus protocol and its implementation, the cryptography (range proofs, Feldman sharing, the canonical format) and a penetration test — none has happened.
2. The confidential-payment and Shamir arithmetic is pure Python and not constant-time.
3. Nine audit findings remain unidentified (H14–H18, O5–O8), and three review concerns are deferred (above).
4. Protocol-1 ledgers keep three defective rules (H1, H3, H9) by design; only protocol-2 ledgers have the fixes.
5. One implementation of the protocol; no formal specification beyond the code and `CANONICAL.md`.
6. Operational controls (key custody, journal backups, monitoring, incident response) exist only as documentation.
