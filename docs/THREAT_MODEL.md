# Threat model

## Assets

1. **Integrity of balances and history** — no unauthorised transfer, no rewriting.
2. **Integrity of contracts** — the text the parties signed is the text anyone later reads; status changes only by the parties' signatures.
3. **Integrity of statistics** — published aggregates equal what the finalised transactions imply.
4. **Availability** — valid transactions are eventually included.
5. **Confidentiality** — restricted contract text, and (future work) individual amounts.

## Assumptions

- Ed25519 and SHA-256 are secure.
- Fewer than one third of validators are Byzantine (arbitrarily malicious) at any time.
- Holders keep their private keys private. Key theft is out of scope for the protocol and in scope for a deployment (hardware keys, recovery, revocation).
- `consensus.py` assumes a synchronous network; `bft.py` assumes only that messages are eventually delivered. See "Known gaps".

## Adversaries and outcomes

| # | Adversary and action | Defence | Residual risk |
|---|---|---|---|
| 1 | Anyone edits a past transaction or block | Signature, Merkle root, hash chain and certificate all break; `Chain.audit` fails | None within assumptions |
| 2 | Validator includes a payment it forged from a victim | Honest validators re-execute, refuse to vote; the round is skipped | One wasted round |
| 3 | Account holder replays a transaction, here or on another network | Nonce; `chain_id` inside the signed bytes | None |
| 4 | Account holder double-spends | Deterministic ordering inside a finalised block; balance check | None |
| 5 | Proposer sends different blocks to different validators (equivocation) | Any two quorums share an honest validator, so at most one block finalises; two signed headers are self-contained proof; `EVIDENCE` removes the validator | Validator misbehaves once before removal |
| 6 | Validator censors an account | Proposer rotation: the next honest proposer includes it | Delay of roughly `f` blocks with `f` censoring validators |
| 7 | Validators go offline | Live while more than two thirds remain | At one third or more offline the chain halts — deliberately, in preference to finalising with too few checks |
| 8 | Two thirds or more of validators collude to finalise an invalid block | Full nodes and auditors re-execute and reject; the fraud is visible and attributable | Light clients that trust certificates alone are fooled. Mitigation: fraud proofs (roadmap) |
| 9 | Household or firm mis-tags a payment to distort statistics | Role/purpose matrix rejects impossible tags; production and expenditure totals must reconcile | Plausible lies within allowed tags (consumption declared as investment). Needs audits, as today |
| 10 | Contract host alters text or serves it secretly | Hash mismatch is detected by any reader; the vault interface requires a finalised receipt | A host can leak text out-of-band. Cryptographic fix: encrypt prose, release keys by threshold of validators on receipt (roadmap) |
| 11 | Non-party reads a restricted contract | `CONTRACT_ACCESS` rejected on-chain, so no receipt exists | Parties can always share text themselves |
| 12 | Fake identities flood the ledger (Sybil attack) | Registration is free but nearly useless: payments above a cap and all contracts need attestations from *k* independent issuers; government, validator and issuer roles cannot be self-registered; issuers can revoke; validators can vote an issuer out and its attestations stop counting at once | *k* colluding or careless issuers. The ledger cannot check that an issuer checked a passport |
| 13 | Analyst reads everyone's payments | Confidential balances: amounts are commitments; range proofs stop negative and overspent transfers; the state refuses commitments outside the prime-order subgroup | Counterparties, purposes and timing are public; the opening travels off-ledger; proofs are large and slow in Python; arithmetic is not constant-time, so keep long-term secrets off measurable hosts |
| 14 | Someone accuses an honest validator with fabricated evidence | Evidence must contain two *valid* signatures by the accused over *different* headers at the same height and round | None |

| 15 | The arbitrator named in a contract abuses its role | It can act only on an open dispute raised by a party, once, only on obligations in dispute, and only to reduce, postpone or waive; it cannot move money; every read and decision is signed and on record | A corrupt arbitrator can wrongly waive a genuine debt. Remedy is outside the ledger: challenge the award in court, using the evidence file |

| 16 | Key theft or loss | Owner rotates the key at once (`KEY_ROTATE`); a lost key is recovered by the issuers that attested the account, after a waiting period during which the current key can veto; contracts, obligations and evidence files follow the new key; the old key can never sign again | A thief who acts before the owner rotates. *k* colluding issuers against an owner who does not look for the whole veto window |
| 20 | An attacker on the network impersonates a validator or eavesdrops | TLS 1.3 with the certificate pinned to the validator key; signed challenge before any consensus frame is accepted | Denial of service by flooding; no per-source rate limit yet |
| 17 | A forged or unsigned consensus vote | Every proposal, prevote and precommit is signed and verified on receipt; announcements of finality are accepted only with a verifiable certificate | None within assumptions |
| 19 | A validator crashes mid-consensus | It restarts from its store, asks a peer for the blocks it missed, re-verifies each certificate, and rejoins at the current height; the others never stopped (they are a quorum) | Two of four crashing halts the chain until one returns — by design |
| 18 | The block file is edited on disk, or power fails mid-write | The store re-audits every block when opened; a torn final line (no newline) is cut off; a damaged *complete* record stops the store with `CorruptStore` and nothing is truncated (0.26, audit H7); a block is acknowledged only after it is flushed to disk | Loss of the whole disk: keep replicas (every validator is one) |

| 21 | Someone forges a range proof | Fiat-Shamir Schnorr OR-proofs over a prime-order group with a hash-derived second generator; a proof is bound to its commitment | Relies on the discrete-log assumption on Ed25519 and SHA-512; no formal proof of this implementation |

| 22 | A forged snapshot | A snapshot is accepted only with a quorum certificate from validators the verifier already trusts, and only if the restored state hashes to the certified `state_root`; the access log is checked against its rolling digest. Since 0.26 (audit F04) the trusted set never comes from the snapshot file: genesis validators, then `--trust-validators`, then `anchor.json` signed by the validator's own key, then a replay of `archive/` from genesis | A snapshot hides nothing but also proves nothing about history before it; keep archives |

| 23 | A key file is copied from a disk or backup | Key files can be sealed with a passphrase (scrypt, then AES-256-GCM with the address as associated data); plain key files are written mode 600 and a warning is printed if they are readable by others | A weak passphrase; a machine compromised while the key is in memory |
| 24 | One account floods the ledger with valid transactions | A validator-voted policy caps transactions per account per block (`max_tx_per_block`); excess transactions wait for later blocks instead of being dropped; government, validators and issuers are exempt | Many accounts flooding together; per-source network rate limits and identity attestations bound that |

| 25 | The statistics API is abused or used to change data | Read-only database connection and no write routes (405); bound parameters only; capped result sizes; per-client token-bucket rate limit (429); loopback by default; it serves only data the public ledger already publishes | Volumetric flooding at the network layer; put it behind a reverse proxy for public exposure |

| 26 | A networked machine holding keys is compromised | Offline signing: the browser wallet signs with nothing sent anywhere and the signed transaction travels as a file (`jurisledger submit`); a changed byte fails the signature, a replayed file fails the transaction number; browser-sealed keys use PBKDF2-HMAC-SHA256 at 600,000 iterations and every key file's cost parameters are bounded, so a crafted file cannot make opening it hang | A compromised browser or operating system on the signing machine |

| 27 | A peer sends a forged snapshot to a validator that is catching up | The snapshot is accepted only with signatures from more than two thirds of the validator set this node already trusts, and only if the restored state's digest equals the certified one; otherwise it is counted as rejected and ignored | A validator set that changed by vote after the joining node's last known state: it must first learn the new set (from blocks or a trusted operator) |
| 28 | A store is edited on disk, or two processes write it at once | The snapshot file is checked like any certificate on every start; the blocks after it are re-audited; writes are temp-file, fsync, rename; an exclusive lock refuses a second writer | An attacker who controls the machine (it can also replace the program) |
| 29 | The host of restricted contract texts is breached, subpoenaed or curious | Texts are stored encrypted (AES-256-GCM) with the key split 3-of-5 (Shamir) among independent custodians, each piece encrypted to its custodian; a custodian releases only to an authorised reader with an unspent VIEW receipt on the ledger, encrypted to that reader, journalled to disk first; every piece is checked against public Feldman commitments; custodians are replaced and the threshold changed by verifiable proactive re-sharing without the key being rebuilt | Three custodians colluding; retired custodians who did not erase their old pieces; a reader who has the text sharing it further |

| 30 | Anyone sends malformed frames to a validator's public port (audit F01) | Strict transaction parsing (`MalformedTransaction`); a per-message fault boundary in the event loop; bounded mempool (20,000), future-height buffer (64 heights × 512) and client frame size (1 MiB) | Volumetric flooding of the listener (network layer) |
| 31 | An honest validator restarts mid-height and signs again (audit F02) | Durable signing journal (`store/sign_state.json`): a signature is issued only for a strictly later height/round/step, written with fsync before it leaves; the precommit lock is restored; an unreadable journal stops the validator | Two processes on two machines with copies of the same key and journal: the journal is per machine. Never run a key twice |
| 32 | A key-change record from another network completes a contract's signatures (audit F03) | Evidence verifiers (Python and browser) accept key changes only from the bundle's own network, count signatures per party by the height the key was held, and refuse bundles in which two parties resolve to one key | Validators shared between networks still certify both; the `chain_id` binding is what separates them |
| 33 | An unsolicited confidential payment freezes the recipient's hidden balance (audit H1) | Protocol 2: incoming hidden payments wait in an inbox until the recipient accepts (it can open them) or refuses (they return to the payer) | Protocol-1 ledgers keep the old rule: their state roots cannot change. Start new networks at protocol 2 (`jurisledger init` does) |
| 34 | A recovery completes on authority that was withdrawn (audit H3) | Protocol 2: finalisation re-counts issuers that are still accredited and still attest the account; a revocation also withdraws the issuer's request | Protocol-1 ledgers keep the old rule |
| 35 | A second arbitral award worsens the terms (audit H9) | Protocol 2: limits apply to the effective terms after earlier awards; a waiver cannot be reinstated | Protocol-1 ledgers keep the old rule |
| 36 | A damaged custodian journal lets a receipt be spent twice (audit H4) | Hash-chained journal lines; any damaged complete line stops the custodian (`VaultJournalCorrupt`); only a torn last line is cut | Deleting the *last* lines of a journal is not detectable from the journal alone; back journals up off-machine |
| 37 | A crafted key file exhausts memory or CPU (audit H5) | Every key-derivation parameter is type-checked and bounded (scrypt N, r, p and 128·N·r ≤ 256 MiB; PBKDF2 iterations) before any derivation | None known |
| 38 | Published statistics leak whether one firm exists (audit H6) | Suppression on a noisy count; integer (discrete Laplace) noise from the operating system's generator; budget split by composition | Seeded releases are reproducible and NOT private; the privacy unit is a firm, not a transaction |
| 39 | A query over pruned history looks complete (audit H8) | `HistoryPruned` is raised for ranges that start inside pruned history | Callers that opt in with `partial_ok=True` must say so to their users |
| 40 | Data shown in a browser is mistaken for verified data, or carries script (audit H12, H13) | Every dynamic `innerHTML` goes through the escaping `html` template (checked by a test); a Content Security Policy built from script hashes; typed API input; paging past the 5,000-row cap; a trust line on the dashboard | A hostile API can still show wrong numbers labelled as unverified API data |

## Trust boundaries (0.26)

```
 genesis.json  (trust anchor you obtain out of band)  ── fingerprint printed by `jurisledger audit`
      │
      ├─► validator set ──► certificates on blocks, snapshots, evidence files
      │                         ▲
      │                         │ only these may vouch; a file never names its own certifiers
      │
 your key ──► sign_state.json (what you have signed)    anchor.json (signed by your key)
                                                        ▲
 an API, a dropped file, a peer ────────────────────────┘ untrusted input: parsed strictly,
                                                          rendered as text, labelled "not verified"
```

## Pruning and history

Pruning keeps validators' disks bounded, but a legal ledger must keep its history somewhere. Pruned blocks go to `store/archive/` by default, and the archived blocks plus the current store replay to exactly the same state (tested). A validator that joins by snapshot has no history before the snapshot: it can validate new blocks but cannot produce evidence files for older contracts. Deployments should run at least one archive node without pruning.

## Invariant fuzzing

`jurisledger fuzz` (and every CI run, 25,000 transactions) throws seeded random mixtures of honest, malformed and hostile transactions at the state machine and checks eight properties after each one: money conserved (I1), no negative balance (I2), a refused transaction changes nothing (I3), an accepted one advances its sender's number by exactly one (I4), forgeries, other ledgers' transactions, replays, future numbers, unregistered senders, overspending, outsiders signing, the wrong arbitrator and debt-raising awards are always refused (I5), a contract is active exactly when every party signed its text (I6), replaying the accepted transactions reproduces the same state (I7), and a snapshot restores to the same state (I8). A campaign of 150,000 transactions found no violation. Two tests plant bugs on purpose (a payment that credits one cent too many; a refusal that still bumps the sender's number) and require the fuzzer to catch them, so a silent oracle cannot pass unnoticed. Floats never reach the state machine: canonical encoding refuses to sign them.

## Known gaps

- **Transport.** Connections are TLS 1.3; a validator's certificate is self-signed by its own Ed25519 key and checked by pinning against the genesis, so no certificate authority is involved and a stolen hostname gains nothing. Peers prove key possession by signing a per-connection challenge inside the tunnel; only proven peers may send consensus or block-sync frames, and a peer may only relay under its own index. Inbound connections are capped at 256 and each source address may open at most 60 connections per 10 seconds. Still missing: any defence against volumetric flooding of the listener itself, which is a network-layer job.
- **Snapshot trust anchor.** `Chain.load` checks a snapshot against the *genesis* validators by default. After governance has changed the validator set, a store needs an external anchor (0.26: `--trust-validators`, a signed `anchor.json`, or `archive/`); `jurisledger audit FILE --genesis G` checks an export against a founding record you trust. Without `--genesis`, an audit proves self-consistency only.
- **Protocol versions.** The audited rules (claim-based confidential crediting, recovery re-checks, award limits on effective terms) apply from `protocol_version: 2` in genesis. Existing protocol-1 ledgers keep their rules because changing them would change historical state roots; migrating means starting a new ledger (or a future, explicitly voted upgrade height).
- **Empty blocks.** An idle proposer waits two seconds and then proposes an empty block, so a quiet ledger still grows. Acceptable for a public register; tune `IDLE_BLOCK_SECONDS` or add a proper idle mode for low-volume deployments.
- **The one-third bound is a hard limit.** Two colluding validators out of four fork even the two-phase protocol. What remains is accountability: the conflicting signatures are evidence. Choosing validators so that no single interest controls a third of the seats is therefore a governance requirement, not a detail.
- **No fees.** Spam is bounded by the per-account block quota, the unverified-payment cap and network rate limits rather than by fees.
- **Validator and issuer keys** change only through governance votes (remove the old key, add the new); there is no in-place rotation for them.
- **Timestamps.** Blocks now carry the proposer's clock and each vote endorses it; validators refuse a header more than five minutes from their own clock. A finalised timestamp is therefore within tolerance of an honest clock, not exact. Fine for due dates measured in blocks or hours; not for microsecond ordering.
- **Long-range history rewriting by retired validators** is not addressed; standard mitigations are checkpoints and unbonding periods.

## Why "limited action" is the core idea

A central operator's power is general: it can do anything to the database. An JurisLedger validator's power is a short list — order valid transactions, vote, propose changes to the validator set — and every item is either checked by all other validators before it takes effect or provable after the fact. The adversarial experiments exist to keep that list honest: each new capability added to the protocol should arrive with an attack that tries to abuse it.
