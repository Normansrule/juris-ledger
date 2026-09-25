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
| 13 | Analyst de-anonymises participants from public payments | Experimental commitments and differentially private releases | **Not solved.** Amounts and counterparties are public in this version |
| 14 | Someone accuses an honest validator with fabricated evidence | Evidence must contain two *valid* signatures by the accused over *different* headers at the same height and round | None |

| 15 | The arbitrator named in a contract abuses its role | It can act only on an open dispute raised by a party, once, only on obligations in dispute, and only to reduce, postpone or waive; it cannot move money; every read and decision is signed and on record | A corrupt arbitrator can wrongly waive a genuine debt. Remedy is outside the ledger: challenge the award in court, using the evidence file |

| 16 | Key theft or loss | Owner rotates the key at once (`KEY_ROTATE`); a lost key is recovered by the issuers that attested the account, after a waiting period during which the current key can veto; contracts, obligations and evidence files follow the new key; the old key can never sign again | A thief who acts before the owner rotates. *k* colluding issuers against an owner who does not look for the whole veto window |
| 20 | An attacker on the network impersonates a validator or eavesdrops | TLS 1.3 with the certificate pinned to the validator key; signed challenge before any consensus frame is accepted | Denial of service by flooding; no per-source rate limit yet |
| 17 | A forged or unsigned consensus vote | Every proposal, prevote and precommit is signed and verified on receipt; announcements of finality are accepted only with a verifiable certificate | None within assumptions |
| 19 | A validator crashes mid-consensus | It restarts from its store, asks a peer for the blocks it missed, re-verifies each certificate, and rejoins at the current height; the others never stopped (they are a quorum) | Two of four crashing halts the chain until one returns — by design |
| 18 | The block file is edited on disk, or power fails mid-write | The store re-audits every block when opened; a torn final line is detected and cut off; a block is acknowledged only after it is flushed to disk | Loss of the whole disk: keep replicas (every validator is one) |

## Known gaps

- **Transport.** Connections are TLS 1.3; a validator's certificate is self-signed by its own Ed25519 key and checked by pinning against the genesis, so no certificate authority is involved and a stolen hostname gains nothing. Peers prove key possession by signing a per-connection challenge inside the tunnel; only proven peers may send consensus or block-sync frames, and a peer may only relay under its own index. Inbound connections are capped at 256. Still missing: rate limiting by source address and any defence against volumetric flooding of the listener itself.
- **Empty blocks.** An idle proposer waits two seconds and then proposes an empty block, so a quiet ledger still grows. Acceptable for a public register; tune `IDLE_BLOCK_SECONDS` or add a proper idle mode for low-volume deployments.
- **The one-third bound is a hard limit.** Two colluding validators out of four fork even the two-phase protocol. What remains is accountability: the conflicting signatures are evidence. Choosing validators so that no single interest controls a third of the seats is therefore a governance requirement, not a detail.
- **No fees or rate limits.** Spam resistance is out of scope.
- **Validator and issuer keys** change only through governance votes (remove the old key, add the new); there is no in-place rotation for them.
- **Timestamps.** Blocks now carry the proposer's clock and each vote endorses it; validators refuse a header more than five minutes from their own clock. A finalised timestamp is therefore within tolerance of an honest clock, not exact. Fine for due dates measured in blocks or hours; not for microsecond ordering.
- **Long-range history rewriting by retired validators** is not addressed; standard mitigations are checkpoints and unbonding periods.

## Why "limited action" is the core idea

A central operator's power is general: it can do anything to the database. An JurisLedger validator's power is a short list — order valid transactions, vote, propose changes to the validator set — and every item is either checked by all other validators before it takes effect or provable after the fact. The adversarial experiments exist to keep that list honest: each new capability added to the protocol should arrive with an attack that tries to abuse it.
