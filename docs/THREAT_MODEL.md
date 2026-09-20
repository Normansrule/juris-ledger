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
- The simulated network is synchronous. See "Known gaps".

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
| 12 | Fake identities flood the ledger (Sybil attack) | Government and validator roles cannot be self-registered | **Not solved.** Needs credential attestations from several independent issuers |
| 13 | Analyst de-anonymises participants from public payments | Experimental commitments and differentially private releases | **Not solved.** Amounts and counterparties are public in this version |
| 14 | Someone accuses an honest validator with fabricated evidence | Evidence must contain two *valid* signatures by the accused over *different* headers at the same height and round | None |

| 15 | The arbitrator named in a contract abuses its role | It can act only on an open dispute raised by a party, once, only on obligations in dispute, and only to reduce, postpone or waive; it cannot move money; every read and decision is signed and on record | A corrupt arbitrator can wrongly waive a genuine debt. Remedy is outside the ledger: challenge the award in court, using the evidence file |

## Known gaps

- **Single-phase voting.** Over an asynchronous network with round changes, a block could gather a quorum that some validators never see, while a later round finalises a different block. Tendermint's prevote/precommit locking or HotStuff's chained quorum certificates close this. Validity and accountability rules are unaffected.
- **No fees or rate limits.** Spam resistance is out of scope.
- **No key rotation or recovery.**
- **Long-range history rewriting by retired validators** is not addressed; standard mitigations are checkpoints and unbonding periods.

## Why "limited action" is the core idea

A central operator's power is general: it can do anything to the database. An JurisLedger validator's power is a short list — order valid transactions, vote, propose changes to the validator set — and every item is either checked by all other validators before it takes effect or provable after the fact. The adversarial experiments exist to keep that list honest: each new capability added to the protocol should arrive with an attack that tries to abuse it.
