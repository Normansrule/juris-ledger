# Experiments

Each experiment is a function in [`jurisledger/experiments.py`](../jurisledger/experiments.py) returning a list of `(claim, passed)` pairs. `python -m jurisledger <name>` prints them; `tests/test_experiments.py` asserts them. Results below are from seed 7 and are reproducible bit-for-bit.

## 1. `gdp` — can national accounts be read off the ledger?

**Hypothesis.** If payment purposes are validated at entry, GDP by expenditure and by production computed from the chain equal each other and equal the simulator's independent books.

**Method.** 24 households, 16 firms in 4 sectors, a government, a rest-of-world account, 6 periods, 1,144 payments, 4 validators. The simulator tallies C, I, G, X and M as it generates activity; `stats.gdp` sees only finalised blocks.

**Result.** All three approaches and the ground truth: 2,196,332.41. Discrepancy zero in every period. An exported chain re-verifies from genesis.

**Counter-result.** With 10 % and 30 % of goods purchases paid off-ledger, the ledger captures 95.8 % and 87.3 % of true GDP.

**Does not show.** That real economies can be tagged this cleanly, or that survey error is as large as the stylised comparison prints (small population).

## 2. `contracts` — signed, referenced, receipted

**Hypothesis.** A contract can be bound to its exact text, its parties, its sources and its readers without putting the text on the ledger.

**Result.** Eleven claims pass: draft/active lifecycle; signing a different text is rejected; altered prose is refused by the vault; reads need an on-chain receipt; non-parties cannot access restricted contracts until granted; payments under a contract are logged as uses; a renegotiated schedule supersedes the old one, which can no longer be paid under but is never deleted; the provenance tree reaches the cited statute.

**Does not show.** That a court would accept it. That is a question of law in each jurisdiction, not of code.

## 2b. `legal` — obligations and evidence files

**Hypothesis.** Performance of a contract can be established from public data alone, and the whole record of one contract can be handed to an outsider who verifies it without access to the network.

**Method.** A lease with three instalments due at blocks 4, 6 and 8. The first is paid early, the second in two parts finishing one block late, the third never. The counterparty then tries to "pay" the debtor's obligation itself. The evidence file is serialised to JSON, read back, and attacked four ways.

**Result.** Ten claims pass: PAID, PAID_LATE and OVERDUE are assigned correctly; the position as of block 5 is reconstructed as PARTIAL and PENDING; the wrong-party payment is rejected. The 12-kilobyte evidence file verifies offline; an edited amount, a swapped contract text, a certificate stripped below quorum, and an unrecognised validator set are each rejected.

**Does not show.** That a tribunal would admit the file, or that nothing relevant was left out of it: omission cannot be detected from the file alone.

## 2c. `disputes` — arbitration with narrow powers

**Hypothesis.** A dispute process can live on the ledger without creating a new authority: the referee's powers can be listed, and each one tested.

**Method.** A restricted lease names an independent arbitrator. The debtor misses an instalment; the creditor opens a dispute; the debtor files a defence. Then an outsider, a party and the arbitrator each try to overstep.

**Result.** Thirteen claims pass. Rejected: an outsider's claim, a party deciding its own case, an award that doubles the debt, an award touching an undisputed obligation, and a second award. Accepted: a receipted read of the restricted text by the arbitrator, and an award reducing the instalment from 500.00 to 400.00 with a later due block, which the debtor then pays on time. The arbitrator's balance never changes. Status history reads OVERDUE, then DISPUTED, then PAID; the claim, defence and award all appear in the offline-verified evidence file.

**Does not show.** Enforcement against a debtor who ignores the award (by design that is a court's job), or appeals and challenges to the arbitrator.

## 2d. `identity` — identity without a gatekeeper, and keys that can be lost

**Hypothesis.** A public ledger can resist fake identities without a single registrar, and let people lose keys without losing accounts, while giving no issuer the power to seize an account.

**Method.** Three issuers, policy "two independent attestations; unverified accounts capped at 100.00; recovery waits 3 blocks". Twenty fake firms helped by one corrupt issuer; an impostor issuer; revocation; validators voting an issuer out; a party rotating its key in the middle of a contract; a genuine lost-key recovery; a hostile recovery by two colluding issuers.

**Result.** Eleven claims pass. The fake firms register but cannot sign or exceed the cap. Removing the corrupt issuer un-verifies everyone who depended on it, at once. After rotation the old key is dead, the contract and its obligation follow the new key, and the offline evidence file still reports "fully signed" by following the proven key change. Recovery works only after the waiting period; the hostile attempt is vetoed by the owner.

**Does not show.** That issuers verify people properly, or what happens when *k* issuers collude against someone who is not watching.

## 3. `attacks` — what each adversary achieves

Fourteen claims, lettered in the source: (a) history tampering, (b) forged payment by a proposer, (c, d) replay, double spend, cross-network replay, (e) role abuse of statistics tags, (f) equivocation and removal, (g) censorship delay, (h) one and two crash faults out of four, (i) minority finalisation, (j) light-client inclusion proof.

**Most informative result.** With two of four validators silent, the chain halts and nothing is finalised. The design prefers stopping to guessing.

## 3b. `asynchrony` — consensus on a hostile network

**Hypothesis.** Single-phase voting, as used by the prototype's chain, is unsafe once messages can be delayed; adding a second phase with locking (Tendermint) repairs it.

**Method.** A message-level simulator in which honest validators gossip every signed message and an adversary may delay any message but never forge or drop one. The scripted adversary (a) cuts validator 1 off during round 0, (b) lets round-0 finalising messages reach only validator 0, and (c) cuts validator 0 off once it decides. The same three rules are applied to both protocols. Then 1,000 random delay schedules per protocol with one validator that lies differently to everyone, and finally two coordinated liars out of four.

**Result.** Single-phase: validator 0 finalises block A, the other three finalise block B — a fork with no dishonest participant. Two-phase: validators 2 and 3 lock on A in round 0, refuse validator 1's block B in round 1, and everyone finalises A in round 2. Random schedules: single-phase forks in 12 of 1,000; two-phase forks in none and always finalises. Two colluders: two-phase forks, and both honest validators can prove which two validators signed conflicting votes.

**Does not show.** A real network stack, or the two-phase protocol driving the actual chain (values here are opaque identifiers). Timers are simplified; the liveness numbers mean "terminates in this model", not a performance claim.

## 3c. `integration` — the real ledger on two-phase consensus

**Hypothesis.** The protocol proven on placeholders in `asynchrony` can carry real blocks without weakening any earlier claim.

**Method.** `ledgernet.py`: proposals carry blocks; validators prevote only for blocks that execute cleanly; every message is signed; the quorum of signed precommits is stored as the certificate together with the round it was cast in. The partition adversary is pointed at block 1 of a real ledger under both protocols. Then all 48 contract, legal, dispute and attack claims are re-run on the new network, a forged vote is injected, a validator is cut off for three blocks, and the full synthetic economy runs under random delays with a validator that equivocates whenever it proposes.

**Result.** Nine claims pass. Under single-phase voting two different block 1s exist, each with a valid certificate, each passing a full audit — the failure is invisible to anyone holding only one of them. Under two-phase voting there is one block 1, proposed in round 0 and finalised in round 2. All 48 earlier claims hold. The forged vote is dropped; the cut-off validator catches up by verifying certificates; the economy's GDP still equals ground truth to the cent and the equivocating validator loses its seat.

**Does not show.** Behaviour over real sockets, or any latency figure.

## 3d. `cluster` — four processes over TCP (not in `all`; run `jurisledger cluster` or `tests/test_net.py`)

**Hypothesis.** The protocol survives real process boundaries, sockets and a crash.

**Method.** Four validator processes on one machine, each with its own key file, port and on-disk store. Three transactions are submitted through three different validators. One process is killed; the others continue; it is restarted from its store and asked to catch up.

**Result.** Block 1 finalises; all three transactions are in the exported, locally re-audited chain; all four nodes hold the same state digest; three nodes keep finalising after the kill; the restarted node reports "caught up: blocks 5-8 received from a peer, every certificate re-verified" and matches the others. About 30 seconds on a laptop.

**Does not show.** Behaviour across real network distances, under packet loss, or under TLS.

## 4. `fraud` — four injected frauds

| Injected | Detector | Found | Note |
|---|---|---|---|
| Three firms pass 250,000 around a ring | `circular_flows` | yes, ranked first by size | |
| Six deposits of 9,400–9,650 under a 10,000 threshold | `structuring` | yes | also catches the Benford fabricator, whose invented amounts sit in the same band |
| Eighty invoices with uniformly random amounts | `benford` | yes (chi-square 21.9 against a critical value of 20.09) | marginal: the test needs volume |
| One receivable financed by two banks | `duplicate_invoice_financing` | yes | trivial on a shared ledger, close to impossible without one |

**False positives.** Five two-party "rings" are flagged in the clean economy: ordinary firms that happened to trade similar amounts in both directions. Flags are leads for a human, never verdicts.

## 5. `privacy` — hidden amounts, provable totals

**Result.** The product of ten Pedersen commitments opens to the true total and rejects a false one. Differentially private sector totals for sixty firms have a mean error of about 257 %, 52 % and 10 % of an average sector total at ε = 0.2, 1 and 5.

**Reading.** Commitments work; differential privacy at this population size does not. Noise scales with one firm's maximum contribution, not with the economy, so the same mechanism is negligible noise over millions of firms and useless over dozens.

---

## Ideas not yet tried

Each is a candidate experiment: state the claim, write the attack, keep the result whichever way it goes.

0. **Awards that increase a debt, safely.** Damages, interest and costs up to a cap the parties pre-agree in the contract; three-member tribunals deciding by majority; a challenge procedure for a conflicted arbitrator.
1. **Counter-signed purposes.** Require the payee to co-sign the purpose tag. Does it cut plausible mis-tagging, and what does it cost in friction?
2. **Validator composition.** Simulate validator sets drawn from interest groups (state, banks, civil society). Which seat allocations keep every single interest under one third?
3. **Multi-machine run.** `jurisledger node` on four hosts with TLS between them; measure block latency and catch-up time honestly.
4. **Threshold-encrypted vault.** Prose encrypted; decryption shares released by validators only against a finalised receipt.
5. **Range proofs.** Add Bulletproofs so committed amounts are provably non-negative, then compute GDP over commitments.
6. **Selective disclosure for audits.** A firm proves to an auditor that its committed payments sum to its declared revenue without opening them.
7. **Hybrid statistics.** Combine exact on-ledger totals with a survey of the off-ledger remainder; measure the total error against either source alone.
8. **Input–output tables.** Sector-by-sector intermediate flows fall straight out of the ledger; build the table and test it against the simulator.
9. **Real-time indicators.** Weekly GDP "nowcasts" by block range, with seasonal patterns injected into the simulator.
10. **Graph-based fraud scoring.** Replace the fixed tolerance in `circular_flows` with a score that weighs ring size against each firm's normal trade, to cut false positives.
