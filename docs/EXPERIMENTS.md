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

## 3. `attacks` — what each adversary achieves

Fourteen claims, lettered in the source: (a) history tampering, (b) forged payment by a proposer, (c, d) replay, double spend, cross-network replay, (e) role abuse of statistics tags, (f) equivocation and removal, (g) censorship delay, (h) one and two crash faults out of four, (i) minority finalisation, (j) light-client inclusion proof.

**Most informative result.** With two of four validators silent, the chain halts and nothing is finalised. The design prefers stopping to guessing.

## 3b. `asynchrony` — consensus on a hostile network

**Hypothesis.** Single-phase voting, as used by the prototype's chain, is unsafe once messages can be delayed; adding a second phase with locking (Tendermint) repairs it.

**Method.** A message-level simulator in which honest validators gossip every signed message and an adversary may delay any message but never forge or drop one. The scripted adversary (a) cuts validator 1 off during round 0, (b) lets round-0 finalising messages reach only validator 0, and (c) cuts validator 0 off once it decides. The same three rules are applied to both protocols. Then 1,000 random delay schedules per protocol with one validator that lies differently to everyone, and finally two coordinated liars out of four.

**Result.** Single-phase: validator 0 finalises block A, the other three finalise block B — a fork with no dishonest participant. Two-phase: validators 2 and 3 lock on A in round 0, refuse validator 1's block B in round 1, and everyone finalises A in round 2. Random schedules: single-phase forks in 12 of 1,000; two-phase forks in none and always finalises. Two colluders: two-phase forks, and both honest validators can prove which two validators signed conflicting votes.

**Does not show.** A real network stack, or the two-phase protocol driving the actual chain (values here are opaque identifiers). Timers are simplified; the liveness numbers mean "terminates in this model", not a performance claim.

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
3. **Integrate two-phase voting.** Drive `chain.py` blocks through `bft.py`'s protocol so the ledger itself, not just a model, survives the partition attack; then add validator-signed timestamps.
4. **Threshold-encrypted vault.** Prose encrypted; decryption shares released by validators only against a finalised receipt.
5. **Range proofs.** Add Bulletproofs so committed amounts are provably non-negative, then compute GDP over commitments.
6. **Selective disclosure for audits.** A firm proves to an auditor that its committed payments sum to its declared revenue without opening them.
7. **Hybrid statistics.** Combine exact on-ledger totals with a survey of the off-ledger remainder; measure the total error against either source alone.
8. **Input–output tables.** Sector-by-sector intermediate flows fall straight out of the ledger; build the table and test it against the simulator.
9. **Real-time indicators.** Weekly GDP "nowcasts" by block range, with seasonal patterns injected into the simulator.
10. **Graph-based fraud scoring.** Replace the fixed tolerance in `circular_flows` with a score that weighs ring size against each firm's normal trade, to cut false positives.
