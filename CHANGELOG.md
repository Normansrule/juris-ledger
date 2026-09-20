# Changelog

## 0.4.0
- `bft.py`: message-level consensus laboratory. Single-phase voting forks under a delaying adversary with four honest validators; Tendermint-style two-phase voting with locks survives the same adversary and 1,000 random schedules with a lying validator. Two colluders of four fork it, and are provably guilty.
- New experiment `asynchrony` (8 claims) and `tests/test_bft.py`. Totals: 8 experiments, 70 claims, 109 tests.

## 0.3.0
- Arbitration: `DISPUTE_OPEN`, `DISPUTE_FILE`, `DISPUTE_WITHDRAW`, `DISPUTE_AWARD`; awards can only reduce, postpone or waive disputed obligations. `DISPUTED` and `WAIVED` compliance states. Experiment `disputes`.

## 0.2.0
- Machine-readable payment obligations, `legal.compliance`, offline-verifiable evidence files. Experiment `legal`. Project renamed from its working titles to JurisLedger.

## 0.1.0
- Ledger, quorum certificates, Ricardian contracts with access receipts, national accounts from the ledger, fraud detectors, Pedersen commitments, adversarial experiments.
