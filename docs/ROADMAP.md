# Roadmap

| Phase | Goal | Done when |
|---|---|---|
| 0 (this release) | Single-process prototype, eight experiments, threat model | `python -m jurisledger all` and `python -m pytest` pass |
| 1 (protocol done in 0.4) | Two-phase Byzantine-fault-tolerant consensus over an adversarial message scheduler. Remaining: drive real blocks through it | The `asynchrony` experiment passes (done); the `attacks` experiment passes with `Network` replaced by the two-phase protocol (to do) |
| 2 | Real networking: nodes as processes, gossip, persistent block store | Four nodes on four machines finalise blocks; one is killed and rejoins |
| 3 | Identity: credential attestations from several independent issuers, key rotation and recovery | Sybil experiment: cost of creating `k` fake firms is measured, not assumed |
| 4 | Confidential amounts with range proofs; GDP computed over commitments | The `gdp` experiment passes with no plaintext amounts on-chain |
| 5 | Threshold-encrypted contract vault | A host that leaks ciphertext leaks nothing |
| 6 | Pilot on synthetic data from a real national-accounts framework (supply–use tables) | Published tables are reproduced from a generated ledger |
| 7 | Legal and governance review with practitioners | Written opinions on evidentiary status and data-protection compatibility |

Non-goals: a cryptocurrency, a token sale, or replacing courts. The ledger records agreements; people and institutions still interpret and enforce them.
