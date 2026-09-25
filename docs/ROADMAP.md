# Roadmap

| Phase | Goal | Done when |
|---|---|---|
| 0 (this release) | Single-process prototype, ten experiments, threat model | `python -m jurisledger all` and `python -m pytest` pass |
| 1 (done in 0.5) | Two-phase Byzantine-fault-tolerant consensus over an adversarial message scheduler, driving real blocks with signed votes | `asynchrony` and `integration` pass; all earlier claims hold on the new network |
| 2 (done in 0.7) | Nodes as processes over TLS with pinned keys, authenticated peers, connection cap, durable stores. Remaining: rate limiting, peer discovery | `jurisledger cluster` passes: four processes finalise, one is killed and rejoins from its store (done); the same across four machines with TLS (to do) |
| 3 (framework done in 0.5) | Identity: attestations from several independent issuers, key rotation and recovery. Remaining: real credential formats, issuer liability rules | `identity` passes (done); a pilot issuer integrates a real credential check (to do) |
| 4 | Confidential amounts with range proofs; GDP computed over commitments | The `gdp` experiment passes with no plaintext amounts on-chain |
| 5 | Threshold-encrypted contract vault | A host that leaks ciphertext leaks nothing |
| 6 | Pilot on synthetic data from a real national-accounts framework (supply–use tables) | Published tables are reproduced from a generated ledger |
| 7 | Legal and governance review with practitioners | Written opinions on evidentiary status and data-protection compatibility |

Non-goals: a cryptocurrency, a token sale, or replacing courts. The ledger records agreements; people and institutions still interpret and enforce them.
