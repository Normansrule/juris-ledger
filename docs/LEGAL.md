# Legal design notes

Written by an engineer for discussion with lawyers. **Not legal advice.** Each section ends with the question a practitioner should press on.

## 1. What a contract is on JurisLedger

| Legal concept | How JurisLedger represents it | Code |
|---|---|---|
| The written agreement | Human-readable prose, stored off the ledger; its SHA-256 hash is on the ledger | `contracts.prose_hash`, `ContractVault` |
| Offer and acceptance | `CONTRACT_CREATE` by one party; `CONTRACT_SIGN` by each other party over the *same hash*. The contract is `ACTIVE` only when every named party has signed | `State._contract_sign` |
| Signature | Ed25519 signature by a key the party controls, over bytes that include the network identifier, a replay counter and the prose hash | `tx.py` |
| Incorporation by reference | Typed references (`cites`, `implements`, `amends`, `supersedes`) to other contracts or to any outside document by hash | `contracts.cite`, `cite_external` |
| Variation / novation | A new contract signed by at least the same parties that cites the old one as `supersedes`. The old one becomes `SUPERSEDED` and stays on record | `State._maybe_activate` |
| Payment obligations | Machine-readable `obligations` in the terms: payer, payee, amount, due block | `legal.obligation`, `State._check_obligations` |
| Performance and breach | Payments name the obligation they discharge; status is computed from public data for any date | `legal.compliance` |
| Dispute resolution | An arbitration clause in the terms names an arbitrator who is not a party. Claims, filings (by hash) and the award are transactions. The award can only reduce, postpone or waive disputed obligations | `State._dispute_award`, `legal.dispute_record` |
| Notice and knowledge | Signed, finalised `CONTRACT_ACCESS` receipts: a party cannot later deny having opened the text | `ContractVault.read` |
| Confidentiality | `restricted` contracts: only parties and explicit grantees can obtain a receipt, and the vault serves text only against a receipt | `State.can_read` |
| Evidence | One file with every relevant transaction, Merkle path and validator certificate, verifiable offline | `legal.evidence_bundle` |

*Press on:* is a signature by a key "the party controls" attributable to the party? That is an identity and key-custody question the prototype does not answer (threat model, item 12).

## 2. Why electronic form is not the obstacle

The United States Uniform Electronic Transactions Act (UETA, 1999) and Electronic Signatures in Global and National Commerce Act (ESIGN, 2000) provide that a record or signature may not be denied legal effect solely because it is electronic. The European Union's Regulation 910/2014 on electronic identification and trust services (eIDAS) does the same and defines tiers of signature; the higher tiers require identity verification by a qualified provider, which JurisLedger does not perform. Several United States states have also legislated specifically on blockchain records.

*Press on:* which signature tier does a given use need, and which categories of document (wills, some property and family-law instruments) are excluded from these statutes altogether?

## 3. What the evidence file does and does not prove

Proves, to anyone holding the validators' public keys:

- each enclosed transaction was signed by the stated key and has not been altered;
- each was finalised by more than two thirds of the validators, at a stated block height;
- every named party signed the same prose hash, and the enclosed text (if any) matches it;
- the order of events.

Does not prove:

- **completeness** — a file can omit a later superseding contract or a payment. Ask a full node, or require the file to be produced by a neutral one;
- **wall-clock time** — blocks have heights, not timestamps, in version 0.3. A deployment would bind heights to time through validator-signed timestamps;
- **who was holding the key**, or that they had capacity and authority;
- **what the words mean.** The ledger records agreements; interpretation stays with people.

*Press on:* authentication and hearsay rules for machine-generated records in the relevant forum, and whether the parties should agree in the contract itself that the ledger record is evidence of payment (the sample lease in `experiments.py` does exactly this in clause 3).

## 4. Data protection

A ledger that never forgets conflicts with erasure rights such as Article 17 of the European Union General Data Protection Regulation (GDPR). JurisLedger's position: keep prose and personal data off-chain, keep hashes and pseudonymous keys on-chain, and let a vault delete text on lawful request — the hash remains and reveals nothing by itself if the text had enough entropy. Short or guessable texts should be salted before hashing (roadmap).

*Press on:* regulators have not uniformly accepted that a hash of personal data is not personal data.

## 5. Arbitration on the ledger

The design follows ordinary arbitration practice in three respects: jurisdiction comes from the parties' agreement (the clause is inside the signed contract), the tribunal acts only on a claim, and the award is final for that dispute. It departs from it in one: the ledger gives the arbitrator **no enforcement power at all**. An award changes what the record says is owed; it never transfers funds. Enforcement stays where the law puts it — for international awards, recognition by national courts under the 1958 New York Convention.

The one-directional limit (an award cannot increase a debt) is a prototype safety choice, not a legal principle: real tribunals award damages, interest and costs. Supporting that safely needs a cap the parties pre-agree in the contract (roadmap).

*Press on:* is an on-ledger award "in writing and signed" for the purposes of the applicable arbitration statute, and was the clause validly agreed by a consumer?

## 6. Deliberate non-features

- **No self-executing penalties.** The ledger reports `OVERDUE`; it does not seize funds. Automatic enforcement removes the judgment that contract law builds in (waiver, force majeure, set-off, mistake).
- **No deletion, even by agreement.** Supersede instead.
- **No anonymous parties.** Every party is a registered account; pseudonymity toward the public is a privacy goal, anonymity toward the counterparty is not.
