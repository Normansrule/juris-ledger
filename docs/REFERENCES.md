# References

An annotated list: each entry says what JurisLedger took from the source. Entries are limited to works whose bibliographic details the author could state with confidence; verify before citing in formal work.

## Ledgers and timestamping

1. Haber, S., & Stornetta, W. S. (1991). How to time-stamp a digital document. *Journal of Cryptology*, 3(2), 99–111. — Hash-linked records that cannot be back-dated; the ancestor of every blockchain.
2. Merkle, R. C. (1988). A digital signature based on a conventional encryption function. *Advances in Cryptology — CRYPTO '87*. — Merkle trees; `crypto.merkle_root` and inclusion proofs.
3. Nakamoto, S. (2008). *Bitcoin: A peer-to-peer electronic cash system.* — The hash chain plus open consensus. JurisLedger keeps the chain and replaces proof of work.
4. Buterin, V. (2014). *Ethereum white paper: A next-generation smart contract and decentralized application platform.* — Account model with nonces; general state machines on a chain.
5. Androulaki, E., et al. (2018). Hyperledger Fabric: A distributed operating system for permissioned blockchains. *EuroSys '18*. — Permissioned ledgers among identified organisations.
6. Narayanan, A., Bonneau, J., Felten, E., Miller, A., & Goldfeder, S. (2016). *Bitcoin and Cryptocurrency Technologies.* Princeton University Press. — General background.
7. Laurie, B., Langley, A., & Kasper, E. (2013). *RFC 6962: Certificate Transparency.* — Leaf/node domain separation in Merkle trees; public, append-only logs as an accountability tool.

## Consensus and fault tolerance

8. Lamport, L., Shostak, R., & Pease, M. (1982). The Byzantine generals problem. *ACM Transactions on Programming Languages and Systems*, 4(3), 382–401. — Why agreement needs more than two thirds honest participants.
9. Fischer, M. J., Lynch, N. A., & Paterson, M. S. (1985). Impossibility of distributed consensus with one faulty process. *Journal of the ACM*, 32(2), 374–382. — Why liveness cannot be guaranteed under full asynchrony.
10. Dwork, C., Lynch, N., & Stockmeyer, L. (1988). Consensus in the presence of partial synchrony. *Journal of the ACM*, 35(2), 288–323. — The timing model real Byzantine-fault-tolerant protocols assume.
11. Schneider, F. B. (1990). Implementing fault-tolerant services using the state machine approach. *ACM Computing Surveys*, 22(4), 299–319. — Replicated deterministic state machines; the shape of `state.py`.
12. Castro, M., & Liskov, B. (1999). Practical Byzantine fault tolerance. *OSDI '99*. — Quorum certificates of `2f + 1` out of `3f + 1`.
13. Buchman, E., Kwon, J., & Milosevic, Z. (2018). The latest gossip on BFT consensus. *arXiv:1807.04938*. — Tendermint: rotating proposers, rounds, and the two-phase locking JurisLedger still lacks.
14. Yin, M., Malkhi, D., Reiter, M. K., Gueta, G. G., & Abraham, I. (2019). HotStuff: BFT consensus with linearity and responsiveness. *PODC '19*. — A simpler path to the same safety property.
15. Douceur, J. R. (2002). The Sybil attack. *IPTPS '02*. — Why open registration needs an identity answer.

## Cryptography

16. Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B.-Y. (2012). High-speed high-security signatures. *Journal of Cryptographic Engineering*, 2, 77–89; and Josefsson, S., & Liusvaara, I. (2017). *RFC 8032: Edwards-Curve Digital Signature Algorithm.* — Ed25519.
17. Pedersen, T. P. (1992). Non-interactive and information-theoretic secure verifiable secret sharing. *Advances in Cryptology — CRYPTO '91*. — Additively homomorphic commitments; `privacy.py`.
18. Kivinen, T., & Kojo, M. (2003). *RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups.* — The 2048-bit safe-prime group used for commitments.
19. Bünz, B., Bootle, J., Boneh, D., Poelstra, A., Wuille, P., & Maxwell, G. (2018). Bulletproofs: Short proofs for confidential transactions and more. *IEEE Symposium on Security and Privacy*. — The range proofs the prototype is missing.
20. Rundgren, A., Jordan, B., & Erdtman, S. (2020). *RFC 8785: JSON Canonicalization Scheme.* — Motivation for canonical encoding before hashing.
20a. Cramer, R., Damgård, I., & Schoenmakers, B. (1994). Proofs of partial knowledge and simplified design of witness hiding protocols. *CRYPTO '94*. — The OR-proof used per bit in the range proofs.
20b. Hisil, H., Wong, K. K.-H., Carter, G., & Dawson, E. (2008). Twisted Edwards curves revisited. *ASIACRYPT 2008*. — Extended coordinates in `ec.py`.
20c. Fiat, A., & Shamir, A. (1986). How to prove yourself: Practical solutions to identification and signature problems. *CRYPTO '86*. — Making the proofs non-interactive.

## Contracts and law

21. Grigg, I. (2004). The Ricardian contract. *Proceedings of the First IEEE International Workshop on Electronic Contracting*. — One document that is legal prose, machine-readable terms and a signed hash; the model for `contracts.py`.
22. Szabo, N. (1997). Formalizing and securing relationships on public networks. *First Monday*, 2(9). — The original "smart contracts" argument.
23. National Conference of Commissioners on Uniform State Laws (1999). *Uniform Electronic Transactions Act.* — Electronic records and signatures are not denied legal effect for being electronic.
24. United States (2000). *Electronic Signatures in Global and National Commerce Act*, 15 U.S.C. § 7001 et seq.
25. European Union (2014). *Regulation (EU) No 910/2014 on electronic identification and trust services (eIDAS).*
26. European Union (2016). *Regulation (EU) 2016/679 (General Data Protection Regulation)*, Article 17. — The erasure right that motivates keeping prose and personal data off-chain.
27. United States. 31 U.S.C. § 5324. — Structuring transactions to evade reporting requirements.
28a. United Nations (1958). *Convention on the Recognition and Enforcement of Foreign Arbitral Awards* (the New York Convention). — Why enforcement of an award is left to courts and not to the ledger.

## Economics and statistics

28. Akerlof, G. A. (1970). The market for "lemons": Quality uncertainty and the market mechanism. *Quarterly Journal of Economics*, 84(3), 488–500.
29. Spence, M. (1973). Job market signaling. *Quarterly Journal of Economics*, 87(3), 355–374.
30. Stiglitz, J. E., & Weiss, A. (1981). Credit rationing in markets with imperfect information. *American Economic Review*, 71(3), 393–410.
31. Catalini, C., & Gans, J. S. (2016). *Some simple economics of the blockchain.* NBER Working Paper 22952. — Cost of verification and cost of networking.
32. Auer, R. (2019). *Embedded supervision: How to build regulation into blockchain finance.* BIS Working Paper 811. — Supervisors reading a ledger directly instead of collecting reports.
33. United Nations, European Commission, International Monetary Fund, Organisation for Economic Co-operation and Development, & World Bank (2009). *System of National Accounts 2008.* — The definitions `stats.py` approximates.
34. Coyle, D. (2014). *GDP: A Brief but Affectionate History.* Princeton University Press. — What GDP does and does not measure.
35. Medina, L., & Schneider, F. (2018). *Shadow economies around the world: What did we learn over the last 20 years?* IMF Working Paper 18/17. — Size of off-ledger activity.

## Privacy and fraud analytics

36. Dwork, C., McSherry, F., Nissim, K., & Smith, A. (2006). Calibrating noise to sensitivity in private data analysis. *Theory of Cryptography Conference*. — The Laplace mechanism in `stats.private_sector_release`.
37. Sweeney, L. (2002). k-anonymity: A model for protecting privacy. *International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems*, 10(5), 557–570. — Small-cell suppression.
38. Nigrini, M. J. (2012). *Benford's Law: Applications for Forensic Accounting, Auditing, and Fraud Detection.* Wiley.
39. Johnson, D. B. (1975). Finding all the elementary circuits of a directed graph. *SIAM Journal on Computing*, 4(1), 77–84. — The efficient algorithm that should replace the bounded search in `fraud.circular_flows`.
