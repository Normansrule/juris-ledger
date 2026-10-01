"""Invariant fuzzing of the state machine.

Unit tests check the cases someone thought of.  This throws seeded random sequences of
transactions at ``State.apply`` -- honest ones, malformed ones and deliberate attacks mixed
together -- and after every single one checks properties that must hold whatever happens:

  I1  money is conserved: public balances always sum to what genesis created
  I2  no balance is ever negative
  I3  a rejected transaction changes nothing (the state root is identical before and after)
  I4  an accepted transaction moves its sender's transaction number up by exactly one
  I5  attacks are always refused: forged signatures, other ledgers' transactions, replays,
      wrong numbers, non-integer or non-positive amounts, overspending, outsiders signing
      contracts, the wrong arbitrator deciding, awards that raise a debt
  I6  a contract is active exactly when every party has signed the text it was written with
  I7  replaying every accepted transaction into a fresh state reproduces the same root
      (determinism: what every validator relies on)
  I8  a snapshot restores to the same root

    jurisledger fuzz                        # 20 seeds x 400 transactions
    jurisledger fuzz --runs 200 --steps 1000

A failure prints the seed, the step, the transaction and the broken invariant, so it can be
replayed exactly with --seed.
"""
from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import legal
from . import state as S
from . import tx as T
from .contracts import Wallet
from .crypto import KeyPair

NAMES = [("alice", S.HOUSEHOLD, ""), ("bob", S.HOUSEHOLD, ""), ("bakery", S.FIRM, "services"),
         ("mill", S.FIRM, "manufacturing"), ("farm", S.FIRM, "agriculture"), ("treasury", S.GOVERNMENT, ""),
         ("importer", S.FOREIGN, ""), ("bank", S.BANK, ""), ("arbiter", S.FIRM, "services")]
PURPOSES = [S.FINAL_CONSUMPTION, S.INTERMEDIATE, S.INVESTMENT, S.GOVERNMENT_PURCHASE, S.EXPORT, S.WAGES,
            S.TAX, S.TRANSFER, S.FINANCIAL, "BRIBE"]
PROSE = ["LEASE\nThe tenant pays rent each period.", "SUPPLY\nThe supplier delivers grain.", "LOAN\nThe bank lends."]


class InvariantBroken(AssertionError):
    pass


@dataclass
class Report:
    runs: int = 0
    steps: int = 0
    accepted: int = 0
    rejected: int = 0
    attacks_refused: int = 0
    by_kind: Dict[str, List[int]] = field(default_factory=dict)      # kind -> [accepted, rejected]

    def add(self, kind: str, ok: bool) -> None:
        self.by_kind.setdefault(kind, [0, 0])[0 if ok else 1] += 1


class Fuzzer:
    def __init__(self, seed: int, chain_id: str = "fuzz"):
        self.rng, self.chain_id = random.Random(seed), chain_id
        self.keys = {n: KeyPair.from_seed(f"fuzz/{n}") for n, _, _ in NAMES}
        self.genesis = {"chain_id": chain_id, "validators": [KeyPair.from_seed(f"fuzz/v{i}").address for i in range(4)],
                        "accounts": [{"address": self.keys[n].address, "name": n, "role": r, "sector": s,
                                      "balance": self.rng.randint(0, 50_000_00)} for n, r, s in NAMES]}
        self.state = S.State.from_genesis(self.genesis)
        self.total = sum(a["balance"] for a in self.genesis["accounts"])
        self.height, self.accepted_log, self.accepted_heights = 1, [], []
        self.contracts: List[Tuple[str, str]] = []                    # (contract id, prose)
        self.disputes: List[Tuple[str, str]] = []                     # (contract id, dispute id)

    # ---------------------------------------------------------------- helpers
    def w(self, name: str, nonce_shift: int = 0) -> Wallet:
        k = self.keys[name]
        return Wallet(k, self.chain_id, self.state.accounts[k.address]["nonce"] + nonce_shift)

    def who(self) -> str:
        return self.rng.choice([n for n, _, _ in NAMES])

    def amount(self) -> Any:
        r = self.rng.random()
        if r < 0.80:
            return self.rng.randint(1, 20_000_00)
        return self.rng.choice([0, -5, "100", True, None, 10 ** 30])      # floats cannot even be signed: canonical() refuses them

    # ---------------------------------------------------------------- generators: (tx, must_be_refused)
    SENSIBLE = [("alice", "bakery", S.FINAL_CONSUMPTION), ("bob", "farm", S.FINAL_CONSUMPTION), ("bakery", "mill", S.INTERMEDIATE),
                ("mill", "farm", S.INTERMEDIATE), ("treasury", "bakery", S.GOVERNMENT_PURCHASE), ("bakery", "alice", S.WAGES),
                ("alice", "treasury", S.TAX), ("importer", "farm", S.EXPORT), ("bank", "mill", S.FINANCIAL),
                ("mill", "bank", S.INVESTMENT), ("treasury", "bob", S.TRANSFER)]

    def g_payment(self):
        if self.rng.random() < 0.6:                                   # mostly honest trade, so state actually evolves
            a, b, purpose = self.rng.choice(self.SENSIBLE)
            amt = self.rng.randint(1, 2_000_00) if self.rng.random() < 0.9 else self.amount()
        else:
            a, b, purpose, amt = self.who(), self.who(), self.rng.choice(PURPOSES), self.amount()
        t = self.w(a).pay(self.keys[b].address, amt, purpose)
        amt = t.payload["amount"]
        bad = not (isinstance(amt, int) and not isinstance(amt, bool) and 0 < amt) or a == b
        if isinstance(amt, int) and not isinstance(amt, bool) and amt > self.state.accounts[t.sender]["balance"]:
            bad = True
        return t, bad

    def g_contract(self):
        parties = self.rng.sample([n for n, _, _ in NAMES if n != "arbiter"], self.rng.randint(2, 3))
        prose = self.rng.choice(PROSE)
        obs = [legal.obligation(f"ob-{i}", self.keys[parties[1]].address, self.keys[parties[0]].address,
                                self.rng.randint(1, 5_000_00), self.height + self.rng.randint(1, 20)) for i in range(2)]
        terms: Dict[str, Any] = {"obligations": obs}
        if self.rng.random() < 0.7:
            terms["arbitration"] = {"arbitrator": self.keys["arbiter"].address}
        return self.w(parties[0]).create_contract("Fuzz agreement", prose, terms, [self.keys[p].address for p in parties]), False

    def g_sign(self):
        if not self.contracts:
            return self.g_payment()
        cid, prose = self.rng.choice(self.contracts)
        parties = [n for n, _, _ in NAMES if self.keys[n].address in self.state.contracts[cid]["parties"]]
        signer = self.rng.choice(parties) if self.rng.random() < 0.8 else self.who()
        wrong_text = self.rng.random() < 0.2
        t = self.w(signer).sign_contract(cid, prose + ("\nand one more clause" if wrong_text else ""))
        outsider = self.keys[signer].address not in self.state.contracts[cid]["parties"]
        return t, outsider or wrong_text

    def g_access(self):
        if not self.contracts:
            return self.g_payment()
        cid, _ = self.rng.choice(self.contracts)
        return self.w(self.who()).access(cid, self.rng.choice(["VIEW", "USE", "CITE", "DELETE"])), False

    def g_dispute(self):
        if not self.contracts:
            return self.g_payment()
        cid, _ = self.rng.choice(self.contracts)
        c = self.state.contracts[cid]
        obs = [o["id"] for o in c["terms"].get("obligations", [])]
        parties = [n for n, _, _ in NAMES if self.keys[n].address in c["parties"]]
        opener = self.rng.choice(parties) if self.rng.random() < 0.85 else self.who()
        active = [x for x, _ in self.contracts if self.state.contracts[x]["status"] == S.ACTIVE]
        if active and self.rng.random() < 0.8:
            cid = self.rng.choice(active); c = self.state.contracts[cid]
            obs = [o["id"] for o in c["terms"].get("obligations", [])]
            opener = self.rng.choice([n for n, _, _ in NAMES if self.keys[n].address in c["parties"]])
        t = self.w(opener).open_dispute(cid, "the rent was not paid", self.rng.sample(obs, self.rng.randint(0, len(obs))))
        return t, t.sender not in c["parties"]

    def g_award(self):
        if not self.disputes:
            return self.g_dispute()
        cid, did = self.rng.choice(self.disputes)
        c, d = self.state.contracts[cid], self.state.disputes[did]
        arbiter = self.rng.random() < 0.8
        by = "arbiter" if arbiter else self.who()
        originals = {o["id"]: o for o in c["terms"].get("obligations", [])}
        adjustments, raises = [], False
        for oid in d["obligations"]:
            if self.rng.random() < 0.6:
                amt = self.rng.randint(1, originals[oid]["amount"] * 2)
                raises |= amt > originals[oid]["amount"]
                adjustments.append({"obligation": oid, "amount": amt})
        t = self.w(by).award(cid, did, self.rng.choice(["UPHELD", "DISMISSED", "SETTLED"]), "award", adjustments)
        wrong_judge = self.keys[by].address != self.state.arbitrator_of(c)
        return t, raises or wrong_judge

    def g_attack(self):
        """Always invalid, whatever the state: the oracle for I5."""
        a, b = self.who(), self.who()
        honest = self.w(a).pay(self.keys[b].address, 1_00, S.TRANSFER)
        kind = self.rng.randrange(5)
        if kind == 0:                                               # forged signature
            d = honest.to_dict(); d["payload"]["amount"] = 999_999_00
            return T.Transaction.from_dict(d), True
        if kind == 1:                                               # another ledger's transaction
            return Wallet(self.keys[a], "elsewhere", honest.nonce).pay(self.keys[b].address, 1_00, S.TRANSFER), True
        if kind == 2 and self.accepted_log:                         # replay of an accepted one
            return self.rng.choice(self.accepted_log), True
        if kind == 3:                                               # a number from the future
            return self.w(a, nonce_shift=self.rng.randint(1, 5)).pay(self.keys[b].address, 1_00, S.TRANSFER), True
        stranger = KeyPair.generate()                               # an unregistered sender
        return Wallet(stranger, self.chain_id).pay(self.keys[b].address, 1_00, S.TRANSFER), True

    GENERATORS: List[Tuple[str, float]] = [("g_payment", 0.42), ("g_contract", 0.09), ("g_sign", 0.13), ("g_access", 0.08),
                                           ("g_dispute", 0.08), ("g_award", 0.08), ("g_attack", 0.12)]

    # ---------------------------------------------------------------- the oracle
    def check(self, where: str) -> None:
        st = self.state
        bal = [a["balance"] for a in st.accounts.values()]
        if sum(bal) != self.total:
            raise InvariantBroken(f"I1 money not conserved at {where}: {sum(bal)} != {self.total}")
        if min(bal) < 0:
            raise InvariantBroken(f"I2 negative balance at {where}")
        for c in st.contracts.values():
            signed_all = set(c["signatures"]) >= set(c["parties"])
            if (c["status"] == S.ACTIVE) != signed_all and c["status"] in (S.ACTIVE, S.DRAFT):
                raise InvariantBroken(f"I6 contract {c['id'][:12]} is {c['status']} with {len(c['signatures'])}/{len(c['parties'])} signatures at {where}")

    def step(self, i: int, report: Report) -> None:
        names, weights = zip(*self.GENERATORS)
        gen = self.rng.choices(names, weights)[0]
        tx, must_refuse = getattr(self, gen)()
        before = self.state.root()
        sender_nonce = self.state.accounts.get(tx.sender, {}).get("nonce")
        try:
            self.state.apply(tx, self.height)
            ok = True
        except S.InvalidTx:
            ok = False
        where = f"step {i} ({gen}, {tx.kind})"
        if ok:
            if must_refuse:
                raise InvariantBroken(f"I5 an invalid transaction was ACCEPTED at {where}: {tx.to_dict()}")
            if self.state.accounts[tx.sender]["nonce"] != (sender_nonce or 0) + 1:
                raise InvariantBroken(f"I4 transaction number did not advance by one at {where}")
            self.accepted_log.append(tx)
            self.accepted_heights.append(self.height)
            report.accepted += 1
            if tx.kind == T.CONTRACT_CREATE:
                self.contracts.append((tx.txid, next(p for p in PROSE if legal.prose_hash(p) == tx.payload["prose_hash"])))
            if tx.kind == T.DISPUTE_OPEN:
                self.disputes.append((tx.payload["contract_id"], tx.txid))
        else:
            if self.state.root() != before:
                raise InvariantBroken(f"I3 a REJECTED transaction changed the state at {where}: {tx.to_dict()}")
            report.rejected += 1
            report.attacks_refused += gen == "g_attack"
        report.add(tx.kind, ok)
        self.check(where)
        if self.rng.random() < 0.15:
            self.height += 1

    def final_checks(self) -> None:
        replay = S.State.from_genesis(copy.deepcopy(self.genesis))
        for tx, h in zip(self.accepted_log, self.accepted_heights):
            replay.apply(tx, h)
        if replay.root() != self.state.root():
            raise InvariantBroken("I7 replaying the accepted transactions gave a different state")
        restored = S.State.from_snapshot(copy.deepcopy(self.state.to_snapshot()))
        if restored.root() != self.state.root():
            raise InvariantBroken("I8 snapshot restore changed the state")


def run(runs: int = 20, steps: int = 400, seed: Optional[int] = None, log: Callable = print) -> Report:
    report = Report()
    seeds = [seed] if seed is not None else range(runs)
    for s in seeds:
        f = Fuzzer(s)
        for i in range(steps):
            try:
                f.step(i, report)
            except InvariantBroken as err:
                raise InvariantBroken(f"seed {s}: {err}   (replay: jurisledger fuzz --seed {s} --steps {i + 1})") from None
        f.final_checks()
        report.runs += 1
        report.steps += steps
    log(f"{report.runs} runs x {steps} transactions = {report.steps:,}: {report.accepted:,} accepted, {report.rejected:,} refused "
        f"({report.attacks_refused:,} of them deliberate attacks). All eight invariants held after every transaction.")
    for kind, (a, r) in sorted(report.by_kind.items()):
        log(f"   {kind:<18} accepted {a:>6,}   refused {r:>6,}")
    return report
