"""A small synthetic economy that drives the ledger.

Households earn wages and consume; firms in four sectors buy inputs, invest and
export; a government taxes, buys, employs and pays benefits; the rest of the
world buys exports and sells imports.  The simulator keeps its OWN books
(``truth``), independent of the chain, so tests can check that GDP recomputed
from the ledger equals what actually happened.

It is a test harness, not an economic model: behaviour is random, not optimising.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import state as S
from .consensus import Network
from .contracts import Wallet
from .crypto import KeyPair
from .tx import Transaction


@dataclass
class SimConfig:
    chain_id: str = "jurisledger-sim-1"
    seed: int = 7
    n_households: int = 24
    sectors: Tuple[str, ...] = ("agriculture", "manufacturing", "construction", "services")
    firms_per_sector: int = 4
    periods: int = 6
    n_validators: int = 4
    import_share: float = 0.12
    offledger_share: float = 0.0       # share of goods purchases settled in cash, invisible to the ledger


@dataclass
class Truth:
    C: int = 0
    I: int = 0
    G: int = 0
    X: int = 0
    M: int = 0
    gov_wages: int = 0
    output: Dict[str, int] = field(default_factory=dict)
    intermediate: Dict[str, int] = field(default_factory=dict)

    @property
    def gdp(self) -> int:
        return self.C + self.I + self.G + self.X - self.M

    def value_added(self) -> Dict[str, int]:
        return {f: self.output.get(f, 0) - self.intermediate.get(f, 0)
                for f in set(self.output) | set(self.intermediate)}


class Economy:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.truth = Truth()
        self.period_truth: List[Truth] = []
        self.wallets: Dict[str, Wallet] = {}
        self.accounts: List[Dict[str, Any]] = []

        def add(name: str, role: str, sector: str, balance: int) -> Wallet:
            w = Wallet(KeyPair.from_seed(f"{cfg.chain_id}/{name}"), cfg.chain_id)
            self.wallets[name] = w
            self.accounts.append({"address": w.address, "name": name, "role": role,
                                  "sector": sector, "balance": balance})
            return w

        self.households = [add(f"household-{i:02d}", S.HOUSEHOLD, "", 500_000_00) for i in range(cfg.n_households)]
        self.firms: List[Wallet] = []
        self.firm_sector: Dict[str, str] = {}
        for s in cfg.sectors:
            for i in range(cfg.firms_per_sector):
                w = add(f"{s}-firm-{i}", S.FIRM, s, 5_000_000_00)
                self.firms.append(w)
                self.firm_sector[w.address] = s
        self.government = add("government", S.GOVERNMENT, "", 50_000_000_00)
        self.foreign = add("rest-of-world", S.FOREIGN, "", 50_000_000_00)
        self.banks = [add(f"bank-{i}", S.BANK, "", 10_000_000_00) for i in range(2)]
        self.validator_keys = [KeyPair.from_seed(f"{cfg.chain_id}/validator-{i}") for i in range(cfg.n_validators)]

        # employment: most households work for a firm, every sixth for the government
        self.employer: Dict[str, Wallet] = {}
        for i, h in enumerate(self.households):
            self.employer[h.address] = self.government if i % 6 == 5 else self.firms[i % len(self.firms)]

    # ------------------------------------------------------------------ #
    def genesis(self) -> Dict[str, Any]:
        return {"chain_id": self.cfg.chain_id, "accounts": self.accounts,
                "validators": [k.address for k in self.validator_keys]}

    def wallet(self, name: str) -> Wallet:
        return self.wallets[name]

    def _amount(self, median: int, sigma: float = 0.9) -> int:
        import math
        return max(100, int(self.rng.lognormvariate(math.log(median), sigma)))

    # ------------------------------------------------------------------ #
    def period(self) -> List[Transaction]:
        """Generate one period of economic activity; returns on-ledger transactions."""
        rng, cfg = self.rng, self.cfg
        txs: List[Transaction] = []
        now = Truth()

        def goods(payer: Wallet, payee: Wallet, amount: int, purpose: str) -> None:
            imported = payee is self.foreign
            for t in (self.truth, now):
                if purpose == S.FINAL_CONSUMPTION:
                    t.C += amount
                elif purpose == S.INVESTMENT:
                    t.I += amount
                elif purpose == S.GOVERNMENT_PURCHASE:
                    t.G += amount
                elif purpose == S.EXPORT:
                    t.X += amount
                if imported:
                    t.M += amount
                else:
                    t.output[payee.address] = t.output.get(payee.address, 0) + amount
                if purpose == S.INTERMEDIATE:
                    t.intermediate[payer.address] = t.intermediate.get(payer.address, 0) + amount
            if rng.random() >= cfg.offledger_share:      # otherwise: paid in cash, never recorded
                txs.append(payer.pay(payee.address, amount, purpose))

        def seller(exclude: Optional[Wallet] = None, sectors: Optional[Tuple[str, ...]] = None) -> Wallet:
            if rng.random() < cfg.import_share:
                return self.foreign
            pool = [f for f in self.firms if f is not exclude
                    and (sectors is None or self.firm_sector[f.address] in sectors)]
            return rng.choice(pool)

        # 1. wages, income tax
        for h in self.households:
            boss = self.employer[h.address]
            wage = self._amount(4_000_00, 0.35)
            txs.append(boss.pay(h.address, wage, S.WAGES))
            if boss is self.government:
                for t in (self.truth, now):
                    t.G += wage
                    t.gov_wages += wage
            txs.append(h.pay(self.government.address, wage * 15 // 100, S.TAX, tax_type="income"))
        # 2. household consumption
        for h in self.households:
            for _ in range(3):
                goods(h, seller(), self._amount(700_00), S.FINAL_CONSUMPTION)
        # 3. intermediate inputs, production taxes
        for f in self.firms:
            for _ in range(2):
                goods(f, seller(exclude=f), self._amount(6_000_00), S.INTERMEDIATE)
            txs.append(f.pay(self.government.address, self._amount(900_00, 0.4), S.TAX, tax_type="production"))
        # 4. investment
        for f in self.firms:
            if rng.random() < 0.5:
                goods(f, seller(exclude=f, sectors=("manufacturing", "construction")),
                      self._amount(15_000_00), S.INVESTMENT)
        # 5. government purchases, benefits, a farm subsidy
        for _ in range(5):
            goods(self.government, seller(), self._amount(20_000_00), S.GOVERNMENT_PURCHASE)
        for h in rng.sample(self.households, 4):
            txs.append(self.government.pay(h.address, self._amount(900_00, 0.2), S.TRANSFER))
        txs.append(self.government.pay(self.firms[0].address, 1_500_00, S.TRANSFER))
        # 6. exports
        for _ in range(5):
            goods(self.foreign, rng.choice(self.firms), self._amount(18_000_00), S.EXPORT)

        self.period_truth.append(now)
        return txs


@dataclass
class SimResult:
    economy: Economy
    network: Network
    period_blocks: List[Tuple[int, int]]      # (first_height, last_height) for each period

    @property
    def chain(self):
        return self.network.reference.chain


def run_simulation(cfg: Optional[SimConfig] = None,
                   behaviours: Optional[Dict[int, Tuple[str, Optional[str]]]] = None) -> SimResult:
    cfg = cfg or SimConfig()
    eco = Economy(cfg)
    net = Network.create(eco.genesis(), eco.validator_keys, behaviours)
    spans = []
    for _ in range(cfg.periods):
        first = net.reference.chain.height + 1
        for t in eco.period():
            net.submit(t)
        net.run_until_empty()
        spans.append((first, net.reference.chain.height))
    return SimResult(eco, net, spans)


# --------------------------------------------------------------------------- #
def survey_estimate(truth: Truth, sample_frac: float, response_rate: float, noise_sd: float,
                    underreport: float, seed: int) -> float:
    """A stylised survey-based GDP estimate, for comparison with the ledger.

    A random sample of firms is asked for value added.  Some do not answer;
    those that do report with noise and shade their figures down.  The office
    scales the respondents' mean up to the whole population of firms.
    """
    rng = random.Random(seed)
    va = truth.value_added()
    firms = sorted(va)
    sample = rng.sample(firms, max(2, int(len(firms) * sample_frac)))
    answers = [va[f] * (1 - underreport) * (1 + rng.gauss(0, noise_sd))
               for f in sample if rng.random() < response_rate]
    if not answers:
        return float("nan")
    return sum(answers) / len(answers) * len(firms) + truth.gov_wages
