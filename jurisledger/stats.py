"""Gross Domestic Product (GDP) measured directly from finalised transactions.

Statistical offices estimate GDP from surveys, tax files and models, then revise
for years.  If payments carry a validated *purpose* tag, the three textbook
approaches of the System of National Accounts 2008 become plain sums:

Expenditure   GDP = C + I + G + (X - M)
Production    GDP = sum over resident producers of (output - intermediate consumption)
Income        GDP = compensation of employees + net taxes on production + operating surplus

The first two are computed from *different* sets of transactions, so their
agreement is a real consistency check on the ledger (see ``discrepancy``).
Operating surplus is a residual, exactly as in official practice.

Simplifications (see docs/ECONOMICS.md): no inventories, no depreciation, no
imputed rents, no financial-intermediation services, government output valued
at its wage cost, and everything at purchasers' prices.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Dict, Optional

from . import state as S
from . import tx as T
from .chain import Chain


@dataclass
class GDPReport:
    start: int
    end: int
    C: int = 0
    I: int = 0
    G: int = 0
    X: int = 0
    M: int = 0
    gov_wages: int = 0
    output: Dict[str, int] = field(default_factory=dict)          # per firm
    intermediate: Dict[str, int] = field(default_factory=dict)    # per firm
    wages: int = 0
    production_taxes: int = 0
    subsidies: int = 0
    n_payments: int = 0
    sector_of: Dict[str, str] = field(default_factory=dict)

    # -- three approaches ------------------------------------------------ #
    @property
    def expenditure(self) -> int:
        return self.C + self.I + self.G + self.X - self.M

    def value_added(self) -> Dict[str, int]:
        firms = set(self.output) | set(self.intermediate)
        return {f: self.output.get(f, 0) - self.intermediate.get(f, 0) for f in firms}

    @property
    def production(self) -> int:
        return sum(self.value_added().values()) + self.gov_wages

    @property
    def operating_surplus(self) -> int:
        return self.production - self.wages - (self.production_taxes - self.subsidies)

    @property
    def income(self) -> int:
        return self.wages + (self.production_taxes - self.subsidies) + self.operating_surplus

    @property
    def discrepancy(self) -> int:
        """Expenditure minus production.  Zero on a consistently tagged ledger."""
        return self.expenditure - self.production

    def by_sector(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f, va in self.value_added().items():
            out[self.sector_of[f]] = out.get(self.sector_of[f], 0) + va
        out["government"] = self.gov_wages
        return out

    def firms_per_sector(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.value_added():
            out[self.sector_of[f]] = out.get(self.sector_of[f], 0) + 1
        return out


def gdp(chain: Chain, start: int = 1, end: Optional[int] = None) -> GDPReport:
    """Compute national accounts for blocks ``start..end`` (inclusive)."""
    end = chain.height if end is None else end
    acc = chain.state.accounts            # roles and sectors are immutable once registered
    r = GDPReport(start, end)
    for _, t in chain.iter_txs(start, end):
        if t.kind != T.PAYMENT:
            continue
        p = t.payload
        amt, purpose, payer, payee = p["amount"], p["purpose"], t.sender, p["to"]
        payer_role, payee_role = acc[payer]["role"], acc[payee]["role"]
        r.n_payments += 1

        if purpose == S.FINAL_CONSUMPTION:
            r.C += amt
        elif purpose == S.INVESTMENT:
            r.I += amt
        elif purpose == S.GOVERNMENT_PURCHASE:
            r.G += amt
        elif purpose == S.EXPORT:
            r.X += amt
        elif purpose == S.WAGES:
            r.wages += amt
            if payer_role == S.GOVERNMENT:
                r.G += amt                # government output is valued at cost
                r.gov_wages += amt
        elif purpose == S.TAX and p.get("tax_type") == "production" and payer_role == S.FIRM:
            r.production_taxes += amt
        elif purpose == S.TRANSFER and payee_role == S.FIRM:
            r.subsidies += amt

        if purpose in S.GOODS_PURPOSES:
            if payee_role == S.FOREIGN:
                r.M += amt                # any purchase from a non-resident is an import
            elif payee_role == S.FIRM:
                r.output[payee] = r.output.get(payee, 0) + amt
                r.sector_of[payee] = acc[payee]["sector"]
            if purpose == S.INTERMEDIATE and payer_role == S.FIRM:
                r.intermediate[payer] = r.intermediate.get(payer, 0) + amt
                r.sector_of[payer] = acc[payer]["sector"]
    return r


# --------------------------------------------------------------------------- #
# Publishing statistics without exposing individual firms
# --------------------------------------------------------------------------- #
def laplace(rng: random.Random, scale: float) -> float:
    u = rng.random() - 0.5
    return -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))


def two_sided_geometric(rng: random.Random, scale: float) -> int:
    """Integer ("discrete Laplace") noise with P(k) proportional to exp(-|k| / scale).

    Integer noise on integer totals avoids the floating-point attacks on textbook Laplace
    sampling (Mironov 2012); the difference of two geometric variables has this distribution."""
    if scale <= 0:
        return 0
    q = math.exp(-1.0 / scale)                       # P(geometric >= k) = q^k

    def geometric() -> int:
        u = 1.0 - rng.random()                       # (0, 1]
        return int(math.floor(math.log(u) / math.log(q))) if q > 0 else 0
    return geometric() - geometric()


def private_sector_release(report: GDPReport, epsilon: float, clip: int, k_min: int = 3,
                           seed: Optional[int] = None, count_share: float = 0.2) -> Dict[str, Optional[int]]:
    """Sector value added with small-cell suppression and differential privacy.

    * Each firm's contribution is clipped to ``[-clip, clip]``, so adding or removing one
      firm changes a sector total by at most ``clip``.
    * Suppression is decided on a **noisy** firm count (audit H6): a deterministic "fewer than
      k_min firms" rule distinguishes two ledgers that differ by one firm with certainty, which
      no differentially private mechanism may do.  ``count_share`` of the budget goes to the count.
    * The total gets integer noise of scale ``clip / epsilon_total``.  By sequential composition
      the release as a whole is ``epsilon``-differentially private per firm (Dwork et al. 2006).
    * Noise comes from the operating system's cryptographic generator.  ``seed`` makes the
      output reproducible **for tests and experiments only**: a seeded release is not private,
      because anyone who knows the seed can subtract the noise.
    """
    if not 0 < count_share < 1 or epsilon <= 0:
        raise ValueError("need epsilon > 0 and 0 < count_share < 1")
    rng: random.Random = random.Random(seed) if seed is not None else random.SystemRandom()
    eps_count, eps_total = epsilon * count_share, epsilon * (1 - count_share)
    counts = report.firms_per_sector()
    totals: Dict[str, int] = {}
    for f, va in report.value_added().items():
        sec = report.sector_of[f]
        totals[sec] = totals.get(sec, 0) + max(-clip, min(clip, va))
    out: Dict[str, Optional[int]] = {}
    for sec in sorted(set(counts) | set(totals)):
        noisy_n = counts.get(sec, 0) + two_sided_geometric(rng, 1 / eps_count)
        out[sec] = None if noisy_n < k_min else totals.get(sec, 0) + two_sided_geometric(rng, clip / eps_total)
    return out


def committed_totals(chain: Chain, start: int = 1, end: Optional[int] = None) -> Dict[str, Dict[str, object]]:
    """Per purpose: the sum of all confidential payment commitments and their count.

    Whoever holds the openings (the parties, or a statistics office they report to)
    can open the *sum* with :func:`privacy.aggregate_opening`; anyone can check it
    against this total without learning a single payment.
    """
    from . import privacy as PV
    out: Dict[str, Dict[str, object]] = {}
    for _, t in chain.iter_txs(start, end):
        if t.kind == T.CONFIDENTIAL_PAYMENT:
            p = out.setdefault(t.payload["purpose"], {"commitment": PV.IDENTITY, "count": 0})
            p["commitment"] = p["commitment"] + PV.commitment_from_hex(t.payload["commitment"])  # type: ignore[operator]
            p["count"] += 1  # type: ignore[operator]
    return out
