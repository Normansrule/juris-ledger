"""Supply and use tables, and input-output analysis, from the ledger.

A national statistics office publishes GDP as one number, but builds it from a pair of tables
(System of National Accounts 2008, chapter 14; Eurostat, "Manual of Supply, Use and
Input-Output Tables", 2008):

  supply table   who produced each product: domestic industries, plus imports
  use table      who used it: industries as inputs (intermediate consumption), and final uses
                 C (households), I (investment), G (government), X (exports);
                 under each industry, its value added split into compensation of employees,
                 net taxes on production, and operating surplus

Two identities must hold.  For every PRODUCT, total supply equals total use.  For every
INDUSTRY, output equals intermediate consumption plus value added.  In official practice the
supply and use sides come from different surveys and "balancing" them takes months; the gap that
remains is published as the statistical discrepancy.  On a ledger whose payments carry validated
purposes both sides are read from the same transactions, so the identities hold exactly, product
by product and industry by industry.

From the use table follows the input-output (Leontief) model: technical coefficients
A = intermediate use / industry output, and the Leontief inverse L = (I - A)^-1, which says how
much each industry must produce, directly and through its suppliers, to deliver one more unit of
final demand.  It is computed here in exact rational arithmetic, so the check x = L f (output
equals the inverse times final demand) is an equality, not an approximation.

Classification used here (see docs/ECONOMICS.md): a product is identified with the sector of the
firm that sells it; anything bought from a non-resident is the single product "imports";
government output is "government services", valued at its wage cost and used only as G.
Financial services are not measured (banks have no output), so bank wages appear as a separate
"financial (not measured)" column with negative operating surplus, which is exactly how the
whole-economy income approach already treats them.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import state as S
from . import tx as T

FINAL = ["C", "I", "G", "X"]
FINAL_OF = {S.FINAL_CONSUMPTION: "C", S.INVESTMENT: "I", S.GOVERNMENT_PURCHASE: "G", S.EXPORT: "X"}
GOV_PRODUCT = "government services"
IMPORTS = "imports"
FINANCIAL = "financial (not measured)"
VA_ROWS = ["compensation of employees", "net taxes on production", "operating surplus"]

# one payment, as the tables need it: (payer, payee, amount, purpose, tax_type)
Payment = Tuple[str, str, int, str, Optional[str]]


@dataclass
class SupplyUse:
    start: int
    end: int
    industries: List[str] = field(default_factory=list)          # firm sectors + government (+ financial if any)
    products: List[str] = field(default_factory=list)            # firm sectors + government services + imports
    output: Dict[str, int] = field(default_factory=dict)         # industry -> output (supply table diagonal)
    imports: int = 0
    use: Dict[Tuple[str, str], int] = field(default_factory=dict)       # (product, industry) -> intermediate use
    final: Dict[Tuple[str, str], int] = field(default_factory=dict)     # (product, C|I|G|X) -> final use
    comp: Dict[str, int] = field(default_factory=dict)           # industry -> compensation of employees
    net_taxes: Dict[str, int] = field(default_factory=dict)      # industry -> production taxes - subsidies
    n_payments: int = 0

    # -- reading the tables ------------------------------------------------- #
    def supply_of(self, p: str) -> int:
        return self.imports if p == IMPORTS else self.output.get(_industry_of_product(p), 0)

    def use_of(self, p: str) -> int:
        return sum(self.use.get((p, i), 0) for i in self.industries) + sum(self.final.get((p, f), 0) for f in FINAL)

    def intermediate_of(self, i: str) -> int:
        return sum(self.use.get((p, i), 0) for p in self.products)

    def value_added(self, i: str) -> int:
        return self.output.get(i, 0) - self.intermediate_of(i)

    def surplus(self, i: str) -> int:
        return self.value_added(i) - self.comp.get(i, 0) - self.net_taxes.get(i, 0)

    def final_total(self, f: str) -> int:
        return sum(self.final.get((p, f), 0) for p in self.products)

    @property
    def gdp_production(self) -> int:
        return sum(self.value_added(i) for i in self.industries)

    @property
    def gdp_expenditure(self) -> int:
        return sum(self.final_total(f) for f in FINAL) - self.imports

    @property
    def gdp_income(self) -> int:
        return sum(self.comp.get(i, 0) + self.net_taxes.get(i, 0) + self.surplus(i) for i in self.industries)

    def product_imbalances(self) -> Dict[str, int]:
        """Supply minus use, per product: all zero on a consistently tagged ledger."""
        return {p: self.supply_of(p) - self.use_of(p) for p in self.products}

    # -- input-output analysis ------------------------------------------------ #
    def domestic(self) -> List[str]:
        """Industries with measured output, in the same order as their products."""
        return [i for i in self.industries if i != FINANCIAL]

    def coefficients(self) -> List[List[Fraction]]:
        """A[r][c]: domestic product r used per unit of industry c's output."""
        dom = self.domestic()
        return [[Fraction(self.use.get((_product_of_industry(r), c), 0), self.output[c]) if self.output.get(c) else Fraction(0)
                 for c in dom] for r in dom]

    def leontief(self) -> List[List[Fraction]]:
        A, n = self.coefficients(), len(self.domestic())
        return _inverse([[(1 if r == c else 0) - A[r][c] for c in range(n)] for r in range(n)])

    def final_domestic(self) -> List[int]:
        return [sum(self.final.get((_product_of_industry(i), f), 0) for f in FINAL) for i in self.domestic()]

    def multipliers(self) -> Dict[str, float]:
        """Output across the whole economy needed per unit of final demand for each industry's product."""
        L, dom = self.leontief(), self.domestic()
        return {dom[c]: float(sum(L[r][c] for r in range(len(dom)))) for c in range(len(dom))}

    def what_if(self, extra: Dict[str, int]) -> Dict[str, int]:
        """Additional output each industry must produce if final demand for these products rises."""
        L, dom = self.leontief(), self.domestic()
        df = [Fraction(extra.get(i, 0)) for i in dom]
        return {dom[r]: round(sum(L[r][c] * df[c] for c in range(len(dom)))) for r in range(len(dom))}

    # -- export ------------------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        L, dom = self.leontief(), self.domestic()
        return {
            "from": self.start, "to": self.end, "industries": self.industries, "products": self.products,
            "final_columns": FINAL, "imports": self.imports,
            "supply": {p: self.supply_of(p) for p in self.products},
            "use": [[self.use.get((p, i), 0) for i in self.industries] for p in self.products],
            "final": [[self.final.get((p, f), 0) for f in FINAL] for p in self.products],
            "output": [self.output.get(i, 0) for i in self.industries],
            "value_added": {
                "compensation of employees": [self.comp.get(i, 0) for i in self.industries],
                "net taxes on production": [self.net_taxes.get(i, 0) for i in self.industries],
                "operating surplus": [self.surplus(i) for i in self.industries],
            },
            "gdp": {"production": self.gdp_production, "expenditure": self.gdp_expenditure, "income": self.gdp_income},
            "imbalances": self.product_imbalances(),
            "leontief": {"industries": dom, "matrix": [[float(v) for v in row] for row in L],
                         "multipliers": self.multipliers()},
        }

    def write_csv(self, directory: str | Path) -> List[Path]:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        out = []
        with open(d / "supply.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["product"] + self.industries + ["imports", "total supply"])
            for p in self.products:
                ind = _industry_of_product(p)
                w.writerow([p] + [self.output.get(i, 0) if i == ind else 0 for i in self.industries]
                           + [self.imports if p == IMPORTS else 0, self.supply_of(p)])
            out.append(d / "supply.csv")
        with open(d / "use.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["product"] + self.industries + FINAL + ["total use"])
            for p in self.products:
                w.writerow([p] + [self.use.get((p, i), 0) for i in self.industries]
                           + [self.final.get((p, c), 0) for c in FINAL] + [self.use_of(p)])
            w.writerow(["intermediate consumption"] + [self.intermediate_of(i) for i in self.industries])
            w.writerow([VA_ROWS[0]] + [self.comp.get(i, 0) for i in self.industries])
            w.writerow([VA_ROWS[1]] + [self.net_taxes.get(i, 0) for i in self.industries])
            w.writerow([VA_ROWS[2]] + [self.surplus(i) for i in self.industries])
            w.writerow(["output"] + [self.output.get(i, 0) for i in self.industries])
            out.append(d / "use.csv")
        with open(d / "leontief.csv", "w", newline="") as f:
            w = csv.writer(f)
            dom, L = self.domestic(), self.leontief()
            w.writerow(["output needed in / per unit of final demand for"] + dom)
            for r, row in enumerate(L):
                w.writerow([dom[r]] + [f"{float(v):.6f}" for v in row])
            out.append(d / "leontief.csv")
        return out


def _product_of_industry(i: str) -> str:
    return GOV_PRODUCT if i == S.GOVERNMENT else i


def _industry_of_product(p: str) -> str:
    return S.GOVERNMENT if p == GOV_PRODUCT else p


def _inverse(M: List[List[Fraction]]) -> List[List[Fraction]]:
    """Gauss-Jordan elimination in exact rational arithmetic."""
    n = len(M)
    a = [[Fraction(v) for v in row] + [Fraction(1 if r == c else 0) for c in range(n)] for r, row in enumerate(M)]
    for col in range(n):
        piv = next((r for r in range(col, n) if a[r][col] != 0), None)
        if piv is None:
            raise ZeroDivisionError("the input-output matrix is singular")
        a[col], a[piv] = a[piv], a[col]
        p = a[col][col]
        a[col] = [v / p for v in a[col]]
        for r in range(n):
            if r != col and a[r][col] != 0:
                f = a[r][col]
                a[r] = [x - f * y for x, y in zip(a[r], a[col])]
    return [row[n:] for row in a]


# --------------------------------------------------------------------------- #
# building
# --------------------------------------------------------------------------- #
def build(payments: Iterable[Payment], accounts: Dict[str, Dict[str, Any]], start: int = 1, end: int = 0) -> SupplyUse:
    """``accounts``: address -> {"role", "sector"}.  Every successor key must be present too."""
    t = SupplyUse(start, end)
    role = lambda a: accounts.get(a, {}).get("role")               # noqa: E731
    sector = lambda a: accounts.get(a, {}).get("sector") or "other"  # noqa: E731
    sectors = sorted({v.get("sector") or "other" for v in accounts.values() if v.get("role") == S.FIRM})
    bank_wages = False
    for payer, payee, amt, purpose, tax_type in payments:
        t.n_payments += 1
        pr, ee = role(payer), role(payee)
        if purpose in S.GOODS_PURPOSES:
            if ee == S.FOREIGN:
                product = IMPORTS
                t.imports += amt
            else:                                                   # rules: the payee is a resident firm
                product = sector(payee)
                t.output[product] = t.output.get(product, 0) + amt
            if purpose == S.INTERMEDIATE:                           # rules: the payer is a firm
                key = (product, sector(payer))
                t.use[key] = t.use.get(key, 0) + amt
            else:
                key = (product, FINAL_OF[purpose])
                t.final[key] = t.final.get(key, 0) + amt
        elif purpose == S.WAGES:
            ind = sector(payer) if pr == S.FIRM else S.GOVERNMENT if pr == S.GOVERNMENT else FINANCIAL
            bank_wages |= ind == FINANCIAL
            t.comp[ind] = t.comp.get(ind, 0) + amt
            if pr == S.GOVERNMENT:                                  # government output valued at its wage cost
                t.output[S.GOVERNMENT] = t.output.get(S.GOVERNMENT, 0) + amt
                key = (GOV_PRODUCT, "G")
                t.final[key] = t.final.get(key, 0) + amt
        elif purpose == S.TAX and tax_type == "production" and pr == S.FIRM:
            t.net_taxes[sector(payer)] = t.net_taxes.get(sector(payer), 0) + amt
        elif purpose == S.TRANSFER and ee == S.FIRM:                # subsidies reduce net taxes on production
            t.net_taxes[sector(payee)] = t.net_taxes.get(sector(payee), 0) - amt
    t.industries = sectors + [S.GOVERNMENT] + ([FINANCIAL] if bank_wages else [])
    t.products = sectors + [GOV_PRODUCT, IMPORTS]
    return t


def from_chain(chain, start: int = 1, end: Optional[int] = None) -> SupplyUse:
    end = chain.height if end is None else end
    accounts = chain.state.accounts
    rows = ((t.sender, t.payload["to"], t.payload["amount"], t.payload["purpose"], t.payload.get("tax_type"))
            for _, t in chain.iter_txs(start, end) if t.kind == T.PAYMENT)
    return build(rows, accounts, start, end)


def from_index(index, start: int = 1, end: Optional[int] = None) -> SupplyUse:
    if not any(r[1] == "tax_type" for r in index.db.execute("PRAGMA table_info(payments)")):
        from .index import IndexError_
        raise IndexError_(f"{index.path} was built by an older version; run `jurisledger index` on it again to upgrade")
    end = index.height if end is None else end
    accounts = {a: {"role": r, "sector": s} for a, r, s in index.db.execute("SELECT address, role, sector FROM accounts")}
    rows = index.db.execute("SELECT payer, payee, amount, purpose, tax_type FROM payments WHERE height BETWEEN ? AND ? "
                            "ORDER BY height, txid", (start, end))
    return build(rows, accounts, start, end)


# --------------------------------------------------------------------------- #
# printing
# --------------------------------------------------------------------------- #
def render(t: SupplyUse) -> str:
    def m(c: int) -> str:
        return f"{c / 100:>13,.0f}"
    short = {i: i[:12] for i in t.industries}
    lines = [f"Supply and use, blocks {t.start}-{t.end}, {t.n_payments:,} payments (amounts in whole currency units)", "",
             "USE: rows are products; columns are who used them", "  " + " " * 20 + "".join(f"{short[i]:>14}" for i in t.industries)
             + "".join(f"{f:>14}" for f in FINAL) + f"{'total use':>14}{'supply':>14}"]
    for p in t.products:
        lines.append(f"  {p[:20]:<20}" + "".join(m(t.use.get((p, i), 0)) + " " for i in t.industries)
                     + "".join(m(t.final.get((p, f), 0)) + " " for f in FINAL) + m(t.use_of(p)) + " " + m(t.supply_of(p)))
    lines.append(f"  {'intermediate total':<20}" + "".join(m(t.intermediate_of(i)) + " " for i in t.industries))
    for label, vals in ((VA_ROWS[0], t.comp), (VA_ROWS[1], t.net_taxes)):
        lines.append(f"  {label[:20]:<20}" + "".join(m(vals.get(i, 0)) + " " for i in t.industries))
    lines.append(f"  {VA_ROWS[2][:20]:<20}" + "".join(m(t.surplus(i)) + " " for i in t.industries))
    lines.append(f"  {'output':<20}" + "".join(m(t.output.get(i, 0)) + " " for i in t.industries))
    bad = {p: v for p, v in t.product_imbalances().items() if v}
    lines += ["", "CHECKS",
              f"  supply = use for every product:          {'yes' if not bad else 'NO ' + str(bad)}",
              f"  GDP production / expenditure / income:   {t.gdp_production / 100:,.2f} / {t.gdp_expenditure / 100:,.2f} / "
              f"{t.gdp_income / 100:,.2f}",
              "", "OUTPUT MULTIPLIERS (output across the economy per 1.00 of final demand for the product)"]
    for i, v in t.multipliers().items():
        lines.append(f"  {i:<20}{v:>8.3f}  " + "#" * round(v * 10))
    return "\n".join(lines)
