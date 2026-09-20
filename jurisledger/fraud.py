"""Fraud and anomaly detectors that run on the public ledger.

Some fraud is made *impossible* by the protocol (forged payments, replay,
double spending, back-dated or altered contracts).  The detectors here target
what stays possible: honest-looking transactions with dishonest intent.

Every detector returns plain dictionaries: they raise flags for human review,
never automatic punishment.  False positives are expected.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from . import state as S
from . import tx as T
from .chain import Chain


def _payments(chain: Chain, start: int = 1, end: Optional[int] = None):
    for h, t in chain.iter_txs(start, end):
        if t.kind == T.PAYMENT:
            yield h, t


def _name(chain: Chain, a: str) -> str:
    return chain.state.accounts[a]["name"]


# --------------------------------------------------------------------------- #
def structuring(chain: Chain, threshold: int, band: float = 0.10, min_count: int = 3,
                window: int = 5) -> List[Dict[str, Any]]:
    """Many payments just under a reporting threshold within a few blocks.

    Splitting one large payment to dodge a reporting rule ("smurfing") is a
    crime in its own right in many jurisdictions, e.g. 31 U.S.C. section 5324.
    """
    low = int(threshold * (1 - band))
    hits: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    for h, t in _payments(chain):
        if low <= t.payload["amount"] < threshold:
            hits[t.sender].append((h, t.payload["amount"]))
    flags = []
    for sender, items in hits.items():
        items.sort()
        best: List[Tuple[int, int]] = []
        for i in range(len(items)):
            run = [x for x in items[i:] if x[0] - items[i][0] <= window]
            if len(run) > len(best):
                best = run
        if len(best) >= min_count:
            flags.append({"detector": "structuring", "account": sender, "name": _name(chain, sender),
                          "count": len(best), "total": sum(a for _, a in best),
                          "blocks": [best[0][0], best[-1][0]]})
    return flags


# --------------------------------------------------------------------------- #
def circular_flows(chain: Chain, max_len: int = 5, tolerance: float = 0.10, window: int = 6,
                   min_amount: int = 1) -> List[Dict[str, Any]]:
    """Money that returns to its origin through a ring of similar-sized payments.

    The signature of wash trading, round-tripping to inflate revenue, and
    carousel (missing-trader) tax fraud.  Bounded depth-first search over the
    payment graph; each ring is reported once.
    """
    edges: Dict[str, List[Tuple[str, int, int, str]]] = defaultdict(list)
    for h, t in _payments(chain):
        p = t.payload
        if p["purpose"] in (S.WAGES, S.TAX, S.TRANSFER) or p["amount"] < min_amount:
            continue
        edges[t.sender].append((p["to"], p["amount"], h, t.txid))

    found: Dict[frozenset, Dict[str, Any]] = {}

    def walk(origin: str, node: str, path: List[str], amounts: List[int], heights: List[int], txids: List[str]):
        for to, amt, h, txid in edges.get(node, []):
            if amounts and not (1 - tolerance) * amounts[0] <= amt <= (1 + tolerance) * amounts[0]:
                continue
            if heights and not (heights[-1] <= h <= heights[0] + window):
                continue
            if to == origin and len(path) >= 2:
                key = frozenset(txids + [txid])
                found.setdefault(key, {"detector": "circular_flow",
                                       "ring": [_name(chain, a) for a in path] + [_name(chain, origin)],
                                       "accounts": list(path), "hops": len(path),
                                       "amounts": amounts + [amt], "total": sum(amounts) + amt,
                                       "blocks": [heights[0], h]})
            elif to not in path and len(path) < max_len:
                walk(origin, to, path + [to], amounts + [amt], heights + [h], txids + [txid])

    for origin in list(edges):
        walk(origin, origin, [origin], [], [], [])

    # keep one report per set of accounts (the ring seen from its earliest start)
    unique: Dict[frozenset, Dict[str, Any]] = {}
    for f in found.values():
        k = frozenset(f["accounts"])
        if k not in unique or f["blocks"][0] < unique[k]["blocks"][0]:
            unique[k] = f
    return sorted(unique.values(), key=lambda f: -f["total"])      # biggest rings first


# --------------------------------------------------------------------------- #
BENFORD = [math.log10(1 + 1 / d) for d in range(1, 10)]
CHI2_CRIT_8DF_001 = 20.09           # chi-square critical value, 8 degrees of freedom, p = 0.01


def benford(chain: Chain, min_payments: int = 60) -> List[Dict[str, Any]]:
    """First-digit test on each account's outgoing payment amounts.

    Naturally occurring amounts spanning several orders of magnitude follow
    Benford's law; invented figures usually do not (Nigrini 2012).  Accounts
    paying fixed amounts (salaries, rent) will be flagged too -- this is a
    screening tool, not proof.
    """
    by_sender: Dict[str, List[int]] = defaultdict(list)
    for _, t in _payments(chain):
        if t.payload["purpose"] in (S.WAGES, S.TAX, S.TRANSFER):
            continue
        by_sender[t.sender].append(t.payload["amount"])
    flags = []
    for sender, amounts in by_sender.items():
        n = len(amounts)
        if n < min_payments:
            continue
        counts = [0] * 9
        for a in amounts:
            counts[int(str(a)[0]) - 1] += 1
        chi2 = sum((counts[i] - n * BENFORD[i]) ** 2 / (n * BENFORD[i]) for i in range(9))
        if chi2 > CHI2_CRIT_8DF_001:
            flags.append({"detector": "benford", "account": sender, "name": _name(chain, sender),
                          "payments": n, "chi2": round(chi2, 1), "critical": CHI2_CRIT_8DF_001})
    return flags


# --------------------------------------------------------------------------- #
def duplicate_invoice_financing(chain: Chain) -> List[Dict[str, Any]]:
    """The same invoice hash pledged for FINANCIAL payments from several lenders.

    Without a shared ledger each lender sees only its own book, which is what
    makes double-pledging receivables work.  On a shared ledger it is a lookup.
    """
    lenders: Dict[Tuple[str, str], set] = defaultdict(set)
    for _, t in _payments(chain):
        p = t.payload
        if p["purpose"] == S.FINANCIAL and "invoice" in p:
            lenders[(p["invoice"], p["to"])].add(t.sender)
    return [{"detector": "duplicate_invoice_financing", "invoice": inv, "borrower": _name(chain, b),
             "lenders": sorted(_name(chain, l) for l in ls)}
            for (inv, b), ls in lenders.items() if len(ls) > 1]


def run_all(chain: Chain, threshold: int) -> List[Dict[str, Any]]:
    return (structuring(chain, threshold) + circular_flows(chain) + benford(chain)
            + duplicate_invoice_financing(chain))
