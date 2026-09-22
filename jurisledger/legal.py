"""Legal tooling on top of the ledger.

1. **Obligations and compliance.**  A contract's machine-readable terms may list
   payment duties -- who owes whom how much by which block.  Payments that name
   the obligation discharge it; ``compliance`` reports PAID, PAID_LATE, PARTIAL,
   OVERDUE or PENDING from public data, so neither party has to be believed.

2. **Evidence bundles.**  ``evidence_bundle`` packs everything about one contract
   into a single file: every relevant signed transaction, the Merkle path from
   each transaction to its block header, and the validators' commit certificate
   for that header.  ``verify_evidence_bundle`` checks the file *offline*, with
   nothing but the list of validator public keys.  This is the artefact you would
   hand to a court-appointed expert, an arbitrator or an auditor.

   A bundle proves what happened.  It cannot prove that nothing *else* happened
   (for example, that no later contract superseded this one): omission is
   undetectable from the file alone.  For that, query a full node.

Nothing here is legal advice, and whether a tribunal admits such evidence is a
matter of local law (see docs/LEGAL.md).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import tx as T
from .chain import Chain
from .contracts import prose_hash
from .tx import Transaction

BUNDLE_FORMAT = "jurisledger/evidence/v1"


# --------------------------------------------------------------------------- #
# Obligations
# --------------------------------------------------------------------------- #
def obligation(id: str, payer: str, payee: str, amount: int, due_height: int) -> Dict[str, Any]:
    return {"id": id, "payer": payer, "payee": payee, "amount": amount, "due_height": due_height}


def compliance(chain: Chain, contract_id: str, at_height: Optional[int] = None) -> List[Dict[str, Any]]:
    """Status of every obligation in a contract as of ``at_height`` (default: now).

    Arbitral awards made by block ``at_height`` change the effective amount and
    due block (or waive the obligation); an obligation under an open dispute is
    reported as DISPUTED instead of OVERDUE, because whether it is owed is the
    very thing being decided.
    """
    at = chain.height if at_height is None else at_height
    c = chain.state.contracts[contract_id]
    names = chain.state.accounts
    disputes = [d for d in chain.state.disputes.values() if d["contract_id"] == contract_id]
    out = []
    for ob in c["terms"].get("obligations", []):
        adj = c["adjustments"].get(ob["id"])
        adj = adj if adj and adj["height"] <= at else {}
        amount, due = adj.get("amount", ob["amount"]), adj.get("due_height", ob["due_height"])
        paid, settled_at, payments = 0, None, []
        for h, t in chain.iter_txs(1, at):
            p = t.payload
            if t.kind == T.PAYMENT and p.get("contract") == contract_id and p.get("obligation") == ob["id"]:
                paid += p["amount"]
                payments.append({"height": h, "amount": p["amount"], "txid": t.txid})
                if settled_at is None and paid >= amount:
                    settled_at = h
        in_dispute = any(ob["id"] in d["obligations"] and d["opened_height"] <= at
                         and (d["closed_height"] is None or d["closed_height"] > at) for d in disputes)
        if settled_at is not None:
            status = "PAID" if settled_at <= due else "PAID_LATE"
        elif adj.get("waived"):
            status = "WAIVED"
        elif in_dispute:
            status = "DISPUTED"
        elif at > due:
            status = "OVERDUE"
        else:
            status = "PARTIAL" if paid else "PENDING"
        out.append({"id": ob["id"], "payer": names[ob["payer"]]["name"], "payee": names[ob["payee"]]["name"],
                    "amount": amount, "original_amount": ob["amount"], "paid": paid, "due_height": due,
                    "original_due_height": ob["due_height"], "settled_at": settled_at, "status": status,
                    "adjusted_by_award": bool(adj), "payments": payments})
    return out


def dispute_record(chain: Chain, dispute_id: str) -> Dict[str, Any]:
    """A dispute with names resolved, for display."""
    d = chain.state.disputes[dispute_id]
    names = chain.state.accounts
    c = chain.state.contracts[d["contract_id"]]
    return {**d, "contract_title": c["title"], "claimant": names[d["claimant"]]["name"],
            "arbitrator": names[chain.state.arbitrator_of(c)]["name"],
            "filings": [{**f, "by": names[f["by"]]["name"]} for f in d["filings"]]}


# --------------------------------------------------------------------------- #
# Evidence bundles
# --------------------------------------------------------------------------- #
def _relates(t: Transaction, cid: str) -> bool:
    p = t.payload
    if t.txid == cid or p.get("contract_id") == cid or p.get("contract") == cid:
        return True
    return t.kind == T.CONTRACT_CREATE and any(
        r.get("kind") == "contract" and r.get("id") == cid for r in p.get("references", []))


def _key_change(t: Transaction) -> Optional[tuple]:
    if t.kind == T.KEY_ROTATE:
        return t.sender, t.payload.get("new_key")
    if t.kind == T.RECOVERY_FINALIZE:
        return t.payload.get("subject"), t.payload.get("new_key")
    return None


def evidence_bundle(chain: Chain, contract_id: str, prose: Optional[str] = None) -> Dict[str, Any]:
    if contract_id not in chain.state.contracts:
        raise KeyError("unknown contract")
    items, changes = [], []
    for block in chain.blocks:
        for t in block.txs:
            if _relates(t, contract_id):
                items.append({"tx": t.to_dict(), "inclusion": chain.tx_proof(t.txid)})
            elif _key_change(t):
                changes.append(t)
    # key changes of the parties (followed transitively), so signatures by a replaced key still make sense
    create = next(Transaction.from_dict(i["tx"]) for i in items if i["tx"]["kind"] == T.CONTRACT_CREATE
                  and Transaction.from_dict(i["tx"]).txid == contract_id)
    keys, key_changes = set(create.payload["parties"]), []
    for t in changes:                                  # chain order, so chains of rotations resolve
        old, new = _key_change(t)
        if old in keys:
            keys.add(new)
            key_changes.append({"tx": t.to_dict(), "inclusion": chain.tx_proof(t.txid)})
    labels = {a: chain.state.accounts[a]["name"] for i in items for a in [i["tx"]["sender"]]}
    return {"format": BUNDLE_FORMAT, "chain_id": chain.chain_id, "contract_id": contract_id,
            "prose": prose, "items": items, "key_changes": key_changes,
            "labels": labels}     # names are a convenience for the reader and are NOT proven by the file


def verify_evidence_bundle(bundle: Dict[str, Any], validators: List[str]) -> Dict[str, Any]:
    """Offline verification.  ``validators`` is the verifier's own trusted list of keys."""
    problems: List[str] = []
    timeline: List[Dict[str, Any]] = []
    cid = bundle.get("contract_id")
    create: Optional[Transaction] = None
    if bundle.get("format") != BUNDLE_FORMAT:
        problems.append("unknown bundle format")

    for i, item in enumerate(bundle.get("items", [])):
        try:
            t = Transaction.from_dict(item["tx"])
            header = item["inclusion"]["header"]
        except (KeyError, TypeError):
            problems.append(f"item {i}: malformed")
            continue
        if t.chain_id != bundle.get("chain_id") or header.get("chain_id") != bundle.get("chain_id"):
            problems.append(f"item {i}: belongs to another network")
        if not t.signature_valid():
            problems.append(f"item {i}: transaction signature is invalid")
        if not Chain.verify_tx_proof(t.txid, item["inclusion"], validators):
            problems.append(f"item {i}: not proven final (bad Merkle path or too few validator votes)")
        if not _relates(t, cid):
            problems.append(f"item {i}: unrelated to this contract")
        if t.txid == cid and t.kind == T.CONTRACT_CREATE:
            create = t
        timeline.append({"height": header.get("height"), "kind": t.kind, "by": t.sender, "txid": t.txid,
                         "detail": {k: v for k, v in t.payload.items()
                                    if k in ("action", "context", "amount", "obligation", "obligations", "grantee",
                                             "title", "note", "outcome", "adjustments")}})

    successor: Dict[str, str] = {}
    for i, item in enumerate(bundle.get("key_changes", [])):
        try:
            t = Transaction.from_dict(item["tx"])
            change = _key_change(t)
            if change is None or not t.signature_valid() or not Chain.verify_tx_proof(t.txid, item["inclusion"], validators):
                problems.append(f"key change {i}: not a proven, final key change")
            else:
                successor[change[0]] = change[1]
        except (KeyError, TypeError):
            problems.append(f"key change {i}: malformed")

    def current(key: str) -> str:
        hops = 0
        while key in successor and hops < 100:
            key, hops = successor[key], hops + 1
        return key

    report: Dict[str, Any] = {"contract_id": cid, "timeline": sorted(timeline, key=lambda e: e["height"] or 0)}
    if create is None:
        problems.append("the bundle does not contain the contract's creating transaction")
    else:
        p = create.payload
        parties = {current(a) for a in p["parties"]}
        signed = {current(create.sender)} if current(create.sender) in parties else set()
        for item in bundle["items"]:
            t = Transaction.from_dict(item["tx"])
            if (t.kind == T.CONTRACT_SIGN and t.payload.get("contract_id") == cid
                    and t.payload.get("prose_hash") == p["prose_hash"] and current(t.sender) in parties):
                signed.add(current(t.sender))
        report.update({"title": p["title"], "parties": p["parties"], "signed_by": sorted(signed),
                       "fully_signed": signed == parties, "prose_hash": p["prose_hash"],
                       "key_changes": dict(successor),
                       "references": p.get("references", [])})
        if bundle.get("prose") is not None:
            report["prose_matches"] = prose_hash(bundle["prose"]) == p["prose_hash"]
            if not report["prose_matches"]:
                problems.append("the enclosed text is NOT the text the parties signed")
    report["problems"] = problems
    report["valid"] = not problems
    return report
