"""Digitally signed, legally readable contracts with a public audit trail.

The design follows Ian Grigg's *Ricardian contract* (2004): one document that is
(a) readable by people and courts, (b) parseable by programs, and (c) identified
by its cryptographic hash, which every party signs.

On-chain (public, permanent):   title, SHA-256 of the prose, machine-readable
                                terms, parties, signatures, references, and an
                                access log of who viewed / used / cited it.
Off-chain (the :class:`ContractVault`): the prose itself.

Keeping prose off-chain matters: a permanent ledger must not hold personal data
that someone may later have a legal right to erase, and restricted contracts
must not be world-readable.  The hash still proves nobody altered the text.

How "who viewed it" is enforced: the vault releases text only in exchange for a
*finalised* ``CONTRACT_ACCESS`` receipt signed by the reader -- one receipt per
read.  The vault is an ordinary service; several independent vaults can mirror
the same prose, and none can forge a receipt or alter the text undetected.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import tx as T
from .chain import Chain
from .crypto import KeyPair, sha256_hex


class Wallet:
    """A key plus local nonce tracking, so callers can queue many transactions."""

    def __init__(self, key: KeyPair, chain_id: str, next_nonce: int = 0):
        self.key, self.chain_id, self.next_nonce = key, chain_id, next_nonce

    @property
    def address(self) -> str:
        return self.key.address

    def resync(self, chain: Chain) -> None:
        """Reset the local nonce from the chain (after a transaction of ours was rejected)."""
        acct = chain.state.accounts.get(self.address)
        self.next_nonce = acct["nonce"] if acct else 0

    def make(self, kind: str, payload: Dict[str, Any]) -> T.Transaction:
        tx = T.Transaction.create(self.chain_id, kind, self.key, self.next_nonce, payload)
        self.next_nonce += 1
        return tx

    # convenience builders ---------------------------------------------- #
    def register(self, name: str, role: str, sector: str = "") -> T.Transaction:
        return self.make(T.REGISTER, {"name": name, "role": role, "sector": sector})

    def pay(self, to: str, amount: int, purpose: str, **extra: Any) -> T.Transaction:
        return self.make(T.PAYMENT, {"to": to, "amount": amount, "purpose": purpose, **extra})

    def create_contract(self, title: str, prose: str, terms: Dict[str, Any], parties: List[str],
                        references: Optional[List[Dict[str, Any]]] = None,
                        visibility: str = "public") -> T.Transaction:
        return self.make(T.CONTRACT_CREATE, {
            "title": title, "prose_hash": prose_hash(prose), "terms": terms, "parties": parties,
            "references": references or [], "visibility": visibility})

    def sign_contract(self, contract_id: str, prose: str) -> T.Transaction:
        return self.make(T.CONTRACT_SIGN, {"contract_id": contract_id, "prose_hash": prose_hash(prose)})

    def access(self, contract_id: str, action: str = "VIEW", context: str = "") -> T.Transaction:
        return self.make(T.CONTRACT_ACCESS, {"contract_id": contract_id, "action": action, "context": context})

    def grant(self, contract_id: str, grantee: str) -> T.Transaction:
        return self.make(T.CONTRACT_GRANT, {"contract_id": contract_id, "grantee": grantee})

    # identity and key helpers ------------------------------------------ #
    def attest(self, subject: str, credential: str) -> T.Transaction:
        return self.make(T.ATTEST, {"subject": subject, "credential_hash": prose_hash(credential)})

    def revoke_attestation(self, subject: str) -> T.Transaction:
        return self.make(T.ATTEST_REVOKE, {"subject": subject})

    def rotate_key(self, new_key: str) -> T.Transaction:
        return self.make(T.KEY_ROTATE, {"new_key": new_key})

    def request_recovery(self, subject: str, new_key: str) -> T.Transaction:
        return self.make(T.RECOVERY_REQUEST, {"subject": subject, "new_key": new_key})

    def veto_recovery(self) -> T.Transaction:
        return self.make(T.RECOVERY_VETO, {})

    def finalize_recovery(self, subject: str, new_key: str) -> T.Transaction:
        return self.make(T.RECOVERY_FINALIZE, {"subject": subject, "new_key": new_key})

    # dispute helpers ---------------------------------------------------- #
    def open_dispute(self, contract_id: str, claim: str, obligations: Optional[List[str]] = None) -> T.Transaction:
        return self.make(T.DISPUTE_OPEN, {"contract_id": contract_id, "claim_hash": prose_hash(claim),
                                          "obligations": obligations or []})

    def file_document(self, contract_id: str, dispute_id: str, document: str, note: str = "") -> T.Transaction:
        return self.make(T.DISPUTE_FILE, {"contract_id": contract_id, "dispute_id": dispute_id,
                                          "document_hash": prose_hash(document), "note": note})

    def withdraw_dispute(self, contract_id: str, dispute_id: str) -> T.Transaction:
        return self.make(T.DISPUTE_WITHDRAW, {"contract_id": contract_id, "dispute_id": dispute_id})

    def award(self, contract_id: str, dispute_id: str, outcome: str, award_text: str,
              adjustments: Optional[List[Dict[str, Any]]] = None) -> T.Transaction:
        return self.make(T.DISPUTE_AWARD, {"contract_id": contract_id, "dispute_id": dispute_id,
                                           "outcome": outcome, "award_hash": prose_hash(award_text),
                                           "adjustments": adjustments or []})


def prose_hash(prose: str) -> str:
    return sha256_hex(prose.encode("utf-8"))


def cite(contract_id: str, relation: str = "cites") -> Dict[str, Any]:
    return {"kind": "contract", "id": contract_id, "relation": relation}


def cite_external(document: bytes, uri: str, note: str = "", relation: str = "cites") -> Dict[str, Any]:
    """Reference a statute, standard, invoice or any file by its hash."""
    return {"kind": "external", "hash": sha256_hex(document), "uri": uri, "note": note, "relation": relation}


# --------------------------------------------------------------------------- #
class VaultError(Exception):
    pass


class ContractVault:
    """Off-chain prose store that only answers receipted, authorised reads."""

    def __init__(self) -> None:
        self._prose: Dict[str, str] = {}
        self._served: Dict[tuple, int] = {}

    def deposit(self, contract_id: str, prose: str, chain: Chain) -> None:
        c = chain.state.contracts.get(contract_id)
        if c is None:
            raise VaultError("unknown contract")
        if prose_hash(prose) != c["prose_hash"]:
            raise VaultError("prose does not match the hash the parties signed")
        self._prose[contract_id] = prose

    def read(self, contract_id: str, reader: str, chain: Chain) -> str:
        if contract_id not in self._prose:
            raise VaultError("prose not held by this vault")
        if not chain.state.can_read(contract_id, reader):
            raise VaultError("reader is not authorised for this contract")
        receipts = sum(1 for e in chain.state.access_log
                       if e["contract_id"] == contract_id and e["accessor"] == reader and e["action"] == "VIEW")
        served = self._served.get((contract_id, reader), 0)
        if served >= receipts:
            raise VaultError("no unspent on-chain VIEW receipt: submit CONTRACT_ACCESS first")
        self._served[(contract_id, reader)] = served + 1
        return self._prose[contract_id]


# --------------------------------------------------------------------------- #
# Queries anyone can run against a chain
# --------------------------------------------------------------------------- #
def audit_trail(chain: Chain, contract_id: str) -> List[Dict[str, Any]]:
    """Every recorded view / use / citation of a contract, with names resolved."""
    out = []
    for e in chain.state.access_log:
        if e["contract_id"] == contract_id:
            out.append({**e, "accessor_name": chain.state.accounts[e["accessor"]]["name"]})
    return out


def cited_by(chain: Chain, contract_id: str) -> List[str]:
    return [c["id"] for c in chain.state.contracts.values()
            if any(r["kind"] == "contract" and r["id"] == contract_id for r in c["references"])]


def provenance(chain: Chain, contract_id: str, _seen: Optional[set] = None) -> Dict[str, Any]:
    """The full tree of what a contract rests on (contracts and external documents)."""
    _seen = _seen if _seen is not None else set()
    c = chain.state.contracts[contract_id]
    node: Dict[str, Any] = {"id": contract_id, "title": c["title"], "status": c["status"], "references": []}
    if contract_id in _seen:
        return node
    _seen.add(contract_id)
    for r in c["references"]:
        if r["kind"] == "contract":
            node["references"].append({"relation": r["relation"], **provenance(chain, r["id"], _seen)})
        else:
            node["references"].append({"relation": r["relation"], "external": r.get("uri", ""),
                                       "hash": r["hash"], "note": r.get("note", "")})
    return node


def summary(chain: Chain, contract_id: str) -> Dict[str, Any]:
    c = chain.state.contracts[contract_id]
    names = chain.state.accounts
    trail = audit_trail(chain, contract_id)
    return {
        "id": contract_id, "title": c["title"], "status": c["status"],
        "parties": [names[a]["name"] for a in c["parties"]],
        "signed_by": {names[a]["name"]: h for a, h in c["signatures"].items()},
        "visibility": c["visibility"],
        "views": sum(1 for e in trail if e["action"] == "VIEW"),
        "uses": sum(1 for e in trail if e["action"] == "USE"),
        "citations": sum(1 for e in trail if e["action"] == "CITE"),
        "cited_by": [chain.state.contracts[i]["title"] for i in cited_by(chain, contract_id)],
    }


# --------------------------------------------------------------------------- #
class ConfidentialWallet:
    """Tracks the opening of an account's hidden balance and builds the proofs.

    The opening (amount and blinding) is the secret that makes the hidden balance
    spendable.  Losing it means the hidden funds cannot be proven and are stuck --
    back it up like the key.  A payment produces a *note* (amount, blinding) that
    must reach the recipient off-ledger, or encrypted in the transaction's ``note``
    field (encryption is not implemented here).
    """

    def __init__(self, wallet: Wallet):
        from . import privacy as PV
        self.w, self.PV = wallet, PV
        self.amount, self.blinding = 0, 0

    @property
    def opening(self):
        return self.PV.Opening(self.amount, self.blinding % self.PV.Q)

    def shield(self, amount: int) -> T.Transaction:
        import secrets
        r = secrets.randbelow(self.PV.Q)
        self.amount, self.blinding = self.amount + amount, (self.blinding + r) % self.PV.Q
        return self.w.make(T.SHIELD, {"amount": amount, "blinding": hex(r)})

    def pay(self, to: str, amount: int, purpose: str, encrypt: bool = True) -> Tuple[T.Transaction, Dict[str, Any]]:
        """Returns the transaction and the secret note.  With ``encrypt`` (default) the note
        also travels inside the transaction, readable only with the recipient's key."""
        PV = self.PV
        if not 0 < amount <= self.amount:
            raise ValueError("insufficient hidden balance")
        c, op = PV.commit(amount)
        remaining = PV.Opening(self.amount - amount, (self.blinding - op.blinding) % PV.Q)
        secret = {"amount": amount, "blinding": hex(op.blinding)}
        tx = self.w.make(T.CONFIDENTIAL_PAYMENT, {
            "to": to, "purpose": purpose, "commitment": PV.commitment_hex(c),
            "proof_amount": PV.range_proof(op), "proof_remaining": PV.range_proof(remaining),
            "note": PV.encrypt_note(to, secret) if encrypt else ""})
        self.amount, self.blinding = remaining.amount, remaining.blinding
        return tx, secret

    def scan(self, chain: Any) -> int:
        """Pick up every confidential payment addressed to us whose note we can decrypt.  Returns the count."""
        PV = self.PV
        seen = getattr(self, "_seen", set())
        found = 0
        for _, t in chain.iter_txs():
            if t.kind == T.CONFIDENTIAL_PAYMENT and t.payload.get("to") == self.w.address and t.txid not in seen and t.payload.get("note"):
                try:
                    note = PV.decrypt_note(self.w.key.secret_hex(), self.w.address, t.payload["note"])
                except Exception:
                    continue
                if PV.verify_opening(PV.commitment_from_hex(t.payload["commitment"]),
                                     PV.Opening(note["amount"], int(note["blinding"], 16))):
                    self.receive(note)
                    found += 1
                seen.add(t.txid)
        self._seen = seen
        return found

    def receive(self, secret_note: Dict[str, Any]) -> None:
        self.amount += secret_note["amount"]
        self.blinding = (self.blinding + int(secret_note["blinding"], 16)) % self.PV.Q

    def unshield(self, amount: int) -> T.Transaction:
        PV = self.PV
        if not 0 < amount <= self.amount:
            raise ValueError("insufficient hidden balance")
        remaining = PV.Opening(self.amount - amount, self.blinding)
        tx = self.w.make(T.UNSHIELD, {"amount": amount, "proof_remaining": PV.range_proof(remaining)})
        self.amount = remaining.amount
        return tx
