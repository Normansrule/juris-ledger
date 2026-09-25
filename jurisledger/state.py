"""The deterministic state machine.

``State.apply(tx, height)`` is the *only* way the ledger changes.  Every
validator and every independent auditor runs exactly this code, so anybody can
recompute the state from the genesis file and the blocks -- nobody has to be
trusted about balances, contract status or who accessed what.

A failed transaction raises :class:`InvalidTx` and leaves the state untouched.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Tuple

from . import privacy as PV
from . import tx as T
from .block import BlockHeader, vote_message
from .crypto import hash_obj, sha256_hex, canonical, verify


class InvalidTx(Exception):
    """Raised when a transaction violates a protocol rule."""


# --------------------------------------------------------------------------- #
# Economic vocabulary (kept deliberately close to the System of National
# Accounts 2008 so that statistics can be computed straight from the ledger).
# --------------------------------------------------------------------------- #
HOUSEHOLD, FIRM, GOVERNMENT, FOREIGN, BANK, VALIDATOR, ISSUER = (
    "household", "firm", "government", "foreign", "bank", "validator", "issuer")
ROLES = {HOUSEHOLD, FIRM, GOVERNMENT, FOREIGN, BANK, VALIDATOR, ISSUER}
INSTITUTIONAL = {GOVERNMENT, VALIDATOR, ISSUER}     # exist only through genesis or governance
SELF_REGISTER_ROLES = {HOUSEHOLD, FIRM, FOREIGN, BANK}

FINAL_CONSUMPTION = "FINAL_CONSUMPTION"        # household buys goods/services        -> C
INTERMEDIATE = "INTERMEDIATE"                  # firm buys inputs from a firm          -> not in GDP
INVESTMENT = "INVESTMENT"                      # purchase of capital goods             -> I
GOVERNMENT_PURCHASE = "GOVERNMENT_PURCHASE"    # government buys goods/services        -> G
EXPORT = "EXPORT"                              # non-resident buys from resident firm  -> X
WAGES = "WAGES"                                # compensation of employees
TAX = "TAX"                                    # payment to government
TRANSFER = "TRANSFER"                          # benefits / subsidies from government
FINANCIAL = "FINANCIAL"                        # loans, repayments, asset trades       -> not in GDP

GOODS_PURPOSES = {FINAL_CONSUMPTION, INTERMEDIATE, INVESTMENT, GOVERNMENT_PURCHASE, EXPORT}

# purpose -> (allowed payer roles, allowed payee roles)
PAYMENT_RULES = {
    FINAL_CONSUMPTION:   ({HOUSEHOLD},               {FIRM, FOREIGN}),
    INTERMEDIATE:        ({FIRM},                    {FIRM, FOREIGN}),
    INVESTMENT:          ({FIRM, HOUSEHOLD},         {FIRM, FOREIGN}),
    GOVERNMENT_PURCHASE: ({GOVERNMENT},              {FIRM, FOREIGN}),
    EXPORT:              ({FOREIGN},                 {FIRM}),
    WAGES:               ({FIRM, GOVERNMENT, BANK},  {HOUSEHOLD}),
    TAX:                 ({HOUSEHOLD, FIRM, BANK, FOREIGN}, {GOVERNMENT}),
    TRANSFER:            ({GOVERNMENT},              {HOUSEHOLD, FIRM}),
    FINANCIAL:           (ROLES - {VALIDATOR, ISSUER}, ROLES - {VALIDATOR, ISSUER}),
}
TAX_TYPES = {"production", "income"}

DRAFT, ACTIVE, SUPERSEDED = "DRAFT", "ACTIVE", "SUPERSEDED"
RELATIONS = {"cites", "amends", "supersedes", "implements"}
VISIBILITIES = {"public", "restricted"}
ACCESS_ACTIONS = {"VIEW", "USE"}
OPEN, CLOSED, WITHDRAWN = "OPEN", "CLOSED", "WITHDRAWN"
AWARD_OUTCOMES = {"UPHELD", "DISMISSED", "SETTLED"}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def quorum(n_validators: int) -> int:
    """Votes needed to finalise: strictly more than two thirds (Byzantine quorum)."""
    return (2 * n_validators) // 3 + 1


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise InvalidTx(msg)


def _is_hash(x: Any) -> bool:
    return isinstance(x, str) and bool(_HEX64.match(x))


class State:
    def __init__(self, chain_id: str):
        self.chain_id = chain_id
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.disputes: Dict[str, Dict[str, Any]] = {}
        self.access_log: List[Dict[str, Any]] = []     # derived, fully auditable
        self.access_digest = sha256_hex(b"jurisledger-access-log")
        self.validators: List[str] = []
        self.slashed: List[str] = []
        self.gov_votes: Dict[str, List[str]] = {}
        self.evidence_seen: List[str] = []
        self.issuers: List[str] = []                       # accredited identity issuers
        self.policy: Dict[str, int] = {}                   # empty = open network (no identity rules)
        self.recoveries: Dict[str, Dict[str, Any]] = {}    # subject -> pending lost-key recovery

    # ------------------------------------------------------------------ #
    @staticmethod
    def from_genesis(genesis: Dict[str, Any]) -> "State":
        s = State(genesis["chain_id"])
        for a in genesis.get("accounts", []):
            _need(a["role"] in ROLES, f"bad role in genesis: {a['role']}")
            s.accounts[a["address"]] = {
                "name": a["name"], "role": a["role"], "sector": a.get("sector", ""),
                "balance": int(a.get("balance", 0)), "nonce": 0,
            }
            if a.get("attestations"):
                s.accounts[a["address"]]["attestations"] = dict(a["attestations"])
        for i in genesis.get("issuers", []):
            s.issuers.append(i["address"])
            s.accounts[i["address"]] = {"name": i["name"], "role": ISSUER, "sector": "", "balance": 0, "nonce": 0}
        s.policy = {k: int(v) for k, v in genesis.get("policy", {}).items()}
        for v in genesis["validators"]:
            s.validators.append(v)
            s.accounts.setdefault(v, {"name": f"validator-{v[:8]}", "role": VALIDATOR,
                                      "sector": "", "balance": 0, "nonce": 0})
        return s

    def copy(self) -> "State":
        return copy.deepcopy(self)

    def root(self) -> str:
        return hash_obj({
            "accounts": self.accounts, "contracts": self.contracts, "disputes": self.disputes,
            "validators": self.validators, "slashed": self.slashed,
            "gov_votes": self.gov_votes, "evidence": self.evidence_seen,
            "issuers": self.issuers, "policy": self.policy, "recoveries": self.recoveries,
            "access_digest": self.access_digest,
        })

    def is_resident(self, address: str) -> bool:
        return self.accounts[address]["role"] != FOREIGN

    # ------------------------------------------------------------------ #
    def apply(self, tx: T.Transaction, height: int) -> None:
        _need(tx.chain_id == self.chain_id, "wrong chain_id (cross-chain replay?)")
        _need(tx.kind in T.KINDS, f"unknown transaction kind {tx.kind}")
        _need(isinstance(tx.nonce, int) and tx.nonce >= 0, "bad nonce")
        _need(tx.signature_valid(), "invalid signature")

        if tx.kind == T.REGISTER:
            self._register(tx)
            return

        acct = self.accounts.get(tx.sender)
        _need(acct is not None, "sender is not registered")
        _need("successor" not in acct, "this key was replaced; sign with the account's new key")
        _need(tx.nonce == acct["nonce"], f"bad nonce (expected {acct['nonce']}, got {tx.nonce})")

        handler = {
            T.PAYMENT: self._payment,
            T.CONTRACT_CREATE: self._contract_create,
            T.CONTRACT_SIGN: self._contract_sign,
            T.CONTRACT_ACCESS: self._contract_access,
            T.CONTRACT_GRANT: self._contract_grant,
            T.DISPUTE_OPEN: self._dispute_open,
            T.DISPUTE_FILE: self._dispute_file,
            T.DISPUTE_WITHDRAW: self._dispute_withdraw,
            T.DISPUTE_AWARD: self._dispute_award,
            T.SHIELD: self._shield,
            T.CONFIDENTIAL_PAYMENT: self._confidential_payment,
            T.UNSHIELD: self._unshield,
            T.ATTEST: self._attest,
            T.ATTEST_REVOKE: self._attest_revoke,
            T.KEY_ROTATE: self._key_rotate,
            T.RECOVERY_REQUEST: self._recovery_request,
            T.RECOVERY_VETO: self._recovery_veto,
            T.RECOVERY_FINALIZE: self._recovery_finalize,
            T.EVIDENCE: self._evidence,
            T.VALIDATOR_VOTE: self._validator_vote,
        }[tx.kind]
        handler(tx, height)               # validates fully before mutating
        acct["nonce"] += 1

    # -- accounts ------------------------------------------------------- #
    def _register(self, tx: T.Transaction) -> None:
        p = tx.payload
        _need(tx.sender not in self.accounts, "account already registered")
        _need(tx.nonce == 0, "REGISTER must use nonce 0")
        _need(p.get("role") in SELF_REGISTER_ROLES,
              "role cannot be self-registered (government/validator come from genesis or governance)")
        _need(isinstance(p.get("name"), str) and 0 < len(p["name"]) <= 80, "bad name")
        sector = p.get("sector", "")
        _need(isinstance(sector, str) and len(sector) <= 40, "bad sector")
        if p["role"] == FIRM:
            _need(sector != "", "firms must declare a sector")
        self.accounts[tx.sender] = {"name": p["name"], "role": p["role"], "sector": sector,
                                    "balance": 0, "nonce": 1}

    # -- payments ------------------------------------------------------- #
    def _payment(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        payer = self.accounts[tx.sender]
        to = p.get("to")
        _need(to in self.accounts, "recipient is not registered")
        _need(to != tx.sender, "cannot pay yourself")
        payee = self.accounts[to]
        amount = p.get("amount")
        _need(isinstance(amount, int) and not isinstance(amount, bool) and amount > 0,
              "amount must be a positive integer (minor units)")
        purpose = p.get("purpose")
        _need(purpose in PAYMENT_RULES, f"unknown purpose {purpose}")
        payer_roles, payee_roles = PAYMENT_RULES[purpose]
        _need(payer["role"] in payer_roles, f"a {payer['role']} cannot pay for {purpose}")
        _need(payee["role"] in payee_roles, f"a {payee['role']} cannot be paid for {purpose}")
        if purpose == TAX:
            _need(p.get("tax_type") in TAX_TYPES, "TAX needs tax_type production|income")
        if "invoice" in p:
            _need(_is_hash(p["invoice"]), "invoice must be a SHA-256 hex digest")
        _need("successor" not in payee, "the recipient's key was replaced; pay the account's new key")
        if amount > self.policy.get("unverified_payment_limit", amount):
            self._require_verified(tx.sender, "pay more than the limit for unverified accounts")
        _need(payer["balance"] >= amount, "insufficient balance")

        contract = None
        if "contract" in p:
            contract = self.contracts.get(p["contract"])
            _need(contract is not None, "unknown contract")
            _need(contract["status"] == ACTIVE, "contract is not ACTIVE")
            _need(tx.sender in contract["parties"] and to in contract["parties"],
                  "payer and payee must both be parties to the contract")
        if "obligation" in p:
            _need(contract is not None, "an obligation payment must name its contract")
            ob = next((o for o in contract["terms"].get("obligations", []) if o["id"] == p["obligation"]), None)
            _need(ob is not None, "unknown obligation")
            _need(ob["payer"] == tx.sender and ob["payee"] == to, "payment does not match the obligation's payer and payee")

        payer["balance"] -= amount
        payee["balance"] += amount
        if contract is not None:
            self._log_access(contract["id"], tx.sender, "USE", f"payment {tx.txid[:12]}", height, tx.txid)

    # -- contracts ------------------------------------------------------ #
    def _contract_create(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        _need(isinstance(p.get("title"), str) and 0 < len(p["title"]) <= 200, "bad title")
        _need(_is_hash(p.get("prose_hash")), "prose_hash must be a SHA-256 hex digest")
        _need(isinstance(p.get("terms"), dict), "terms must be an object")
        parties = p.get("parties")
        _need(isinstance(parties, list) and parties and len(set(parties)) == len(parties),
              "parties must be a non-empty list without duplicates")
        for a in parties:
            _need(a in self.accounts, f"party {str(a)[:12]} is not registered")
        for a in parties:
            self._require_verified(a, "be a party to a contract")
        visibility = p.get("visibility", "public")
        _need(visibility in VISIBILITIES, "bad visibility")
        refs = p.get("references", [])
        _need(isinstance(refs, list), "references must be a list")
        for r in refs:
            _need(isinstance(r, dict) and r.get("relation") in RELATIONS, "bad reference relation")
            if r.get("kind") == "contract":
                _need(r.get("id") in self.contracts, "referenced contract does not exist")
            elif r.get("kind") == "external":
                _need(_is_hash(r.get("hash")), "external reference needs a SHA-256 hash")
            else:
                raise InvalidTx("reference kind must be contract|external")

        self._check_obligations(p["terms"].get("obligations", []), parties)
        if "arbitration" in p["terms"]:
            arb = p["terms"]["arbitration"]
            _need(isinstance(arb, dict) and arb.get("arbitrator") in self.accounts,
                  "arbitration clause must name a registered arbitrator")
            _need(arb["arbitrator"] not in parties, "a party cannot be its own arbitrator")

        cid = tx.txid
        _need(cid not in self.contracts, "duplicate contract")
        c = {"id": cid, "creator": tx.sender, "title": p["title"], "prose_hash": p["prose_hash"],
             "terms": p["terms"], "parties": list(parties), "references": refs,
             "visibility": visibility, "grantees": [], "adjustments": {}, "signatures": {}, "status": DRAFT,
             "created_height": height, "activated_height": None}
        self.contracts[cid] = c
        for r in refs:
            if r["kind"] == "contract":
                self._log_access(r["id"], tx.sender, "CITE", f"{r['relation']} by {cid[:12]}", height, tx.txid)
        if tx.sender in parties:          # the creator's signature on this tx covers prose_hash
            c["signatures"][tx.sender] = height
            self._maybe_activate(c, height)

    @staticmethod
    def _check_obligations(obs: Any, parties: List[str]) -> None:
        """Optional machine-readable payment duties: who owes whom how much by which block."""
        _need(isinstance(obs, list), "terms.obligations must be a list")
        seen = set()
        for o in obs:
            _need(isinstance(o, dict), "bad obligation")
            _need(isinstance(o.get("id"), str) and 0 < len(o["id"]) <= 40 and o["id"] not in seen,
                  "obligation ids must be unique short strings")
            seen.add(o["id"])
            _need(o.get("payer") in parties and o.get("payee") in parties and o["payer"] != o["payee"],
                  "obligation payer and payee must be two different parties")
            for k in ("amount", "due_height"):
                _need(isinstance(o.get(k), int) and not isinstance(o[k], bool) and o[k] > 0,
                      f"obligation {k} must be a positive integer")

    def _contract_sign(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        c = self.contracts.get(p.get("contract_id"))
        _need(c is not None, "unknown contract")
        _need(c["status"] == DRAFT, "contract is not open for signature")
        _need(tx.sender in c["parties"], "only a named party may sign")
        _need(tx.sender not in c["signatures"], "already signed")
        self._require_verified(tx.sender, "sign a contract")
        _need(p.get("prose_hash") == c["prose_hash"],
              "signer must attest to the exact prose hash they are agreeing to")
        c["signatures"][tx.sender] = height
        self._maybe_activate(c, height)

    def _maybe_activate(self, c: Dict[str, Any], height: int) -> None:
        if set(c["signatures"]) != set(c["parties"]):
            return
        c["status"] = ACTIVE
        c["activated_height"] = height
        for r in c["references"]:
            if r["kind"] == "contract" and r["relation"] == "supersedes":
                old = self.contracts[r["id"]]
                # Only the old contract's own parties can replace it.
                if old["status"] == ACTIVE and set(old["parties"]) <= set(c["parties"]):
                    old["status"] = SUPERSEDED

    def can_read(self, contract_id: str, address: str) -> bool:
        c = self.contracts.get(contract_id)
        if c is None or address not in self.accounts:
            return False
        return (c["visibility"] == "public" or address in c["parties"] or address in c["grantees"]
                or address == self.arbitrator_of(c))

    @staticmethod
    def arbitrator_of(contract: Dict[str, Any]) -> Optional[str]:
        return contract["terms"].get("arbitration", {}).get("arbitrator")

    def _contract_access(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        cid = p.get("contract_id")
        _need(cid in self.contracts, "unknown contract")
        _need(p.get("action") in ACCESS_ACTIONS, "action must be VIEW|USE")
        context = p.get("context", "")
        _need(isinstance(context, str) and len(context) <= 200, "bad context")
        _need(self.can_read(cid, tx.sender), "not authorised to access this contract")
        self._log_access(cid, tx.sender, p["action"], context, height, tx.txid)

    def _contract_grant(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        c = self.contracts.get(p.get("contract_id"))
        _need(c is not None, "unknown contract")
        _need(tx.sender in c["parties"], "only a party may grant access")
        _need(p.get("grantee") in self.accounts, "grantee is not registered")
        _need(p["grantee"] not in c["grantees"], "already granted")
        c["grantees"].append(p["grantee"])

    def _log_access(self, cid: str, who: str, action: str, context: str, height: int, txid: str) -> None:
        entry = {"contract_id": cid, "accessor": who, "action": action,
                 "context": context, "height": height, "txid": txid}
        self.access_log.append(entry)
        self.access_digest = sha256_hex(bytes.fromhex(self.access_digest) + canonical(entry))

    # -- disputes ------------------------------------------------------- #
    # The arbitrator is chosen by the parties, inside the contract they all signed.
    # Its powers are deliberately narrow: it acts only after a party opens a dispute,
    # only once per dispute, only on the obligations in dispute, and it can only
    # reduce, postpone or waive what is owed.  It can never move money.
    def _dispute_open(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        c = self.contracts.get(p.get("contract_id"))
        _need(c is not None, "unknown contract")
        _need(c["status"] != DRAFT, "a draft contract cannot be disputed")
        _need(tx.sender in c["parties"], "only a party may open a dispute")
        _need(self.arbitrator_of(c) is not None, "the contract has no arbitration clause")
        _need(_is_hash(p.get("claim_hash")), "claim_hash must be a SHA-256 hex digest")
        obs = p.get("obligations", [])
        known = {o["id"] for o in c["terms"].get("obligations", [])}
        _need(isinstance(obs, list) and len(set(obs)) == len(obs) and all(o in known for o in obs),
              "disputed obligations must be distinct obligations of this contract")
        self.disputes[tx.txid] = {"id": tx.txid, "contract_id": c["id"], "claimant": tx.sender,
                                  "claim_hash": p["claim_hash"], "obligations": list(obs), "status": OPEN,
                                  "opened_height": height, "closed_height": None, "filings": [], "award": None}

    def _open_dispute(self, p: Dict[str, Any]) -> Dict[str, Any]:
        d = self.disputes.get(p.get("dispute_id"))
        _need(d is not None and d["contract_id"] == p.get("contract_id"), "unknown dispute for this contract")
        _need(d["status"] == OPEN, "the dispute is no longer open")
        return d

    def _dispute_file(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        d = self._open_dispute(p)
        c = self.contracts[d["contract_id"]]
        _need(tx.sender in c["parties"] or tx.sender == self.arbitrator_of(c),
              "only the parties and the arbitrator may file")
        _need(_is_hash(p.get("document_hash")), "document_hash must be a SHA-256 hex digest")
        note = p.get("note", "")
        _need(isinstance(note, str) and len(note) <= 200, "bad note")
        d["filings"].append({"by": tx.sender, "document_hash": p["document_hash"], "note": note, "height": height})

    def _dispute_withdraw(self, tx: T.Transaction, height: int) -> None:
        d = self._open_dispute(tx.payload)
        _need(tx.sender == d["claimant"], "only the claimant may withdraw")
        d["status"], d["closed_height"] = WITHDRAWN, height

    def _dispute_award(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        d = self._open_dispute(p)
        c = self.contracts[d["contract_id"]]
        _need(tx.sender == self.arbitrator_of(c), "only the arbitrator named in the contract may decide")
        _need(p.get("outcome") in AWARD_OUTCOMES, "outcome must be UPHELD|DISMISSED|SETTLED")
        _need(_is_hash(p.get("award_hash")), "award_hash must be a SHA-256 hex digest")
        adjustments = p.get("adjustments", [])
        _need(isinstance(adjustments, list), "adjustments must be a list")
        originals = {o["id"]: o for o in c["terms"].get("obligations", [])}
        clean: Dict[str, Dict[str, Any]] = {}
        for a in adjustments:
            _need(isinstance(a, dict) and a.get("obligation") in d["obligations"] and a["obligation"] not in clean,
                  "an award may only adjust obligations that are in dispute, once each")
            ob, adj = originals[a["obligation"]], {"height": height, "dispute_id": d["id"]}
            if "amount" in a:
                _need(isinstance(a["amount"], int) and not isinstance(a["amount"], bool)
                      and 0 < a["amount"] <= ob["amount"], "an award cannot increase what is owed")
                adj["amount"] = a["amount"]
            if "due_height" in a:
                _need(isinstance(a["due_height"], int) and not isinstance(a["due_height"], bool)
                      and a["due_height"] >= ob["due_height"], "an award cannot bring a due date forward")
                adj["due_height"] = a["due_height"]
            if "waived" in a:
                _need(a["waived"] is True, "waived must be true when present")
                adj["waived"] = True
            _need(len(adj) > 2, "empty adjustment")
            clean[a["obligation"]] = adj
        c["adjustments"].update(clean)
        d["status"], d["closed_height"] = CLOSED, height
        d["award"] = {"outcome": p["outcome"], "award_hash": p["award_hash"], "height": height,
                      "adjusted": sorted(clean)}

    # -- confidential balances ------------------------------------------ #
    # Each account may hold, beside its public balance, a *hidden* balance known
    # only as a Pedersen commitment.  Amounts moved between hidden balances are
    # never revealed; the range proofs guarantee that nothing negative is ever
    # transferred and that nobody spends more than they have.  Purpose tags and
    # counterparties stay public, so statistics can still add the commitments up.
    _proof_cache: Dict[Tuple[str, str], bool] = {}

    def hidden(self, address: str):
        h = self.accounts[address].get("hidden")
        return PV.commitment_from_hex(h) if h else PV.IDENTITY

    def _set_hidden(self, address: str, c) -> None:
        if c == PV.IDENTITY:
            self.accounts[address].pop("hidden", None)
        else:
            self.accounts[address]["hidden"] = PV.commitment_hex(c)

    @classmethod
    def _range_ok(cls, commitment, proof: Any) -> bool:
        key = (PV.commitment_hex(commitment), hash_obj(proof) if isinstance(proof, dict) else "")
        if key not in cls._proof_cache:
            if len(cls._proof_cache) > 10_000:
                cls._proof_cache.clear()
            cls._proof_cache[key] = PV.verify_range_proof(commitment, proof)
        return cls._proof_cache[key]

    def _confidential_allowed(self, *addresses: str) -> None:
        for a in addresses:
            self._require_verified(a, "use confidential balances")

    def _shield(self, tx: T.Transaction, height: int) -> None:
        p, acct = tx.payload, self.accounts[tx.sender]
        amount = p.get("amount")
        _need(isinstance(amount, int) and not isinstance(amount, bool) and 0 < amount <= PV.MAX_HIDDEN,
              f"amount must be a positive integer up to {PV.MAX_HIDDEN}")
        _need(isinstance(p.get("blinding"), str), "blinding must be a hex string")
        try:
            blinding = int(p["blinding"], 16)
        except ValueError:
            raise InvalidTx("blinding must be a hex string")
        self._confidential_allowed(tx.sender)
        _need(acct["balance"] >= amount, "insufficient balance")
        acct["balance"] -= amount
        self._set_hidden(tx.sender, self.hidden(tx.sender) + PV.commit(amount, blinding)[0])

    def _confidential_payment(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        to = p.get("to")
        _need(to in self.accounts and to != tx.sender, "bad recipient")
        _need("successor" not in self.accounts[to], "the recipient's key was replaced")
        purpose = p.get("purpose")
        _need(purpose in PAYMENT_RULES, f"unknown purpose {purpose}")
        payer_roles, payee_roles = PAYMENT_RULES[purpose]
        _need(self.accounts[tx.sender]["role"] in payer_roles, f"a {self.accounts[tx.sender]['role']} cannot pay for {purpose}")
        _need(self.accounts[to]["role"] in payee_roles, f"a {self.accounts[to]['role']} cannot be paid for {purpose}")
        note = p.get("note", "")
        _need(isinstance(note, str) and len(note) <= 1024, "note too long")
        self._confidential_allowed(tx.sender, to)
        try:
            amount_c = PV.commitment_from_hex(p.get("commitment", ""))
        except (ValueError, TypeError):
            raise InvalidTx("commitment must be a valid curve point in hex")
        remaining = self.hidden(tx.sender) - amount_c
        _need(self._range_ok(amount_c, p.get("proof_amount")), "range proof on the amount is invalid")
        _need(self._range_ok(remaining, p.get("proof_remaining")),
              "range proof on the remaining balance is invalid (overspending or a negative amount)")
        self._set_hidden(tx.sender, remaining)
        self._set_hidden(to, self.hidden(to) + amount_c)

    def _unshield(self, tx: T.Transaction, height: int) -> None:
        p, acct = tx.payload, self.accounts[tx.sender]
        amount = p.get("amount")
        _need(isinstance(amount, int) and not isinstance(amount, bool) and 0 < amount <= PV.MAX_HIDDEN, "bad amount")
        remaining = self.hidden(tx.sender) - PV.G * amount
        _need(self._range_ok(remaining, p.get("proof_remaining")),
              "range proof on the remaining balance is invalid (withdrawing more than is held)")
        self._set_hidden(tx.sender, remaining)
        acct["balance"] += amount

    # -- identity: several independent issuers, no single gatekeeper ---- #
    def attestation_count(self, address: str) -> int:
        held = self.accounts.get(address, {}).get("attestations", {})
        return sum(1 for issuer in held if issuer in self.issuers)

    def is_verified(self, address: str) -> bool:
        need = self.policy.get("min_attestations", 0)
        acct = self.accounts.get(address)
        return acct is not None and (need == 0 or acct["role"] in INSTITUTIONAL
                                     or self.attestation_count(address) >= need)

    def _require_verified(self, address: str, what: str) -> None:
        _need(self.is_verified(address),
              f"{self.accounts[address]['name']} needs {self.policy.get('min_attestations', 0)} independent "
              f"identity attestations to {what} (has {self.attestation_count(address)})")

    def _attest(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        _need(tx.sender in self.issuers, "only an accredited issuer may attest")
        subject = self.accounts.get(p.get("subject"))
        _need(subject is not None and "successor" not in subject, "unknown subject")
        _need(subject["role"] not in INSTITUTIONAL, "institutional accounts are not attested")
        _need(_is_hash(p.get("credential_hash")), "credential_hash must be a SHA-256 hex digest")
        subject.setdefault("attestations", {})[tx.sender] = {"credential_hash": p["credential_hash"], "height": height}

    def _attest_revoke(self, tx: T.Transaction, height: int) -> None:
        subject = self.accounts.get(tx.payload.get("subject"))
        _need(subject is not None and tx.sender in subject.get("attestations", {}),
              "no attestation by this issuer to revoke")
        del subject["attestations"][tx.sender]

    # -- keys: rotation by the owner, recovery through issuers + waiting period
    def _migrate(self, old: str, new: str, height: int) -> None:
        src = self.accounts[old]
        self.accounts[new] = {**copy.deepcopy(src), "nonce": 0, "previous_key": old}
        src.update({"balance": 0, "successor": new, "replaced_at": height})
        src.pop("attestations", None)
        swap = lambda a: new if a == old else a
        for c in self.contracts.values():
            c["parties"] = [swap(a) for a in c["parties"]]
            c["grantees"] = [swap(a) for a in c["grantees"]]
            c["signatures"] = {swap(a): h for a, h in c["signatures"].items()}
            for ob in c["terms"].get("obligations", []):
                ob["payer"], ob["payee"] = swap(ob["payer"]), swap(ob["payee"])
            if self.arbitrator_of(c) == old:
                c["terms"]["arbitration"]["arbitrator"] = new
        for d in self.disputes.values():
            d["claimant"] = swap(d["claimant"])
        self.recoveries.pop(old, None)

    def _check_new_key(self, new: Any) -> None:
        _need(_is_hash(new), "new_key must be a 32-byte public key in hex")
        _need(new not in self.accounts, "new_key is already in use")

    def _key_rotate(self, tx: T.Transaction, height: int) -> None:
        _need(self.accounts[tx.sender]["role"] not in {VALIDATOR, ISSUER},
              "validators and issuers change keys through governance votes")
        self._check_new_key(tx.payload.get("new_key"))
        self._migrate(tx.sender, tx.payload["new_key"], height)

    def _recovery_request(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        _need(tx.sender in self.issuers, "only an accredited issuer may request a recovery")
        subject = self.accounts.get(p.get("subject"))
        _need(subject is not None and "successor" not in subject and subject["role"] not in INSTITUTIONAL,
              "unknown or ineligible subject")
        _need(tx.sender in subject.get("attestations", {}), "an issuer may only recover accounts it has attested")
        self._check_new_key(p.get("new_key"))
        r = self.recoveries.get(p["subject"])
        if r is None or r["new_key"] != p["new_key"]:
            r = self.recoveries[p["subject"]] = {"new_key": p["new_key"], "issuers": [], "effective_height": None}
        _need(tx.sender not in r["issuers"], "this issuer already requested it")
        r["issuers"].append(tx.sender)
        if len(r["issuers"]) >= max(1, self.policy.get("min_attestations", 1)) and r["effective_height"] is None:
            r["effective_height"] = height + self.policy.get("recovery_delay", 10)

    def _recovery_veto(self, tx: T.Transaction, height: int) -> None:
        _need(tx.sender in self.recoveries, "there is no pending recovery for this account")
        del self.recoveries[tx.sender]

    def _recovery_finalize(self, tx: T.Transaction, height: int) -> None:
        subject = tx.payload.get("subject")
        r = self.recoveries.get(subject)
        _need(r is not None and r["effective_height"] is not None, "no approved recovery for this account")
        _need(tx.payload.get("new_key") == r["new_key"], "new_key does not match the approved recovery")
        _need(height >= r["effective_height"],
              f"the waiting period runs until block {r['effective_height']} so the owner can veto")
        self._check_new_key(r["new_key"])
        self._migrate(subject, r["new_key"], height)

    # -- validator accountability --------------------------------------- #
    def _evidence(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        v = p.get("validator")
        _need(v in self.validators, "accused is not an active validator")
        try:
            ha, hb = BlockHeader.from_dict(p["header_a"]), BlockHeader.from_dict(p["header_b"])
            sa, sb = p["sig_a"], p["sig_b"]
        except (KeyError, TypeError):
            raise InvalidTx("malformed evidence")
        _need(ha.chain_id == hb.chain_id == self.chain_id, "evidence is for another chain")
        _need(ha.height == hb.height, "headers are not for the same height")
        _need(ha.hash != hb.hash, "headers are identical - no equivocation")
        # Equivocation = two finalising votes in the SAME voting round.  (Under two-phase
        # consensus an honest validator may vote for different blocks in different rounds.)
        vote_round = p.get("round", ha.round)
        _need(isinstance(vote_round, int) and not isinstance(vote_round, bool) and vote_round >= 0, "bad round")
        if "round" not in p:
            _need(ha.round == hb.round, "headers are not for the same round")
        _need(verify(v, vote_message(self.chain_id, ha.height, vote_round, ha.hash), sa), "sig_a invalid")
        _need(verify(v, vote_message(self.chain_id, hb.height, vote_round, hb.hash), sb), "sig_b invalid")
        self.validators.remove(v)
        self.slashed.append(v)
        self.evidence_seen.append(f"{v}:{ha.height}:{vote_round}")
        self.gov_votes = {}               # validator set changed; pending tallies are void

    def _validator_vote(self, tx: T.Transaction, height: int) -> None:
        p = tx.payload
        _need(tx.sender in self.validators, "only validators vote on the validator set")
        action, target = p.get("action"), p.get("target")
        _need(action in {"ADD", "REMOVE", "ADD_ISSUER", "REMOVE_ISSUER"},
              "action must be ADD|REMOVE|ADD_ISSUER|REMOVE_ISSUER")
        _need(isinstance(target, str) and re.match(r"^[0-9a-f]{64}$", target) is not None, "bad target")
        if action == "ADD":
            _need(target not in self.validators, "already a validator")
            _need(target not in self.slashed, "slashed validators cannot return")
        elif action == "REMOVE":
            _need(target in self.validators, "target is not a validator")
            _need(len(self.validators) > 1, "cannot remove the last validator")
        elif action == "ADD_ISSUER":
            _need(target not in self.issuers and target not in self.accounts, "issuer key must be new")
            _need(isinstance(p.get("name"), str) and 0 < len(p["name"]) <= 80, "ADD_ISSUER needs a name")
        else:
            _need(target in self.issuers, "target is not an issuer")
        key = f"{action}:{target}"
        voters = self.gov_votes.setdefault(key, [])
        _need(tx.sender not in voters, "already voted")
        voters.append(tx.sender)
        live = [v for v in voters if v in self.validators]
        if len(live) >= quorum(len(self.validators)):
            if action == "ADD":
                self.validators.append(target)
                self.accounts.setdefault(target, {"name": f"validator-{target[:8]}", "role": VALIDATOR,
                                                  "sector": "", "balance": 0, "nonce": 0})
            elif action == "REMOVE":
                self.validators.remove(target)
            elif action == "ADD_ISSUER":
                self.issuers.append(target)
                self.accounts[target] = {"name": p["name"], "role": ISSUER, "sector": "", "balance": 0, "nonce": 0}
            else:
                self.issuers.remove(target)          # its attestations stop counting at once
            self.gov_votes = {}
