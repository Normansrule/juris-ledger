"""Signed transactions.

Every state change in JurisLedger is a transaction signed by the account that
authorises it.  A transaction is bound to

* a ``chain_id``  -> cannot be replayed on another JurisLedger network,
* a ``nonce``     -> cannot be replayed on the same network,
* its ``sender``  -> the Ed25519 public key that must have produced ``signature``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from .crypto import KeyPair, canonical, sha256_hex, verify

# Transaction kinds ---------------------------------------------------------- #
REGISTER = "REGISTER"                  # create an account (role, sector, residency)
PAYMENT = "PAYMENT"                    # move money, tagged with an economic purpose
CONTRACT_CREATE = "CONTRACT_CREATE"    # publish a Ricardian contract (hash of prose + terms)
CONTRACT_SIGN = "CONTRACT_SIGN"        # a party signs the exact prose hash
CONTRACT_ACCESS = "CONTRACT_ACCESS"    # signed receipt: who viewed / used / cited a contract
CONTRACT_GRANT = "CONTRACT_GRANT"      # a party lets a third account read a restricted contract
DISPUTE_OPEN = "DISPUTE_OPEN"          # a party files a claim under the contract's arbitration clause
DISPUTE_FILE = "DISPUTE_FILE"          # a party or the arbitrator files a document (by hash)
DISPUTE_WITHDRAW = "DISPUTE_WITHDRAW"  # the claimant withdraws
DISPUTE_AWARD = "DISPUTE_AWARD"        # the named arbitrator decides, within narrow limits
EVIDENCE = "EVIDENCE"                  # proof that a validator signed two blocks at one height
VALIDATOR_VOTE = "VALIDATOR_VOTE"      # validators vote to add / remove a validator

KINDS = {
    REGISTER, PAYMENT, CONTRACT_CREATE, CONTRACT_SIGN, CONTRACT_ACCESS,
    CONTRACT_GRANT, DISPUTE_OPEN, DISPUTE_FILE, DISPUTE_WITHDRAW, DISPUTE_AWARD,
    EVIDENCE, VALIDATOR_VOTE,
}


@dataclass(frozen=True)
class Transaction:
    chain_id: str
    kind: str
    sender: str
    nonce: int
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    # -- identity ----------------------------------------------------------- #
    def body(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "kind": self.kind,
            "sender": self.sender,
            "nonce": self.nonce,
            "payload": self.payload,
        }

    def signing_bytes(self) -> bytes:
        return b"jurisledger/tx/v1:" + canonical(self.body())

    @property
    def txid(self) -> str:
        """Hash of the signed content (the signature itself is excluded)."""
        return sha256_hex(self.signing_bytes())

    # -- construction / verification ---------------------------------------- #
    @staticmethod
    def create(chain_id: str, kind: str, key: KeyPair, nonce: int, payload: Dict[str, Any]) -> "Transaction":
        unsigned = Transaction(chain_id, kind, key.address, nonce, payload)
        return Transaction(chain_id, kind, key.address, nonce, payload, key.sign(unsigned.signing_bytes()))

    def signature_valid(self) -> bool:
        return verify(self.sender, self.signing_bytes(), self.signature)

    # -- (de)serialisation -------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        d = self.body()
        d["signature"] = self.signature
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Transaction":
        return Transaction(d["chain_id"], d["kind"], d["sender"], d["nonce"], d["payload"], d["signature"])
