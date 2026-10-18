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

from .crypto import KeyPair, canonical, check_portable, sha256_hex, verify

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
SHIELD = "SHIELD"                      # move a public amount into a hidden (committed) balance
CONFIDENTIAL_PAYMENT = "CONFIDENTIAL_PAYMENT"  # pay a hidden amount: commitment + two range proofs
UNSHIELD = "UNSHIELD"                  # reveal and withdraw an amount from the hidden balance
CONFIDENTIAL_CLAIM = "CONFIDENTIAL_CLAIM"  # protocol 2: the recipient accepts (or refuses) an incoming hidden payment
ATTEST = "ATTEST"                      # an accredited issuer vouches for an account (credential by hash)
ATTEST_REVOKE = "ATTEST_REVOKE"        # the issuer withdraws it
KEY_ROTATE = "KEY_ROTATE"              # the owner moves the account to a new key
RECOVERY_REQUEST = "RECOVERY_REQUEST"  # an issuer asks to move a lost-key account to a new key
RECOVERY_VETO = "RECOVERY_VETO"        # the current key cancels a pending recovery
RECOVERY_FINALIZE = "RECOVERY_FINALIZE"  # anyone completes a recovery once the waiting period is over
EVIDENCE = "EVIDENCE"                  # proof that a validator signed two blocks at one height
VALIDATOR_VOTE = "VALIDATOR_VOTE"      # validators vote to add / remove a validator

KINDS = {
    REGISTER, PAYMENT, CONTRACT_CREATE, CONTRACT_SIGN, CONTRACT_ACCESS,
    CONTRACT_GRANT, DISPUTE_OPEN, DISPUTE_FILE, DISPUTE_WITHDRAW, DISPUTE_AWARD,
    SHIELD, CONFIDENTIAL_PAYMENT, UNSHIELD, CONFIDENTIAL_CLAIM, ATTEST, ATTEST_REVOKE, KEY_ROTATE, RECOVERY_REQUEST, RECOVERY_VETO, RECOVERY_FINALIZE,
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
        check_portable(payload)            # never sign what a browser verifier could not reproduce (audit H10)
        unsigned = Transaction(chain_id, kind, key.address, nonce, payload)
        return Transaction(chain_id, kind, key.address, nonce, payload, key.sign(unsigned.signing_bytes()))

    def signature_valid(self) -> bool:
        """Never raises: malformed content (floats, unsafe integers, bad hex) is simply invalid."""
        try:
            return verify(self.sender, self.signing_bytes(), self.signature)
        except (TypeError, ValueError, OverflowError):
            return False

    # -- (de)serialisation -------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        d = self.body()
        d["signature"] = self.signature
        return d

    @staticmethod
    def from_dict(d: Any, strict: bool = True) -> "Transaction":
        """Parse a transaction.  Raises MalformedTransaction (a ValueError) on any shape error,
        so callers need exactly one ``except ValueError``.

        ``strict`` (default; network input, files to submit): every field must have the shape an honest
        wallet produces and the payload must be portable canonical data (audit F01, H10).
        ``strict=False`` (blocks and evidence already on a ledger): only the structure is checked, so
        history written under protocol 1 parses exactly as it always did; the state machine and the
        signature check decide validity."""
        if not isinstance(d, dict):
            raise MalformedTransaction("a transaction must be a JSON object")
        missing = {"chain_id", "kind", "sender", "nonce", "payload", "signature"} - set(d)
        if missing:
            raise MalformedTransaction(f"missing fields: {sorted(missing)}")
        cid, kind, sender, nonce, payload, sig = (d["chain_id"], d["kind"], d["sender"], d["nonce"],
                                                   d["payload"], d["signature"])
        if not strict:
            return Transaction(cid, kind, sender, nonce, payload, sig)
        if not isinstance(cid, str) or not 0 < len(cid) <= 128:
            raise MalformedTransaction("chain_id must be a string of 1-128 characters")
        if kind not in KINDS:
            raise MalformedTransaction("unknown transaction kind")
        if not _is_hex(sender, 64):
            raise MalformedTransaction("sender must be 64 hexadecimal characters")
        if type(nonce) is not int or not 0 <= nonce <= MAX_SAFE_INTEGER:
            raise MalformedTransaction("nonce must be an integer between 0 and 2^53 - 1")
        if not isinstance(payload, dict):
            raise MalformedTransaction("payload must be a JSON object")
        try:
            check_portable(payload)
        except (TypeError, ValueError) as err:
            raise MalformedTransaction(f"payload is not portable canonical data: {err}") from None
        if not (sig == "" or _is_hex(sig, 128)):
            raise MalformedTransaction("signature must be 128 hexadecimal characters")
        return Transaction(cid, kind, sender, nonce, payload, sig)


MAX_SAFE_INTEGER = 2 ** 53 - 1          # largest integer JavaScript represents exactly


class MalformedTransaction(ValueError):
    """Untrusted input that is not a transaction."""


def _is_hex(v: Any, n: int) -> bool:
    return isinstance(v, str) and len(v) == n and all(c in "0123456789abcdef" for c in v)
