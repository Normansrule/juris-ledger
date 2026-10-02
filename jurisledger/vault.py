"""Threshold-encrypted contract vault.

`ContractVault` (contracts.py) refuses reads without an on-chain receipt, but whoever runs it
holds every restricted contract in plain text: one subpoena, one insider or one breach and
they are all out.  This vault removes that single point:

    prose --AES-256-GCM(data key)--> ciphertext            (stored anywhere; useless alone)
    data key --Shamir k-of-n--> n shares, each encrypted to one custodian's own key

A custodian (in practice: a validator, a court registry, the statistics office) releases its
share to a reader only when the chain shows that reader is authorised for the contract and has
recorded an unspent VIEW receipt; the share travels encrypted to the reader's key.  With k
shares the reader rebuilds the data key and decrypts; the text is checked against the hash the
parties signed.  Therefore:

* the storage host, or anyone who steals the sealed file, learns nothing;
* any k-1 custodians, colluding, learn nothing (Shamir's scheme is information-theoretic);
* every read leaves a trace on the public ledger *before* it can happen;
* a custodian that returns a bad share is caught by a per-share hash fixed at sealing time.

Shamir, "How to share a secret", Communications of the ACM 22(11), 1979.  Shares live in the
field of integers modulo the Mersenne prime 2^521 - 1, which holds a 256-bit key with room.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .chain import Chain
from .contracts import prose_hash
from .crypto import KeyPair
from .privacy import decrypt_note, encrypt_note

P = 2 ** 521 - 1
VERSION = 1


class VaultError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Shamir secret sharing
# --------------------------------------------------------------------------- #
def split(secret: int, n: int, k: int) -> List[Tuple[int, int]]:
    if not 1 <= k <= n:
        raise ValueError("need 1 <= k <= n")
    coeffs = [secret] + [secrets.randbelow(P) for _ in range(k - 1)]
    return [(x, sum(c * pow(x, j, P) for j, c in enumerate(coeffs)) % P) for x in range(1, n + 1)]


def combine(shares: Sequence[Tuple[int, int]]) -> int:
    """Lagrange interpolation at zero."""
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share")
    total = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % P
                den = den * (xi - xj) % P
        total = (total + yi * num * pow(den, -1, P)) % P
    return total


def _share_digest(contract_id: str, x: int, y: int) -> str:
    return hashlib.sha256(f"jurisledger/vault-share/v1:{contract_id}:{x}:{y}".encode()).hexdigest()


# --------------------------------------------------------------------------- #
# sealing and opening
# --------------------------------------------------------------------------- #
def seal(contract_id: str, prose: str, chain: Chain, custodians: List[str], threshold: int) -> Dict[str, Any]:
    """Encrypt a contract's text for the vault.  The text must be the one the parties signed."""
    c = chain.state.contracts.get(contract_id)
    if c is None:
        raise VaultError("unknown contract")
    if prose_hash(prose) != c["prose_hash"]:
        raise VaultError("text does not match the hash the parties signed")
    if len(set(custodians)) != len(custodians) or not 1 <= threshold <= len(custodians):
        raise VaultError("need distinct custodians and 1 <= threshold <= number of custodians")
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, prose.encode(), contract_id.encode())
    shares = split(int.from_bytes(key, "big"), len(custodians), threshold)
    return {
        "version": VERSION, "contract_id": contract_id, "prose_hash": c["prose_hash"], "threshold": threshold,
        "nonce": nonce.hex(), "ciphertext": ct.hex(), "custodians": list(custodians),
        "shares": {cust: encrypt_note(cust, {"contract_id": contract_id, "x": x, "y": format(y, "x")})
                   for cust, (x, y) in zip(custodians, shares)},
        "share_digests": {str(x): _share_digest(contract_id, x, y) for x, y in shares},
    }


def open_sealed(sealed: Dict[str, Any], reader: KeyPair, releases: List[str]) -> Tuple[str, List[str]]:
    """Combine released shares (each encrypted to ``reader``) and decrypt.  Returns the text and
    the list of custodians whose release was rejected as invalid."""
    cid, good, bad = sealed["contract_id"], [], []
    for blob in releases:
        try:
            note = decrypt_note(reader.secret_hex(), reader.address, blob)
            x, y = int(note["x"]), int(note["y"], 16)
        except Exception:  # noqa: BLE001 - garbage in a release is a bad release, never a crash
            bad.append("?")
            continue
        if note.get("contract_id") != cid or sealed["share_digests"].get(str(x)) != _share_digest(cid, x, y):
            bad.append(note.get("custodian", "?"))
            continue
        if x not in {g[0] for g in good}:
            good.append((x, y))
    k = sealed["threshold"]
    if len(good) < k:
        raise VaultError(f"{len(good)} valid shares, {k} needed")
    key = combine(good[:k]).to_bytes(32, "big")
    try:
        prose = AESGCM(key).decrypt(bytes.fromhex(sealed["nonce"]), bytes.fromhex(sealed["ciphertext"]), cid.encode()).decode()
    except Exception:  # noqa: BLE001
        raise VaultError("decryption failed: the sealed file was altered") from None
    if prose_hash(prose) != sealed["prose_hash"]:
        raise VaultError("decrypted text does not match the signed hash")
    return prose, bad


# --------------------------------------------------------------------------- #
# custodians
# --------------------------------------------------------------------------- #
@dataclass
class Custodian:
    """Holds one share per sealed contract and releases it only against an on-chain receipt.

    ``journal``: a file where every release is appended and fsync'ed before the share leaves.
    Without it, a restarted custodian would forget which receipts it has already honoured and a
    single receipt could be spent again after every restart."""
    key: KeyPair
    journal: Optional[str] = None
    released: Dict[Tuple[str, str], int] = field(default_factory=dict)
    log: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.journal and os.path.exists(self.journal):
            with open(self.journal) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        break                                   # torn last line: that release never left
                    self.released[(e["contract_id"], e["reader"])] = e["receipt"]
                    self.log.append(e)

    @property
    def address(self) -> str:
        return self.key.address

    def release(self, sealed: Dict[str, Any], reader: str, chain: Chain) -> str:
        cid = sealed["contract_id"]
        if self.address not in sealed["shares"]:
            raise VaultError("this custodian holds no share of that contract")
        c = chain.state.contracts.get(cid)
        if c is None or c["prose_hash"] != sealed["prose_hash"]:
            raise VaultError("the sealed file does not match a contract on this ledger")
        if not chain.state.can_read(cid, reader):
            raise VaultError("the reader is not authorised for this contract on the ledger")
        receipts = sum(1 for e in chain.state.access_log
                       if e["contract_id"] == cid and e["accessor"] == reader and e["action"] == "VIEW")
        used = self.released.get((cid, reader), 0)
        if used >= receipts:
            raise VaultError("no unspent VIEW receipt on the ledger: the reader must record CONTRACT_ACCESS first")
        note = decrypt_note(self.key.secret_hex(), self.address, sealed["shares"][self.address])
        if note.get("contract_id") != cid:
            raise VaultError("share was sealed for another contract")
        entry = {"contract_id": cid, "reader": reader, "height": chain.height, "receipt": used + 1}
        if self.journal:                                        # durable before the share leaves
            with open(self.journal, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        self.released[(cid, reader)] = used + 1
        self.log.append(entry)
        return encrypt_note(reader, {**note, "custodian": self.address})


def collect(sealed: Dict[str, Any], reader: KeyPair, custodians: List[Custodian], chain: Chain) -> Tuple[str, Dict[str, str]]:
    """Ask every custodian; open with whatever valid shares come back.  Returns (text, refusals)."""
    releases, refusals = [], {}
    for cu in custodians:
        try:
            releases.append(cu.release(sealed, reader.address, chain))
        except VaultError as err:
            refusals[cu.address] = str(err)
    prose, bad = open_sealed(sealed, reader, releases)
    for b in bad:
        refusals[b] = "returned an invalid share"
    return prose, refusals


def sealed_bytes(sealed: Dict[str, Any]) -> int:
    return len(json.dumps(sealed))
