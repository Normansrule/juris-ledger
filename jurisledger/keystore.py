"""Key files, optionally encrypted at rest.

A plain key file holds the raw Ed25519 seed: whoever can read the file can sign as that
account.  An encrypted key file ("keystore") holds the seed sealed with a passphrase:

    passphrase --scrypt(salt, N=2^15, r=8, p=1)--> 256-bit key --AES-256-GCM(nonce)--> ciphertext

scrypt (Percival 2009, RFC 7914) makes every passphrase guess cost memory and time, so a
stolen file does not fall to a fast offline dictionary attack.  AES-GCM authenticates as
well as encrypts, and the account address is bound in as associated data, so a keystore
cannot be edited or swapped onto another address undetected.  The passphrase comes from
the caller, the JURISLEDGER_PASSPHRASE environment variable, or an interactive prompt.
"""
from __future__ import annotations

import getpass
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import KeyPair

VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


class KeystoreError(Exception):
    pass


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def seal(key: KeyPair, passphrase: str) -> dict:
    if len(passphrase) < 8:
        raise KeystoreError("use a passphrase of at least 8 characters")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(
        nonce, bytes.fromhex(key.secret_hex()), bytes.fromhex(key.address))
    return {"version": VERSION, "address": key.address, "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": salt.hex(), "cipher": "aes-256-gcm", "nonce": nonce.hex(), "ciphertext": ct.hex()}


def open_sealed(data: dict, passphrase: str) -> KeyPair:
    try:
        k = _derive(passphrase, bytes.fromhex(data["salt"]), int(data["n"]), int(data["r"]), int(data["p"]))
        seed = AESGCM(k).decrypt(bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]), bytes.fromhex(data["address"]))
    except (KeyError, ValueError) as err:
        raise KeystoreError(f"malformed keystore: {err}") from None
    except Exception:  # noqa: BLE001  (cryptography raises InvalidTag)
        raise KeystoreError("wrong passphrase, or the keystore was altered") from None
    key = KeyPair.from_secret_hex(seed.hex())
    if key.address != data["address"]:
        raise KeystoreError("keystore address does not match its key")
    return key


def passphrase_from_env_or_prompt(prompt: str = "passphrase: ", confirm: bool = False) -> str:
    env = os.environ.get("JURISLEDGER_PASSPHRASE")
    if env:
        return env
    if not sys.stdin.isatty():
        raise KeystoreError("encrypted key file: set JURISLEDGER_PASSPHRASE or run interactively")
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("again: ") != pw:
        raise KeystoreError("the two passphrases differ")
    return pw


def save(key: KeyPair, path: str | os.PathLike, passphrase: Optional[str] = None) -> None:
    data = seal(key, passphrase) if passphrase else {"secret": key.secret_hex(), "address": key.address}
    p = Path(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)      # never world-readable, not even briefly
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(p, 0o600)


def load(path: str | os.PathLike, passphrase: Optional[str] = None) -> KeyPair:
    p = Path(path)
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError) as err:
        raise KeystoreError(f"could not read key file {p}: {err}") from None
    if "ciphertext" in data:
        return open_sealed(data, passphrase or passphrase_from_env_or_prompt(f"passphrase for {p.name}: "))
    if "secret" not in data:
        raise KeystoreError(f"{p} is not a JurisLedger key file")
    if os.name == "posix" and p.stat().st_mode & 0o077:
        print(f"warning: {p} is readable by other users; run: chmod 600 {p}", file=sys.stderr)
    return KeyPair.from_secret_hex(data["secret"])


def is_encrypted(path: str | os.PathLike) -> bool:
    try:
        return "ciphertext" in json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return False
