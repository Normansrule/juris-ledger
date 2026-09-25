"""A command-line wallet that talks to a running validator.

    jurisledger wallet new -o me.json
    jurisledger wallet register HOST:PORT --key me.json --name "Ana" --role household
    jurisledger wallet balance  HOST:PORT --key me.json
    jurisledger wallet pay      HOST:PORT --key me.json --to ADDRESS --amount 12.50 --purpose FINAL_CONSUMPTION

Amounts are written in major units ("12.50") and stored as integer cents.  The wallet
reads the account's nonce from the node before signing, waits for the payment to be
finalised, and re-audits the export before believing anything the node says about it.
"""
from __future__ import annotations

import json
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Optional

from . import state as S
from .contracts import Wallet
from .crypto import KeyPair
from .net import Client


def parse_amount(text: str) -> int:
    try:
        cents = (Decimal(text) * 100).quantize(Decimal(1))
    except InvalidOperation:
        raise SystemExit(f"'{text}' is not an amount; write it like 12.50")
    if cents <= 0:
        raise SystemExit("the amount must be positive")
    return int(cents)


def load_key(path: str) -> KeyPair:
    try:
        return KeyPair.from_secret_hex(json.loads(Path(path).read_text())["secret"])
    except (OSError, KeyError, ValueError) as err:
        raise SystemExit(f"could not read the key file {path}: {err}. Make one with: jurisledger wallet new -o {path}")


def connect(target: str, pin: Optional[str]) -> Client:
    host, port = target.rsplit(":", 1)
    return Client(host, int(port), expect_address=pin)


def cmd_new(out: str) -> int:
    k = KeyPair.generate()
    p = Path(out)
    p.write_text(json.dumps({"secret": k.secret_hex(), "address": k.address}))
    try:
        p.chmod(0o600)
    except OSError:
        pass
    print(f"wrote {out}\naddress: {k.address}\nThis file IS the account. Back it up; anyone who reads it can spend.")
    return 0


def cmd_register(client: Client, key: KeyPair, name: str, role: str, sector: str) -> int:
    st = client.status()
    w = Wallet(key, st.get("chain_id") or _chain_id(client))
    acct = client.account(key.address)
    if acct.get("found"):
        print(f"already registered as '{acct['name']}' ({acct['role']})")
        return 0
    client.submit(w.register(name, role, sector))
    return _wait(client, lambda: client.account(key.address).get("found"), "registration")


def cmd_balance(client: Client, key: KeyPair) -> int:
    a = client.account(key.address)
    if not a.get("found"):
        print("this key is not registered on the ledger yet (jurisledger wallet register ...)")
        return 1
    hidden = "  hidden balance: yes (commitment on record)" if a.get("hidden") else ""
    print(f"{a['name']} ({a['role']}{', ' + a['sector'] if a['sector'] else ''})\n"
          f"  balance: {a['balance'] / 100:,.2f}   transactions sent: {a['nonce']}   as of block {a['height']}{hidden}")
    return 0


def cmd_pay(client: Client, key: KeyPair, to: str, amount_text: str, purpose: str, **extra: Any) -> int:
    amount = parse_amount(amount_text)
    if purpose not in S.PAYMENT_RULES:
        raise SystemExit(f"purpose must be one of: {', '.join(sorted(S.PAYMENT_RULES))}")
    a = client.account(key.address)
    if not a.get("found"):
        raise SystemExit("this key is not registered on the ledger")
    if a["balance"] < amount:
        raise SystemExit(f"insufficient balance: {a['balance'] / 100:,.2f} available")
    recipient = client.account(to)
    if not recipient.get("found"):
        raise SystemExit("the recipient address is not registered")
    w = Wallet(key, _chain_id(client), next_nonce=a["nonce"])
    tx = w.pay(to, amount, purpose, **{k: v for k, v in extra.items() if v})
    client.submit(tx)
    print(f"sent {amount / 100:,.2f} to {recipient['name']} ({purpose}); waiting for finality...")
    return _wait(client, lambda: client.account(key.address).get("nonce", 0) > a["nonce"], "payment",
                 after=lambda: print(f"final. transaction {tx.txid}"))


def _chain_id(client: Client) -> str:
    return client.export().chain_id


def _wait(client: Client, done, what: str, after=None, timeout: float = 30) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if done():
            if after:
                after()
            return 0
        time.sleep(0.5)
    print(f"the {what} was not finalised within {timeout:.0f} s; check the node with: jurisledger status HOST:PORT")
    return 1
