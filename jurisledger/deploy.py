"""Prepare a multi-machine deployment.

    jurisledger init --out net/ --validators desk.local:7701,laptop.local:7702,vm1:7703,vm2:7704 \\
                     --issuers registry,tax --min-attestations 2

Writes ``genesis.json`` and ``peers.json`` (shared by everyone), one ``validator-i/`` folder
per machine holding ONLY that machine's key file plus a ``start.sh``, and ``issuer-*.key.json``
files for the identity issuers.  Copy each validator folder to its machine together with the
two shared files, then run ``start.sh`` there.  Nothing secret is shared between machines.
"""
from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Dict, List

from . import state as S
from .crypto import KeyPair


def init(out_dir: str, validators: List[str], issuers: List[str], chain_id: str, min_attestations: int,
         unverified_limit_cents: int, recovery_delay: int, treasury_cents: int) -> Dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    vkeys = [KeyPair.generate() for _ in validators]
    ikeys = {n: KeyPair.generate() for n in issuers}
    treasury = KeyPair.generate()
    genesis = {
        "chain_id": chain_id,
        "validators": [k.address for k in vkeys],
        "accounts": [{"address": k.address, "name": f"validator-{i} ({host.split(':')[0]})", "role": S.VALIDATOR,
                      "sector": "", "balance": 0} for i, (k, host) in enumerate(zip(vkeys, validators))]
                    + [{"address": treasury.address, "name": "treasury", "role": S.GOVERNMENT, "sector": "",
                        "balance": treasury_cents}],
        "issuers": [{"address": k.address, "name": n} for n, k in ikeys.items()],
        "policy": {"min_attestations": min_attestations, "unverified_payment_limit": unverified_limit_cents,
                   "recovery_delay": recovery_delay} if issuers else {},
    }
    (out / "genesis.json").write_text(json.dumps(genesis, indent=1))
    (out / "peers.json").write_text(json.dumps(validators, indent=1))
    for i, (k, host) in enumerate(zip(vkeys, validators)):
        d = out / f"validator-{i}"
        d.mkdir(exist_ok=True)
        keyfile = d / f"validator-{i}.key.json"
        keyfile.write_text(json.dumps({"secret": k.secret_hex(), "address": k.address}))
        keyfile.chmod(0o600)
        port = host.rsplit(":", 1)[1]
        script = d / "start.sh"
        script.write_text(f'''#!/usr/bin/env bash
# Validator {i} of {chain_id}.  Run from a folder containing genesis.json and peers.json.
set -euo pipefail
cd "$(dirname "$0")"
exec jurisledger node --genesis ../genesis.json --key validator-{i}.key.json --peers ../peers.json \\
     --store store --index {i} --listen 0.0.0.0:{port}
''')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    for n, k in ikeys.items():
        f = out / f"issuer-{n}.key.json"
        f.write_text(json.dumps({"secret": k.secret_hex(), "address": k.address}))
        f.chmod(0o600)
    tf = out / "treasury.key.json"
    tf.write_text(json.dumps({"secret": treasury.secret_hex(), "address": treasury.address}))
    tf.chmod(0o600)
    return {"genesis": str(out / "genesis.json"), "peers": str(out / "peers.json"),
            "validators": ", ".join(f"validator-{i}/" for i in range(len(validators)))}
