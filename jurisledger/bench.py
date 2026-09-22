"""Honest performance numbers for this pure-Python prototype, on this machine."""
from __future__ import annotations

import json
import time
from typing import Dict

from . import legal
from . import state as S
from .chain import Chain
from .contracts import Wallet
from .crypto import KeyPair
from .experiments import MiniWorld
from .ledgernet import LedgerNetwork


def run(n_tx: int = 3000, verbose: bool = True) -> Dict[str, float]:
    m = MiniWorld(network=LedgerNetwork)
    payers = [m.w["alice"], m.w["bakery"], m.w["mill"]]
    t0 = time.perf_counter()
    txs = []
    for i in range(n_tx):
        w = payers[i % 3]
        to = m.w["bakery"] if w is not m.w["bakery"] else m.w["mill"]
        purpose = S.FINAL_CONSUMPTION if w is m.w["alice"] else S.INTERMEDIATE
        txs.append(w.pay(to.address, 100 + i % 900, purpose))
    sign = n_tx / (time.perf_counter() - t0)

    state = m.chain.state.copy()
    t0 = time.perf_counter()
    for t in txs:
        state.apply(t, 1)
    apply = n_tx / (time.perf_counter() - t0)

    for t in txs:
        m.net.submit(t)
    t0 = time.perf_counter()
    blocks = m.net.run_until_empty()
    consensus = n_tx / (time.perf_counter() - t0)

    exported = m.chain.export()
    t0 = time.perf_counter()
    Chain.load(exported)
    audit = n_tx / (time.perf_counter() - t0)

    proof = m.chain.tx_proof(txs[n_tx // 2].txid)
    t0 = time.perf_counter()
    for _ in range(200):
        Chain.verify_tx_proof(txs[n_tx // 2].txid, proof, m.genesis["validators"])
    light = 200 / (time.perf_counter() - t0)

    out = {"sign_per_s": sign, "validate_per_s": apply, "consensus_tx_per_s": consensus,
           "audit_tx_per_s": audit, "light_proofs_per_s": light, "blocks": blocks,
           "bytes_per_tx": len(exported) / n_tx}
    if verbose:
        print(f"  {n_tx} signed payments, 4 validators, two-phase consensus, one CPU core, pure Python")
        print(f"    signing                         {sign:>10,.0f} transactions / second")
        print(f"    validating (signature + rules)  {apply:>10,.0f} transactions / second")
        print(f"    through consensus, 4 validators {consensus:>10,.0f} transactions / second  ({blocks} blocks)")
        print(f"    independent audit from genesis  {audit:>10,.0f} transactions / second")
        print(f"    light-client inclusion proofs   {light:>10,.0f} proofs / second")
        print(f"    storage                         {out['bytes_per_tx']:>10,.0f} bytes / transaction (JSON, uncompressed)")
        per_day = apply * 86_400
        print(f"  reading: one core validates about {per_day / 1e6:,.0f} million transactions a day. Signature checks")
        print("  dominate and are independent of each other, so this scales with cores; consensus here re-executes")
        print("  each block on every simulated validator inside one process, which a real deployment does in parallel.")
    return out
