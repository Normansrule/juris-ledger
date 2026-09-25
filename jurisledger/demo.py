"""Build a small, realistic ledger and write everything a newcomer needs to explore it.

    jurisledger demo --out demo/

writes ``chain.json`` (the whole ledger), ``validators.json`` (the public keys to check it
against), ``evidence-*.json`` (one contract, verifiable offline), ``register.html`` (open it
in a browser) and ``store/`` (the durable on-disk format).
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict

from . import legal
from . import state as S
from .contracts import Wallet, cite_external
from .crypto import KeyPair, sha256_hex
from .dashboard import render
from .ledgernet import LedgerNetwork
from .sim import Economy, SimConfig
from .storage import BlockStore

LEASE = """COLD-STORAGE LEASE
1. The Lessor lets one refrigerated warehouse bay to the Lessee for two periods.
2. Rent is 12,000.00 per period, due at the blocks stated in the machine-readable terms.
3. The parties accept the ledger's record of payment heights as evidence of payment.
4. Disputes are decided by the arbitrator named in the terms.
"""
SUPPLY = """GRAIN SUPPLY AGREEMENT
The Supplier delivers 40 tonnes of milling wheat per period at 310.00 per tonne, payable on delivery.
"""


def build(out_dir: str, seed: int = 7) -> Dict[str, str]:
    cfg = SimConfig(chain_id="demo-republic", seed=seed, periods=3)
    eco = Economy(cfg)
    issuers = {n: Wallet(KeyPair.from_seed(f"demo/issuer/{n}"), cfg.chain_id)
               for n in ("company-registry", "tax-authority", "civil-registry")}
    genesis = eco.genesis()
    seats = ("central-bank", "statistics-office", "court-administration", "university-consortium")
    genesis["accounts"] += [{"address": k.address, "name": n, "role": S.VALIDATOR, "sector": "", "balance": 0}
                            for n, k in zip(seats, eco.validator_keys)]
    genesis["issuers"] = [{"address": w.address, "name": n} for n, w in issuers.items()]
    genesis["policy"] = {"min_attestations": 2, "unverified_payment_limit": 5_000_00, "recovery_delay": 5}
    rng = random.Random(seed)
    net = LedgerNetwork.create(genesis, eco.validator_keys,
                               delay=lambda _m: rng.randint(1, 3) if rng.random() < 0.85 else rng.randint(4, 15))
    import shutil
    shutil.rmtree(Path(out_dir) / "store", ignore_errors=True)        # the demo is rebuilt from scratch every run
    store = BlockStore.create(Path(out_dir) / "store", genesis)

    def settle() -> None:
        net.run_until_empty()

    # 1. everyone is onboarded by two independent issuers
    people = [w for n, w in eco.wallets.items() if n != "government"]
    for w in people:
        a, b = rng.sample(list(issuers.values()), 2)
        net.submit(a.attest(w.address, f"credential for {w.address[:8]}"))
        net.submit(b.attest(w.address, f"second credential for {w.address[:8]}"))
    settle()

    # 2. contracts between real participants
    lessor, lessee, arbiter = eco.wallet("construction-firm-0"), eco.wallet("agriculture-firm-1"), eco.wallet("bank-0")
    h = net.reference.chain.height
    lease = lessor.create_contract("Cold-storage lease", LEASE, {
        "obligations": [legal.obligation("rent-period-1", lessee.address, lessor.address, 12_000_00, h + 4),
                        legal.obligation("rent-period-2", lessee.address, lessor.address, 12_000_00, h + 6)],
        "arbitration": {"arbitrator": arbiter.address}}, [lessor.address, lessee.address],
        [cite_external(b"Commercial Tenancies Act, consolidated text", "https://example.gov/acts/tenancies", "governing statute")],
        visibility="restricted")
    supplier, miller = eco.wallet("agriculture-firm-0"), eco.wallet("manufacturing-firm-2")
    supply = supplier.create_contract("Grain supply agreement", SUPPLY, {"tonnes": 40, "price_cents": 310_00},
                                      [supplier.address, miller.address])
    net.submit(lease); net.submit(supply); settle()
    net.submit(lessee.sign_contract(lease.txid, LEASE)); net.submit(miller.sign_contract(supply.txid, SUPPLY)); settle()

    # 3. three periods of economic activity, with the contracts being used along the way
    for period in range(cfg.periods):
        for t in eco.period():
            net.submit(t)
        net.submit(miller.pay(supplier.address, 12_400_00, S.INTERMEDIATE, contract=supply.txid,
                              invoice=sha256_hex(f"grain invoice {period}".encode())))
        if period == 0:
            net.submit(lessee.pay(lessor.address, 12_000_00, S.INTERMEDIATE, contract=lease.txid, obligation="rent-period-1"))
            net.submit(miller.access(supply.txid, "VIEW", "checking the delivery schedule"))
        settle()

    # 4. the second rent is missed, disputed and reduced by the arbitrator; then paid
    claim = lessor.open_dispute(lease.txid, "Rent for period 2 is unpaid.", ["rent-period-2"])
    net.submit(claim); settle()
    net.submit(lessee.file_document(lease.txid, claim.txid, "The cooling unit failed for nine days.", "defence")); settle()
    net.submit(arbiter.access(lease.txid, "VIEW", "reading the lease for the arbitration")); settle()
    net.submit(arbiter.award(lease.txid, claim.txid, "SETTLED", "Rent abated by one quarter for the outage.",
                             [{"obligation": "rent-period-2", "amount": 9_000_00,
                               "due_height": net.reference.chain.height + 6}])); settle()
    net.submit(lessee.pay(lessor.address, 9_000_00, S.INTERMEDIATE, contract=lease.txid, obligation="rent-period-2")); settle()

    # 5. something for the review flags: three firms pass the same money in a circle
    ring = [eco.firms[5], eco.firms[9], eco.firms[13]]
    for i, a in enumerate(ring):
        net.submit(a.pay(ring[(i + 1) % 3].address, 180_000_00 + i * 500_00, S.INTERMEDIATE))
    settle()

    chain = net.reference.chain
    store.save(chain)
    out = Path(out_dir)
    paths = {"chain": out / "chain.json", "validators": out / "validators.json",
             "evidence": out / "evidence-cold-storage-lease.json", "register": out / "register.html"}
    paths["chain"].write_text(chain.export())
    paths["validators"].write_text(json.dumps({"chain_id": chain.chain_id, "validators": genesis["validators"]}, indent=2))
    paths["evidence"].write_text(json.dumps(legal.evidence_bundle(chain, lease.txid, LEASE), indent=1))
    paths["register"].write_text(render(chain))
    return {k: str(v) for k, v in paths.items()} | {"store": str(out / "store"), "blocks": str(chain.height)}
