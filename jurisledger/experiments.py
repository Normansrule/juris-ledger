"""Runnable experiments.  Each returns a dict of results whose ``checks`` entry is
a list of (claim, bool); the test-suite asserts that every claim holds, and the
command-line interface prints them.  Run:  python -m jurisledger all
"""
from __future__ import annotations

import copy
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import consensus as C
from . import bft, fraud, legal, privacy
from . import state as S
from . import tx as T
from .block import Block
from .chain import Chain, InvalidBlock
from .consensus import Network
from .contracts import (ContractVault, VaultError, Wallet, audit_trail, cite, cite_external,
                        provenance, summary)
from .crypto import KeyPair, sha256_hex
from .sim import SimConfig, run_simulation, survey_estimate
from .stats import gdp, private_sector_release

Check = Tuple[str, bool]


def money(cents: float) -> str:
    return f"${cents / 100:,.2f}"


# --------------------------------------------------------------------------- #
# A tiny hand-built network used by the contract and attack experiments
# --------------------------------------------------------------------------- #
class MiniWorld:
    NAMES = [("alice", S.HOUSEHOLD, ""), ("bakery", S.FIRM, "services"), ("mill", S.FIRM, "manufacturing"),
             ("treasury", S.GOVERNMENT, ""), ("importer", S.FOREIGN, ""), ("bank-a", S.BANK, ""),
             ("bank-b", S.BANK, ""), ("auditor", S.FIRM, "services")]

    def __init__(self, behaviours: Optional[Dict[int, Tuple[str, Optional[str]]]] = None,
                 chain_id: str = "jurisledger-mini", n_validators: int = 4,
                 behaviour_targets: Optional[Dict[int, Tuple[str, str]]] = None):
        self.chain_id = chain_id
        self.w: Dict[str, Wallet] = {n: Wallet(KeyPair.from_seed(f"{chain_id}/{n}"), chain_id)
                                     for n, _, _ in self.NAMES}
        self.vkeys = [KeyPair.from_seed(f"{chain_id}/validator-{i}") for i in range(n_validators)]
        self.genesis = {
            "chain_id": chain_id,
            "accounts": [{"address": self.w[n].address, "name": n, "role": r, "sector": s,
                          "balance": 1_000_000_00} for n, r, s in self.NAMES],
            "validators": [k.address for k in self.vkeys],
        }
        behaviours = dict(behaviours or {})
        for i, (b, name) in (behaviour_targets or {}).items():
            behaviours[i] = (b, self.w[name].address)
        self.net = Network.create(self.genesis, self.vkeys, behaviours)

    @property
    def chain(self) -> Chain:
        return self.net.reference.chain

    def send(self, *txs: T.Transaction) -> Optional[Block]:
        for t in txs:
            self.net.submit(t)
        return self.net.produce_block()

    def balance(self, name: str) -> int:
        return self.chain.state.accounts[self.w[name].address]["balance"]


# --------------------------------------------------------------------------- #
def exp_gdp(verbose: bool = True) -> Dict[str, Any]:
    """Ledger-measured GDP versus ground truth versus a stylised survey."""
    res = run_simulation(SimConfig())
    chain, truth = res.chain, res.economy.truth
    rep = gdp(chain)
    checks: List[Check] = [
        ("ledger GDP (expenditure) equals ground truth exactly", rep.expenditure == truth.gdp),
        ("expenditure and production approaches agree (discrepancy = 0)", rep.discrepancy == 0),
        ("income approach reconciles", rep.income == rep.production),
        ("an outsider can re-verify the whole chain from the export", Chain.load(chain.export()).state.root() == chain.state.root()),
    ]
    per_period = []
    for (a, b), t in zip(res.period_blocks, res.economy.period_truth):
        r = gdp(chain, a, b)
        per_period.append({"blocks": (a, b), "ledger": r.expenditure, "truth": t.gdp})
    checks.append(("every period's GDP matches its ground truth", all(p["ledger"] == p["truth"] for p in per_period)))

    surveys = [survey_estimate(truth, 0.4, 0.7, 0.10, 0.08, seed) for seed in range(200)]
    surveys = [s for s in surveys if s == s]
    mean_abs_err = sum(abs(s - truth.gdp) for s in surveys) / len(surveys) / truth.gdp

    sweep = []
    for share in (0.0, 0.1, 0.3):
        r2 = run_simulation(SimConfig(offledger_share=share, periods=3))
        g2, t2 = gdp(r2.chain).expenditure, r2.economy.truth.gdp
        sweep.append({"offledger_share": share, "ledger": g2, "truth": t2, "captured": g2 / t2})
    checks.append(("ledger coverage falls as cash (off-ledger) activity rises",
                   sweep[0]["captured"] == 1.0 and sweep[2]["captured"] < sweep[1]["captured"] < 1.0))

    if verbose:
        print(f"  blocks {chain.height}, payments {rep.n_payments}")
        print(f"  C={money(rep.C)}  I={money(rep.I)}  G={money(rep.G)}  X={money(rep.X)}  M={money(rep.M)}")
        print(f"  GDP expenditure : {money(rep.expenditure)}")
        print(f"  GDP production  : {money(rep.production)}")
        print(f"  GDP income      : {money(rep.income)}  (wages {money(rep.wages)}, "
              f"net production taxes {money(rep.production_taxes - rep.subsidies)}, "
              f"operating surplus {money(rep.operating_surplus)})")
        print(f"  ground truth    : {money(truth.gdp)}")
        print("  value added by sector:")
        for s, v in sorted(rep.by_sector().items()):
            print(f"    {s:<14}{money(v):>18}")
        print(f"  stylised survey of the same {len(truth.value_added())} firms (40% sample, 70% response, 10% noise, "
              f"8% under-reporting):\n    mean absolute error {mean_abs_err:.1%} over {len(surveys)} draws "
              f"(illustrative: a tiny population exaggerates sampling error);  ledger error 0.0%")
        print("  honesty check - the ledger only sees what is on it:")
        for row in sweep:
            print(f"    cash share {row['offledger_share']:.0%}: ledger captures {row['captured']:.1%} of true GDP")
    return {"checks": checks, "report": rep, "survey_mae": mean_abs_err, "sweep": sweep}


# --------------------------------------------------------------------------- #
FRAMEWORK_PROSE = """MASTER SUPPLY FRAMEWORK
1. The Mill supplies flour to the Bakery on the Bakery's written order.
2. Price and quantity are fixed in each Supply Schedule that cites this Framework.
3. Disputes go to arbitration seated where the Bakery is registered.
"""
SCHEDULE_PROSE = """SUPPLY SCHEDULE 1 (under the Master Supply Framework)
The Mill delivers 2,000 kg of flour per month at 0.85 per kg. Payment within 30 days.
"""
SCHEDULE_V2_PROSE = SCHEDULE_PROSE.replace("0.85", "0.80")
STATUTE = b"Uniform Electronic Transactions Act (1999), section 7: a record or signature may not be denied legal effect solely because it is in electronic form."


def exp_contracts(verbose: bool = True) -> Dict[str, Any]:
    """Signed digital contracts: references, signatures, receipted reads, supersession."""
    m = MiniWorld()
    w, vault, checks = m.w, ContractVault(), []
    bakery, mill, auditor, alice = w["bakery"], w["mill"], w["auditor"], w["alice"]

    # 1. a public framework agreement that cites a statute by hash
    t_frame = mill.create_contract("Master Supply Framework", FRAMEWORK_PROSE, {"governing": "arbitration"},
                                   [mill.address, bakery.address],
                                   [cite_external(STATUTE, "https://www.uniformlaws.org/", "legal effect of e-signatures")])
    m.send(t_frame)
    frame = t_frame.txid
    checks.append(("contract is DRAFT until every party has signed", m.chain.state.contracts[frame]["status"] == S.DRAFT))
    m.send(bakery.sign_contract(frame, FRAMEWORK_PROSE))
    checks.append(("contract becomes ACTIVE once all parties signed", m.chain.state.contracts[frame]["status"] == S.ACTIVE))

    # 2. a restricted schedule that implements the framework
    t_s1 = mill.create_contract("Supply Schedule 1", SCHEDULE_PROSE, {"kg_per_month": 2000, "price_per_kg_milli": 850},
                                [mill.address, bakery.address], [cite(frame, "implements")], "restricted")
    m.send(t_s1)
    s1 = t_s1.txid
    m.send(bakery.sign_contract(s1, "The Mill delivers 2,000 kg at 0.10 per kg."))   # wrong text
    checks.append(("signing a different text than the one on record is rejected",
                   m.chain.state.contracts[s1]["status"] == S.DRAFT))
    bakery.resync(m.chain)                                  # that transaction never entered a block
    m.send(bakery.sign_contract(s1, SCHEDULE_PROSE))
    vault.deposit(frame, FRAMEWORK_PROSE, m.chain)
    vault.deposit(s1, SCHEDULE_PROSE, m.chain)

    try:
        vault.deposit(s1, SCHEDULE_PROSE.replace("30 days", "300 days"), m.chain)
        altered = True
    except VaultError:
        altered = False
    checks.append(("altered prose is detected by its hash", not altered))

    # 3. reading requires an on-chain receipt
    try:
        vault.read(s1, bakery.address, m.chain); leaked = True
    except VaultError:
        leaked = False
    checks.append(("the vault refuses a read that has no on-chain receipt", not leaked))
    m.send(bakery.access(s1, "VIEW", "monthly review"))
    checks.append(("a receipted read returns the exact signed text", vault.read(s1, bakery.address, m.chain) == SCHEDULE_PROSE))

    # 4. outsiders are locked out of restricted contracts until a party grants access
    m.send(alice.access(s1, "VIEW", "curious"))
    alice.resync(m.chain)
    checks.append(("a non-party cannot even record an access to a restricted contract",
                   not any(e["accessor"] == alice.address for e in m.chain.state.access_log)))
    m.send(bakery.grant(s1, auditor.address))
    m.send(auditor.access(s1, "VIEW", "annual audit"))
    checks.append(("a granted auditor can read, and the read is on the record",
                   vault.read(s1, auditor.address, m.chain) == SCHEDULE_PROSE))

    # 5. paying under the contract is logged as a USE
    m.send(bakery.pay(mill.address, 1_700_00, S.INTERMEDIATE, contract=s1,
                      invoice=sha256_hex(b"invoice 2026-001")))
    # 6. renegotiation: schedule 2 supersedes schedule 1
    t_s2 = bakery.create_contract("Supply Schedule 1 (revised price)", SCHEDULE_V2_PROSE,
                                  {"kg_per_month": 2000, "price_per_kg_milli": 800},
                                  [mill.address, bakery.address],
                                  [cite(s1, "supersedes"), cite(frame, "implements")], "restricted")
    m.send(t_s2)
    m.send(mill.sign_contract(t_s2.txid, SCHEDULE_V2_PROSE))
    checks.append(("the old schedule is marked SUPERSEDED, never deleted",
                   m.chain.state.contracts[s1]["status"] == S.SUPERSEDED))
    m.send(bakery.pay(mill.address, 100, S.INTERMEDIATE, contract=s1))
    bakery.resync(m.chain)
    checks.append(("payments can no longer be made under a superseded contract",
                   summary(m.chain, s1)["uses"] == 1))

    trail = audit_trail(m.chain, s1)
    checks.append(("audit trail shows view, view, use, cite in order",
                   [e["action"] for e in trail] == ["VIEW", "VIEW", "USE", "CITE"]))
    tree = provenance(m.chain, t_s2.txid)
    if verbose:
        print("  audit trail of 'Supply Schedule 1':")
        for e in trail:
            print(f"    block {e['height']:>2}  {e['action']:<5} by {e['accessor_name']:<8} {e['context']}")
        print("  provenance of the revised schedule:")
        print("    " + json.dumps(tree, indent=2).replace("\n", "\n    "))
    return {"checks": checks, "trail": trail, "provenance": tree}


# --------------------------------------------------------------------------- #
def exp_attacks(verbose: bool = True) -> Dict[str, Any]:
    """Adversarial experiments: what each kind of attacker can and cannot do."""
    checks: List[Check] = []
    notes: List[str] = []

    # a. rewrite history
    m = MiniWorld()
    m.send(m.w["alice"].pay(m.w["bakery"].address, 50_00, S.FINAL_CONSUMPTION))
    m.send(m.w["bakery"].pay(m.w["mill"].address, 20_00, S.INTERMEDIATE))
    exported = json.loads(m.chain.export())
    forged = copy.deepcopy(exported)
    forged["blocks"][0]["txs"][0]["payload"]["amount"] = 5_000_000
    try:
        Chain.load(json.dumps(forged)); caught = False
    except InvalidBlock as e:
        caught = True; notes.append(f"tampered history rejected: {e}")
    checks.append(("editing an old transaction breaks the audit", caught))

    # b. a validator forges a payment from a victim
    m = MiniWorld(behaviour_targets={1: (C.FORGER, "alice")})
    before = m.balance("alice")
    while m.chain.height < 3:
        m.send(m.w["bakery"].pay(m.w["mill"].address, 1_00, S.INTERMEDIATE))
    rejected = [r for r in m.net.log if r.outcome == "no quorum"]
    checks.append(("a block containing a forged payment gets no honest votes", len(rejected) >= 1))
    checks.append(("the victim's balance is untouched and the chain keeps moving", m.balance("alice") == before))

    # c/d. replay and double spend
    m = MiniWorld()
    pay = m.w["alice"].pay(m.w["bakery"].address, 600_000_00, S.FINAL_CONSUMPTION)
    m.send(pay)
    m.send(pay)                                             # replay the identical signed transaction
    checks.append(("replaying a signed transaction has no effect", m.balance("alice") == 400_000_00))
    m.send(m.w["alice"].pay(m.w["mill"].address, 600_000_00, S.FINAL_CONSUMPTION))   # spend money already spent
    checks.append(("double spending is rejected", m.balance("alice") == 400_000_00))
    other = MiniWorld(chain_id="jurisledger-other")
    other.send(pay)
    checks.append(("a transaction cannot be replayed on another network", other.balance("alice") == 1_000_000_00))

    # e. role abuse: statistics tags are validated, not self-declared
    m = MiniWorld()
    m.send(m.w["alice"].pay(m.w["bakery"].address, 10_00, S.GOVERNMENT_PURCHASE))
    checks.append(("a household cannot tag its spending as government purchases",
                   gdp(m.chain).G == 0 and m.chain.height == 1 and len(m.chain.blocks[0].txs) == 0))

    # f. equivocation -> provable -> removed
    m = MiniWorld(behaviours={1: (C.EQUIVOCATOR, None)})
    bad = m.vkeys[1].address
    for i in range(6):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 1_00 + i, S.FINAL_CONSUMPTION),
               m.w["mill"].pay(m.w["bakery"].address, 2_00 + i, S.INTERMEDIATE))
    roots = {n.chain.state.root() for n in m.net.nodes if n.behaviour == C.HONEST}
    checks.append(("an equivocating proposer cannot make honest nodes disagree", len(roots) == 1))
    checks.append(("equivocation is proven on-chain and the validator is removed",
                   bad in m.chain.state.slashed and bad not in m.chain.state.validators))

    # g. censorship is bounded by proposer rotation
    m = MiniWorld(behaviour_targets={1: (C.CENSOR, "alice")})
    t = m.w["alice"].pay(m.w["bakery"].address, 7_00, S.FINAL_CONSUMPTION)
    m.net.submit(t)
    waited = 0
    while m.chain.find_tx(t.txid) is None and waited < 8:
        m.net.produce_block(); waited += 1
    checks.append(("a censoring validator only delays a transaction until the next honest proposer", 1 <= waited <= 2))
    notes.append(f"censored transaction was included after {waited} block(s)")

    # h. crash faults: f = 1 of 4 tolerated, 2 of 4 halts the chain but never corrupts it
    m = MiniWorld(behaviours={2: (C.SILENT, None)})
    ok = all(m.send(m.w["alice"].pay(m.w["bakery"].address, 1_00 + i, S.FINAL_CONSUMPTION)) is not None for i in range(4))
    checks.append(("the network stays live with 1 of 4 validators down", ok and m.chain.height == 4))
    m = MiniWorld(behaviours={2: (C.SILENT, None), 3: (C.SILENT, None)})
    blk = m.send(m.w["alice"].pay(m.w["bakery"].address, 1_00, S.FINAL_CONSUMPTION))
    checks.append(("with 2 of 4 down nothing is finalised (liveness lost, safety kept)",
                   blk is None and m.chain.height == 0 and m.balance("alice") == 1_000_000_00))

    # i. a block signed by too few validators is not final, whoever signs it
    m = MiniWorld()
    node = m.net.node(m.chain.expected_proposer(1, 0))
    block = node.build_block(1, 0)
    block.votes = {node.address: node.sign_vote(block)}
    try:
        Chain(m.genesis).add_block(block); minority = True
    except InvalidBlock:
        minority = False
    checks.append(("a single validator cannot finalise a block alone", not minority))

    # j. light client
    m = MiniWorld()
    t = m.w["alice"].pay(m.w["bakery"].address, 12_34, S.FINAL_CONSUMPTION)
    m.send(t, m.w["mill"].pay(m.w["bakery"].address, 5_00, S.INTERMEDIATE),
           m.w["bakery"].pay(m.w["mill"].address, 3_00, S.INTERMEDIATE))
    proof = m.chain.tx_proof(t.txid)
    vals = m.genesis["validators"]
    fake = T.Transaction.create(m.chain_id, T.PAYMENT, m.w["alice"].key, 9, {"to": "x", "amount": 1, "purpose": "FINANCIAL"})
    checks.append(("a light client verifies inclusion from a header, its votes and a Merkle path",
                   Chain.verify_tx_proof(t.txid, proof, vals) and not Chain.verify_tx_proof(fake.txid, proof, vals)))

    if verbose:
        for n in notes:
            print("  note:", n)
    return {"checks": checks, "notes": notes}


# --------------------------------------------------------------------------- #
def exp_fraud(verbose: bool = True) -> Dict[str, Any]:
    """Inject four frauds into a clean economy and see what the detectors find."""
    threshold = 10_000_00
    clean = run_simulation(SimConfig(periods=4))
    baseline = fraud.run_all(clean.chain, threshold)

    cfg = SimConfig(periods=4)
    res = run_simulation(cfg)
    eco, net = res.economy, res.network
    f = eco.firms
    ring = [f[1], f[6], f[11]]
    for i, a in enumerate(ring):                           # round-tripping to inflate revenue
        net.submit(a.pay(ring[(i + 1) % 3].address, 250_000_00 + i * 1_000_00, S.INTERMEDIATE))
    for i in range(6):                                     # structuring under the reporting threshold
        net.submit(f[3].pay(eco.banks[0].address, 9_400_00 + i * 50_00, S.FINANCIAL))
    rng = eco.rng
    for _ in range(80):                                    # invented invoices: digits drawn uniformly
        net.submit(f[8].pay(f[9].address, rng.randint(1_000_00, 9_999_00), S.INTERMEDIATE))
    inv = sha256_hex(b"receivable #77")
    for b in eco.banks:                                    # the same receivable pledged twice
        net.submit(b.pay(f[14].address, 80_000_00, S.FINANCIAL, invoice=inv))
    net.run_until_empty()

    flags = fraud.run_all(res.chain, threshold)
    kinds = {k: [x for x in flags if x["detector"] == k] for k in
             ("circular_flow", "structuring", "benford", "duplicate_invoice_financing")}
    name_of = {a["address"]: a["name"] for a in eco.accounts}
    ring_names = {name_of[w.address] for w in ring}
    checks: List[Check] = [
        ("the round-trip ring is found", any(set(x["ring"]) == ring_names for x in kinds["circular_flow"])),
        ("structuring under the threshold is found", any(x["account"] == f[3].address for x in kinds["structuring"])),
        ("fabricated amounts fail the first-digit test", any(x["account"] == f[8].address for x in kinds["benford"])),
        ("the twice-pledged receivable is found", len(kinds["duplicate_invoice_financing"]) == 1),
    ]
    if verbose:
        print(f"  flags on the clean economy (false positives): {len(baseline)}")
        for x in baseline:
            print("    ", {k: v for k, v in x.items() if k not in ('accounts',)})
        print(f"  flags after injecting four frauds: {len(flags)}")
        for x in flags:
            print("    ", {k: v for k, v in x.items() if k not in ('accounts', 'account')})
    return {"checks": checks, "flags": flags, "baseline": baseline}


# --------------------------------------------------------------------------- #
def exp_privacy(verbose: bool = True) -> Dict[str, Any]:
    """Hidden amounts with a provable total, and a differentially private release."""
    res = run_simulation(SimConfig(periods=2))
    rep = gdp(res.chain)
    amounts = [t.payload["amount"] for _, t in res.chain.iter_txs()
               if t.kind == T.PAYMENT and t.payload["purpose"] == S.EXPORT][:10]
    pairs = [privacy.commit(a) for a in amounts]
    product = privacy.combine(c for c, _ in pairs)
    total = privacy.aggregate_opening([o for _, o in pairs])
    lie = privacy.Opening(total.amount - 1_000_00, total.blinding)
    checks: List[Check] = [
        ("the product of hidden amounts opens to the true total", privacy.verify_opening(product, total) and total.amount == sum(amounts)),
        ("a false total is rejected", not privacy.verify_opening(product, lie)),
    ]
    big = gdp(run_simulation(SimConfig(periods=2, firms_per_sector=15, n_households=150)).chain)
    exact = big.by_sector()
    clip = 300_000_00
    scale = sum(abs(v) for k, v in exact.items() if k != "government") / 4
    sweep = {}
    for eps in (0.2, 1.0, 5.0):
        errs = []
        for seed in range(30):
            rel = private_sector_release(big, epsilon=eps, clip=clip, k_min=3, seed=seed)
            errs += [abs(v - exact[s]) / scale for s, v in rel.items()]
        sweep[eps] = sum(errs) / len(errs)
    release = private_sector_release(big, epsilon=1.0, clip=clip, k_min=3, seed=1)
    thin = private_sector_release(rep, epsilon=1.0, clip=clip, k_min=5, seed=1)
    checks.append(("sectors with too few firms are suppressed", all(v is None for v in thin.values())))
    checks.append(("more privacy (smaller epsilon) costs more accuracy", sweep[0.2] > sweep[1.0] > sweep[5.0]))
    if verbose:
        print(f"  {len(amounts)} export payments committed; only their total {money(total.amount)} is opened")
        print("  differentially private value added, 15 firms per sector, per-firm clip $300,000, epsilon = 1:")
        for s, v in release.items():
            print(f"    {s:<14} published {money(v):>16}   exact {money(exact[s]):>16}")
        print("  privacy / accuracy trade-off (mean error as a share of the average sector total):")
        for eps, e in sweep.items():
            print(f"    epsilon {eps:<4} -> {e:.1%}")
    return {"checks": checks, "release": release}


LEASE_PROSE = """EQUIPMENT LEASE
1. The Mill leases one stone grinder to the Bakery.
2. The Bakery pays three instalments of 500.00, due at blocks 4, 6 and 8.
3. Late payment is a breach; the ledger's record of payment heights is agreed evidence.
"""


def exp_legal(verbose: bool = True) -> Dict[str, Any]:
    """Obligations tracked from public data, and an evidence file a third party verifies offline."""
    m = MiniWorld()
    bakery, mill, alice = m.w["bakery"], m.w["mill"], m.w["alice"]
    obs = [legal.obligation(f"instalment-{i + 1}", bakery.address, mill.address, 500_00, due)
           for i, due in enumerate((4, 6, 8))]
    t = mill.create_contract("Equipment lease", LEASE_PROSE, {"obligations": obs},
                             [mill.address, bakery.address], [cite_external(STATUTE, "https://www.uniformlaws.org/")])
    m.send(t)                                                          # block 1
    lease = t.txid
    m.send(bakery.sign_contract(lease, LEASE_PROSE))                   # block 2
    pay = lambda ob, amt: bakery.pay(mill.address, amt, S.INTERMEDIATE, contract=lease, obligation=ob)
    m.send(pay("instalment-1", 500_00))                                # block 3: on time
    m.send(bakery.access(lease, "VIEW", "checking due dates"))         # block 4
    m.send(pay("instalment-2", 200_00))                                # block 5: part payment
    m.send(alice.pay(bakery.address, 1_00, S.FINAL_CONSUMPTION))       # block 6
    m.send(pay("instalment-2", 300_00))                                # block 7: completes it, one block late
    m.send(alice.pay(bakery.address, 1_00, S.FINAL_CONSUMPTION))       # block 8
    m.send(alice.pay(bakery.address, 1_00, S.FINAL_CONSUMPTION))       # block 9: instalment 3 never paid
    m.send(mill.pay(bakery.address, 500_00, S.INTERMEDIATE, contract=lease, obligation="instalment-3"))
    mill.resync(m.chain)

    status = {o["id"]: o["status"] for o in legal.compliance(m.chain, lease)}
    mid = {o["id"]: o["status"] for o in legal.compliance(m.chain, lease, at_height=5)}
    checks: List[Check] = [
        ("an instalment paid before its due block is PAID", status["instalment-1"] == "PAID"),
        ("an instalment completed after its due block is PAID_LATE", status["instalment-2"] == "PAID_LATE"),
        ("an unpaid instalment past its due block is OVERDUE", status["instalment-3"] == "OVERDUE"),
        ("the position on any past date can be reconstructed (block 5: PARTIAL, PENDING)",
         mid["instalment-2"] == "PARTIAL" and mid["instalment-3"] == "PENDING"),
        ("the wrong party cannot discharge an obligation", legal.compliance(m.chain, lease)[2]["paid"] == 0),
    ]

    validators = m.genesis["validators"]
    bundle = json.loads(json.dumps(legal.evidence_bundle(m.chain, lease, LEASE_PROSE)))   # as read from a file
    report = legal.verify_evidence_bundle(bundle, validators)
    checks.append(("an evidence file verifies offline with only the validators' public keys",
                   report["valid"] and report["fully_signed"] and report["prose_matches"]))

    forged = copy.deepcopy(bundle)
    forged["items"][2]["tx"]["payload"]["amount"] = 5_00
    checks.append(("changing an amount inside the evidence file is detected",
                   not legal.verify_evidence_bundle(forged, validators)["valid"]))
    swapped = copy.deepcopy(bundle)
    swapped["prose"] = LEASE_PROSE.replace("500.00", "50.00")
    checks.append(("enclosing a different contract text is detected",
                   not legal.verify_evidence_bundle(swapped, validators)["valid"]))
    thin = copy.deepcopy(bundle)
    votes = thin["items"][0]["inclusion"]["votes"]
    for v in list(votes)[2:]:
        votes.pop(v)
    checks.append(("evidence backed by too few validator signatures is rejected",
                   not legal.verify_evidence_bundle(thin, validators)["valid"]))
    strangers = [KeyPair.from_seed(f"stranger-{i}").address for i in range(4)]
    checks.append(("evidence from a network the verifier does not recognise is rejected",
                   not legal.verify_evidence_bundle(bundle, strangers)["valid"]))

    if verbose:
        print("  obligations under 'Equipment lease' as of block", m.chain.height)
        for o in legal.compliance(m.chain, lease):
            print(f"    {o['id']:<14} due block {o['due_height']}  paid {money(o['paid'])} of {money(o['amount'])}"
                  f"  settled at {o['settled_at']}  -> {o['status']}")
        print(f"  evidence file: {len(bundle['items'])} signed transactions, {len(json.dumps(bundle)):,} bytes; timeline:")
        name = {a: v["name"] for a, v in m.chain.state.accounts.items()}
        for e in report["timeline"]:
            print(f"    block {e['height']:>2}  {e['kind']:<16} by {name[e['by']]:<7} {e['detail']}")
    return {"checks": checks, "report": report}


def exp_disputes(verbose: bool = True) -> Dict[str, Any]:
    """Arbitration on the ledger: a referee the parties chose, with deliberately narrow powers."""
    m = MiniWorld()
    bakery, mill, alice, arb = m.w["bakery"], m.w["mill"], m.w["alice"], m.w["auditor"]
    vault = ContractVault()
    obs = [legal.obligation("instalment-1", bakery.address, mill.address, 500_00, 4),
           legal.obligation("instalment-2", bakery.address, mill.address, 500_00, 6)]
    t = mill.create_contract("Equipment lease with arbitration", LEASE_PROSE,
                             {"obligations": obs, "arbitration": {"arbitrator": arb.address}},
                             [mill.address, bakery.address], visibility="restricted")
    m.send(t); lease = t.txid                                           # block 1
    m.send(bakery.sign_contract(lease, LEASE_PROSE))                    # block 2
    vault.deposit(lease, LEASE_PROSE, m.chain)
    m.send(bakery.pay(mill.address, 500_00, S.INTERMEDIATE, contract=lease, obligation="instalment-1"))
    while m.chain.height < 7:
        m.net.produce_block()                                           # time passes; instalment 2 falls due
    status = lambda at=None: {o["id"]: o for o in legal.compliance(m.chain, lease, at)}
    checks: List[Check] = [("before any dispute the missed instalment is OVERDUE", status()["instalment-2"]["status"] == "OVERDUE")]

    def rejected(wallet: Wallet, tx: T.Transaction) -> bool:
        m.send(tx)
        ok = m.chain.find_tx(tx.txid) is None
        wallet.resync(m.chain)
        return ok

    checks.append(("an outsider cannot open a dispute",
                   rejected(alice, alice.open_dispute(lease, "I object", ["instalment-2"]))))
    claim = mill.open_dispute(lease, "Instalment 2 unpaid since block 6.", ["instalment-2"])
    m.send(claim); dispute = claim.txid
    during = m.chain.height
    checks.append(("an obligation under an open dispute is reported as DISPUTED, not OVERDUE",
                   status()["instalment-2"]["status"] == "DISPUTED"))
    m.send(bakery.file_document(lease, dispute, "The grinder was out of service for two weeks.", "defence"))

    checks.append(("a party cannot decide its own dispute",
                   rejected(bakery, bakery.award(lease, dispute, "DISMISSED", "I win", []))))
    checks.append(("the arbitrator cannot increase what is owed",
                   rejected(arb, arb.award(lease, dispute, "UPHELD", "pay double",
                                           [{"obligation": "instalment-2", "amount": 1_000_00}]))))
    checks.append(("the arbitrator cannot touch an obligation that is not in dispute",
                   rejected(arb, arb.award(lease, dispute, "UPHELD", "refund",
                                           [{"obligation": "instalment-1", "waived": True}]))))
    m.send(arb.access(lease, "VIEW", "reading the lease for the arbitration"))
    checks.append(("the named arbitrator may read a restricted contract, and the read is on record",
                   vault.read(lease, arb.address, m.chain) == LEASE_PROSE))

    arb_balance, new_due = m.balance("auditor"), m.chain.height + 4
    m.send(arb.award(lease, dispute, "SETTLED", "Rent abated by one fifth for the outage; pay 400.00 by the new date.",
                     [{"obligation": "instalment-2", "amount": 400_00, "due_height": new_due}]))
    after = status()["instalment-2"]
    checks.append(("the award reduces and postpones the obligation",
                   (after["amount"], after["due_height"], after["status"]) == (400_00, new_due, "PENDING")))
    checks.append(("a dispute can be decided only once",
                   rejected(arb, arb.award(lease, dispute, "DISMISSED", "second thoughts", []))))
    mill_before = m.balance("mill")
    m.send(bakery.pay(mill.address, 400_00, S.INTERMEDIATE, contract=lease, obligation="instalment-2"))
    checks.append(("paying the awarded amount on time settles the obligation", status()["instalment-2"]["status"] == "PAID"))
    checks.append(("the award moved no money: only the debtor's own payment did",
                   m.balance("mill") - mill_before == 400_00 and m.balance("auditor") == arb_balance))
    checks.append(("history is preserved: OVERDUE at block 7, DISPUTED during the case",
                   status(7)["instalment-2"]["status"] == "OVERDUE" and status(during)["instalment-2"]["status"] == "DISPUTED"))
    report = legal.verify_evidence_bundle(json.loads(json.dumps(legal.evidence_bundle(m.chain, lease, LEASE_PROSE))),
                                          m.genesis["validators"])
    kinds = [e["kind"] for e in report["timeline"]]
    checks.append(("the claim, the defence and the award are all in the offline-verifiable evidence file",
                   report["valid"] and {T.DISPUTE_OPEN, T.DISPUTE_FILE, T.DISPUTE_AWARD} <= set(kinds)))

    if verbose:
        d = legal.dispute_record(m.chain, dispute)
        print(f"  dispute over '{d['contract_title']}': claimant {d['claimant']}, arbitrator {d['arbitrator']}, "
              f"opened block {d['opened_height']}, closed block {d['closed_height']}, outcome {d['award']['outcome']}")
        for f in d["filings"]:
            print(f"    filing at block {f['height']} by {f['by']}: {f['note']} ({f['document_hash'][:12]}...)")
        o = status()["instalment-2"]
        print(f"  instalment-2: originally {money(o['original_amount'])} due block {o['original_due_height']}; "
              f"after award {money(o['amount'])} due block {o['due_height']}; paid at block {o['settled_at']} -> {o['status']}")
    return {"checks": checks, "report": report}


def exp_asynchrony(verbose: bool = True, runs: int = 1000) -> Dict[str, Any]:
    """Why one round of voting is unsafe on a real network, and what fixes it."""
    single, double = bft.run_partition(two_phase=False), bft.run_partition(two_phase=True)
    a = double.nodes[0].decision
    rival = "block-r1-by-v1"
    checks: List[Check] = [
        ("single-phase voting FORKS under a partition, with zero dishonest validators", single.forked()),
        ("two-phase voting with locks, same adversary: all four validators finalise the same block",
         not double.forked() and all(d == a for d in double.decisions().values())),
        ("the lock did the work: a rival block was proposed in round 1, locked validators refused it",
         rival in double.nodes[2].proposals.get(1, {}) and bft.TwoPhaseNode._n(double.nodes[2].prevotes, 1, rival) < 3
         and double.nodes[2].locked_value == a and double.nodes[3].locked_value == a),
    ]

    stats = {}
    for two_phase in (False, True):
        forks = undecided = 0
        for seed in range(runs):
            sim = bft.run_fuzz(two_phase, seed, byzantine=1)
            forks += sim.forked(sim.honest)
            undecided += any(v is None for v in sim.decisions(sim.honest).values())
        stats[two_phase] = (forks, undecided)
    checks.append((f"{runs} random schedules with one lying validator: single-phase forks in some",
                   stats[False][0] > 0))
    checks.append((f"{runs} random schedules with one lying validator: two-phase never forks and always finalises",
                   stats[True] == (0, 0)))

    col = bft.run_collusion()
    checks.append(("honesty check - the one-third bound is real: two of four colluding validators fork even two-phase",
                   col.forked({2, 3})))
    checks.append(("...but both colluders are provably guilty: every honest validator holds their conflicting signatures",
                   bft.equivocators(col.nodes[2]) == {0, 1} == bft.equivocators(col.nodes[3])))
    checks.append(("no honest validator is ever implicated", all(not bft.equivocators(n) for n in double.nodes)))

    if verbose:
        for label, sim in (("single-phase", single), ("two-phase   ", double)):
            print(f"  {label}: " + "  ".join(f"v{i}={d}" for i, d in sim.decisions().items())
                  + f"   -> {'FORK' if sim.forked() else 'agreement'}")
        print(f"  random schedules ({runs} each, one lying validator): single-phase {stats[False][0]} forks; "
              f"two-phase {stats[True][0]} forks, {stats[True][1]} unfinished")
        print(f"  two colluders of four: v2={col.nodes[2].decision}, v3={col.nodes[3].decision}; "
              f"provably guilty: {sorted(bft.equivocators(col.nodes[2]))}")
    return {"checks": checks, "stats": stats}


EXPERIMENTS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "contracts": exp_contracts, "legal": exp_legal, "disputes": exp_disputes, "attacks": exp_attacks, "asynchrony": exp_asynchrony, "gdp": exp_gdp,
    "fraud": exp_fraud, "privacy": exp_privacy,
}
