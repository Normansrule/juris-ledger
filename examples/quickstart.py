"""Ten-minute tour: build a four-validator network by hand, pay, contract, audit.

    python examples/quickstart.py
"""
from jurisledger import state as S
from jurisledger.chain import Chain
from jurisledger.consensus import Network
from jurisledger.contracts import ContractVault, Wallet, audit_trail, cite_external
from jurisledger.crypto import KeyPair
from jurisledger.stats import gdp

CHAIN_ID = "quickstart"

# 1. Keys.  Real users call KeyPair.generate(); seeds make this script repeatable.
people = {name: Wallet(KeyPair.from_seed(name), CHAIN_ID) for name in ("ana", "cafe", "roaster", "city")}
validators = [KeyPair.from_seed(f"validator-{i}") for i in range(4)]

# 2. Genesis: who exists, what they start with, who validates.
roles = {"ana": (S.HOUSEHOLD, ""), "cafe": (S.FIRM, "services"),
         "roaster": (S.FIRM, "manufacturing"), "city": (S.GOVERNMENT, "")}
genesis = {
    "chain_id": CHAIN_ID,
    "validators": [v.address for v in validators],
    "accounts": [{"address": w.address, "name": n, "role": roles[n][0], "sector": roles[n][1],
                  "balance": 10_000_00} for n, w in people.items()],
}
net = Network.create(genesis, validators)
ana, cafe, roaster, city = (people[n] for n in ("ana", "cafe", "roaster", "city"))

# 3. A signed supply contract that cites an external document by hash.
prose = "The Roaster supplies the Cafe with 40 kg of beans per month at 18.00 per kg."
create = roaster.create_contract("Bean supply 2026", prose, {"kg": 40, "price_cents": 1800},
                                 [roaster.address, cafe.address],
                                 [cite_external(b"Food safety code, chapter 4", "https://example.org/code", "quality standard")])
net.submit(create)
net.produce_block()
net.submit(cafe.sign_contract(create.txid, prose))
net.produce_block()

# 4. Economic activity, each payment tagged with what it is for.
for tx in (
    ana.pay(cafe.address, 4_50, S.FINAL_CONSUMPTION),
    cafe.pay(roaster.address, 720_00, S.INTERMEDIATE, contract=create.txid),
    city.pay(cafe.address, 300_00, S.GOVERNMENT_PURCHASE),
    cafe.pay(ana.address, 1_200_00, S.WAGES),
):
    net.submit(tx)
net.produce_block()

chain = net.reference.chain
report = gdp(chain)
print(f"blocks: {chain.height}   GDP by expenditure: {report.expenditure / 100:.2f}   "
      f"by production: {report.production / 100:.2f}")

# 5. Reading the contract needs an on-chain receipt, and leaves a trail.
vault = ContractVault()
vault.deposit(create.txid, prose, chain)
net.submit(cafe.access(create.txid, "VIEW", "checking the price"))
net.produce_block()
print("cafe reads:", vault.read(create.txid, cafe.address, chain))
for e in audit_trail(chain, create.txid):
    print(f"  block {e['height']}: {e['action']} by {e['accessor_name']} ({e['context']})")

# 6. Anyone can re-verify everything from the exported file alone.
audited = Chain.load(chain.export())
print("independent audit reproduces the state:", audited.state.root() == chain.state.root())
