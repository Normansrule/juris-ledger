from jurisledger import privacy
from jurisledger import state as S
from jurisledger.experiments import MiniWorld
from jurisledger.stats import gdp


def test_hand_computed_gdp():
    m = MiniWorld()
    w = m.w
    m.send(
        w["alice"].pay(w["bakery"].address, 1000, S.FINAL_CONSUMPTION),      # C  +1000
        w["bakery"].pay(w["mill"].address, 400, S.INTERMEDIATE),             # input, not GDP
        w["mill"].pay(w["importer"].address, 150, S.INTERMEDIATE),           # imported input, M +150
        w["treasury"].pay(w["mill"].address, 300, S.GOVERNMENT_PURCHASE),    # G  +300
        w["treasury"].pay(w["alice"].address, 200, S.WAGES),                 # G  +200 (output at cost)
        w["importer"].pay(w["mill"].address, 500, S.EXPORT),                 # X  +500
        w["bakery"].pay(w["auditor"].address, 250, S.INVESTMENT),            # I  +250
        w["bank-a"].pay(w["bakery"].address, 9999, S.FINANCIAL),             # loan, not GDP
        w["bakery"].pay(w["alice"].address, 350, S.WAGES),
        w["bakery"].pay(w["treasury"].address, 50, S.TAX, tax_type="production"),
    )
    r = gdp(m.chain)
    assert (r.C, r.I, r.G, r.X, r.M) == (1000, 250, 500, 500, 150)
    assert r.expenditure == 2100
    va = {m.chain.state.accounts[a]["name"]: v for a, v in r.value_added().items()}
    assert va == {"bakery": 600, "mill": 1050, "auditor": 250}
    assert r.production == 600 + 1050 + 250 + 200 == r.expenditure
    assert r.wages == 550 and r.production_taxes == 50
    assert r.operating_surplus == 2100 - 550 - 50


def test_pedersen_group_and_homomorphism():
    assert privacy.G.in_subgroup() and privacy.H.in_subgroup() and privacy.G != privacy.H
    (c1, o1), (c2, o2) = privacy.commit(40), privacy.commit(2)
    assert c1 != privacy.commit(40)[0]                                       # hiding: fresh randomness
    assert privacy.verify_opening(privacy.combine([c1, c2]), privacy.aggregate_opening([o1, o2]))
    assert not privacy.verify_opening(c1, privacy.Opening(41, o1.blinding))  # binding
