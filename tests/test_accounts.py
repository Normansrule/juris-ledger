import json
import sqlite3
import threading
import urllib.request
from fractions import Fraction

import pytest

from jurisledger import accounts as A
from jurisledger import state as S
from jurisledger.__main__ import main
from jurisledger.experiments import EXPERIMENTS, MiniWorld
from jurisledger.index import Index, IndexError_
from jurisledger.sim import SimConfig, run_simulation


@pytest.fixture(scope="module")
def econ():
    return run_simulation(SimConfig(periods=3))


def test_identities_on_a_simulated_economy(econ):
    t = A.from_chain(econ.chain)
    assert all(v == 0 for v in t.product_imbalances().values())
    assert t.gdp_production == t.gdp_expenditure == t.gdp_income == econ.economy.truth.gdp
    for i in t.industries:
        assert t.output.get(i, 0) == t.intermediate_of(i) + t.comp.get(i, 0) + t.net_taxes.get(i, 0) + t.surplus(i)


def test_hand_built_economy_matches_a_hand_calculation():
    """Five payments whose tables can be checked with a pencil."""
    m = MiniWorld()
    w = m.w
    m.send(w["alice"].pay(w["bakery"].address, 100_00, S.FINAL_CONSUMPTION),     # bakery sells bread: C
           w["bakery"].pay(w["mill"].address, 40_00, S.INTERMEDIATE),            # bakery buys flour from the mill
           w["mill"].pay(w["importer"].address, 10_00, S.INTERMEDIATE),          # the mill imports grain
           w["bakery"].pay(w["alice"].address, 30_00, S.WAGES),                  # wages
           w["treasury"].pay(w["alice"].address, 20_00, S.WAGES))                # a public servant's salary
    t = A.from_chain(m.chain)
    assert t.output == {"services": 100_00, "manufacturing": 40_00, "government": 20_00}
    assert t.use[("manufacturing", "services")] == 40_00 and t.use[("imports", "manufacturing")] == 10_00
    assert t.value_added("services") == 60_00 and t.value_added("manufacturing") == 30_00
    assert t.surplus("services") == 30_00 and t.surplus("government") == 0
    assert t.gdp_expenditure == 100_00 + 20_00 - 10_00 == t.gdp_production       # C + G - M
    L = t.leontief()                                                              # bread needs 0.4 of flour per unit
    dom = t.domestic()
    s, mf = dom.index("services"), dom.index("manufacturing")
    assert L[mf][s] == Fraction(2, 5) and L[s][s] == 1
    assert t.what_if({"services": 50_00}) == {"manufacturing": 20_00, "services": 50_00, "government": 0,
                                              **{i: 0 for i in dom if i not in ("manufacturing", "services", "government")}}


def test_index_tables_equal_chain_tables_and_old_indexes_upgrade(econ, tmp_path):
    db = tmp_path / "l.db"
    idx = Index(db)
    idx.sync(econ.chain)
    assert A.from_index(idx).to_dict() == A.from_chain(econ.chain).to_dict()
    idx.close()
    con = sqlite3.connect(db)                                     # make it look like a version-1 index
    con.executescript("ALTER TABLE payments DROP COLUMN tax_type;")
    con.close()
    old = Index(db)
    with pytest.raises(IndexError_, match="older version"):
        A.from_index(old)
    assert old.sync(econ.chain)["rebuilt"] is True                # re-indexing upgrades it in place
    assert A.from_index(old).to_dict() == A.from_chain(econ.chain).to_dict()


def test_cli_and_api(econ, tmp_path, capsys):
    from jurisledger.api import serve
    from jurisledger.net import free_ports
    chain_file = tmp_path / "chain.json"
    chain_file.write_text(econ.chain.export())
    assert main(["jurisledger", "sut", str(chain_file), "-o", str(tmp_path / "sut")]) == 0
    out = capsys.readouterr().out
    assert "supply = use for every product:          yes" in out and (tmp_path / "sut" / "use.csv").exists()
    db = tmp_path / "l.db"
    Index(db).sync(econ.chain)
    port = free_ports(1)[0]
    server, stop = serve(str(db), port=port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        d = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/sut", timeout=5).read())
        assert d["gdp"]["expenditure"] == econ.economy.truth.gdp and set(d["imbalances"].values()) == {0}
    finally:
        stop.set(); server.shutdown()


def test_accounts_experiment_passes():
    assert all(ok for _, ok in EXPERIMENTS["accounts"](verbose=False)["checks"])
