import json

import pytest

from jurisledger import state as S
from jurisledger.__main__ import main
from jurisledger.chain import Chain
from jurisledger.demo import build
from jurisledger.experiments import MiniWorld
from jurisledger.index import Index, IndexError_
from jurisledger.sim import SimConfig, run_simulation
from jurisledger.stats import gdp


@pytest.fixture(scope="module")
def econ():
    return run_simulation(SimConfig(periods=3)).chain


def test_index_gdp_matches_stats_for_every_range(econ, tmp_path):
    idx = Index(tmp_path / "l.db")
    idx.sync(econ)
    for a, b in ((1, econ.height), (1, 1), (2, econ.height), (econ.height, econ.height)):
        g, py = idx.gdp(a, b), gdp(econ, a, b)
        assert (g["C"], g["I"], g["G"], g["X"], g["M"], g["gdp"]) == (py.C, py.I, py.G, py.X, py.M, py.expenditure)


def test_index_is_incremental_and_refuses_a_different_history(tmp_path):
    m = MiniWorld()
    for i in range(3):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 100 + i, S.FINAL_CONSUMPTION))
    idx = Index(tmp_path / "l.db")
    assert idx.sync(m.chain)["blocks_added"] == 3 and idx.sync(m.chain)["blocks_added"] == 0
    m.send(m.w["alice"].pay(m.w["bakery"].address, 999, S.FINAL_CONSUMPTION))
    assert idx.sync(m.chain)["blocks_added"] == 1 and idx.height == 4
    other = MiniWorld()                                             # same genesis, different blocks
    for i in range(5):
        other.send(other.w["alice"].pay(other.w["mill"].address, 7 + i, S.FINAL_CONSUMPTION))
    with pytest.raises(IndexError_, match="not the same history"):
        idx.sync(other.chain)
    with pytest.raises(IndexError_, match="different ledger"):
        Index(tmp_path / "l.db").sync(MiniWorld(chain_id="elsewhere").chain)


def test_account_history_contract_timeline_and_metrics(tmp_path):
    made = build(str(tmp_path / "demo"))
    chain = Chain.load(open(made["chain"]).read())
    idx = Index(tmp_path / "l.db")
    idx.sync(chain)
    lease = next(c for c in chain.state.contracts.values() if c["title"] == "Cold-storage lease")
    kinds = [e["kind"] for e in idx.contract_timeline(lease["id"])]
    assert kinds[0] == "CONTRACT_CREATE" and "DISPUTE_AWARD" in kinds and kinds.count("PAYMENT") == 2
    hist = idx.account_history(idx.resolve("agriculture-firm-1"))
    assert any(r["purpose"] == S.INTERMEDIATE and r["direction"] == "out" for r in hist)
    rows = list(idx.metrics())
    assert len(rows) == chain.height and sum(r["n_tx"] for r in rows) == sum(len(b.txs) for b in chain.blocks)
    assert sum(r["gdp_contribution"] for r in rows) == gdp(chain).expenditure


def test_cli_index_query_metrics(tmp_path, capsys):
    made = build(str(tmp_path / "demo"))
    db = str(tmp_path / "l.db")
    assert main(["jurisledger", "index", made["chain"], "-o", db]) == 0
    assert main(["jurisledger", "query", db, "gdp"]) == 0
    assert "GDP 1,121,298.41" in capsys.readouterr().out
    assert main(["jurisledger", "query", db, "account", "bank-0"]) == 0
    assert main(["jurisledger", "metrics", db, "-o", str(tmp_path / "m.csv")]) == 0
    assert (tmp_path / "m.csv").read_text().startswith("height,timestamp")
    bad = json.loads(open(made["chain"]).read()); bad["blocks"][2]["votes"] = {}
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    assert main(["jurisledger", "index", str(tmp_path / "bad.json"), "-o", str(tmp_path / "x.db")]) == 1
