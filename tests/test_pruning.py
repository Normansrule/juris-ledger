import gzip
import json

import pytest

from jurisledger import state as S
from jurisledger.__main__ import main
from jurisledger.block import Block
from jurisledger.chain import Chain, InvalidBlock
from jurisledger.experiments import MiniWorld
from jurisledger.storage import BlockStore, StoreBusy


@pytest.fixture
def world():
    m = MiniWorld()
    for i in range(30):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 100 + i, S.FINAL_CONSUMPTION))
    return m


def stored(m, tmp_path, name="s"):
    st = BlockStore.create(tmp_path / name, m.genesis)
    st.save(m.chain)
    return st


def test_prune_keeps_state_archives_history_and_can_prune_again(world, tmp_path):
    st = stored(world, tmp_path)
    r = st.compact(10)
    assert r["pruned"] == 20 and r["base"] == 20 and r["bytes_after"] < r["bytes_before"] / 2
    c = BlockStore(tmp_path / "s").load()
    assert (c.height, c.base_height, c.state.root()) == (30, 20, world.chain.state.root())
    for i in range(10):                                              # the ledger keeps growing
        world.send(world.w["alice"].pay(world.w["mill"].address, 7, S.FINAL_CONSUMPTION))
    assert st.save(world.chain) == 10
    assert st.compact(5)["pruned"] == 15                              # prune an already pruned store
    archived = [b for f in st.archived() for b in gzip.decompress(f.read_bytes()).splitlines()]
    heights = [json.loads(x)["header"]["height"] for x in archived]
    assert heights == list(range(1, 36))                              # nothing lost: every retired block archived, in order
    full = Chain.audit(world.genesis, [Block.from_dict(json.loads(x)) for x in archived]
                       + BlockStore(tmp_path / "s").load().blocks)
    assert full.state.root() == world.chain.state.root()              # archive + store replay to the same state


def test_no_archive_drops_history(world, tmp_path):
    st = stored(world, tmp_path)
    st.compact(10, keep_archive=False)
    assert not st.archived() and BlockStore(tmp_path / "s").load().height == 30


def test_crash_between_snapshot_and_rewrite_still_opens(world, tmp_path):
    st = stored(world, tmp_path)
    full = st.blocks_path.read_bytes()
    st.compact(5)
    st.blocks_path.write_bytes(full)                                  # the final rename never happened
    c = BlockStore(tmp_path / "s").load()
    assert c.height == 30 and c.state.root() == world.chain.state.root()


def test_tampered_snapshot_and_foreign_snapshot_are_refused(world, tmp_path):
    st = stored(world, tmp_path)
    st.compact(10)
    snap = json.loads(st.snapshot_path.read_text())
    snap["state"]["accounts"][world.w["alice"].address]["balance"] += 1
    st.snapshot_path.write_text(json.dumps(snap))
    with pytest.raises(InvalidBlock):
        BlockStore(tmp_path / "s").load()
    other = MiniWorld(chain_id="elsewhere")
    for _ in range(3):
        other.send(other.w["alice"].pay(other.w["bakery"].address, 5, S.FINAL_CONSUMPTION))
    st2 = stored(world, tmp_path, "t")
    st2.snapshot_path.write_text(json.dumps({**other.chain.make_snapshot(), "certified_by": other.genesis["validators"]}))
    with pytest.raises(InvalidBlock):
        BlockStore(tmp_path / "t").load()


def test_lock_is_exclusive_and_cli_prune(world, tmp_path, capsys):
    st = stored(world, tmp_path)
    st.lock()
    with pytest.raises(StoreBusy):
        BlockStore(tmp_path / "s").lock()
    assert main(["jurisledger", "prune", "--store", str(tmp_path / "s"), "--keep", "10"]) == 1
    assert "REFUSED" in capsys.readouterr().out
    st.unlock()
    assert main(["jurisledger", "prune", "--store", str(tmp_path / "s"), "--keep", "10"]) == 0
    assert "pruned blocks up to 20" in capsys.readouterr().out
    assert main(["jurisledger", "prune", "--store", str(tmp_path / "s"), "--keep", "10"]) == 0
    assert "nothing to prune" in capsys.readouterr().out


def test_index_refuses_a_gap_left_by_pruning(world, tmp_path):
    from jurisledger.index import Index, IndexError_
    m = MiniWorld()
    for i in range(5):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 10 + i, S.FINAL_CONSUMPTION))
    idx = Index(tmp_path / "l.db")
    idx.sync(m.chain)
    for i in range(10):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 20 + i, S.FINAL_CONSUMPTION))
    st = stored(m, tmp_path)
    st.compact(3)
    with pytest.raises(IndexError_, match="were pruned"):
        idx.sync(BlockStore(tmp_path / "s").load())
