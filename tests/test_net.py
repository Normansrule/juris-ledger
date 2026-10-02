"""Real processes, real sockets.  Slow (about a minute) but this is the claim that matters most."""
import json
import socket
import threading

import pytest

from jurisledger import net
from jurisledger.block import Block, BlockHeader
from jurisledger.cluster import run


def test_framing_roundtrip_and_oversize_rejected():
    a, b = socket.socketpair()
    net._send_frame(a, {"t": "status", "x": [1, 2, 3]})
    assert net._recv_frame(b) == {"t": "status", "x": [1, 2, 3]}
    a.sendall((net.MAX_FRAME + 1).to_bytes(4, "big"))
    assert net._recv_frame(b) is None
    a.close(); b.close()


def test_msg_wire_roundtrip_with_block():
    header = BlockHeader("c", 1, 0, "00" * 32, "11" * 32, "22" * 32, "ab" * 32, 1700000000000)
    block = Block(header, [], {"ab" * 32: "sig"}, commit_round=2)
    m = net.bft.Msg(net.bft.PROPOSAL, 0, block.hash, 1, 2, -1, via=1, sig="s", payload=block)
    back = net.msg_from_wire(json.loads(json.dumps(net.msg_to_wire(m, 1))))
    assert back.kind == m.kind and back.payload.hash == block.hash and back.payload.vote_round == 2


@pytest.mark.timeout(240)
def test_four_process_cluster_survives_a_crash(tmp_path):
    result = run(str(tmp_path / "cluster"), n=4, log=lambda *_: None)
    assert result.get("ok"), result


def test_store_from_another_ledger_is_refused(tmp_path):
    from jurisledger.experiments import MiniWorld
    from jurisledger.storage import BlockStore
    from jurisledger.net import Validator
    a, b = MiniWorld(chain_id="ledger-a"), MiniWorld(chain_id="ledger-b")
    store = BlockStore.create(tmp_path / "s", a.genesis)
    with pytest.raises(SystemExit):
        Validator(b.vkeys[0], b.genesis, [("127.0.0.1", 1)] * 4, store, ("127.0.0.1", 0), log=lambda *_: None)


def test_cluster_can_be_rerun_in_the_same_directory(tmp_path):
    out = tmp_path / "c"
    assert run(str(out), n=4, log=lambda *_: None).get("ok")
    assert run(str(out), n=4, log=lambda *_: None).get("ok")


def _one_validator(tmp_path):
    """A single live validator process-in-a-thread, for wire-level tests."""
    from jurisledger.experiments import MiniWorld
    from jurisledger.storage import BlockStore
    from jurisledger.net import Validator, free_ports
    m = MiniWorld(chain_id="wire-test")
    port = free_ports(1)[0]
    store = BlockStore.create(tmp_path / "s", m.genesis)
    v = Validator(m.vkeys[0], m.genesis, [("127.0.0.1", port)] + [("127.0.0.1", 1)] * 3, store,
                  ("127.0.0.1", port), log=lambda *_: None)
    t = threading.Thread(target=v.run, daemon=True)
    t.start()
    import time
    time.sleep(0.5)
    return m, v, port


def test_tls_pinning_rejects_the_wrong_key_and_accepts_the_right_one(tmp_path):
    from jurisledger.crypto import KeyPair
    m, v, port = _one_validator(tmp_path)
    try:
        assert net.Client("127.0.0.1", port, expect_address=m.vkeys[0].address).status()["height"] >= 0
        with pytest.raises(net.ssl.SSLError):
            net.Client("127.0.0.1", port, expect_address=KeyPair.from_seed("impostor").address).status()
        s = net.tls_connect(("127.0.0.1", port), None)
        assert s.version() == "TLSv1.3"
        s.close()
    finally:
        v.stop_event.set()


def test_unauthenticated_connections_cannot_send_consensus_traffic(tmp_path):
    m, v, port = _one_validator(tmp_path)
    try:
        s = net.tls_connect(("127.0.0.1", port), m.vkeys[0].address)
        net._recv_frame(s)                                            # challenge ignored: we are a stranger
        before = v.unauthenticated_frames
        net._send_frame(s, {"t": "get_blocks", "from": 1, "reply_to": 1})
        net._send_frame(s, {"t": "hello", "index": 1, "sig": "00" * 64})   # forged hello
        net._send_frame(s, {"t": "get_blocks", "from": 1, "reply_to": 1})
        import time
        time.sleep(0.5)
        assert v.unauthenticated_frames >= before + 3
        # a real peer key answering the challenge IS accepted
        s2 = net.tls_connect(("127.0.0.1", port), m.vkeys[0].address)
        ch = net._recv_frame(s2)
        net._send_frame(s2, {"t": "hello", "index": 1, "sig": m.vkeys[1].sign(net.HELLO_PREFIX + bytes.fromhex(ch["nonce"]))})
        net._send_frame(s2, {"t": "get_blocks", "from": 1, "reply_to": 1})
        time.sleep(0.5)
        assert v.unauthenticated_frames == before + 3
        s.close(); s2.close()
    finally:
        v.stop_event.set()


def test_pruning_validators_keep_running_and_a_late_validator_joins_by_snapshot(tmp_path):
    import subprocess
    import time
    from jurisledger.cluster import node_command, wait_height, write_cluster_files
    from jurisledger.net import Client
    from jurisledger.storage import BlockStore
    f = write_cluster_files(tmp_path, 4)
    vals = f["genesis"]["validators"]
    logs = [open(tmp_path / f"v{i}.log", "w") for i in range(4)]
    cmd = lambda i: node_command(tmp_path, i) + ["--prune-every", "4"]
    procs = {i: subprocess.Popen(cmd(i), stdout=logs[i], stderr=subprocess.STDOUT) for i in range(3)}  # v3 stays offline
    try:
        c0 = Client("127.0.0.1", f["ports"][0], expect_address=vals[0])
        assert wait_height(c0, 14, 120).get("height", 0) >= 14
        store0 = BlockStore(tmp_path / "store-0")
        assert store0.snapshot() and store0.archived()                       # pruned while running, history archived
        procs[3] = subprocess.Popen(cmd(3), stdout=logs[3], stderr=subprocess.STDOUT)
        c3 = Client("127.0.0.1", f["ports"][3], expect_address=vals[3])
        target = c0.status()["height"] + 2
        assert wait_height(c3, target, 120).get("height", 0) >= target       # caught up past the pruned blocks
        time.sleep(1)
        assert "certified snapshot" in (tmp_path / "v3.log").read_text()
        for i in range(4):
            procs[i].terminate(); procs[i].wait(10)
        chains = [BlockStore(tmp_path / f"store-{i}").load() for i in range(4)]   # every store reopens and re-verifies
        h = min(c.height for c in chains)
        assert all(c.height >= h for c in chains) and chains[3].base_height > 0
        busy = BlockStore(tmp_path / "store-0"); busy.lock()
        r = subprocess.run(node_command(tmp_path, 0), capture_output=True, text=True, timeout=30)
        assert "REFUSED" in r.stdout and "another process" in r.stdout              # a second validator on one store is refused
        busy.unlock()
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.kill()
