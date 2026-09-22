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
