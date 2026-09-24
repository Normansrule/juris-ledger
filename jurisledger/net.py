"""Validators as real processes talking over TCP.

Each validator runs :func:`serve`: one process, one key, one on-disk :class:`BlockStore`,
one listening port.  It speaks the same signed two-phase protocol as
:mod:`jurisledger.ledgernet` - the protocol nodes are reused unchanged - with the
in-process simulator replaced by :class:`Transport`, which carries messages as
length-prefixed JSON frames over persistent TCP connections.

Wire messages (all JSON objects with a ``t`` field):

``msg``         a consensus message: height plus the fields of :class:`bft.Msg`;
                every one is Ed25519-signed by its sender and verified on receipt
``tx``          a signed transaction, gossiped to every peer
``get_blocks``  "send me finalised blocks from height h" - how a node that was down,
                or simply late, catches up; every received block's certificate is
                re-verified before it is accepted
``blocks``      the reply
``status``      / ``status_reply``  height, state digest, mempool size, validators

Peers are trusted for nothing: a frame that fails signature or certificate checks is
dropped and counted.  Transport security (encryption, peer authentication at the socket
level) is *not* provided here; run it over a private network or a TLS tunnel.  A crashed
node restarts from its store and rejoins by asking peers for the blocks it missed.
"""
from __future__ import annotations

import json
import os
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import bft
from . import consensus as C
from . import tx as T
from .block import Block
from .chain import Chain, InvalidBlock
from .consensus import Node
from .crypto import KeyPair
from .ledgernet import TwoPhaseBlockNode
from .storage import BlockStore

IDLE_BLOCK_SECONDS = 2.0     # with an empty mempool the proposer waits this long before proposing an empty block
TICK_SECONDS = 0.5           # one protocol tick; timeouts are 4 + 2 * round ticks
MAX_FRAME = 32 * 1024 * 1024


# --------------------------------------------------------------------------- #
# framing
# --------------------------------------------------------------------------- #
def _send_frame(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_frame(sock: socket.socket) -> Optional[Dict[str, Any]]:
    head = _recv_exact(sock, 4)
    if head is None:
        return None
    (n,) = struct.unpack(">I", head)
    if n > MAX_FRAME:
        return None
    body = _recv_exact(sock, n)
    return None if body is None else json.loads(body)


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def msg_to_wire(m: bft.Msg, height: int) -> Dict[str, Any]:
    return {"t": "msg", "h": height, "kind": m.kind, "round": m.round, "value": m.value, "src": m.src,
            "dst": m.dst, "valid_round": m.valid_round, "via": m.via, "sig": m.sig,
            "payload": m.payload.to_dict() if isinstance(m.payload, Block) else None}


def msg_from_wire(d: Dict[str, Any]) -> bft.Msg:
    payload = Block.from_dict(d["payload"]) if d.get("payload") else None
    return bft.Msg(d["kind"], d["round"], d["value"], d["src"], d["dst"], d["valid_round"],
                   via=d["via"], sig=d["sig"], payload=payload)


# --------------------------------------------------------------------------- #
# transport: the Sim interface the protocol nodes expect, over sockets
# --------------------------------------------------------------------------- #
class Transport:
    def __init__(self, index: int, peers: List[Tuple[str, int]], inbox: "queue.Queue[Dict[str, Any]]"):
        self.i, self.peers, self.inbox = index, peers, inbox
        self.time, self.flags = 0, {}
        self.height = 0
        self.local: Optional[TwoPhaseBlockNode] = None
        self._socks: Dict[int, socket.socket] = {}
        self._lock = threading.Lock()
        self.sent_frames = self.failed_sends = 0

    def _sock(self, dst: int) -> Optional[socket.socket]:
        s = self._socks.get(dst)
        if s is None:
            try:
                s = socket.create_connection(self.peers[dst], timeout=2)
                s.settimeout(None)
                self._socks[dst] = s
            except OSError:
                return None
        return s

    def send_raw(self, dst: int, obj: Dict[str, Any]) -> None:
        if dst == self.i:
            self.inbox.put(obj)
            return
        with self._lock:
            s = self._sock(dst)
            if s is None:
                self.failed_sends += 1
                return
            try:
                _send_frame(s, obj)
                self.sent_frames += 1
            except OSError:
                self.failed_sends += 1
                self._socks.pop(dst, None)
                try:
                    s.close()
                except OSError:
                    pass

    def broadcast_raw(self, obj: Dict[str, Any]) -> None:
        for dst in range(len(self.peers)):
            if dst != self.i:
                self.send_raw(dst, obj)

    # -- the Sim interface -------------------------------------------------- #
    def send(self, m: bft.Msg) -> None:
        m.sent = self.time
        self.send_raw(m.dst, msg_to_wire(m, self.height))

    def broadcast(self, m: bft.Msg) -> None:
        m.sent = self.time
        for dst in range(len(self.peers)):
            copy = bft.replace(m, dst=dst, via=m.src)
            if dst == self.i and self.local is not None:
                self.local.receive(copy)
            else:
                self.send_raw(dst, msg_to_wire(copy, self.height))

    def relay(self, m: bft.Msg, relayer: int) -> None:
        for dst in range(len(self.peers)):
            if dst not in (relayer, m.src, m.via):
                self.send_raw(dst, msg_to_wire(bft.replace(m, dst=dst, via=relayer), self.height))

    def close(self) -> None:
        with self._lock:
            for s in self._socks.values():
                try:
                    s.close()
                except OSError:
                    pass
            self._socks.clear()


# --------------------------------------------------------------------------- #
# the validator process
# --------------------------------------------------------------------------- #
@dataclass
class Validator:
    key: KeyPair
    genesis: Dict[str, Any]
    peers: List[Tuple[str, int]]          # index = position in genesis["validators"]
    store: BlockStore
    listen: Tuple[str, int]
    log: Any = print
    inbox: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)
    stop_event: threading.Event = field(default_factory=threading.Event)
    rejected: int = 0

    def __post_init__(self) -> None:
        self.index = self.genesis["validators"].index(self.key.address)
        self.inner = Node(self.key, self.genesis)
        from .crypto import hash_obj
        if hash_obj(self.store.genesis()) != hash_obj(self.genesis):
            raise SystemExit(f"the store in {self.store.dir} belongs to a different ledger (its founding record "
                             f"differs from {self.genesis['chain_id']}). Use an empty --store directory for a new "
                             f"ledger, or the matching genesis file to resume this one.")
        recovered = self.store.load()                          # resume from disk; re-audits every block
        for b in recovered.blocks:
            self.inner.commit(b)
        if recovered.height:
            self.log(f"[v{self.index}] resumed from disk at block {recovered.height}")
        self.transport = Transport(self.index, self.peers, self.inbox)
        self.proto: Optional[TwoPhaseBlockNode] = None
        self.future: Dict[int, List[bft.Msg]] = {}
        self.blocks_committed = 0

    # -- lifecycle ---------------------------------------------------------- #
    @property
    def chain(self) -> Chain:
        return self.inner.chain

    def _start_height(self) -> None:
        height = self.chain.height + 1
        addresses = list(self.chain.state.validators)
        self.proto = TwoPhaseBlockNode(addresses.index(self.key.address), len(addresses))
        self.proto.attach(self.inner, addresses, height)
        self.proto.sim = self.transport
        self.transport.local, self.transport.height = self.proto, height
        self.transport.time = 0
        self.height_started = time.monotonic()
        self.proposal_pending = self.proto.proposer(0) == self.proto.i     # we propose: maybe wait for work
        if not self.proposal_pending:
            self.proto.start_round(0)
        for m in self.future.pop(height, []):
            self.proto.receive(m)

    def _commit(self, block: Block) -> None:
        self.inner.commit(block)
        self.store.append(block)
        self.blocks_committed += 1
        for ev in (self.proto.evidence if self.proto else []):
            self.inner.receive_tx(ev)
            self.transport.broadcast_raw({"t": "tx", "tx": ev.to_dict()})
        if block.txs or block.header.height % 20 == 0:
            self.log(f"[v{self.index}] committed block {block.header.height} "
                     f"({len(block.txs)} tx, round {block.vote_round}, {len(block.votes)} votes)")

    def _handle(self, obj: Dict[str, Any]) -> None:
        t = obj.get("t")
        if t == "msg":
            h = obj.get("h", 0)
            if h < self.chain.height + 1:
                return                                          # stale height
            m = msg_from_wire(obj)
            if h > self.chain.height + 1:
                self.future.setdefault(h, []).append(m)
                if len(self.future[h]) == 1:                    # we are behind: ask for blocks
                    self.transport.send_raw(m.src, {"t": "get_blocks", "from": self.chain.height + 1,
                                                    "reply_to": self.index})
                return
            if self.proto is not None:
                try:
                    self.proto.receive(m)
                except (KeyError, ValueError, TypeError):
                    self.rejected += 1
        elif t == "tx":
            tx = T.Transaction.from_dict(obj["tx"])
            if tx.txid not in self.inner.mempool and tx.signature_valid():
                self.inner.receive_tx(tx)
                self.transport.broadcast_raw(obj)               # gossip once
        elif t == "get_blocks":
            start = int(obj.get("from", 1))
            blocks = [b.to_dict() for b in self.chain.blocks[start - 1:start + 49]]
            self.transport.send_raw(int(obj["reply_to"]), {"t": "blocks", "blocks": blocks})
        elif t == "blocks":
            before = self.chain.height
            for d in obj.get("blocks", []):
                try:
                    block = Block.from_dict(d)
                    if block.header.height != self.chain.height + 1:
                        continue
                    self.inner.chain.execute(block)             # every rule, including the certificate
                    self.inner.chain.check_certificate(block, self.chain.state.validators)
                    self._commit(block)
                    self._start_height()
                except (InvalidBlock, KeyError, ValueError):
                    self.rejected += 1
                    break
            if self.chain.height > before:
                self.log(f"[v{self.index}] caught up: blocks {before + 1}-{self.chain.height} received from a peer, "
                         f"every certificate re-verified")
        elif t == "status":
            self.transport.send_raw(int(obj["reply_to"]), {"t": "status_reply", "index": self.index,
                                                             "height": self.chain.height, "root": self.chain.state.root(),
                                                             "mempool": len(self.inner.mempool)})

    def run(self, until_height: Optional[int] = None) -> None:
        listener = threading.Thread(target=self._listen, daemon=True)
        listener.start()
        self._start_height()
        last_tick = time.monotonic()
        while not self.stop_event.is_set():
            try:
                obj = self.inbox.get(timeout=0.02)
                self._handle(obj)
            except queue.Empty:
                pass
            now = time.monotonic()
            if self.proto is not None and getattr(self, "proposal_pending", False) and \
                    (self.inner.mempool or now - self.height_started >= IDLE_BLOCK_SECONDS):
                self.proposal_pending = False
                self.proto.start_round(0)
            if now - last_tick >= TICK_SECONDS and self.proto is not None:
                last_tick = now
                self.transport.time += 1
                self.proto.tick()                               # idle validators still finalise (empty) blocks
            if self.proto is not None and self.proto.decision is not None and self.proto.decided_block is not None:
                self._commit(self.proto.decided_block)
                self._start_height()
                if until_height is not None and self.chain.height >= until_height:
                    break
        self.transport.close()

    def _listen(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(self.listen)
        srv.listen(64)
        srv.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._reader, args=(conn,), daemon=True).start()
        srv.close()

    def _reader(self, conn: socket.socket) -> None:
        with conn:
            while not self.stop_event.is_set():
                try:
                    obj = _recv_frame(conn)
                except (OSError, ValueError):
                    return
                if obj is None:
                    return
                if obj.get("t") == "status" and "reply_to" not in obj:   # a client, not a peer: answer inline
                    try:
                        _send_frame(conn, {"t": "status_reply", "index": self.index, "height": self.chain.height,
                                           "root": self.chain.state.root(), "mempool": len(self.inner.mempool),
                                           "validators": list(self.chain.state.validators)})
                    except OSError:
                        return
                    continue
                if obj.get("t") == "export":
                    try:
                        _send_frame(conn, {"t": "export_reply", "chain": self.chain.export()})
                    except OSError:
                        return
                    continue
                self.inbox.put(obj)


def serve(key: KeyPair, genesis: Dict[str, Any], peers: List[Tuple[str, int]], store_dir: str,
          listen: Tuple[str, int], until_height: Optional[int] = None, log: Any = print) -> Validator:
    if not (BlockStore(store_dir).genesis_path.exists()):
        store = BlockStore.create(store_dir, genesis)
    else:
        store = BlockStore(store_dir)
    v = Validator(key, genesis, peers, store, listen, log=log)
    v.run(until_height)
    return v


# --------------------------------------------------------------------------- #
# client
# --------------------------------------------------------------------------- #
class Client:
    """Talk to one validator: submit transactions, read status, export the chain."""

    def __init__(self, host: str, port: int):
        self.addr = (host, port)

    def _call(self, obj: Dict[str, Any], expect_reply: bool) -> Optional[Dict[str, Any]]:
        with socket.create_connection(self.addr, timeout=5) as s:
            _send_frame(s, obj)
            return _recv_frame(s) if expect_reply else None

    def submit(self, tx: T.Transaction) -> None:
        self._call({"t": "tx", "tx": tx.to_dict()}, expect_reply=False)

    def status(self) -> Dict[str, Any]:
        r = self._call({"t": "status"}, expect_reply=True)
        return r or {}

    def export(self) -> Chain:
        r = self._call({"t": "export"}, expect_reply=True)
        return Chain.load(r["chain"])            # re-audited locally: the node is not trusted


def free_ports(n: int) -> List[int]:
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports
