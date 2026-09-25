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

Transport security.  Every connection is Transport Layer Security (TLS) 1.3.  A validator's
certificate is self-signed with its own Ed25519 validator key, so there is no certificate
authority to trust: a connecting node checks that the certificate's public key IS the
validator address listed in the genesis (public-key pinning).  Inside the tunnel the server
issues a random challenge; a peer proves it holds a validator key by signing it, and only
authenticated peers may send consensus messages or block-sync traffic.  Wallets and tools
connect the same way without answering the challenge and may only submit transactions or
read status.  Connections are capped per listener.

Peers are trusted for nothing beyond that: a frame that fails signature or certificate
checks is dropped and counted.  A crashed node restarts from its store and rejoins by
asking peers for the blocks it missed.
"""
from __future__ import annotations

import datetime
import json
import os
import queue
import secrets
import socket
import ssl
import struct
import tempfile
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
from .crypto import KeyPair, verify
from .ledgernet import TwoPhaseBlockNode
from .storage import BlockStore

IDLE_BLOCK_SECONDS = 2.0     # with an empty mempool the proposer waits this long before proposing an empty block
MAX_CONNECTIONS = 256        # simultaneous inbound connections per validator
RATE_WINDOW_SECONDS = 10.0   # per-source connection rate limit: at most RATE_MAX new connections per window
RATE_MAX = 60
HELLO_PREFIX = b"jurisledger/peer-hello/v1:"
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


# --------------------------------------------------------------------------- #
# TLS with public-key pinning (no certificate authority)
# --------------------------------------------------------------------------- #
def make_certificate(key: KeyPair) -> str:
    """A self-signed X.509 certificate for the validator's own Ed25519 key, plus that key,
    as one PEM string (written to a private temp file for the ssl module)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    priv = key._private
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"validator {key.address[:16]}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(priv, None))
    return (cert.public_bytes(serialization.Encoding.PEM)
            + priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())).decode()


def server_context(key: KeyPair) -> ssl.SSLContext:
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    os.chmod(f.name, 0o600)
    f.write(make_certificate(key))
    f.close()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(f.name)
    os.unlink(f.name)
    return ctx


def client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # no CA: the certificate is checked by pinning, below
    return ctx


def peer_public_key(sock: ssl.SSLSocket) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    der = sock.getpeercert(binary_form=True)
    pub = x509.load_der_x509_certificate(der).public_key()
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def tls_connect(addr: Tuple[str, int], expect_address: Optional[str], timeout: float = 2) -> ssl.SSLSocket:
    """Connect, upgrade to TLS, and refuse to talk unless the certificate belongs to ``expect_address``."""
    raw = socket.create_connection(addr, timeout=timeout)
    s = client_context().wrap_socket(raw, server_hostname=addr[0])
    if expect_address is not None and peer_public_key(s) != expect_address:
        s.close()
        raise ssl.SSLError(f"certificate at {addr[0]}:{addr[1]} is not the expected validator key (pinning failed)")
    s.settimeout(None)
    return s


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
    def __init__(self, index: int, peers: List[Tuple[str, int]], inbox: "queue.Queue[Dict[str, Any]]",
                 addresses: Optional[List[str]] = None, key: Optional[KeyPair] = None):
        self.i, self.peers, self.inbox = index, peers, inbox
        self.addresses, self.key = addresses, key
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
                expect = self.addresses[dst] if self.addresses else None
                s = tls_connect(self.peers[dst], expect)
                challenge = _recv_frame(s)                       # prove we hold a validator key
                if self.key is not None and challenge and challenge.get("t") == "challenge":
                    _send_frame(s, {"t": "hello", "index": self.i,
                                    "sig": self.key.sign(HELLO_PREFIX + bytes.fromhex(challenge["nonce"]))})
                self._socks[dst] = s
            except (OSError, ssl.SSLError, ValueError):
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
        self.transport = Transport(self.index, self.peers, self.inbox, list(self.genesis["validators"]), self.key)
        self.tls = server_context(self.key)
        self.connections = threading.Semaphore(MAX_CONNECTIONS)
        self.unauthenticated_frames = 0
        self.rate_limited = 0
        self._recent: Dict[str, List[float]] = {}
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

    PEER_ONLY = {"msg", "get_blocks", "blocks", "status_reply"}

    def _handle(self, obj: Dict[str, Any]) -> None:
        t = obj.get("t")
        if t in self.PEER_ONLY and obj.get("_peer") is None:
            self.unauthenticated_frames += 1                    # consensus traffic needs a proven peer
            return
        if t == "msg" and obj.get("via") != obj.get("_peer"):
            self.unauthenticated_frames += 1                    # a peer may only speak for itself
            return
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
            lo = max(0, start - self.chain.base_height - 1)
            blocks = [b.to_dict() for b in self.chain.blocks[lo:lo + 50]]
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
                conn, (src_ip, _) = srv.accept()
            except socket.timeout:
                continue
            now = time.monotonic()
            recent = [t for t in self._recent.get(src_ip, []) if now - t < RATE_WINDOW_SECONDS]
            if len(recent) >= RATE_MAX:
                self.rate_limited += 1
                conn.close()                                    # this source is opening connections too fast
                continue
            recent.append(now)
            self._recent[src_ip] = recent
            if not self.connections.acquire(blocking=False):
                conn.close()                                    # over the cap: refuse, do not queue
                continue
            threading.Thread(target=self._reader, args=(conn,), daemon=True).start()
        srv.close()

    def _reader(self, raw: socket.socket) -> None:
        try:
            self._reader_inner(raw)
        finally:
            self.connections.release()

    def _reader_inner(self, raw: socket.socket) -> None:
        try:
            raw.settimeout(5)
            conn = self.tls.wrap_socket(raw, server_side=True)
            conn.settimeout(None)
            nonce = secrets.token_bytes(32)
            _send_frame(conn, {"t": "challenge", "nonce": nonce.hex()})
        except (OSError, ssl.SSLError):
            raw.close()
            return
        peer: Optional[int] = None
        with conn:
            while not self.stop_event.is_set():
                try:
                    obj = _recv_frame(conn)
                except (OSError, ValueError):
                    return
                if obj is None:
                    return
                if obj.get("t") == "hello":
                    idx = obj.get("index")
                    vals = self.genesis["validators"]
                    if isinstance(idx, int) and 0 <= idx < len(vals) and idx != self.index and \
                            verify(vals[idx], HELLO_PREFIX + nonce, str(obj.get("sig", ""))):
                        peer = idx
                    else:
                        self.unauthenticated_frames += 1
                    continue
                obj["_peer"] = peer
                if obj.get("t") == "status" and "reply_to" not in obj:   # a client, not a peer: answer inline
                    try:
                        _send_frame(conn, {"t": "status_reply", "index": self.index, "height": self.chain.height,
                                           "root": self.chain.state.root(), "mempool": len(self.inner.mempool),
                                           "validators": list(self.chain.state.validators)})
                    except OSError:
                        return
                    continue
                if obj.get("t") == "account":
                    a = self.chain.state.accounts.get(str(obj.get("address")), None)
                    try:
                        _send_frame(conn, {"t": "account_reply", "found": a is not None,
                                           **({k: a[k] for k in ("name", "role", "sector", "balance", "nonce")} if a else {}),
                                           "hidden": a.get("hidden") if a else None, "height": self.chain.height})
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

    def __init__(self, host: str, port: int, expect_address: Optional[str] = None):
        """``expect_address`` pins the validator's key; without it the tunnel is encrypted but
        the server is not authenticated (fine on localhost, not across a network)."""
        self.addr, self.expect = (host, port), expect_address

    def _call(self, obj: Dict[str, Any], expect_reply: bool) -> Optional[Dict[str, Any]]:
        with tls_connect(self.addr, self.expect, timeout=5) as s:
            _recv_frame(s)                                      # the challenge; clients need not answer it
            _send_frame(s, obj)
            return _recv_frame(s) if expect_reply else None

    def submit(self, tx: T.Transaction) -> None:
        self._call({"t": "tx", "tx": tx.to_dict()}, expect_reply=False)

    def status(self) -> Dict[str, Any]:
        r = self._call({"t": "status"}, expect_reply=True)
        return r or {}

    def account(self, address: str) -> Dict[str, Any]:
        return self._call({"t": "account", "address": address}, expect_reply=True) or {}

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
