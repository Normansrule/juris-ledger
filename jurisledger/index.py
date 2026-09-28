"""A queryable index of the ledger, kept in SQLite, built incrementally.

The chain is the source of truth and replaying it answers every question -- slowly, and
more slowly every year.  A statistics office, a court registry or a dashboard needs
"all payments by this firm", "GDP for blocks 1,000 to 2,000" or "volume per block" in
milliseconds.  This module keeps those answers in an index:

* **derived, never trusted.**  Only blocks from an audited :class:`Chain` are indexed, and
  every stored block keeps its hash.  If the chain offered next time does not extend the
  history already indexed, the index refuses and says to rebuild.
* **incremental.**  ``sync`` appends only blocks it has not seen, in one database transaction,
  so a crash leaves the index at a block boundary.
* **one file, standard SQL.**  SQLite ships with Python; any analyst tool can open the file.

Tables: meta, accounts, blocks, txs, payments, contract_events, block_metrics.
"""
from __future__ import annotations

import csv
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import state as S
from . import tx as T
from .chain import Chain

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (address TEXT PRIMARY KEY, name TEXT, role TEXT, sector TEXT,
                                     successor TEXT, first_height INTEGER);
CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, prev_hash TEXT NOT NULL,
                                   timestamp INTEGER, proposer TEXT, round INTEGER, commit_round INTEGER,
                                   n_tx INTEGER, n_votes INTEGER);
CREATE TABLE IF NOT EXISTS txs (txid TEXT PRIMARY KEY, height INTEGER NOT NULL, idx INTEGER NOT NULL,
                                kind TEXT NOT NULL, sender TEXT NOT NULL, nonce INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS payments (txid TEXT PRIMARY KEY, height INTEGER NOT NULL, payer TEXT NOT NULL,
                                     payee TEXT NOT NULL, amount INTEGER NOT NULL, purpose TEXT NOT NULL,
                                     contract TEXT, obligation TEXT, invoice TEXT);
CREATE TABLE IF NOT EXISTS contract_events (txid TEXT PRIMARY KEY, contract_id TEXT NOT NULL, kind TEXT NOT NULL,
                                            actor TEXT NOT NULL, height INTEGER NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS block_metrics (height INTEGER PRIMARY KEY, n_tx INTEGER, n_payments INTEGER,
                                          volume INTEGER, c INTEGER, i INTEGER, g INTEGER, x INTEGER, m INTEGER,
                                          confidential INTEGER);
CREATE INDEX IF NOT EXISTS txs_sender ON txs(sender);
CREATE INDEX IF NOT EXISTS txs_height ON txs(height);
CREATE INDEX IF NOT EXISTS pay_payer ON payments(payer, height);
CREATE INDEX IF NOT EXISTS pay_payee ON payments(payee, height);
CREATE INDEX IF NOT EXISTS pay_purpose ON payments(purpose, height);
CREATE INDEX IF NOT EXISTS ce_contract ON contract_events(contract_id, height);
"""
GOODS = {S.FINAL_CONSUMPTION, S.INTERMEDIATE, S.INVESTMENT, S.GOVERNMENT_PURCHASE, S.EXPORT}


class IndexError_(Exception):
    pass


class Index:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")          # readers never block the writer
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # -- bookkeeping ------------------------------------------------------- #
    def meta(self, key: str) -> Optional[str]:
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r[0] if r else None

    @property
    def height(self) -> int:
        return self.db.execute("SELECT COALESCE(MAX(height), 0) FROM blocks").fetchone()[0]

    def _role(self, address: str) -> Optional[str]:
        r = self.db.execute("SELECT role FROM accounts WHERE address=?", (address,)).fetchone()
        return r[0] if r else None

    # -- building ------------------------------------------------------------ #
    def sync(self, chain: Chain) -> Dict[str, Any]:
        """Append every block of ``chain`` not yet indexed.  ``chain`` must already be audited
        (Chain.load / Chain.audit / a running node's chain)."""
        t0 = time.perf_counter()
        cid, gh = self.meta("chain_id"), self.meta("genesis_hash")
        if cid is None:
            with self.db:
                self.db.executemany("INSERT INTO meta VALUES (?,?)", [
                    ("chain_id", chain.chain_id), ("genesis_hash", chain.genesis_hash), ("schema", str(SCHEMA_VERSION)),
                    ("base_height", str(chain.base_height))])
                accounts = chain.genesis.get("accounts", []) + [
                    {"address": i["address"], "name": i["name"], "role": S.ISSUER} for i in chain.genesis.get("issuers", [])]
                if chain.base_height:                       # started from a snapshot: take accounts from its state
                    accounts = [{"address": a, **v} for a, v in chain.snapshot["state"]["accounts"].items()]
                self.db.executemany("INSERT OR IGNORE INTO accounts VALUES (?,?,?,?,NULL,0)",
                                    [(a["address"], a["name"], a["role"], a.get("sector", "")) for a in accounts])
        elif cid != chain.chain_id or gh != chain.genesis_hash:
            raise IndexError_(f"{self.path} indexes a different ledger ({cid}); use a new index file")
        have = self.height
        if have > chain.height:
            raise IndexError_(f"the index is at block {have} but the chain offered ends at block {chain.height}")
        if have and have > chain.base_height:
            stored = self.db.execute("SELECT hash FROM blocks WHERE height=?", (have,)).fetchone()[0]
            if chain.block_at(have).hash != stored:
                raise IndexError_(f"block {have} differs from the one indexed: this is not the same history; rebuild the index")
        added = tx_added = 0
        with self.db:                                       # one transaction: all or nothing
            for b in chain.blocks[max(0, have - chain.base_height):]:
                self._add_block(b)
                added += 1
                tx_added += len(b.txs)
        dt = time.perf_counter() - t0
        return {"blocks_added": added, "transactions_added": tx_added, "height": self.height, "seconds": dt,
                "tx_per_second": tx_added / dt if dt and tx_added else 0.0}

    def _add_block(self, b) -> None:
        h = b.header
        self.db.execute("INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?)",
                        (h.height, b.hash, h.prev_hash, h.timestamp, h.proposer, h.round, b.vote_round, len(b.txs), len(b.votes)))
        m = {"n_payments": 0, "volume": 0, "c": 0, "i": 0, "g": 0, "x": 0, "m": 0, "confidential": 0}
        for idx, t in enumerate(b.txs):
            txid, p = t.txid, t.payload
            self.db.execute("INSERT INTO txs VALUES (?,?,?,?,?,?)", (txid, h.height, idx, t.kind, t.sender, t.nonce))
            if t.kind == T.REGISTER:
                self.db.execute("INSERT OR IGNORE INTO accounts VALUES (?,?,?,?,NULL,?)",
                                (t.sender, p["name"], p["role"], p.get("sector", ""), h.height))
            elif t.kind in (T.KEY_ROTATE, T.RECOVERY_FINALIZE):
                old = t.sender if t.kind == T.KEY_ROTATE else p["subject"]
                row = self.db.execute("SELECT name, role, sector FROM accounts WHERE address=?", (old,)).fetchone()
                if row:
                    self.db.execute("INSERT OR IGNORE INTO accounts VALUES (?,?,?,?,NULL,?)", (p["new_key"], *row, h.height))
                    self.db.execute("UPDATE accounts SET successor=? WHERE address=?", (p["new_key"], old))
            elif t.kind == T.PAYMENT:
                self.db.execute("INSERT INTO payments VALUES (?,?,?,?,?,?,?,?,?)",
                                (txid, h.height, t.sender, p["to"], p["amount"], p["purpose"], p.get("contract"),
                                 p.get("obligation"), p.get("invoice")))
                m["n_payments"] += 1
                m["volume"] += p["amount"]
                self._accounts_add(m, t.sender, p)
            elif t.kind == T.CONFIDENTIAL_PAYMENT:
                m["confidential"] += 1
            cid = txid if t.kind == T.CONTRACT_CREATE else p.get("contract_id") or (p.get("contract") if t.kind == T.PAYMENT else None)
            if cid:
                detail = p.get("title") or p.get("action") or p.get("outcome") or p.get("obligation") or ""
                self.db.execute("INSERT INTO contract_events VALUES (?,?,?,?,?,?)", (txid, cid, t.kind, t.sender, h.height, str(detail)))
        self.db.execute("INSERT INTO block_metrics VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (h.height, len(b.txs), m["n_payments"], m["volume"], m["c"], m["i"], m["g"], m["x"], m["m"], m["confidential"]))

    def _accounts_add(self, m: Dict[str, int], payer: str, p: Dict[str, Any]) -> None:
        purpose, amount = p["purpose"], p["amount"]
        if purpose == S.FINAL_CONSUMPTION:
            m["c"] += amount
        elif purpose == S.INVESTMENT:
            m["i"] += amount
        elif purpose == S.GOVERNMENT_PURCHASE:
            m["g"] += amount
        elif purpose == S.EXPORT:
            m["x"] += amount
        elif purpose == S.WAGES and self._role(payer) == S.GOVERNMENT:
            m["g"] += amount
        if purpose in GOODS and self._role(p["to"]) == S.FOREIGN:
            m["m"] += amount

    # -- asking -------------------------------------------------------------- #
    def gdp(self, start: int = 1, end: Optional[int] = None) -> Dict[str, int]:
        end = self.height if end is None else end
        c, i, g, x, m = self.db.execute("SELECT COALESCE(SUM(c),0), COALESCE(SUM(i),0), COALESCE(SUM(g),0), "
                                        "COALESCE(SUM(x),0), COALESCE(SUM(m),0) FROM block_metrics WHERE height BETWEEN ? AND ?",
                                        (start, end)).fetchone()
        return {"C": c, "I": i, "G": g, "X": x, "M": m, "gdp": c + i + g + x - m, "from": start, "to": end}

    def resolve(self, who: str) -> Optional[str]:
        r = self.db.execute("SELECT address FROM accounts WHERE address=? OR name=? LIMIT 1", (who, who)).fetchone()
        return r[0] if r else None

    def account_history(self, address: str, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self.db.execute("""
            SELECT p.height, p.txid, p.payer, pa.name, p.payee, pb.name, p.amount, p.purpose
            FROM payments p LEFT JOIN accounts pa ON pa.address = p.payer LEFT JOIN accounts pb ON pb.address = p.payee
            WHERE p.payer = ? OR p.payee = ? ORDER BY p.height DESC, p.txid LIMIT ?""", (address, address, limit)).fetchall()
        return [{"height": h, "txid": t, "direction": "out" if a == address else "in",
                 "counterparty": (bn if a == address else an), "amount": amt, "purpose": pur}
                for h, t, a, an, b, bn, amt, pur in rows]

    def top_accounts(self, n: int = 10) -> List[Dict[str, Any]]:
        rows = self.db.execute("""
            SELECT a.name, a.role, COALESCE(o.v,0), COALESCE(i.v,0) FROM accounts a
            LEFT JOIN (SELECT payer k, SUM(amount) v FROM payments GROUP BY payer) o ON o.k = a.address
            LEFT JOIN (SELECT payee k, SUM(amount) v FROM payments GROUP BY payee) i ON i.k = a.address
            ORDER BY COALESCE(o.v,0) + COALESCE(i.v,0) DESC LIMIT ?""", (n,)).fetchall()
        return [{"name": r[0], "role": r[1], "paid": r[2], "received": r[3]} for r in rows]

    def contract_timeline(self, contract_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute("""SELECT e.height, e.kind, a.name, e.detail FROM contract_events e
                                  LEFT JOIN accounts a ON a.address = e.actor WHERE e.contract_id = ? ORDER BY e.height, e.txid""",
                               (contract_id,)).fetchall()
        return [{"height": h, "kind": k, "actor": n, "detail": d} for h, k, n, d in rows]

    def metrics(self) -> Iterable[Dict[str, Any]]:
        cur = self.db.execute("""SELECT b.height, b.timestamp, b.n_votes, b.commit_round, m.n_tx, m.n_payments, m.volume,
                                        m.c, m.i, m.g, m.x, m.m, m.confidential
                                 FROM blocks b JOIN block_metrics m ON m.height = b.height ORDER BY b.height""")
        cols = [d[0] for d in cur.description]
        for row in cur:
            d = dict(zip(cols, row))
            d["gdp_contribution"] = d["c"] + d["i"] + d["g"] + d["x"] - d["m"]
            yield d

    def write_metrics_csv(self, path: str | Path) -> int:
        rows = list(self.metrics())
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["height"])
            w.writeheader()
            w.writerows(rows)
        return len(rows)
