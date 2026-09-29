"""A read-only JSON API over the ledger index, for dashboards and analysts.

    jurisledger api ledger.db                         # serve http://127.0.0.1:8080
    jurisledger api ledger.db --follow 10.0.0.5:7701 --pin <validator address> --every 10
                                                      # ...and keep the index current from a validator

Endpoints (GET only; everything else is 405):

    /api/status                           height, chain, block time, counts
    /api/gdp?from=A&to=B                  GDP by expenditure for a block range
    /api/metrics?from=A&to=B              the per-block time series (at most 5,000 rows per call)
    /api/accounts/top?n=10                busiest accounts
    /api/account/<name or address>        one account's latest payments
    /api/contract/<id>                    a contract's timeline

Safety, in order of importance:
* **Read-only.**  The database is opened with SQLite's read-only mode; the server has no code
  path that writes, and only the follow thread (a separate connection) ever appends.
* **Public data only.**  The index holds nothing the public ledger does not already publish.
* **Bounded.**  Every parameter is parsed as an integer or looked up by exact match through bound
  SQL parameters; result sizes are capped; each client address gets a token bucket
  (``rate`` requests per second, ``burst`` at once) and is answered 429 beyond it.
* **Loopback by default.**  Binding to another interface is an explicit ``--host`` choice.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .index import Index

MAX_ROWS = 5000


class RateLimiter:
    def __init__(self, rate: float = 20.0, burst: int = 40):
        self.rate, self.burst, self.buckets, self.lock = rate, burst, {}, threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(client, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.buckets[client] = (tokens, now)
                return False
            self.buckets[client] = (tokens - 1, now)
            if len(self.buckets) > 10000:                     # forget idle clients
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 60}
            return True


class ReadOnlyIndex(Index):
    """The same queries as Index, over a connection that cannot write."""

    def __init__(self, path: str | Path):                   # noqa: D401 - deliberately skips Index.__init__
        self.path = Path(path)
        self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)


def _int(q: Dict[str, list], key: str, default: Optional[int]) -> Optional[int]:
    v = q.get(key, [None])[0]
    if v is None:
        return default
    n = int(v)                                               # ValueError -> 400
    if n < 0 or n > 10 ** 12:
        raise ValueError(key)
    return n


def make_handler(db_path: Path, limiter: RateLimiter, cors: str) -> type:
    local = threading.local()

    def idx() -> ReadOnlyIndex:
        if not hasattr(local, "idx"):
            local.idx = ReadOnlyIndex(db_path)
        return local.idx

    def status(_q, _p):
        i = idx()
        h = i.height
        times = [r[0] for r in i.db.execute("SELECT timestamp FROM blocks ORDER BY height DESC LIMIT 21")]
        gaps = [a - b for a, b in zip(times, times[1:]) if a and b]
        return {"chain_id": i.meta("chain_id"), "height": h,
                "transactions": i.db.execute("SELECT COUNT(*) FROM txs").fetchone()[0],
                "accounts": i.db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0],
                "contracts": i.db.execute("SELECT COUNT(DISTINCT contract_id) FROM contract_events WHERE kind='CONTRACT_CREATE'").fetchone()[0],
                "median_block_ms": sorted(gaps)[len(gaps) // 2] if gaps else None,
                "last_block_time": times[0] if times else None}

    def gdp(q, _p):
        i = idx()
        return i.gdp(_int(q, "from", 1), _int(q, "to", i.height))

    def metrics(q, _p):
        i = idx()
        a, b = _int(q, "from", 1), _int(q, "to", i.height)
        b = min(b, a + MAX_ROWS - 1)
        return {"from": a, "to": b, "rows": list(i.metrics(a, b))}

    def top(q, _p):
        return {"accounts": idx().top_accounts(min(_int(q, "n", 10), 100))}

    def account(_q, who):
        i = idx()
        a = i.resolve(who)
        if not a:
            raise LookupError(f"no account named or addressed {who!r}")
        return {"address": a, "payments": i.account_history(a, 200)}

    def contract(_q, cid):
        events = idx().contract_timeline(cid)
        if not events:
            raise LookupError(f"no contract {cid!r}")
        return {"contract_id": cid, "events": events}

    exact: Dict[str, Callable] = {"/api/status": status, "/api/gdp": gdp, "/api/metrics": metrics, "/api/accounts/top": top}
    prefix: Tuple[Tuple[str, Callable], ...] = (("/api/account/", account), ("/api/contract/", contract))

    class Handler(BaseHTTPRequestHandler):
        server_version = "jurisledger-api/1"

        def log_message(self, *args: Any) -> None:            # quiet by default
            pass

        def _send(self, code: int, body: Dict[str, Any]) -> None:
            data = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if cors:
                self.send_header("Access-Control-Allow-Origin", cors)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:                             # noqa: N802
            if not limiter.allow(self.client_address[0]):
                return self._send(429, {"error": "too many requests; slow down"})
            url = urlparse(self.path)
            q = parse_qs(url.query)
            try:
                if url.path in exact:
                    return self._send(200, exact[url.path](q, None))
                for p, fn in prefix:
                    if url.path.startswith(p) and len(url.path) > len(p):
                        return self._send(200, fn(q, unquote(url.path[len(p):])[:200]))
                return self._send(404, {"error": "no such endpoint", "endpoints": list(exact) + [p + "<id>" for p, _ in prefix]})
            except LookupError as err:
                return self._send(404, {"error": str(err)})
            except ValueError:
                return self._send(400, {"error": "parameters must be small non-negative integers"})

        def do_OPTIONS(self) -> None:                         # noqa: N802 - CORS / private-network preflight
            self.send_response(204)
            if cors:
                self.send_header("Access-Control-Allow-Origin", cors)
                self.send_header("Access-Control-Allow-Methods", "GET")
                self.send_header("Access-Control-Allow-Private-Network", "true")   # lets the public site read a local API
            self.end_headers()

        def _no(self) -> None:
            self._send(405, {"error": "this API is read-only"})

        do_POST = do_PUT = do_DELETE = do_PATCH = _no     # noqa: N815

    return Handler


def follow(db_path: Path, source: str, every: float, pin: Optional[str], stop: threading.Event, log: Callable) -> None:
    """Keep the index current: every `every` seconds, export from a validator (re-audited
    locally by Client.export) and append new blocks."""
    from .net import Client
    host, port = source.rsplit(":", 1)
    client, index = Client(host, int(port), expect_address=pin), Index(db_path)
    while not stop.is_set():
        try:
            r = index.sync(client.export())
            if r["blocks_added"]:
                log(f"follow: +{r['blocks_added']} blocks, index at {r['height']}")
        except Exception as err:  # noqa: BLE001 - keep serving; report and retry
            log(f"follow: {err}")
        stop.wait(every)


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8080, rate: float = 20.0, burst: int = 40,
          cors: str = "*", follow_source: Optional[str] = None, every: float = 10.0, pin: Optional[str] = None,
          log: Callable = print) -> Tuple[ThreadingHTTPServer, threading.Event]:
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist; build it with: jurisledger index CHAIN.json -o {path}")
    server = ThreadingHTTPServer((host, port), make_handler(path, RateLimiter(rate, burst), cors))
    server.daemon_threads = True
    stop = threading.Event()
    if follow_source:
        threading.Thread(target=follow, args=(path, follow_source, every, pin, stop, log), daemon=True).start()
    return server, stop
