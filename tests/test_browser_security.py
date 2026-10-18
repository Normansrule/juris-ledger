"""The dashboard against a hostile API, in a real browser (audit H12 and H13).

A fake API serves (a) script-injection payloads in every string field and (b) more than
5,000 metric rows, then grows by one block.  The page must execute nothing, must draw
every row (paging past the API's 5,000-row cap), and must refresh when the height changes.
Skipped when Playwright or its Chromium is not installed.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

pw = pytest.importorskip("playwright.sync_api")

SITE = Path(os.environ.get("JURISLEDGER_SITE") or Path(__file__).resolve().parent.parent / "site").resolve()
XSS = '<img src=x onerror="window.__pwned=(window.__pwned||0)+1">'


class Fake:
    height = 5003
    max_rows = 5000

    @classmethod
    def row(cls, h):
        return {"height": h, "timestamp": 1_700_000_000_000 + h * 1000, "n_votes": 3, "commit_round": 0, "n_tx": 1,
                "n_payments": 1, "volume": 100, "c": 100, "i": 0, "g": 0, "x": 0, "m": 0, "confidential": 0}


def handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, body):
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/api/status":
                return self._json({"chain_id": XSS, "height": Fake.height, "transactions": XSS})
            if u.path == "/api/metrics":
                a, b = int(q["from"][0]), min(int(q["to"][0]), Fake.height)
                b = min(b, a + Fake.max_rows - 1)
                return self._json({"from": a, "to": b, "rows": [Fake.row(h) for h in range(a, b + 1)]})
            if u.path == "/api/accounts/top":
                return self._json({"accounts": [{"name": XSS, "role": XSS, "paid": XSS, "received": 5}]})
            if u.path == "/api/sut":
                return self._json({"industries": [XSS], "products": [XSS], "final_columns": [XSS], "use": [[1]],
                                   "final": [[1]], "output": [1], "supply": {XSS: 1}, "imbalances": {XSS: 0},
                                   "value_added": {XSS: [1]}, "gdp": {"production": 1, "expenditure": 1, "income": 1},
                                   "leontief": {"industries": [XSS], "matrix": [[1]]}})
            path = SITE / u.path.lstrip("/")
            if path.is_file() and SITE in path.resolve().parents:
                self.send_response(200)
                self.send_header("Content-Type", "text/html" if path.suffix == ".html" else "application/javascript"
                                 if path.suffix == ".js" else "text/css")
                self.end_headers()
                self.wfile.write(path.read_bytes())
            else:
                self.send_response(404)
                self.end_headers()
    return H


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(scope="module")
def browser():
    try:
        p = pw.sync_playwright().start()
        b = p.chromium.launch()
    except Exception as err:  # noqa: BLE001
        pytest.skip(f"Chromium not available: {err}")
    yield b
    b.close()
    p.stop()


@pytest.fixture(scope="module")
def page(server, browser):
    # bypass_csp: these two tests check the FIRST wall (escaping) on its own; the CSP is tested below.
    pg = browser.new_context(bypass_csp=True).new_page()
    pg.goto(server + "/dashboard.html")
    pg.fill("#apiUrl", server)
    pg.click("#connect")
    yield pg


def test_H12_hostile_api_strings_never_execute(page):
    page.wait_for_function("document.querySelector('#liveText').textContent.includes('live')", timeout=20000)
    page.wait_for_timeout(500)
    page.hover("#cTx")                                         # tooltips render API data too
    assert page.evaluate("window.__pwned || 0") == 0
    assert page.locator("#top img").count() == 0 and page.locator("#sut img").count() == 0
    assert XSS in page.inner_text("#top")                     # shown as text, not dropped


def test_H13_dashboard_pages_past_5000_rows_and_refreshes_on_new_blocks(page):
    page.wait_for_function("document.querySelector('#cTx').getAttribute('aria-label')?.includes('5003 blocks')", timeout=20000)
    Fake.height = 5004                                         # one new block, same row count per page
    page.wait_for_function("document.querySelector('#cTx').getAttribute('aria-label')?.includes('5004 blocks')", timeout=20000)
    assert "NOT verified" in page.inner_text("#trust")


@pytest.mark.parametrize("name", ["index.html", "dashboard.html", "explorer.html", "wallet.html"])
def test_H12_pages_run_under_their_csp_without_violations(server, browser, name):
    ctx = browser.new_context()
    try:
        pg = ctx.new_page()
        violations = []
        pg.on("console", lambda m: violations.append(m.text) if "Content Security Policy" in m.text else None)
        pg.goto(f"{server}/{name}")
        pg.wait_for_timeout(1500)
        if name == "explorer.html":
            pg.click("#sample")                               # exercise the page's scripts
            pg.wait_for_timeout(9000)
            assert pg.inner_text("#verdict") == "Verified"
        assert pg.evaluate("!!document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]')")
        assert pg.evaluate("!!window.JurisSafe")                    # the page's own scripts were allowed
        injected = pg.evaluate("""() => { window.__ran = 0; const d = document.createElement('div');
            d.innerHTML = '<img src=x onerror="window.__ran=1">'; document.body.appendChild(d);
            return new Promise(r => setTimeout(() => r(window.__ran), 300)); }""")
        assert injected == 0                                    # even a raw injection is blocked by the policy
        assert all("inline event handler" in v for v in violations), violations   # only our own probe was refused
    finally:
        ctx.close()


def test_H12_csp_is_current():
    import subprocess
    import sys
    r = subprocess.run([sys.executable, str(Path(__file__).resolve().parent.parent / "tools/csp.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("name", ["index.html", "dashboard.html", "explorer.html", "wallet.html"])
def test_pages_do_not_scroll_sideways_on_a_phone(server, browser, name):
    """Audit: mobile layout.  At 375 CSS pixels nothing may push the page wider than the screen."""
    ctx = browser.new_context(viewport={"width": 375, "height": 800}, bypass_csp=True)
    try:
        pg = ctx.new_page()
        pg.goto(f"{server}/{name}")
        pg.wait_for_timeout(1200)
        assert pg.evaluate("document.documentElement.scrollWidth") <= 375
    finally:
        ctx.close()
