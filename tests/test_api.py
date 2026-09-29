import json
import threading
import urllib.error
import urllib.request

import pytest

from jurisledger.api import RateLimiter, serve
from jurisledger.chain import Chain
from jurisledger.demo import build
from jurisledger.index import Index
from jurisledger.net import free_ports
from jurisledger.stats import gdp


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    d = tmp_path_factory.mktemp("api")
    made = build(str(d / "demo"))
    chain = Chain.load(open(made["chain"]).read())
    Index(d / "l.db").sync(chain)
    port = free_ports(1)[0]
    server, stop = serve(str(d / "l.db"), port=port, rate=50, burst=200)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", chain
    stop.set(); server.shutdown()


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_endpoints(api):
    base, chain = api
    code, st = get(base + "/api/status")
    assert code == 200 and st["height"] == chain.height and st["chain_id"] == "demo-republic"
    code, g = get(base + "/api/gdp?from=1&to=12")
    assert g["gdp"] == gdp(chain).expenditure
    code, m = get(base + "/api/metrics?from=3&to=5")
    assert [r["height"] for r in m["rows"]] == [3, 4, 5]
    code, a = get(base + "/api/account/agriculture-firm-1")
    assert code == 200 and a["payments"]
    lease = next(c["id"] for c in chain.state.contracts.values() if c["title"] == "Cold-storage lease")
    code, c = get(base + "/api/contract/" + lease)
    assert code == 200 and c["events"][0]["kind"] == "CONTRACT_CREATE"
    assert get(base + "/api/top-secret")[0] == 404
    assert get(base + "/api/account/nobody")[0] == 404
    assert get(base + "/api/gdp?from=abc")[0] == 400


def test_read_only_and_injection_safe(api):
    base, chain = api
    req = urllib.request.Request(base + "/api/status", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 405
    from urllib.parse import quote
    assert get(base + "/api/account/" + quote("' OR '1'='1"))[0] == 404
    assert get(base + "/api/gdp?from=" + quote("1;DROP TABLE blocks"))[0] == 400
    assert get(base + "/api/status")[1]["height"] == chain.height


def test_rate_limiter():
    rl = RateLimiter(rate=1, burst=3)
    assert [rl.allow("a") for _ in range(4)] == [True, True, True, False]
    assert rl.allow("b")
