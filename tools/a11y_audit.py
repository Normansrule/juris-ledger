"""Accessibility audit: every site page and the generated public register, light and dark,
against WCAG 2.1 A and AA with axe-core (the engine behind most accessibility checkers).

    npm install --prefix /tmp/axe axe-core@4
    pip install playwright && python -m playwright install chromium
    python tools/a11y_audit.py /tmp/axe/node_modules/axe-core/axe.min.js

Exit code 1 if anything is flagged.  Automated checks find roughly a third of real problems;
keyboard-only and screen-reader passes are still done by hand (docs/ACCESSIBILITY.md).
"""
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from jurisledger.demo import build  # noqa: E402

PAGES = {"index.html": None, "explorer.html": "#sample", "dashboard.html": None, "wallet.html": "#newKey"}
RULES = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]


def main(axe_path: str) -> int:
    axe = Path(axe_path).read_text()
    register = build(tempfile.mkdtemp() + "/demo")["register"]
    targets = [(f"site/{p}", "file://" + str(ROOT / "site" / p), c) for p, c in PAGES.items()] + [("register.html", "file://" + register, None)]
    bad = 0
    with sync_playwright() as pw:
        browser = browser_ = pw.chromium.launch()
        for scheme in ("light", "dark"):
            for name, url, click in targets:
                page = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme=scheme)
                page.goto(url)
                page.wait_for_timeout(600)
                if click:
                    page.click(click)
                    page.wait_for_timeout(6000 if "explorer" in name else 600)
                page.add_script_tag(content=axe)
                found = page.evaluate("async r => (await axe.run(document, {runOnly: {type: 'tag', values: r}})).violations"
                                      ".map(v => [v.id, v.nodes.length, v.help])", RULES)
                bad += sum(n for _, n, _ in found)
                print(f"{'ok  ' if not found else 'FAIL'} {scheme:<5} {name:<22}" + "".join(f"\n       {i} x{n}: {h}" for i, n, h in found))
                page.close()
        browser_.close()
    print(f"\n{bad} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/axe/node_modules/axe-core/axe.min.js"))
