"""Write (or check) each page's Content Security Policy from the hashes of its inline scripts.

    python tools/csp.py          # rewrite the <meta http-equiv="Content-Security-Policy"> of every page
    python tools/csp.py --check  # exit 1 if any page's policy is missing or out of date (used by the tests)

The policy allows scripts only from this site and the exact inline scripts it ships, so an
injected <script> or event-handler attribute does not run even if escaping failed somewhere
(audit H12: defence in depth).  Styles stay 'unsafe-inline' because the pages use style
attributes for layout; styles cannot execute code.  connect-src allows any http(s) origin
because the dashboard and wallet talk to an API address the user types in.
"""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent / "site"
PAGES = ["index.html", "dashboard.html", "explorer.html", "wallet.html"]
META = re.compile(r'\s*<meta http-equiv="Content-Security-Policy" content="[^"]*">')
INLINE = re.compile(r"<script>(.*?)</script>", re.S)


def policy(page: str) -> str:
    hashes = sorted("'sha256-" + base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode() + "'"
                    for m in INLINE.finditer(page))
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' " + " ".join(hashes),
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "connect-src 'self' http: https:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ])


def render(text: str) -> str:
    text = META.sub("", text)
    tag = f'<meta http-equiv="Content-Security-Policy" content="{policy(text)}">'
    return text.replace("<head>", "<head>\n" + tag, 1) if "<head>\n" in text or "<head>" in text else text


def main(argv: list[str]) -> int:
    stale = []
    for name in PAGES:
        p = SITE / name
        text = p.read_text()
        want = render(text)
        if want != text:
            stale.append(name)
            if "--check" not in argv:
                p.write_text(want)
    if "--check" in argv and stale:
        print("CSP out of date in: " + ", ".join(stale) + "  (run: python tools/csp.py)")
        return 1
    print("CSP " + ("checked" if "--check" in argv else "written") + f" for {len(PAGES)} pages")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
