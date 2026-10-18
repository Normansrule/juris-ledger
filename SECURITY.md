# Security

## Status

JurisLedger is a **research prototype**. Version 0.26.0 fixes every finding we could reproduce
from the external audit of v0.25.0 (see [`docs/SECURITY_FINDINGS.md`](docs/SECURITY_FINDINGS.md)),
and the decision recorded there is: **not ready for production**. Do not use it for real money,
sensitive contracts, production signing keys or legal-evidence decisions.

A passing test suite is not a proof of security. It shows that the specific failures we know of
stay fixed.

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability** (Security tab of
`Normansrule/juris-ledger`), with a reproduction if you have one. Do not open a public issue for
an unfixed vulnerability. Reproductions are most useful as a script in the style of
[`tools/audit_repro.py`](tools/audit_repro.py) or a failing test.

## What is checked on every change

| Gate | Command |
|---|---|
| Unit, integration, live multi-process and browser security tests | `python -m pytest` |
| Every audit reproduction must be SAFE | `python tools/audit_repro.py` |
| Runtime dependencies have no published advisory | `pip-audit` (CI) |
| Content Security Policies match the shipped scripts | `python tools/csp.py --check` |
| 25,000 random hostile transactions against eight invariants | `jurisledger fuzz --runs 50 --steps 500` |
| Accessibility (WCAG 2.1 AA) | `python tools/a11y_audit.py AXE.js` |
| Every shipped file's hash, pinned to a commit | `python tools/manifest.py -o MANIFEST.sha256.json` |

## Trust model in one paragraph

Trust comes from the **founding record** (genesis) you obtain out of band and from your own
keys. Validator certificates are accepted only from validator sets anchored there. Nothing
vouches for itself: not a snapshot, not an evidence file's key changes, not an API, not a
dropped file. Untrusted input is parsed strictly, rendered as text and labelled unverified. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for adversaries, defences and residual risk.
