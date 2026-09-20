"""Command-line entry point:  python -m jurisledger [all|contracts|legal|disputes|attacks|gdp|fraud|privacy]"""
from __future__ import annotations

import sys

from .experiments import EXPERIMENTS

TITLES = {
    "gdp": "Gross Domestic Product (GDP) measured from the ledger",
    "contracts": "Signed digital contracts with references and an access trail",
    "legal": "Obligations, compliance and court-ready evidence files",
    "disputes": "Disputes and arbitration with deliberately narrow powers",
    "attacks": "Adversarial experiments",
    "fraud": "Fraud detection on a shared ledger",
    "privacy": "Confidential amounts and private statistics (experimental)",
}


def main(argv: list[str]) -> int:
    which = argv[1] if len(argv) > 1 else "all"
    names = list(EXPERIMENTS) if which == "all" else [which]
    if any(n not in EXPERIMENTS for n in names):
        print(__doc__)
        return 2
    failed = 0
    for n in names:
        print(f"\n=== {TITLES[n]} ===")
        result = EXPERIMENTS[n](verbose=True)
        for claim, ok in result["checks"]:
            print(f"  [{'PASS' if ok else 'FAIL'}] {claim}")
            failed += not ok
    print(f"\n{'ALL CHECKS PASSED' if not failed else str(failed) + ' CHECK(S) FAILED'}")
    return 1 if failed else 0


def main_cli() -> None:          # console-script entry point
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    main_cli()
