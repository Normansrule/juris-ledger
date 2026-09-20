# Contributing

JurisLedger is a laboratory. The most useful contribution is an experiment that **breaks** a claim.

1. State the claim in one sentence ("a censoring validator delays a transaction by at most `f` blocks").
2. Write the attack or measurement in `jurisledger/experiments.py` as a `(claim, bool)` check.
3. Keep the result whichever way it goes. A failing claim with a clear explanation is worth more than a passing one.
4. Every new transaction rule needs a test that a rejected transaction leaves the state root unchanged.
5. New references go in `docs/REFERENCES.md` with one line on what was taken from them. Only cite what you have read.

Style: standard library plus `cryptography`; integer money; no floats in anything that gets hashed; write out acronyms on first use.

```bash
pip install -e ".[dev]"
python -m pytest
python -m jurisledger all
```
