# Accessibility

A public register that some citizens cannot read is not public. United States federal sites must meet Section 508, which points to the Web Content Accessibility Guidelines (WCAG) 2.0 AA; most states and the European Union's accessibility rules point to WCAG 2.1 AA. JurisLedger's pages are held to WCAG 2.1 AA.

## Automated audit

```bash
npm install --prefix /tmp/axe axe-core@4
pip install playwright && python -m playwright install chromium
python tools/a11y_audit.py
```

This loads the explainer, the explorer (with the demo ledger open), the dashboard, the wallet and a generated public register, in both light and dark colour schemes, and runs axe-core against every WCAG 2.1 A and AA rule it automates.

**Result for 0.20.0: 0 problems on all ten page-and-scheme combinations.** The first run found 36, all fixed:

| found | fix |
|---|---|
| text in the inactive arbitration panel faded to a 2.8 : 1 contrast ratio | the panel keeps full contrast and is marked `inert` with a tinted background instead of being faded |
| amber warnings at 3.9 : 1 | a darker amber for text (`--amber-ink`) in light mode |
| the red "altered" labels at 4.4 : 1 in dark mode | a slightly lighter red in dark mode |
| comment lines in the command box at 3.9 : 1 | less transparency |
| the verified green at 4.48 : 1 on the register's background | a slightly darker green |
| the 3D view's tabs were plain buttons inside a tab list | proper `role="tab"` with `aria-selected` |

## What automated checks cannot see, and how the pages handle it

- **Keyboard.** Every control is a real button, link or form field. Block cards in the explorer move with the arrow keys; review flags, tabs and the wallet's steps are reachable with Tab.
- **Pictures of data.** The dashboard's four charts carry spoken summaries (`role="img"` and an `aria-label` rewritten from the data after each refresh); the numbers behind them are in the headline figures and in `jurisledger query`. The 3D views are an extra way to see what the block strip, the block panel and the review-flag cards already present in text.
- **Motion.** Every animation respects the operating system's reduced-motion setting.
- **Colour.** Status is never colour alone: verified and rejected states also carry words and symbols.

Automated tools catch roughly a third of real barriers. A release that a government publishes would still need a manual pass with a screen reader (NVDA, VoiceOver) and keyboard-only use, ideally by people who use them every day.
