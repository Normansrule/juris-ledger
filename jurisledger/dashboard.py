"""A public register you can open in a browser: one self-contained HTML file.

No server, no external fonts or scripts, nothing fetched from the network - a
requirement for anything a public body would archive or hand to a court.  The page
is rendered from a chain that has just been re-audited from block 1, and says so.
"""
from __future__ import annotations

from html import escape as e
from typing import Any, Dict, List

from . import fraud, legal
from .chain import Chain
from .contracts import audit_trail, summary
from .stats import gdp

CSS = """
:root{--paper:#F6F8FA;--sheet:#FFFFFF;--ink:#12233F;--soft:#51607A;--line:#C9D3DF;--seal:#0B6E69;
--good:#1E6B3A;--warn:#A8590A;--bad:#A61B1B;--bar:#0B6E69}
@media (prefers-color-scheme:dark){:root{--paper:#0E1726;--sheet:#152238;--ink:#E6ECF5;--soft:#9FB0C8;
--line:#2B3B55;--seal:#4FC3BB;--good:#6CCB8B;--warn:#E5A45A;--bad:#F08A8A;--bar:#4FC3BB}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:2rem 1.25rem 4rem}
h1,h2,h3{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;font-weight:600;line-height:1.2}
h1{font-size:2.1rem;margin:0 0 .25rem} h2{font-size:1.45rem;margin:2.75rem 0 .75rem} h3{font-size:1.05rem;margin:1.25rem 0 .4rem}
p{max-width:68ch;margin:.4rem 0} .soft{color:var(--soft)}
.seal{border-left:6px solid var(--seal);background:var(--sheet);padding:1rem 1.25rem;margin:1.5rem 0;max-width:72ch}
.seal strong{color:var(--seal)}
nav{display:flex;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:.6rem;margin-top:1.5rem}
nav a{margin:0 1.25rem .25rem 0;color:var(--ink);text-decoration:none;border-bottom:2px solid transparent;padding:.15rem 0}
nav a:hover,nav a:focus-visible{border-bottom-color:var(--seal);outline:none}
.wide{overflow-x:auto;background:var(--sheet);border:1px solid var(--line)}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--soft);font-size:.9rem;white-space:nowrap} td.n,th.n{text-align:right}
tr:last-child td{border-bottom:0}
code{font:0.85em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--soft)}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.figures{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:0 2rem;max-width:60rem}
.figures div{border-top:1px solid var(--line);padding:.6rem 0;display:flex;justify-content:space-between;gap:1rem}
.figures b{font-variant-numeric:tabular-nums}
.bar{height:.6rem;background:var(--bar);min-width:2px}
details{background:var(--sheet);border:1px solid var(--line);margin:.5rem 0}
summary{cursor:pointer;padding:.7rem .9rem}
summary>*{margin-right:.9rem}
summary:focus-visible{outline:2px solid var(--seal)} details>div{padding:0 .9rem 1rem}
input[type=search]{font:inherit;padding:.45rem .6rem;border:1px solid var(--line);background:var(--sheet);color:var(--ink);width:min(28rem,100%)}
"""

JS = """
const q=document.getElementById('find');
if(q){q.addEventListener('input',()=>{const t=q.value.toLowerCase();
document.querySelectorAll('#contracts details').forEach(d=>{d.hidden=!d.textContent.toLowerCase().includes(t)})})}
"""


def money(cents: int) -> str:
    return f"{cents / 100:,.2f}"


def _times(n: int) -> str:
    return "once" if n == 1 else "twice" if n == 2 else f"{n} times"


def _status(word: str) -> str:
    cls = {"PAID": "good", "ACTIVE": "good", "WAIVED": "good", "PAID_LATE": "warn", "PARTIAL": "warn",
           "DISPUTED": "warn", "DRAFT": "warn", "SUPERSEDED": "soft", "PENDING": "soft", "OVERDUE": "bad"}.get(word, "")
    return f'<span class="{cls}">{e(word.replace("_", " ").capitalize())}</span>'


def render(chain: Chain, reporting_threshold: int = 10_000_00) -> str:
    audited = Chain.audit(chain.genesis, chain.blocks)             # raises if anything is wrong
    st, names = audited.state, {a: v["name"] for a, v in audited.state.accounts.items()}
    n_tx = sum(len(b.txs) for b in audited.blocks)
    rep = gdp(audited)
    flags = fraud.run_all(audited, reporting_threshold) if n_tx else []
    out: List[str] = []
    w = out.append

    w(f"<h1>Public register of {e(audited.chain_id)}</h1>")
    w('<p class="soft">Signed contracts, payments and the accounts derived from them, as finalised by the validators.</p>')
    w(f'<div class="seal"><strong>Independently re-verified.</strong> This page was produced by replaying blocks 1 to '
      f'{audited.height} from the founding record: {n_tx:,} transaction signatures, every Merkle root, every state '
      f'digest and every commit certificate were checked. State digest <code>{e(st.root()[:24])}</code>. '
      f'You do not have to trust this page: run <code>jurisledger audit chain.json</code> on the same file.</div>')
    w('<nav aria-label="Sections"><a href="#contracts">Contracts</a><a href="#accounts-of-the-economy">National accounts</a>'
      '<a href="#flags">Review flags</a><a href="#validators">Validators and issuers</a><a href="#blocks">Blocks</a>'
      '<a href="#holders">Account holders</a></nav>')

    # ---- contracts
    w(f'<h2 id="contracts">Contracts <span class="soft">({len(st.contracts)})</span></h2>')
    if st.contracts:
        w('<p><label>Find a contract, party or status <br><input id="find" type="search" placeholder="for example: lease, overdue, bakery"></label></p>')
    else:
        w('<p class="soft">No contracts have been recorded yet. A contract appears here once its creating transaction is final.</p>')
    for cid, c in st.contracts.items():
        s = summary(audited, cid)
        obligations = legal.compliance(audited, cid)
        worst = next((o["status"] for o in obligations if o["status"] in ("OVERDUE", "DISPUTED")), None)
        w(f'<details><summary><b>{e(c["title"])}</b> {_status(c["status"])}'
          f'{" " + _status(worst) if worst else ""} <span class="soft">{e(", ".join(s["parties"]))}</span></summary><div>')
        w(f'<p class="soft">Contract <code>{e(cid[:16])}</code>, text fingerprint <code>{e(c["prose_hash"][:16])}</code>, '
          f'{"open to anyone" if c["visibility"] == "public" else "readable by the parties and those they authorise"}. '
          f'Viewed {_times(s["views"])}, used {_times(s["uses"])}, cited {_times(s["citations"])}.</p>')
        if obligations:
            w('<h3>Payment obligations</h3><div class="wide"><table><tr><th>Obligation</th><th>From</th><th>To</th>'
              '<th class="n">Owed</th><th class="n">Paid</th><th class="n">Due block</th><th>Status</th></tr>')
            for o in obligations:
                note = " (changed by award)" if o["adjusted_by_award"] else ""
                w(f'<tr><td>{e(o["id"])}{note}</td><td>{e(o["payer"])}</td><td>{e(o["payee"])}</td>'
                  f'<td class="n">{money(o["amount"])}</td><td class="n">{money(o["paid"])}</td>'
                  f'<td class="n">{o["due_height"]}</td><td>{_status(o["status"])}</td></tr>')
            w("</table></div>")
        for d in (x for x in st.disputes.values() if x["contract_id"] == cid):
            rec = legal.dispute_record(audited, d["id"])
            outcome = f', decided {rec["award"]["outcome"].lower()} at block {rec["closed_height"]}' if rec["award"] else ""
            w(f'<h3>Dispute</h3><p>Opened by {e(rec["claimant"])} at block {rec["opened_height"]} before '
              f'{e(rec["arbitrator"])}{outcome}. {len(rec["filings"])} document(s) filed.</p>')
        if c["references"]:
            w("<h3>Rests on</h3><ul>")
            for r in c["references"]:
                target = st.contracts[r["id"]]["title"] if r["kind"] == "contract" else (r.get("uri") or r["hash"][:16])
                w(f'<li>{e(r["relation"])}: {e(target)}</li>')
            w("</ul>")
        trail = audit_trail(audited, cid)
        if trail:
            w('<h3>Who opened, used or cited it</h3><div class="wide"><table><tr><th class="n">Block</th><th>Action</th><th>By</th><th>Note</th></tr>')
            for t in trail:
                w(f'<tr><td class="n">{t["height"]}</td><td>{e(t["action"].capitalize())}</td>'
                  f'<td>{e(t["accessor_name"])}</td><td>{e(t["context"])}</td></tr>')
            w("</table></div>")
        w("</div></details>")

    # ---- national accounts
    w('<h2 id="accounts-of-the-economy">National accounts from the ledger</h2>')
    agree = "good" if rep.discrepancy == 0 else "bad"
    w(f'<p>Gross domestic product computed three ways from {rep.n_payments:,} finalised payments. '
      f'The expenditure and production totals come from different transactions; '
      f'<span class="{agree}">their difference is {money(rep.discrepancy)}</span>.</p><div class="figures">')
    for label, v in (("By expenditure", rep.expenditure), ("By production", rep.production), ("By income", rep.income),
                     ("Household consumption", rep.C), ("Investment", rep.I), ("Government", rep.G),
                     ("Exports", rep.X), ("Imports", rep.M), ("Wages", rep.wages)):
        w(f"<div><span>{label}</span><b>{money(v)}</b></div>")
    w("</div>")
    sectors = rep.by_sector()
    top = max((abs(v) for v in sectors.values()), default=0) or 1
    w('<h3>Value added by sector</h3><div class="wide"><table>')
    for name, v in sorted(sectors.items(), key=lambda kv: -kv[1]):
        w(f'<tr><td>{e(name.capitalize())}</td><td class="n">{money(v)}</td>'
          f'<td style="width:50%"><div class="bar" style="width:{max(0, v) / top * 100:.1f}%"></div></td></tr>')
    w("</table></div>")

    # ---- flags
    w(f'<h2 id="flags">Flags for human review <span class="soft">({len(flags)})</span></h2>')
    w('<p class="soft">Patterns worth a second look. A flag is a lead, not a finding: ordinary trade triggers some of them.</p>')
    if flags:
        w('<div class="wide"><table><tr><th>Pattern</th><th>Who</th><th>Detail</th></tr>')
        for f in flags:
            who = " → ".join(f["ring"]) if "ring" in f else f.get("name") or f.get("borrower", "")
            detail = {"circular_flow": lambda: f'{money(f["total"])} moved in a circle, blocks {f["blocks"][0]}–{f["blocks"][1]}',
                      "structuring": lambda: f'{f["count"]} payments just under {money(reporting_threshold)}, total {money(f["total"])}',
                      "benford": lambda: f'first digits of {f["payments"]} payments look invented (chi-square {f["chi2"]})',
                      "duplicate_invoice_financing": lambda: "same invoice financed by " + ", ".join(f["lenders"])}[f["detector"]]()
            w(f'<tr><td>{e(f["detector"].replace("_", " ").capitalize())}</td><td>{e(who)}</td><td>{e(detail)}</td></tr>')
        w("</table></div>")
    else:
        w("<p>Nothing flagged in this period.</p>")

    # ---- validators
    w('<h2 id="validators">Validators and identity issuers</h2>')
    w(f'<p>{len(st.validators)} validators; a block is final with {(2 * len(st.validators)) // 3 + 1} of their signatures. '
      f'{len(st.slashed)} removed for signing conflicting blocks.'
      + (f' Accounts need {st.policy.get("min_attestations")} independent attestations from the {len(st.issuers)} issuers '
         f'to sign contracts or pay more than {money(st.policy.get("unverified_payment_limit", 0))}.' if st.policy else "") + "</p>")
    w('<div class="wide"><table><tr><th>Name</th><th>Role</th><th>Key</th></tr>')
    for a in st.validators:
        w(f'<tr><td>{e(names[a])}</td><td>Validator</td><td><code>{e(a[:24])}</code></td></tr>')
    for a in st.slashed:
        w(f'<tr><td>{e(names[a])}</td><td class="bad">Removed</td><td><code>{e(a[:24])}</code></td></tr>')
    for a in st.issuers:
        w(f'<tr><td>{e(names[a])}</td><td>Identity issuer</td><td><code>{e(a[:24])}</code></td></tr>')
    w("</table></div>")

    # ---- blocks
    w('<h2 id="blocks">Blocks</h2><div class="wide"><table><tr><th class="n">Height</th><th>Proposed by</th>'
      '<th class="n">Round proposed</th><th class="n">Round finalised</th><th class="n">Signatures</th>'
      '<th class="n">Transactions</th><th>Fingerprint</th></tr>')
    for b in reversed(audited.blocks[-60:]):
        w(f'<tr><td class="n">{b.header.height}</td><td>{e(names.get(b.header.proposer, "?"))}</td>'
          f'<td class="n">{b.header.round}</td><td class="n">{b.vote_round}</td><td class="n">{len(b.votes)}</td>'
          f'<td class="n">{len(b.txs)}</td><td><code>{e(b.hash[:20])}</code></td></tr>')
    w("</table></div>")
    if audited.height > 60:
        w(f'<p class="soft">Showing the latest 60 of {audited.height} blocks.</p>')

    # ---- holders
    w('<h2 id="holders">Account holders</h2><div class="wide"><table><tr><th>Name</th><th>Role</th><th>Sector</th>'
      '<th>Identity</th><th class="n">Balance</th></tr>')
    for a, v in sorted(st.accounts.items(), key=lambda kv: (kv[1]["role"], kv[1]["name"])):
        if v["role"] in ("validator", "issuer"):
            continue
        if "successor" in v:
            ident = f'<span class="soft">key replaced at block {v["replaced_at"]}</span>'
        elif not st.policy:
            ident = '<span class="soft">not required</span>'
        else:
            ident = (f'<span class="good">verified ({st.attestation_count(a)})</span>' if st.is_verified(a)
                     else f'<span class="warn">unverified ({st.attestation_count(a)})</span>')
        w(f'<tr><td>{e(v["name"])}</td><td>{e(v["role"].capitalize())}</td><td>{e(v["sector"])}</td>'
          f'<td>{ident}</td><td class="n">{money(v["balance"])}</td></tr>')
    w("</table></div>")
    w('<p class="soft" style="margin-top:3rem">Research prototype. Balances and counterparties are public in this version; '
      'see the threat model for what that means.</p>')

    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Public register of {e(audited.chain_id)}</title><style>{CSS}</style></head>'
            f'<body><main>{"".join(out)}</main><script>{JS}</script></body></html>')
