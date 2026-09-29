# Data tracking at scale

The chain is the source of truth. Replaying it answers every question, and takes longer every year. For the questions a statistics office, a court registry or a dashboard asks every day, JurisLedger keeps an **index**: an ordinary SQLite file built from verified blocks, updated incrementally.

```bash
jurisledger index demo/chain.json -o ledger.db          # audit, then add every new block
jurisledger index 127.0.0.1:7701 -o ledger.db --pin <validator address>   # straight from a running validator
jurisledger query ledger.db gdp                          # GDP for the whole ledger
jurisledger query ledger.db gdp 100 200                  # ...or for blocks 100 to 200
jurisledger query ledger.db account agriculture-firm-1   # one account's payments, newest first
jurisledger query ledger.db top 10                       # the ten busiest accounts
jurisledger query ledger.db contract <contract id>       # a contract's whole life
jurisledger metrics ledger.db -o metrics.csv             # one row per block, for any dashboard
```

## Serving it: the read-only API and the dashboard

```bash
jurisledger api ledger.db                                   # http://127.0.0.1:8080
jurisledger api ledger.db --follow 127.0.0.1:7701 --every 10  # and keep indexing a live validator
```

| endpoint | returns |
|---|---|
| `/api/status` | chain, height, transaction and account counts, median block time |
| `/api/gdp?from=A&to=B` | GDP by expenditure for a block range |
| `/api/metrics?from=A&to=B` | the per-block series (at most 5,000 rows per call) |
| `/api/accounts/top?n=10` | busiest accounts |
| `/api/account/<name or address>` | an account's latest payments |
| `/api/contract/<id>` | a contract's timeline |

The server is read-only (SQLite opened in read-only mode; POST, PUT, DELETE answer 405), serves public data only, parses every parameter as a bounded integer or an exact-match lookup through bound SQL parameters, caps result sizes, rate-limits each client address with a token bucket (429 beyond it), and listens on loopback unless told otherwise. `--follow` exports from a validator over pinned TLS, re-audits the export locally and appends new blocks, so the dashboard stays live.

[`site/dashboard.html`](../site/dashboard.html) reads the API (refreshing every five seconds), a `metrics.csv`, or a bundled sample: activity per block, where the money went (C, I, G, X above the line, imports below), GDP accumulating, and consensus health (signatures per block, extra voting rounds).

## Why it can be trusted

| property | how |
|---|---|
| Derived, never authoritative | Only blocks from an audited chain are indexed (`Chain.load` or a live node's chain, which is re-audited on export). |
| Refuses a different history | Every indexed block keeps its hash. If the next chain offered does not extend what is indexed, `index` refuses and says to rebuild; a different founding record is refused too. |
| Crash-safe | Each `sync` is one database transaction: the index is always at a block boundary. |
| Readable by anything | Standard SQL in one file. Write-ahead logging (WAL) mode lets readers query while the indexer writes. |

## Tables

| table | one row per | used for |
|---|---|---|
| `blocks` | block | height, hash, time, proposer, rounds, signatures |
| `txs` | transaction | kind, sender, nonce, position |
| `payments` | public payment | payer, payee, amount, purpose, contract, obligation, invoice |
| `contract_events` | contract-related transaction | a contract's timeline in one query |
| `accounts` | account | name, role, sector, successor key after a rotation |
| `block_metrics` | block | transactions, payments, volume, C, I, G, X, M, confidential payments |

## Measured

On one laptop core, a 20,000-transaction chain indexes in about 0.6 seconds (about 35,000 transactions per second). Afterwards GDP for any block range is one query over `block_metrics` (about 0.1 milliseconds), against about 13 milliseconds to recompute it by replay, and the gap grows linearly with the ledger. An account's latest 50 payments take about 8 milliseconds.

A test requires the index's GDP to equal `stats.gdp` for every block range tried, and the per-block metrics to add up to the whole.

## What it does not do

The index holds public data only. Confidential payments are counted per block but their amounts, being commitments, are not in it. It does not replace `jurisledger audit`: an auditor checks the chain; the index answers questions about a chain someone already checked. For national scale, the same schema moves unchanged to a server database (PostgreSQL), partitioned by height.
