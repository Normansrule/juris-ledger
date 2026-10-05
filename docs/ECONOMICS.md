# Economics

## Asymmetric information

George Akerlof's "lemons" paper showed that when sellers know more than buyers, good products can be driven out of the market. Joseph Stiglitz and Andrew Weiss showed the same mechanism rations credit: a lender who cannot tell safe from risky borrowers restricts lending to everyone. Much financial fraud is an exploitation of exactly this gap — the second bank does not know a receivable is already pledged; the buyer does not know the revenue was round-tripped.

A shared, verifiable record attacks the gap directly, but only for facts that are *on* the record:

| Information problem | What a shared ledger changes | What it does not change |
|---|---|---|
| Hidden prior claims (double pledging) | A pledge is visible to every later lender | Assets that never touch the ledger |
| Fabricated history (revenue, invoices) | History is signed by counterparties and timestamped by consensus | Collusion between both counterparties |
| Version disputes over contracts | One hash, one signature set, one status | Disputes about what the words *mean* |
| Unverifiable official statistics | Anyone can recompute them | Off-ledger and informal activity |

Catalini and Gans describe these as reductions in the **cost of verification** and the **cost of networking**. JurisLedger is an experiment in the first.

## Mapping payments to the System of National Accounts (SNA) 2008

| Purpose tag | Allowed payer → payee | National-accounts treatment |
|---|---|---|
| `FINAL_CONSUMPTION` | household → firm or non-resident | Household final consumption, **C** |
| `INVESTMENT` | firm or household → firm or non-resident | Gross fixed capital formation, **I** |
| `GOVERNMENT_PURCHASE` | government → firm or non-resident | Government final consumption, part of **G** |
| `WAGES` | firm, government or bank → household | Compensation of employees; when the payer is government it is also government output valued at cost, part of **G** |
| `EXPORT` | non-resident → firm | Exports, **X** |
| any goods purpose paid *to* a non-resident | | Imports, **M** |
| `INTERMEDIATE` | firm → firm or non-resident | Intermediate consumption (subtracted in the production approach) |
| `TAX` (`production` / `income`) | → government | Production taxes enter the income approach; income taxes are transfers |
| `TRANSFER` | government → household or firm | Benefits and subsidies; subsidies to firms enter the income approach with a minus sign |
| `FINANCIAL` | anyone → anyone | Loans, repayments, asset trades: not production, excluded from GDP |

**Why the two approaches must agree.** Write purchases from resident firms with subscript *d* and from non-residents with *m*. Firm output is C_d + I_d + G_d + INT_d + X. Intermediate consumption is INT_d + INT_m. Value added is therefore C_d + I_d + G_d + X − INT_m. Expenditure is (C_d + C_m) + (I_d + I_m) + (G_d + G_m) + X − (C_m + I_m + G_m + INT_m), which is the same expression. Government wages appear on both sides. Any non-zero discrepancy on the ledger means a payment was tagged inconsistently.

## Supply and use tables, and input-output analysis

`jurisledger sut` (and `/api/sut`, and the dashboard's *Who supplies whom* and *What if demand rises?* panels) builds the tables a statistics office publishes behind its GDP figure (System of National Accounts 2008, chapter 14; Eurostat *Manual of Supply, Use and Input-Output Tables*, 2008):

| piece | read from the ledger as |
|---|---|
| a product | the sector of the firm paid; anything bought from a non-resident is "imports"; government output is "government services" |
| supply of a product | goods payments to firms of that sector (domestic output), or to non-residents (imports) |
| intermediate use | `INTERMEDIATE` payments: row = product bought, column = buyer's sector |
| final use | `FINAL_CONSUMPTION` (C), `INVESTMENT` (I), `GOVERNMENT_PURCHASE` plus government wages (G), `EXPORT` (X) |
| compensation of employees | `WAGES`, by the payer's sector (government; banks as "financial, not measured") |
| net taxes on production | `TAX` with `tax_type: production` paid by firms, minus `TRANSFER`s to firms |
| operating surplus | the residual, as in official practice |

Two identities must hold: supply equals use for every product, and output equals intermediate consumption plus value added for every industry. Statistics offices take months to balance the two sides, because they come from different sources, and publish what is left over as the statistical discrepancy. Here both come from the same validated payments, so they balance exactly, product by product.

That is a property of the method, not proof of completeness: with 30% of trade in cash the tables still balance perfectly while GDP falls short of the truth (`jurisledger accounts`, last claim). Balance shows consistency; coverage has to be estimated separately.

The Leontief inverse L = (I − A)⁻¹, with A the domestic intermediate use per unit of each industry's output, is computed in exact rational arithmetic, so the check that L times final demand gives back observed output is an equality. Column sums of L are output multipliers: how much output across the economy one more unit of final demand for a product requires. They describe the past structure of the economy; using them for forecasts assumes fixed input proportions and no capacity limits, the standard caveats of input-output analysis.

## Simplifications in this version

- No change in inventories, no consumption of fixed capital (so this is *gross* product only), no imputed rent of owner-occupiers, no financial intermediation services indirectly measured, no non-profit sector.
- No distinction between basic prices and purchasers' prices; taxes on products are not separated.
- Operating surplus is a residual, as it is in official practice.
- Residency equals role: every account that is not `foreign` is resident.
- One currency, no price index, so nominal figures only.

## What the comparison with surveys does and does not show

The `gdp` experiment compares the ledger with a stylised survey (sampling, non-response, reporting noise, under-reporting). The large survey error printed there is mostly the small population of sixteen firms. The defensible claims are narrower: on-ledger activity is measured **without sampling error, without reporting error and without delay**, and the same experiment shows the ledger's own bias — it misses whatever is paid off-ledger. Medina and Schneider's estimates for 158 countries put the shadow economy at around thirty percent of official GDP on average, with a very wide range between countries, so this is not a footnote.
