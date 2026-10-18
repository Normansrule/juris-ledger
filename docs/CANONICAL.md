# Canonical JSON: the contract (`jurisledger/canonical/v1`)

Every signature, transaction identifier, block hash and state root in JurisLedger is computed over
**canonical JSON**. Two programs that disagree on these bytes disagree on what was signed, so every
implementation (Python in `jurisledger/crypto.py`, JavaScript in `site/verify.js`, and any future
one) must follow the same rules. The audit of v0.25.0 (finding H10) found two places where the
Python and JavaScript implementations produced different bytes; this document is the fix.

## The rules

| Value | Encoding | Rejected |
|---|---|---|
| object | `{` keys `:` values `}`, no whitespace, keys sorted by **Unicode code point** | non-string keys, keys with lone surrogates |
| array | `[` values `,` `]`, no whitespace | — |
| string | JSON string; non-ASCII characters as raw UTF-8 (not `\u` escapes); control characters as JSON requires (`\n`, `\t`, `\u001f`, …) | lone surrogates (`\ud800` without its pair) |
| integer | decimal, no leading zeros, no `+` | anything outside **±(2^53 − 1)** |
| `true`, `false`, `null` | as written | — |
| number with a fraction or exponent | — | always (money is integer minor units) |

No Unicode normalisation is applied, by anyone. `"é"` (U+00E9) and `"é"` are different
strings with different bytes, both valid. A verifier that normalised would compute different hashes.

## Why these limits

- **Integers.** JavaScript numbers are IEEE-754 doubles; above 2^53 they cannot represent every
  integer, so `JSON.parse` silently rounds `18446744073709551616` to `18446744073709552000`.
  Python would sign the exact value and a browser would verify a different one. Rejecting both
  sides of the limit keeps them in agreement. No JurisLedger value comes near it: amounts are
  bounded far below, and timestamps in milliseconds reach 2^53 in the year 287,396.
- **Key order.** Python sorts strings by code point; JavaScript's default `sort()` compares UTF-16
  code units. They agree everywhere except when a key contains a character above U+FFFF (an
  emoji, say) and another key contains one between U+E000 and U+FFFF. `site/verify.js` now sorts
  by code point.
- **Lone surrogates** cannot be encoded as UTF-8; Python refused them while JavaScript escaped them,
  so the two produced different results. Both refuse now.

## Two levels: hashing the past, admitting the future

These rules are the **portable** contract. Python applies them in two places, deliberately:

| | What it does | Where |
|---|---|---|
| **Hashing** (`canonical(x)`) | Reproduces every byte the ledger has ever committed to, including an integer above 2^53 that a protocol-1 block may carry in a field the rules ignored. Historical transaction identifiers, block hashes, state roots and evidence keep verifying unchanged. | every hash and signature check |
| **Admission** (`canonical(x, portable=True)`, `check_portable`) | Refuses anything outside the portable contract. | signing a new transaction (`Transaction.create`), parsing network input and files to submit (`Transaction.from_dict`, strict), and the protocol-2 state machine, which refuses a non-portable payload as an invalid transaction |

So no stored value changes meaning, and nothing new outside the contract can be signed, gossiped or,
on a protocol-2 ledger, finalised. A protocol-1 block containing such a value still verifies in
Python; the browser verifier refuses it (it cannot reproduce the bytes) rather than reporting a
wrong verdict.

Key order and lone surrogates needed no such split: Python always sorted by code point and always
refused lone surrogates, so only the browser changed.

## Test vectors

`tests/vectors/canonical.json` lists inputs and the exact expected bytes (hex), or `null` where every
implementation must refuse. `tests/test_audit_v26.py` runs both implementations against it. A new
implementation is conformant when it reproduces every vector.
