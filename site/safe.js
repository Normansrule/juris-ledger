/* Safe HTML for every page of the site (audit finding H12: script injection in the dashboard).
 *
 *   el.innerHTML = html`<b>${name}</b> paid ${amount}`;     // every ${...} is escaped
 *   el.innerHTML = html`<ul>${items.map(i => html`<li>${i}</li>`)}</ul>`;   // nested html stays markup
 *
 * Data from an API, a dropped file or a ledger is never trusted as markup, even when its
 * signatures verify: a valid ledger can still contain an account NAMED "<img onerror=...>".
 * tests/test_audit_v26.py checks that no page assigns an untagged template to innerHTML.
 */
(function (root) {
  "use strict";
  const MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };
  const esc = v => String(v).replace(/[&<>"'`]/g, c => MAP[c]);

  class SafeHTML {
    constructor(s) { this.s = s; }
    toString() { return this.s; }
  }
  const part = v => v instanceof SafeHTML ? v.s
    : Array.isArray(v) ? v.map(part).join("")
    : v === null || v === undefined || v === false ? ""
    : esc(v);

  function html(strings, ...values) {
    let out = strings[0];
    for (let i = 0; i < values.length; i++) out += part(values[i]) + strings[i + 1];
    return new SafeHTML(out);
  }
  /* Only for markup written in this repository, never for data. */
  const raw = s => new SafeHTML(String(s));

  /* A number from an API is a number: anything else becomes NaN and is shown as "—". */
  const num = v => (typeof v === "number" && Number.isFinite(v)) ? v : NaN;

  root.JurisSafe = { html, raw, esc, num, SafeHTML };
})(typeof globalThis !== "undefined" ? globalThis : this);
