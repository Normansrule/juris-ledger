/* Folios rise into place as they reach the reader.  Only position moves (never opacity), so the text
 * keeps full contrast at every frame, and nothing is hidden if this script never runs.  Panels that are
 * hidden at load rise when they first appear.
 */
(() => {
  "use strict";
  if (matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) return;
  const els = [...document.querySelectorAll(".folio .head, .folio .stage, .folio .commands, main .panel, main .chart, main .card3")];
  const io = new IntersectionObserver(entries => entries.forEach(e => {
    if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }), { rootMargin: "0px 0px -6% 0px" });
  // A panel that is hidden at load (the explorer's, until a ledger is open) is observed too, so it rises when it appears.
  els.forEach(el => { if (el.offsetParent !== null && el.getBoundingClientRect().top < innerHeight) el.classList.add("in"); else io.observe(el); });
  document.documentElement.classList.add("reveal");
})();
