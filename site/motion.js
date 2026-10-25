/* Figures that count up the first time they appear.  A container marked data-count-up is watched; when
 * its figures are first written, each plain number (with optional thousands commas, decimals and a short
 * suffix such as " s") runs up from zero on a critically damped spring and lands on the exact text it was
 * given.  Later refreshes are left alone, so live data never animates.  Text is written with textContent.
 */
(() => {
  "use strict";
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const NUM = /^(-?)([\d,]+)(\.\d+)?(\s?[^\d\s]{0,3})$/;

  function run(el) {
    const final = el.textContent, m = final.trim().match(NUM);
    if (!m) return;
    const sign = m[1] ? -1 : 1, places = m[3] ? m[3].length - 1 : 0, commas = m[2].includes(",");
    const goal = sign * Number(m[2].replace(/,/g, "") + (m[3] || ""));
    if (!isFinite(goal) || goal === 0 || Math.abs(goal) >= 1e15) return;   // beyond exact doubles: show it as written
    const fmt = v => {
      const s = Math.abs(v).toFixed(places), [i, d] = s.split(".");
      return (v < 0 ? "-" : "") + (commas ? i.replace(/\B(?=(\d{3})+(?!\d))/g, ",") : i) + (d ? "." + d : "") + m[4];
    };
    let x = 0, v = 0, last = performance.now();
    const k = 90, c = 2 * Math.sqrt(k);
    (function frame(t) {
      if (!el.isConnected) return;                       // a refresh replaced it: nothing to finish
      const dt = Math.min(0.032, (t - last) / 1000 || 0.016); last = t;
      v += (k * (1 - x) - c * v) * dt; x += v * dt;
      if (1 - x < 1e-3 && Math.abs(v) < 1e-3) { el.textContent = final; return; }
      el.textContent = fmt(goal * x);
      requestAnimationFrame(frame);
    })(last);
  }

  document.querySelectorAll("[data-count-up]").forEach(box => {
    const start = () => { box.querySelectorAll("b").forEach(run); };
    if (box.children.length) { start(); return; }
    const mo = new MutationObserver(() => { mo.disconnect(); start(); });
    mo.observe(box, { childList: true });
  });
})();
