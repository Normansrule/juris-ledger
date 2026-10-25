/* The explainer's centrepiece: the bound book.  Six folios, each carrying the SHA-256 fingerprint of
 * the one before.  On a wide screen the section is pinned while you scroll: the folios lie in a pile,
 * deal out into a chain, then folio 2 is altered and the break shows at the next link.  Anyone can
 * alter or restore any folio by hand, which takes over from the scroll.  Narrow screens, short
 * screens and reduced motion get the same chain laid flat, with no pinning.
 * Every fingerprint is computed here with Web Crypto; everything is written with textContent.
 */
(() => {
  "use strict";
  const root = document.getElementById("book");
  if (!root || !window.crypto || !crypto.subtle) return;
  const grid = document.getElementById("bookPages");
  const pages = [...root.querySelectorAll(".page")];
  const steps = [...root.querySelectorAll(".book-steps li")];
  const status = document.getElementById("bookStatus"), reset = document.getElementById("bookReset");
  const enc = new TextEncoder();
  const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  const sha = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
  const ZERO = "0".repeat(64);

  const original = pages.map(p => p.querySelector(".amt").textContent);
  const entry = (i, alt) => {
    const e = pages[i].querySelector(".pg-entry").cloneNode(true);
    e.querySelector(".amt").textContent = alt ? pages[i].dataset.alt : original[i];
    return e.textContent;
  };
  const folio = (i, prev, text) => sha(`folio ${i + 1}\n${prev}\n${text}`);

  // The "previous" fingerprint each folio wrote down when it was sealed.
  let written = [];
  // manual: the reader has altered a folio by hand, so the scroll no longer decides what is altered.
  // hold: the reader restored everything; keep it restored until they scroll back above the alteration.
  let altered = new Set(), manual = false, hold = false, seq = 0;

  function put(el, text) { if (el.textContent !== text) el.textContent = text; }

  async function render() {
    const mine = ++seq;
    const now = [];
    for (let i = 0; i < pages.length; i++) now.push(await folio(i, written[i], entry(i, altered.has(i))));
    if (mine !== seq) return;
    let broken = -1;
    pages.forEach((p, i) => {
      const changed = altered.has(i);
      const link = i > 0 && written[i] !== now[i - 1];
      const after = !changed && !link && broken >= 0;
      if ((changed || link) && broken < 0) broken = i;
      p.dataset.state = changed ? "altered" : link ? "link" : after ? "after" : "ok";
      put(p.querySelector(".amt"), changed ? p.dataset.alt : original[i]);
      put(p.querySelector(".self"), now[i].slice(0, 8));
      put(p.querySelector(".prev"), written[i].slice(0, 8));
      put(p.querySelector(".pg-state"), changed ? "Altered after sealing: the seal no longer fits"
        : link ? `Points at folio ${i}'s old fingerprint` : after ? "Follows a broken link" : "Sealed by quorum");
      put(p.querySelector(".pg-alter"), (changed ? "Restore folio " : "Alter folio ") + (i + 1));
    });
    const list = [...altered].sort((a, b) => a - b).map(i => i + 1);
    put(status, !list.length ? "All six folios are sealed, and each points at the one before."
      : list.length === 1 && list[0] < pages.length
        ? `Folio ${list[0]} was changed after it was sealed. Folio ${list[0] + 1} still points at its old fingerprint, so the break shows at once.`
        : list.length === 1 ? `Folio ${list[0]} was changed after it was sealed, and the quorum's seal on it no longer fits.`
        : `Folios ${list.join(", ")} were changed after they were sealed. The first break is at folio ${list[0]}.`);
    if (manual || hold || !root.classList.contains("pinned")) caption();
    reset.hidden = !manual;
  }

  // Outside scroll control the captions follow what is actually on screen, not the scroll position.
  function caption() {
    const s = !altered.size ? 0 : altered.size === 1 && altered.has(pages.length - 1) ? 1 : 2;
    const flat = !root.classList.contains("pinned");
    steps.forEach((li, i) => li.classList.toggle("on", flat || i === s));
  }

  // Only changes the reader caused are announced; scrolling past the alteration stays quiet.
  const live = on => status.setAttribute("aria-live", on ? "polite" : "off");

  function setAltered(next) {
    const same = next.size === altered.size && [...next].every(i => altered.has(i));
    if (same) return;
    altered = next;
    render();
  }

  pages.forEach((p, i) => p.querySelector(".pg-alter").addEventListener("click", () => {
    if (!manual) { manual = true; hold = false; root.classList.add("manual"); }
    live(true);
    const next = new Set(altered);
    next.has(i) ? next.delete(i) : next.add(i);
    altered = new Set([...next].sort());
    render();
  }));
  reset.addEventListener("click", () => {
    live(true);
    status.focus();                                  // the button is about to hide; keep focus somewhere sensible
    altered = new Set(); manual = false; hold = root.classList.contains("pinned"); root.classList.remove("manual");
    render();
  });

  // ---- Scroll: pinned only where there is room for it and motion is welcome. ----
  const roomy = matchMedia("(min-width: 1101px) and (min-height: 660px) and (prefers-reduced-motion: no-preference)");
  const tilt = [-7, 4, -3, 6, -4, 2];
  let offsets = [], pos = 0, vel = 0, target = 0, raf = 0, last = 0;
  const clamp = x => Math.min(1, Math.max(0, x));
  const smooth = x => x * x * (3 - 2 * x);

  function progress() {
    const r = root.getBoundingClientRect(), span = r.height - innerHeight;
    return span > 0 ? clamp(-r.top / span) : 1;
  }

  function measure() {
    pages.forEach((p, i) => { p.style.transform = ""; p.style.zIndex = pages.length - i; });   // folio 1 on top of the pile
    const g = grid.getBoundingClientRect(), cx = g.left + g.width / 2, cy = g.top + g.height / 2;
    offsets = pages.map(p => { const r = p.getBoundingClientRect(); return [cx - (r.left + r.width / 2), cy - (r.top + r.height / 2)]; });
  }

  function draw(p) {
    pages.forEach((el, i) => {
      const k = 1 - smooth(clamp((p - 0.03 - i * 0.045) / 0.22));
      const [dx, dy] = offsets[i] || [0, 0];
      el.style.transform = k < 0.002 ? "" :
        `translate3d(${(dx * k).toFixed(1)}px,${(dy * k).toFixed(1)}px,${((pages.length - i) * 3 * k).toFixed(1)}px) rotateX(${(52 * k).toFixed(2)}deg) rotateZ(${(tilt[i] * k).toFixed(2)}deg)`;
    });
    const s = p < 0.52 ? 0 : p < 0.72 ? 1 : 2;
    if (hold && s === 0) hold = false;
    if (manual || hold) return;
    steps.forEach((li, i) => li.classList.toggle("on", i === s));
    live(false);
    setAltered(s >= 1 ? new Set([1]) : new Set());
  }

  // A critically damped spring between the scroll position and the drawing: scrolling feels weighted,
  // and a flick settles instead of jumping.
  function frame(t) {
    const dt = Math.min(0.032, (t - last) / 1000 || 0.016); last = t;
    const k = 170, c = 2 * Math.sqrt(k);
    vel += (k * (target - pos) - c * vel) * dt; pos += vel * dt;
    if (Math.abs(target - pos) < 1e-4 && Math.abs(vel) < 1e-4) { pos = target; raf = 0; }
    draw(pos);
    if (raf) raf = requestAnimationFrame(frame);
  }
  function tick() {
    if (!root.classList.contains("pinned")) return;
    target = progress();
    if (!raf) { last = performance.now(); raf = requestAnimationFrame(frame); }
  }

  function mode() {
    const on = roomy.matches;
    root.classList.toggle("pinned", on);
    cancelAnimationFrame(raf); raf = 0;
    if (on) { measure(); pos = target = progress(); vel = 0; draw(pos); }
    else { pages.forEach(p => { p.style.transform = ""; p.style.zIndex = ""; }); hold = false; if (!manual) setAltered(new Set()); caption(); }
  }

  // Keyboard users who tab into the pile get the folios dealt out instead of hidden under each other.
  grid.addEventListener("focusin", () => {
    if (!root.classList.contains("pinned") || pos > 0.48 || !grid.querySelector(":focus-visible")) return;
    const r = root.getBoundingClientRect();
    scrollTo({ top: scrollY + r.top + 0.5 * (r.height - innerHeight), behavior: "instant" });
  });

  addEventListener("scroll", tick, { passive: true });
  addEventListener("resize", () => { if (root.classList.contains("pinned")) { measure(); draw(pos); tick(); } });
  roomy.addEventListener("change", mode);

  (async () => {
    let prev = ZERO;
    for (let i = 0; i < pages.length; i++) { written.push(prev); prev = await folio(i, prev, entry(i, false)); }
    await render();
    mode();
  })().catch(() => { put(status, "This browser cannot compute SHA-256 here (the page needs a secure context)."); });
})();
