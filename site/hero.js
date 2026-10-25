/* The explainer's hero: a live deed.  Two parties sign the SHA-256 fingerprint of the text with real
 * Ed25519 keys (Web Crypto, made fresh on each visit, never stored).  Every edit re-hashes the text and
 * re-verifies both signatures, so changing one word visibly breaks them and cracks the seal.
 * Everything is written with textContent; nothing the reader types is ever parsed as markup.
 */
(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const text = $("deedText"), hashEl = $("deedHash"), status = $("deedStatus"), reset = $("deedReset"), seal = $("deedSeal");
  if (!text || !hashEl) return;
  const sigs = [...document.querySelectorAll(".deed .sig")];
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const original = text.value;
  const enc = new TextEncoder();
  const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  const digest = s => crypto.subtle.digest("SHA-256", enc.encode(s));

  let originalHex = "", keys = null, signatures = null, seq = 0;

  // The fingerprint is rendered character by character; characters that differ from the signed one are marked.
  function showHash(h) {
    const frag = document.createDocumentFragment();
    let run = "", runDiff = false;
    const flush = () => {
      if (!run) return;
      if (runDiff) { const i = document.createElement("i"); i.textContent = run; frag.appendChild(i); }
      else frag.appendChild(document.createTextNode(run));
      run = "";
    };
    for (let k = 0; k < h.length; k++) {
      const d = originalHex !== "" && h[k] !== originalHex[k];
      if (d !== runDiff) { flush(); runDiff = d; }
      run += h[k];
      if (k % 8 === 7 && k < h.length - 1) { flush(); frag.appendChild(document.createTextNode(" ")); }
    }
    flush();
    hashEl.replaceChildren(frag);
  }

  function setState(valid, detail) {
    sigs.forEach((s, i) => {
      s.classList.toggle("valid", valid[i]); s.classList.toggle("broken", !valid[i]);
      s.querySelector(".state").textContent = keys ? (valid[i] ? "Signature valid" : "Does not match this text")
                                                   : (valid[i] ? "Fingerprint matches" : "Fingerprint differs");
    });
    const all = valid.every(Boolean);
    seal.classList.toggle("broken", !all);
    seal.querySelector("title").textContent = all ? "Seal intact" : "Seal broken";
    status.className = "deed-status " + (all ? "ok" : "bad");
    status.textContent = all ? (keys ? "Both signatures match this exact text." : "The fingerprint matches the signed one (signatures not checked).") : detail;
    reset.hidden = all;
  }

  async function check() {
    const mine = ++seq;
    const h = await digest(text.value);
    if (mine !== seq) return;                       // a newer keystroke already started
    showHash(hex(h));
    if (!signatures) return;
    let valid;
    if (keys) {
      try {
        valid = await Promise.all(keys.map((k, i) => crypto.subtle.verify({ name: "Ed25519" }, k.publicKey, signatures[i], h)));
      } catch { valid = [false, false]; }            // a failed check never leaves "valid" on screen
    } else {
      const same = hex(h) === originalHex;          // no Ed25519 in this browser: compare fingerprints instead
      valid = [same, same];
    }
    if (mine !== seq) return;
    setState(valid, text.value === original ? "" : "Changed after signing: neither signature covers this text.");
  }

  async function sign() {
    const h = await digest(original);
    originalHex = hex(h);
    showHash(originalHex);
    try {
      keys = await Promise.all([0, 1].map(() => crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])));
      signatures = await Promise.all(keys.map(k => crypto.subtle.sign({ name: "Ed25519" }, k.privateKey, h)));
      $("deedMethod").textContent = "Checked in your browser: SHA-256 and Ed25519 (Web Crypto). Keys are made fresh on each visit and never leave the page.";
    } catch {
      keys = null; signatures = [true, true];
      $("deedHint").textContent = "Change any word and watch the fingerprint.";
      $("deedMethod").textContent = "This browser has no Ed25519, so the page compares fingerprints instead of verifying signatures.";
    }
    sigs.forEach(s => s.classList.add("drawn"));
    setTimeout(() => seal.classList.add("pressed"), reduced ? 0 : 1100);
    await check();
  }

  text.addEventListener("input", check);
  reset.addEventListener("click", () => { text.value = original; check(); text.focus(); });
  // On a fine pointer the deed tilts toward the cursor like a sheet lifted off the desk, on a slightly
  // underdamped spring so it settles with a little give.  It lies flat again while someone is typing.
  const deed = text.closest(".deed"), hero = deed && deed.closest(".hero");
  if (hero && !reduced && matchMedia("(hover: hover) and (pointer: fine)").matches) {
    let tx = 0, ty = 0, x = 0, y = 0, vx = 0, vy = 0, raf = 0, last = 0;
    const lim = v => Math.max(-1, Math.min(1, v));
    const loop = t => {
      const dt = Math.min(0.032, (t - last) / 1000 || 0.016), k = 120, c = 15; last = t;
      vx += (k * (tx - x) - c * vx) * dt; x += vx * dt;
      vy += (k * (ty - y) - c * vy) * dt; y += vy * dt;
      deed.style.setProperty("--tx", x.toFixed(4)); deed.style.setProperty("--ty", y.toFixed(4));
      const still = Math.abs(tx - x) + Math.abs(ty - y) + Math.abs(vx) + Math.abs(vy) < 1e-3;
      raf = still ? 0 : requestAnimationFrame(loop);
    };
    const go = () => { if (!raf) { last = performance.now(); raf = requestAnimationFrame(loop); } };
    hero.addEventListener("pointermove", e => {
      if (document.activeElement === text) return;
      const r = deed.getBoundingClientRect();
      tx = lim((e.clientX - (r.left + r.width / 2)) / r.width); ty = lim((e.clientY - (r.top + r.height / 2)) / r.height); go();
    });
    hero.addEventListener("pointerleave", () => { tx = ty = 0; go(); });
    text.addEventListener("focus", () => { tx = ty = 0; go(); });
  }

  status.textContent = "Signing the original…";
  sign().catch(() => { status.className = "deed-status bad"; status.textContent = "This browser cannot compute SHA-256 here (the page needs a secure context)."; });
})();
