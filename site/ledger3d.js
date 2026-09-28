/* JurisLedger 3D views, with no library: a few hundred lines of projection and a painter's sort.
 *
 *   Ledger3D.mount(canvas, model) -> view        model = { results, chain, acc, flags }
 *   view.setMode("chain" | "flows"); view.select(index); view.highlight(flagOrNull); view.destroy()
 *
 * "chain": every block a box on a rising spiral, sized by its transactions, linked to the block
 *          before it; the validators orbit it, and the selected block shows who signed it.
 * "flows": every account a sphere, grouped by role; every pair that traded an arc, thicker for more
 *          money; a review flag lights its ring in red.
 * Drag to turn, wheel or pinch to zoom, click a block to select it.  Respects reduced motion.
 */
(function (root) {
  "use strict";
  const TAU = Math.PI * 2;
  const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim() || "#888";
  const hash = s => { let h = 2166136261; for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619); return (h >>> 0) / 4294967295; };

  function hexToRgb(c) {
    if (c.startsWith("rgb")) return c.match(/\d+/g).slice(0, 3).map(Number);
    const h = c.replace("#", ""); const n = parseInt(h.length === 3 ? h.split("").map(x => x + x).join("") : h, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  const shade = (rgb, k, a = 1) => `rgba(${rgb.map(v => Math.round(Math.min(255, v * k))).join(",")},${a})`;

  function mount(canvas, model) {
    const ctx = canvas.getContext("2d");
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let yaw = 0.7, pitch = 0.32, dist = 24, mode = "chain", selected = -1, flag = null, raf = 0, t0 = performance.now();
    let W = 0, H = 0, dpr = 1, dragging = false, lastX = 0, lastY = 0, moved = 0, hoverLabel = null, picks = [];
    const colors = () => ({ ink: hexToRgb(css("--ink")), good: hexToRgb(css("--verified")), bad: hexToRgb(css("--seal")),
      amber: hexToRgb(css("--amber")), soft: hexToRgb(css("--ink-2")), bg: css("--sheet") });

    // ---------------- scene data
    const results = model.results, n = results.length;
    const blocks = results.map((r, i) => {
      const a = i * 0.62, rad = 3.4, y = (i - n / 2) * 0.95;
      const s = 0.35 + 0.28 * Math.log10(1 + r.block.txs.length);
      return { i, p: [rad * Math.cos(a), y, rad * Math.sin(a)], s, r };
    });
    const vals = model.chain.genesis.validators;
    let ringY = 0;                                                   // the validators' orbit follows the selected block
    const valPos = () => vals.map((v, k) => { const a = k / vals.length * TAU + 0.4; return [8.2 * Math.cos(a), ringY, 8.2 * Math.sin(a)]; });

    const acc = model.acc, flows = new Map(), volume = new Map();
    for (const r of results) for (const t of r.block.txs) {
      if (t.kind !== "PAYMENT") continue;
      const k = t.sender + ">" + t.payload.to;
      flows.set(k, (flows.get(k) || 0) + t.payload.amount);
      volume.set(t.sender, (volume.get(t.sender) || 0) + t.payload.amount);
      volume.set(t.payload.to, (volume.get(t.payload.to) || 0) + t.payload.amount);
    }
    const ANCHOR = { household: [0, -0.2, 1], firm: [0.9, 0.2, -0.4], government: [0, 1, 0], foreign: [-1, 0.1, -0.3], bank: [-0.5, -0.7, -0.5], issuer: [0.2, -1, 0.3], validator: [0, -1, 0] };
    const sectorOffset = s => { const h = hash(s || "x"); return [Math.cos(h * TAU) * 0.8, (h - 0.5) * 1.1, Math.sin(h * TAU) * 0.8]; };
    const nodes = new Map();
    for (const [a, info] of Object.entries(acc)) {
      if (!volume.has(a)) continue;
      const base = ANCHOR[info.role] || [0.3, 0.3, 0.3], so = info.role === "firm" ? sectorOffset(info.sector) : [0, 0, 0];
      const j = [hash(a) - 0.5, hash(a + "y") - 0.5, hash(a + "z") - 0.5];
      const v = base.map((b, k) => b + so[k] + j[k] * (info.role === "household" ? 0.9 : 0.55)), L = Math.hypot(...v) || 1;
      nodes.set(a, { a, p: v.map(x => x / L * 7), r: 0.12 + 0.07 * Math.log10(1 + (volume.get(a) || 0) / 100), role: info.role, name: info.name });
    }
    const edges = [...flows].sort((x, y) => y[1] - x[1]).slice(0, 220).map(([k, v]) => { const [a, b] = k.split(">"); return { a, b, v }; });
    const vmax = Math.max(1, ...edges.map(e => e.v));

    // ---------------- projection
    function project(p) {
      const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
      const x1 = p[0] * cy - p[2] * sy, z1 = p[0] * sy + p[2] * cy;
      const y2 = p[1] * cp - z1 * sp, z2 = p[1] * sp + z1 * cp;
      const z = z2 + dist, f = Math.min(W, H) * 1.35 / Math.max(z, 0.1);
      return [W / 2 + x1 * f, H / 2 - y2 * f, z, f];
    }
    const light = [0.4, 0.8, 0.45];
    const CUBE = [[-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1], [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]];
    const FACES = [[0, 1, 2, 3, [0, 0, -1]], [5, 4, 7, 6, [0, 0, 1]], [4, 0, 3, 7, [-1, 0, 0]], [1, 5, 6, 2, [1, 0, 0]], [3, 2, 6, 7, [0, 1, 0]], [4, 5, 1, 0, [0, -1, 0]]];

    function frame(now) {
      const C = colors(), prims = [];
      const age = reduced ? 99 : (now - t0) / 1000;
      if (!dragging && !reduced) yaw += 0.0025;
      picks = [];
      if (mode === "chain") {
        if (selected >= 0 && blocks[selected]) ringY += (blocks[selected].p[1] - ringY) * (reduced ? 1 : 0.08);
        const orbit = []; for (let s = 0; s <= 72; s++) { const a = s / 72 * TAU; orbit.push(project([8.2 * Math.cos(a), ringY, 8.2 * Math.sin(a)])); }
        prims.push({ z: 1e6, draw: () => { ctx.strokeStyle = shade(C.soft, 1, 0.22); ctx.lineWidth = 1; ctx.beginPath();
          orbit.forEach((q, k) => k ? ctx.lineTo(q[0], q[1]) : ctx.moveTo(q[0], q[1])); ctx.stroke(); } });
        const top = project([0, blocks.length ? blocks[blocks.length - 1].p[1] + 1.2 : 1, 0]), bot = project([0, blocks.length ? blocks[0].p[1] - 1.2 : -1, 0]);
        prims.push({ z: 1e6 - 1, draw: () => { ctx.strokeStyle = shade(C.soft, 1, 0.18); ctx.setLineDash([3, 6]); ctx.beginPath(); ctx.moveTo(bot[0], bot[1]); ctx.lineTo(top[0], top[1]); ctx.stroke(); ctx.setLineDash([]);
          ctx.fillStyle = shade(C.soft, 1, 0.8); ctx.font = "11px system-ui,sans-serif"; ctx.textAlign = "center";
          ctx.fillText("genesis", bot[0], bot[1] + 14); ctx.fillText("newest", top[0], top[1] - 6); } });
        blocks.forEach((b, i) => {
          const grow = Math.min(1, Math.max(0, age * 3 - i * 0.08));
          if (grow <= 0) return;
          const s = b.s * grow, col = !b.r.ok ? C.bad : i === selected ? C.amber : C.good;
          const flagged = flag && flag.has(i);
          const pts = CUBE.map(c => project([b.p[0] + c[0] * s, b.p[1] + c[1] * s * 0.6, b.p[2] + c[2] * s]));
          for (const [a, bb, c, d, nrm] of FACES) {
            const q = [pts[a], pts[bb], pts[c], pts[d]];
            const cross = (q[1][0] - q[0][0]) * (q[2][1] - q[0][1]) - (q[1][1] - q[0][1]) * (q[2][0] - q[0][0]);
            if (cross >= 0) continue;                                  // back face
            const lam = 0.55 + 0.45 * Math.max(0, nrm[0] * light[0] + nrm[1] * light[1] + nrm[2] * light[2]);
            prims.push({ z: (q[0][2] + q[2][2]) / 2, draw: () => {
              ctx.beginPath(); ctx.moveTo(q[0][0], q[0][1]); for (let k = 1; k < 4; k++) ctx.lineTo(q[k][0], q[k][1]); ctx.closePath();
              ctx.fillStyle = shade(col, lam, 0.92); ctx.fill();
              ctx.strokeStyle = flagged ? shade(C.amber, 1) : shade(col, 0.55); ctx.lineWidth = flagged ? 2 : 0.8; ctx.stroke(); } });
          }
          const c = project(b.p);
          picks.push({ x: c[0], y: c[1], r: Math.max(8, s * c[3]), i, label: `block ${b.r.block.header.height} · ${b.r.block.txs.length} tx${b.r.ok ? "" : " · FAILED"}` });
          if (i > 0) { const a = project(blocks[i - 1].p); prims.push({ z: (a[2] + c[2]) / 2 + 0.5, draw: () => { ctx.strokeStyle = shade(C.soft, 1, 0.55); ctx.lineWidth = 1.2; ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(c[0], c[1]); ctx.stroke(); } }); }
        });
        const vp = valPos();
        vp.forEach((p, k) => {
          const c = project(p), rr = 0.45 * c[3];
          prims.push({ z: c[2], draw: () => {
            const g = ctx.createRadialGradient(c[0] - rr * 0.3, c[1] - rr * 0.3, rr * 0.1, c[0], c[1], rr);
            g.addColorStop(0, shade(C.ink, 1.6)); g.addColorStop(1, shade(C.ink, 0.9));
            ctx.fillStyle = g; ctx.beginPath(); ctx.arc(c[0], c[1], rr, 0, TAU); ctx.fill();
            ctx.fillStyle = shade(C.soft, 1); ctx.font = "12px system-ui,sans-serif"; ctx.textAlign = "center";
            ctx.fillText((acc[vals[k]] && acc[vals[k]].name) || "v" + k, c[0], c[1] + rr + 14); } });
        });
        if (selected >= 0 && blocks[selected]) {
          const b = blocks[selected], c = project(b.p), signers = new Set(Object.keys(b.r.block.votes || {}));
          vp.forEach((p, k) => {
            const v = project(p), on = signers.has(vals[k]), ph = (age * 0.8 + k * 0.25) % 1;
            prims.push({ z: Math.min(v[2], c[2]) - 0.2, draw: () => {
              ctx.strokeStyle = on ? shade(C.amber, 1, 0.85) : shade(C.soft, 1, 0.25); ctx.setLineDash(on ? [] : [4, 5]); ctx.lineWidth = on ? 1.8 : 1;
              ctx.beginPath(); ctx.moveTo(v[0], v[1]); ctx.lineTo(c[0], c[1]); ctx.stroke(); ctx.setLineDash([]);
              if (on && !reduced) { ctx.fillStyle = shade(C.amber, 1); ctx.beginPath(); ctx.arc(v[0] + (c[0] - v[0]) * ph, v[1] + (c[1] - v[1]) * ph, 3.2, 0, TAU); ctx.fill(); } } });
          });
        }
      } else {
        const ringKeys = new Set(), ringNodes = new Set();
        if (flag && flag.ring) flag.ring.forEach((a, k, arr) => { ringKeys.add(a + ">" + arr[(k + 1) % arr.length]); ringNodes.add(a); });
        edges.forEach(e => {
          const A = nodes.get(e.a), B = nodes.get(e.b); if (!A || !B) return;
          const mid = A.p.map((x, k) => (x + B.p[k]) / 2 * 1.35);             // lift the arc outwards
          const hot = ringKeys.has(e.a + ">" + e.b), steps = 14, pts = [];
          for (let s = 0; s <= steps; s++) { const u = s / steps; pts.push(project(A.p.map((x, k) => (1 - u) * (1 - u) * x + 2 * (1 - u) * u * mid[k] + u * u * B.p[k]))); }
          const w = hot ? 3.2 : 0.4 + 2.2 * Math.sqrt(e.v / vmax), zz = pts[steps >> 1][2];
          prims.push({ z: zz + (hot ? -30 : 0), draw: () => {
            ctx.strokeStyle = hot ? shade(C.bad, 1, 0.95) : shade(C.good, 1, 0.12 + 0.5 * Math.sqrt(e.v / vmax)); ctx.lineWidth = w;
            ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]); for (let s = 1; s <= steps; s++) ctx.lineTo(pts[s][0], pts[s][1]); ctx.stroke();
            if (hot && !reduced) { const ph = Math.floor(((age * 0.6) % 1) * steps); ctx.fillStyle = shade(C.bad, 1.2); ctx.beginPath(); ctx.arc(pts[ph][0], pts[ph][1], 4, 0, TAU); ctx.fill(); } } });
        });
        for (const nd of nodes.values()) {
          const c = project(nd.p), rr = Math.max(2.5, nd.r * c[3]), hot = ringNodes.has(nd.a);
          const col = hot ? C.bad : nd.role === "government" ? C.amber : nd.role === "foreign" ? C.soft : nd.role === "household" ? C.good : C.ink;
          prims.push({ z: c[2], draw: () => {
            const g = ctx.createRadialGradient(c[0] - rr * 0.35, c[1] - rr * 0.35, rr * 0.1, c[0], c[1], rr);
            g.addColorStop(0, shade(col, 1.5)); g.addColorStop(1, shade(col, 0.85));
            ctx.fillStyle = g; ctx.beginPath(); ctx.arc(c[0], c[1], rr, 0, TAU); ctx.fill();
            if (hot || nd.role === "government" || nd.role === "foreign") { ctx.fillStyle = shade(hot ? C.bad : C.soft, 1); ctx.font = "11px system-ui,sans-serif"; ctx.textAlign = "center"; ctx.fillText(nd.name, c[0], c[1] - rr - 5); } } });
          picks.push({ x: c[0], y: c[1], r: Math.max(6, rr), label: `${nd.name} · ${nd.role}` });
        }
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      prims.sort((a, b) => b.z - a.z).forEach(p => p.draw());
      if (hoverLabel) { ctx.font = "12px system-ui,sans-serif"; const w = ctx.measureText(hoverLabel.t).width + 14;
        ctx.fillStyle = shade(hexToRgb(css("--ink")), 1, 0.9); ctx.fillRect(hoverLabel.x + 10, hoverLabel.y - 26, w, 22);
        ctx.fillStyle = css("--paper"); ctx.textAlign = "left"; ctx.fillText(hoverLabel.t, hoverLabel.x + 17, hoverLabel.y - 11); }
      raf = requestAnimationFrame(frame);
    }

    function resize() {
      const r = canvas.getBoundingClientRect(); dpr = Math.min(2, devicePixelRatio || 1);
      W = r.width; H = r.height; canvas.width = W * dpr; canvas.height = H * dpr;
    }
    const pick = (x, y) => { let best = null, bd = 1e9; for (const p of picks) { const d = Math.hypot(p.x - x, p.y - y); if (d < p.r + 4 && d < bd) { best = p; bd = d; } } return best; };
    const pos = e => { const r = canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    canvas.addEventListener("pointerdown", e => { dragging = true; moved = 0; [lastX, lastY] = [e.clientX, e.clientY]; canvas.setPointerCapture(e.pointerId); });
    canvas.addEventListener("pointermove", e => {
      if (dragging) { const dx = e.clientX - lastX, dy = e.clientY - lastY; moved += Math.abs(dx) + Math.abs(dy);
        yaw += dx * 0.008; pitch = Math.max(-1.3, Math.min(1.3, pitch + dy * 0.006)); [lastX, lastY] = [e.clientX, e.clientY]; }
      const [x, y] = pos(e), p = pick(x, y); hoverLabel = p ? { x, y, t: p.label } : null; canvas.style.cursor = p && p.i !== undefined ? "pointer" : "grab";
    });
    canvas.addEventListener("pointerup", e => { dragging = false; if (moved < 5) { const [x, y] = pos(e), p = pick(x, y); if (p && p.i !== undefined && model.onSelect) model.onSelect(p.i); } });
    canvas.addEventListener("pointerleave", () => { hoverLabel = null; });
    canvas.addEventListener("wheel", e => { e.preventDefault(); dist = Math.max(10, Math.min(60, dist * (1 + Math.sign(e.deltaY) * 0.08))); }, { passive: false });
    const ro = new ResizeObserver(resize); ro.observe(canvas); resize();
    raf = requestAnimationFrame(frame);
    return {
      setMode(m) { mode = m; dist = m === "chain" ? Math.max(20, n * 0.85 + 12) : 23; pitch = m === "chain" ? 0.28 : 0.4; t0 = performance.now(); },
      select(i) { selected = i; },
      highlight(f) { flag = f; },
      destroy() { cancelAnimationFrame(raf); ro.disconnect(); },
    };
  }
  root.Ledger3D = { mount };
})(typeof globalThis !== "undefined" ? globalThis : this);
