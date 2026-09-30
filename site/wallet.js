/* JurisLedger wallet core, in the browser.  Exposes globalThis.JurisWallet.
 *
 * Keys never leave this page.  A key is created with the browser's own cryptography, used to sign
 * transactions byte-for-byte as jurisledger/tx.py does, and saved only as a sealed keystore
 * (PBKDF2-HMAC-SHA256, 600,000 iterations, then AES-256-GCM with the address bound in), which the
 * command line opens with `jurisledger`'s keystore module.  Signing needs no network at all: a signed
 * transaction is a file you can carry to any validator (`jurisledger submit tx.json HOST:PORT`).
 * Needs verify.js (canonical JSON and signing bytes) loaded first.
 */
(function (root) {
  "use strict";
  const V = () => root.JurisVerify, subtle = root.crypto.subtle, enc = new TextEncoder();
  const PKCS8_PREFIX = "302e020100300506032b657004220420";     // DER header of an Ed25519 private key
  const ITER = 600000;
  const b64u = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));

  async function fromSeed(seedHex) {
    const seed = V().hexToBytes(seedHex);
    if (seed.length !== 32) throw new Error("a key is 32 bytes (64 hexadecimal characters)");
    const priv = await subtle.importKey("pkcs8", V().hexToBytes(PKCS8_PREFIX + seedHex), { name: "Ed25519" }, true, ["sign"]);
    const jwk = await subtle.exportKey("jwk", priv);
    return { seed: seedHex, address: V().bytesToHex(unb64u(jwk.x)), priv };
  }
  async function generate() {
    return fromSeed(V().bytesToHex(crypto.getRandomValues(new Uint8Array(32))));
  }
  async function sign(key, chainId, kind, nonce, payload) {
    const tx = { chain_id: chainId, kind, sender: key.address, nonce, payload };
    const sig = await subtle.sign({ name: "Ed25519" }, key.priv, V().txSigningBytes(tx));
    return { ...tx, signature: V().bytesToHex(new Uint8Array(sig)) };
  }
  async function pbkdf2(passphrase, salt, iterations) {
    const base = await subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function seal(key, passphrase) {
    if (passphrase.length < 8) throw new Error("use a passphrase of at least 8 characters");
    const salt = crypto.getRandomValues(new Uint8Array(16)), nonce = crypto.getRandomValues(new Uint8Array(12));
    const k = await pbkdf2(passphrase, salt, ITER);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: V().hexToBytes(key.address) }, k, V().hexToBytes(key.seed));
    return { version: 1, address: key.address, kdf: "pbkdf2-sha256", iterations: ITER, salt: V().bytesToHex(salt),
             cipher: "aes-256-gcm", nonce: V().bytesToHex(nonce), ciphertext: V().bytesToHex(new Uint8Array(ct)) };
  }
  async function open(file, passphrase) {
    if (file.secret) return fromSeed(file.secret);                  // a plain key file from `jurisledger keygen`
    if (!file.ciphertext) throw new Error("this is not a JurisLedger key file");
    if (file.kdf !== "pbkdf2-sha256")
      throw new Error("this key is sealed with scrypt, which browsers cannot compute. Re-seal it for the browser on the command line, or sign there.");
    if (!(file.iterations >= 100000 && file.iterations <= 10000000)) throw new Error("the keystore's iteration count is outside the accepted range");
    let seed;
    try {
      const k = await pbkdf2(passphrase, V().hexToBytes(file.salt), file.iterations);
      seed = await subtle.decrypt({ name: "AES-GCM", iv: V().hexToBytes(file.nonce), additionalData: V().hexToBytes(file.address) }, k, V().hexToBytes(file.ciphertext));
    } catch (e) { throw new Error("wrong passphrase, or the keystore was altered"); }
    const key = await fromSeed(V().bytesToHex(new Uint8Array(seed)));
    if (key.address !== file.address) throw new Error("the keystore's address does not match its key");
    return key;
  }
  /* A small symmetric picture derived from the address, so a person can recognise "their" key at a glance
     and notice when a different one is loaded.  Recognition only: it is not a security check. */
  function identicon(address, size = 64) {
    const bits = V().hexToBytes(address.slice(0, 32)), hue = (bits[0] * 360 / 256) | 0, hue2 = (hue + 150) % 360, cell = size / 5;
    let out = `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="picture of this key"><rect width="${size}" height="${size}" rx="${size / 6}" fill="hsl(${hue2} 35% 92%)"/>`;
    for (let y = 0; y < 5; y++) for (let x = 0; x < 3; x++) {
      if ((bits[1 + y * 3 + x] & 1) === 0) continue;
      for (const xx of x === 2 ? [2] : [x, 4 - x]) out += `<rect x="${xx * cell + 1}" y="${y * cell + 1}" width="${cell - 2}" height="${cell - 2}" rx="2" fill="hsl(${hue} 55% 38%)"/>`;
    }
    return out + "</svg>";
  }
  root.JurisWallet = { generate, fromSeed, sign, seal, open, identicon, ITER };
})(typeof globalThis !== "undefined" ? globalThis : this);
