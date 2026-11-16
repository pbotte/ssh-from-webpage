// ============================================================================
//  Ende-zu-Ende-Verschlüsselung Browser <-> Pi  (Protokoll "pi-term-e2e/v1")
//
//  psk   = PBKDF2-SHA256(Terminal-Schlüssel, salt="pi-term-e2e/v1", 600000)
//  Z     = ECDH-P256(Browser-Schlüssel (pro Sitzung), Pi-Schlüssel (pro Sitzung))
//  th    = SHA256("pi-term-e2e/v1" | Sitzungs-ID | pub_browser | pub_pi)
//  okm   = HKDF-SHA256(ikm=Z, salt=psk, info="keys"|th, 96 Bytes)
//          -> k_browser→pi | k_pi→browser | k_confirm
//  Pi beweist Kenntnis von psk + Z:  conf = HMAC(k_confirm, "pi-confirm"|th)
//  Daten: Rahmen = u32 Länge | AES-256-GCM(nonce = 0000|seq64, aad = th)
//  Der erste Rahmen vom Pi ist der Handshake (JSON, unverschlüsselt).
//
//  Funktioniert im Browser (window.PiE2E) und in Node (globalThis.PiE2E).
// ============================================================================
(function (root) {
  'use strict';
  const subtle = root.crypto && root.crypto.subtle;
  const enc = new TextEncoder();
  const MAGIC = enc.encode('pi-term-e2e/v1');
  const PBKDF2_ITER = 600000;
  const MAX_FRAME = 16 * 1024 * 1024;

  class E2EError extends Error {
    // kind: 'auth' (Schlüssel falsch / MITM), 'tamper', 'pi' (Fehler vom Pi), 'proto'
    constructor(msg, kind = 'proto') { super(msg); this.kind = kind; }
  }

  function concat(...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  function b64encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }
  function b64decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function nonce(seq) {
    const b = new Uint8Array(12);
    new DataView(b.buffer).setBigUint64(4, BigInt(seq));
    return b;
  }
  function frame(payload) {
    const h = new Uint8Array(4);
    new DataView(h.buffer).setUint32(0, payload.length);
    return concat(h, payload);
  }

  /** Terminal-Schlüssel -> psk (dauert absichtlich ein paar hundert ms). */
  async function derivePsk(secret) {
    const k = await subtle.importKey('raw', enc.encode(secret.trim()), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: MAGIC, iterations: PBKDF2_ITER }, k, 256);
    return new Uint8Array(bits);
  }

  /** Browser-Seite einer verschlüsselten Sitzung. */
  class Channel {
    static async create(psk) {
      if (!subtle) throw new E2EError('Verschlüsselung braucht HTTPS (WebCrypto nicht verfügbar).');
      const c = new Channel();
      c.psk = psk;
      c.kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      c.pub = new Uint8Array(await subtle.exportKey('raw', c.kp.publicKey));
      c.rxBuf = new Uint8Array(0);
      c.ready = false;
      c.txSeq = 0;
      c.rxSeq = 0;
      return c;
    }

    async _handshake(sid, payload) {
      let msg;
      try { msg = JSON.parse(new TextDecoder().decode(payload)); } catch {
        throw new E2EError('Ungültiger Handshake vom Pi.');
      }
      if (msg.error) throw new E2EError(msg.error, 'pi');
      if (msg.v !== 1 || !msg.pub || !msg.conf) throw new E2EError('Unbekannte Protokollversion.');
      const pubP = b64decode(msg.pub);
      const peer = await subtle.importKey('raw', pubP, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const z = await subtle.deriveBits({ name: 'ECDH', public: peer }, this.kp.privateKey, 256);
      this.th = new Uint8Array(await subtle.digest('SHA-256', concat(MAGIC, enc.encode(sid), this.pub, pubP)));
      const ikm = await subtle.importKey('raw', z, 'HKDF', false, ['deriveBits']);
      const okm = new Uint8Array(await subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: this.psk, info: concat(enc.encode('keys'), this.th) }, ikm, 768));
      this.txKey = await subtle.importKey('raw', okm.slice(0, 32), 'AES-GCM', false, ['encrypt']);
      this.rxKey = await subtle.importKey('raw', okm.slice(32, 64), 'AES-GCM', false, ['decrypt']);
      const confKey = await subtle.importKey('raw', okm.slice(64, 96), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      const ok = await subtle.verify('HMAC', confKey, b64decode(msg.conf), concat(enc.encode('pi-confirm'), this.th));
      if (!ok) {
        throw new E2EError('Der Pi konnte sich nicht ausweisen: Terminal-Schlüssel falsch – oder die Verbindung wurde manipuliert.', 'auth');
      }
      this.ready = true;
    }

    /** Empfangene Bytes (beliebig zerstückelt) -> Liste von Klartext-Blöcken. */
    async receive(sid, bytes) {
      this.rxBuf = concat(this.rxBuf, bytes);
      const out = [];
      while (this.rxBuf.length >= 4) {
        const len = new DataView(this.rxBuf.buffer, this.rxBuf.byteOffset).getUint32(0);
        if (len > MAX_FRAME) throw new E2EError('Ungültiger Datenrahmen.', 'tamper');
        if (this.rxBuf.length < 4 + len) break;
        const payload = this.rxBuf.slice(4, 4 + len);
        this.rxBuf = this.rxBuf.slice(4 + len);
        if (!this.ready) { await this._handshake(sid, payload); continue; }
        const seq = this.rxSeq++;
        let pt;
        try {
          pt = await subtle.decrypt({ name: 'AES-GCM', iv: nonce(seq), additionalData: this.th }, this.rxKey, payload);
        } catch {
          throw new E2EError('Entschlüsselung fehlgeschlagen – Daten wurden unterwegs verändert.', 'tamper');
        }
        out.push(new Uint8Array(pt));
      }
      return out;
    }

    /** Klartext -> verschlüsselter Rahmen. Aufrufe müssen nacheinander erfolgen. */
    async seal(plain) {
      const seq = this.txSeq++;
      const ct = await subtle.encrypt({ name: 'AES-GCM', iv: nonce(seq), additionalData: this.th }, this.txKey, plain);
      return frame(new Uint8Array(ct));
    }
  }

  root.PiE2E = { derivePsk, Channel, E2EError, b64encode, b64decode, concat };
})(typeof window !== 'undefined' ? window : globalThis);
