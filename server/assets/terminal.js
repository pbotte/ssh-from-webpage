// Browser-Terminal: xterm.js <-> api.php (HTTP-Polling), Ende-zu-Ende verschlüsselt (e2e.js)
(() => {
  'use strict';
  const cfg = JSON.parse(document.getElementById('cfg').textContent);
  const T = cfg.timing;
  const enc = new TextEncoder();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const $ = (id) => document.getElementById(id);
  // Fehlende Skripte (nicht hochgeladen / blockiert) sichtbar melden statt stumm zu scheitern
  const missing = (typeof PiE2E === 'undefined') ? 'assets/e2e.js'
    : (typeof Terminal === 'undefined' || typeof FitAddon === 'undefined') ? 'assets/vendor/xterm/'
    : null;
  if (missing) {
    const e = $('sess-status');
    e.textContent = 'Fehler: ' + missing + ' fehlt auf dem Server';
    e.className = 'status err';
    $('btn-new').disabled = true;
    return;
  }
  const { b64encode, b64decode, concat } = PiE2E;

  class ApiError extends Error {
    constructor(msg, status) { super(msg); this.status = status; }
  }

  async function api(action, body = {}) {
    const r = await fetch('api.php?action=' + action, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': cfg.csrf },
      body: JSON.stringify(body),
    });
    if (r.status === 401) { location.reload(); throw new ApiError('Nicht angemeldet', 401); }
    let j;
    try { j = await r.json(); } catch { throw new ApiError('Ungültige Antwort (HTTP ' + r.status + ')', r.status); }
    if (!j.ok) throw new ApiError(j.error || 'Fehler', r.status);
    return j;
  }

  // ---- Terminal ---------------------------------------------------------------
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace',
    fontSize: 14,
    scrollback: 5000,
    theme: { background: '#111418' },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($('terminal'));
  fit.fit();
  term.writeln('\x1b[90mKlicke auf „Neue Sitzung“, um dich mit dem Pi zu verbinden.\x1b[0m');

  const info = (msg) => term.write('\r\n\x1b[90m' + msg + '\x1b[0m\r\n');
  const warn = (msg) => term.write('\r\n\x1b[31m' + msg + '\x1b[0m\r\n');
  const setSessStatus = (txt, cls = '') => { const e = $('sess-status'); e.textContent = txt; e.className = 'status ' + cls; };

  // ---- Terminal-Schlüssel (nur im Browser, nie zum Server) -----------------------
  const KEY_STORE = 'pi-terminal-e2e-psk';
  let pskMem = null;

  function askSecret() {
    return new Promise((resolve, reject) => {
      const dlg = $('keydlg'), inp = $('key-input'), rem = $('key-remember');
      inp.value = '';
      dlg.returnValue = '';
      dlg.showModal();
      inp.focus();
      dlg.onclose = () => {
        dlg.onclose = null;
        const secret = inp.value;
        inp.value = '';
        if (dlg.returnValue === 'ok' && secret.trim()) resolve({ secret, remember: rem.checked });
        else reject(new Error('Abgebrochen'));
      };
    });
  }

  async function getPsk() {
    if (pskMem) return pskMem;
    try {
      const s = localStorage.getItem(KEY_STORE);
      if (s) { pskMem = b64decode(s); return pskMem; }
    } catch { /* Speicher nicht verfügbar */ }
    const { secret, remember } = await askSecret();
    info('Leite Schlüssel ab …');
    pskMem = await PiE2E.derivePsk(secret);
    if (remember) {
      try { localStorage.setItem(KEY_STORE, b64encode(pskMem)); } catch { /* egal */ }
    }
    updateForgetButton();
    return pskMem;
  }

  function forgetPsk() {
    pskMem = null;
    try { localStorage.removeItem(KEY_STORE); } catch { /* egal */ }
    updateForgetButton();
  }

  function updateForgetButton() {
    let stored = false;
    try { stored = !!localStorage.getItem(KEY_STORE); } catch { /* egal */ }
    $('btn-forget').disabled = !(stored || pskMem);
  }

  // ---- Eine Terminal-Sitzung --------------------------------------------------
  class Session {
    constructor(psk) {
      this.psk = psk;
      this.id = null;
      this.chan = null;
      this.inOffset = 0;               // vom Server bestätigte Bytes (verschlüsselt)
      this.outOffset = 0;              // empfangene Bytes (verschlüsselt)
      this.plain = [];                 // getippt, noch nicht verschlüsselt
      this.wire = new Uint8Array(0);   // verschlüsselt, noch nicht bestätigt
      this.sending = false;
      this.flushTimer = null;
      this.running = false;
      this.piSeen = false;
      this.secured = false;
    }

    async start() {
      this.chan = await PiE2E.Channel.create(this.psk);
      const r = await api('open', { cols: term.cols, rows: term.rows, e2e_pub: b64encode(this.chan.pub) });
      this.id = r.id;
      this.running = true;
      term.reset();
      if (!r.pi_online) info('Pi ist gerade offline – warte auf Verbindung …');
      setSessStatus('verbinde …', 'warn');
      this.recvLoop();
    }

    // Tastendruck: sammeln, nach browser_send_interval_ms verschlüsselt senden
    input(str) {
      if (!this.running) return;
      this.plain.push(enc.encode(str));
      this.scheduleFlush();
    }

    scheduleFlush() {
      if (!this.flushTimer && !this.sending) {
        this.flushTimer = setTimeout(() => { this.flushTimer = null; this.flush(); }, T.browser_send_interval_ms);
      }
    }

    async flush() {
      if (this.sending || !this.running || !this.chan.ready) return;   // vor dem Handshake: warten
      if (!this.plain.length && !this.wire.length) return;
      this.sending = true;
      try {
        if (this.plain.length) {
          const p = concat(...this.plain);
          this.plain = [];
          this.wire = concat(this.wire, await this.chan.seal(p));
        }
        // Verschlüsselte Bytes werden bei Fehlern exakt so wiederholt (Server erkennt Duplikate am Offset)
        const r = await api('send', { id: this.id, offset: this.inOffset, data: b64encode(this.wire) });
        if (r.gone) { this.end('Sitzung existiert nicht mehr'); return; }
        const accepted = r.offset - this.inOffset;
        if (accepted > 0) { this.wire = this.wire.slice(accepted); this.inOffset = r.offset; }
        if (r.state !== 'open') this.wire = new Uint8Array(0);
      } catch (e) {
        await sleep(1000);
      } finally {
        this.sending = false;
      }
      if (this.plain.length || this.wire.length) this.flush();
    }

    async recvLoop() {
      let errors = 0;
      while (this.running) {
        let r;
        try {
          r = await api('recv', { id: this.id, offset: this.outOffset, wait: true });
          errors = 0;
        } catch (e) {
          errors++;
          setSessStatus('Verbindungsfehler – versuche erneut …', 'err');
          await sleep(Math.min(10000, 1000 * errors));
          continue;
        }
        if (r.gone) { this.end('Sitzung beendet'); break; }
        if (!this.piSeen && r.pi_seen) { this.piSeen = true; setSessStatus('Handshake …', 'warn'); }
        if (r.data) {
          const bytes = b64decode(r.data);
          this.outOffset = r.offset;
          let parts;
          try {
            parts = await this.chan.receive(this.id, bytes);
          } catch (e) {
            this.cryptoFail(e);
            break;
          }
          if (this.chan.ready && !this.secured) {
            this.secured = true;
            setSessStatus('🔒 Ende-zu-Ende verschlüsselt', 'ok');
            this.flush();                       // vor dem Handshake Getipptes jetzt senden
          }
          for (const p of parts) term.write(p);
        }
        if (r.state === 'closed') { this.end('Sitzung beendet'); break; }
        if (!r.data && T.browser_poll_pause_ms) await sleep(T.browser_poll_pause_ms);
      }
    }

    cryptoFail(e) {
      warn('[Verschlüsselung] ' + e.message);
      if (e.kind === 'auth') {
        forgetPsk();                            // falscher Schlüssel: beim nächsten Mal neu fragen
        info('Der gespeicherte Terminal-Schlüssel wurde verworfen.');
      }
      api('close', { id: this.id }).catch(() => {});
      this.end('Sitzung abgebrochen');
    }

    resize(cols, rows) {
      if (!this.running) return;
      clearTimeout(this.resizeTimer);
      this.resizeTimer = setTimeout(() => api('resize', { id: this.id, cols, rows }).catch(() => {}), 300);
    }

    async close() {
      if (!this.running) return;
      setSessStatus('trenne …', 'warn');
      try { await api('close', { id: this.id }); } catch { this.end('getrennt'); }
      // Die Bestätigung (state=closed) kommt über recvLoop; Fallback nach 10 s:
      setTimeout(() => this.end('getrennt'), 10000);
    }

    closeBeacon() {
      if (!this.running || !navigator.sendBeacon) return;
      const blob = new Blob([JSON.stringify({ id: this.id, csrf: cfg.csrf })], { type: 'application/json' });
      navigator.sendBeacon('api.php?action=close', blob);
    }

    end(msg) {
      if (!this.running) return;
      this.running = false;
      info('[' + msg + ']');
      setSessStatus('keine Sitzung');
      onSessionEnd(this);
    }
  }

  // ---- UI ----------------------------------------------------------------------
  let current = null;

  function onSessionEnd(s) {
    if (current === s) current = null;
    $('btn-new').disabled = false;
    $('btn-close').disabled = true;
  }

  $('btn-new').addEventListener('click', async () => {
    if (current) return;
    $('btn-new').disabled = true;
    try {
      if (!window.crypto || !window.crypto.subtle) {
        throw new Error('Verschlüsselung braucht HTTPS (WebCrypto nicht verfügbar).');
      }
      const s = new Session(await getPsk());
      await s.start();
      current = s;
      $('btn-close').disabled = false;
      term.focus();
    } catch (e) {
      if (e.message !== 'Abgebrochen') warn('Fehler: ' + e.message);
      $('btn-new').disabled = false;
    }
  });
  $('btn-close').addEventListener('click', () => current && current.close());
  $('btn-forget').addEventListener('click', () => { forgetPsk(); info('Terminal-Schlüssel auf diesem Gerät vergessen.'); });
  updateForgetButton();

  term.onData((d) => current && current.input(d));
  term.onBinary((d) => current && current.input(d));
  term.onResize(({ cols, rows }) => current && current.resize(cols, rows));
  window.addEventListener('resize', () => fit.fit());
  window.addEventListener('pagehide', () => current && current.closeBeacon());

  // Pi online/offline anzeigen
  async function statusLoop() {
    while (true) {
      try {
        const r = await api('status');
        const e = $('pi-status');
        e.textContent = r.pi_online ? 'Pi: online' : 'Pi: offline';
        e.className = 'status ' + (r.pi_online ? 'ok' : 'err');
      } catch { /* ignorieren */ }
      await sleep(10000);
    }
  }
  statusLoop();
})();
