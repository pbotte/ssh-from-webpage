#!/usr/bin/env python3
"""
Pi-Agent: verbindet den Raspberry Pi per HTTPS-Polling mit der PHP-Webseite
und stellt dort ein Terminal bereit.

  mode = ssh  -> im Browser-Terminal erscheint "login as:" / "Password:", danach
                 SSH-Verbindung zu localhost (paramiko). Empfohlen.
  mode = pty  -> Shell wird direkt als Benutzer dieses Agenten gestartet.

Zusätzlich: SSH-Tunnel für client/pi_tunnel.py (Mac/PC) – rohe TCP-Verbindung
zum fest konfigurierten Ziel ([tunnel] target, Standard 127.0.0.1:22).

Aufruf:  python3 pi_agent.py [pfad/zu/agent.ini]
"""
import base64
import configparser
import fcntl
import glob
import hashlib
import hmac
import http.client
import json
import logging
import os
import pty
import secrets
import signal
import socket
import ssl
import struct
import sys
import termios
import threading
import time
import urllib.parse

try:
    import paramiko
except ImportError:  # nur für mode = ssh nötig
    paramiko = None

try:  # für die Ende-zu-Ende-Verschlüsselung des Web-Terminals (kommt mit paramiko mit)
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    ec = None

log = logging.getLogger("pi-agent")

DEFAULT_TIMING = {
    "pi_poll_pause_ms": 100,
    "pi_push_interval_ms": 50,
    "longpoll_timeout_s": 20,
}
MAX_PUSH_BYTES = 200_000


# ============================================================================
#  HTTP mit Keep-Alive (spart pro Anfrage einen TLS-Handshake = Latenz)
# ============================================================================
class ApiError(Exception):
    pass


class Api:
    def __init__(self, url: str, token: str, agent_id: str, verify_tls: bool = True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError(f"Ungültige URL: {url}")
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port
        self.path = u.path or "/"
        self.token = token
        self.agent_id = agent_id
        self.ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.conn = None

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None

    def call(self, action: str, payload: dict, timeout: float) -> dict:
        payload = dict(payload, agent_id=self.agent_id)
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Pi-Token": self.token,
            "User-Agent": "pi-agent/1.0",
            "Connection": "keep-alive",
        }
        for attempt in (1, 2):  # 2. Versuch, falls die Keep-Alive-Verbindung schon zu war
            try:
                if self.conn is None:
                    if self.https:
                        self.conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.ctx)
                    else:
                        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
                else:
                    self.conn.timeout = timeout
                    if self.conn.sock:
                        self.conn.sock.settimeout(timeout)
                self.conn.request("POST", f"{self.path}?action={action}", body=body, headers=headers)
                resp = self.conn.getresponse()
                data = resp.read()
                if resp.getheader("Connection", "").lower() == "close":
                    self.close()
            except (http.client.HTTPException, OSError) as e:
                self.close()
                if attempt == 2:
                    raise ApiError(f"Verbindung fehlgeschlagen: {e}") from e
                continue
            try:
                j = json.loads(data)
            except ValueError:
                raise ApiError(f"HTTP {resp.status}, keine JSON-Antwort: {data[:200]!r}")
            if resp.status != 200 or not j.get("ok"):
                raise ApiError(f"HTTP {resp.status}: {j.get('error')}")
            return j
        raise ApiError("unerreichbar")


# ============================================================================
#  Ende-zu-Ende-Verschlüsselung Browser <-> Pi (Protokoll "pi-term-e2e/v1")
#  Gegenstück zu server/assets/e2e.js – Beschreibung des Protokolls dort.
# ============================================================================
E2E_MAGIC = b"pi-term-e2e/v1"
E2E_PBKDF2_ITER = 600_000
E2E_MAX_FRAME = 16 * 1024 * 1024


class E2EError(Exception):
    pass


def e2e_derive_psk(secret: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.strip().encode(), E2E_MAGIC, E2E_PBKDF2_ITER)


def _hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _nonce(seq: int) -> bytes:
    return b"\0\0\0\0" + struct.pack(">Q", seq)


class E2E:
    """Pi-Seite einer verschlüsselten Sitzung."""

    def __init__(self, psk: bytes, sid: str, pub_browser: bytes):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_browser)
        priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = priv.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
        z = priv.exchange(ec.ECDH(), peer)
        self.th = hashlib.sha256(E2E_MAGIC + sid.encode() + pub_browser + self.pub).digest()
        okm = _hkdf_sha256(psk, z, b"keys" + self.th, 96)
        self.rx = AESGCM(okm[0:32])      # Browser -> Pi
        self.tx = AESGCM(okm[32:64])     # Pi -> Browser
        self.conf = hmac.new(okm[64:96], b"pi-confirm" + self.th, hashlib.sha256).digest()
        self.tx_seq = 0
        self.rx_seq = 0
        self.rx_buf = bytearray()

    def handshake_frame(self) -> bytes:
        return _frame(json.dumps({"v": 1, "pub": base64.b64encode(self.pub).decode(),
                                  "conf": base64.b64encode(self.conf).decode()}).encode())

    @staticmethod
    def error_frame(msg: str) -> bytes:
        return _frame(json.dumps({"v": 1, "error": msg}).encode())

    def seal(self, data: bytes) -> bytes:
        ct = self.tx.encrypt(_nonce(self.tx_seq), data, self.th)
        self.tx_seq += 1
        return _frame(ct)

    def open(self, data: bytes) -> bytes:
        """Empfangene (beliebig zerstückelte) Bytes -> Klartext. Wirft E2EError bei Manipulation."""
        self.rx_buf += data
        out = bytearray()
        while len(self.rx_buf) >= 4:
            (n,) = struct.unpack(">I", self.rx_buf[:4])
            if n > E2E_MAX_FRAME:
                raise E2EError("ungültiger Datenrahmen")
            if len(self.rx_buf) < 4 + n:
                break
            ct = bytes(self.rx_buf[4:4 + n])
            del self.rx_buf[:4 + n]
            try:
                out += self.rx.decrypt(_nonce(self.rx_seq), ct, self.th)
            except InvalidTag:
                raise E2EError("Entschlüsselung fehlgeschlagen (falscher Schlüssel oder Manipulation)")
            self.rx_seq += 1
        return bytes(out)


# ============================================================================
#  Sitzungen
# ============================================================================
class BaseSession:
    def __init__(self, agent, sid, cols, rows, out_offset):
        self.agent = agent
        self.sid = sid
        self.cols, self.rows = cols, rows
        self.in_offset = 0
        self.resize_seq = None
        self.out_buf = bytearray()      # noch nicht bestätigte Ausgabe (ggf. verschlüsselt)
        self.out_offset = out_offset    # vom Server bestätigte Ausgabe-Bytes
        self.lock = threading.Lock()
        self.closed = False             # Shell beendet
        self.done = False               # Schließen vom Server bestätigt
        self.e2e = None                 # E2E-Objekt bei verschlüsselten Web-Terminals
        # Backend-Handles werden erst in start() gesetzt. Vorab definiert, damit
        # terminate() auch bei Sitzungen funktioniert, die nie gestartet wurden
        # (z.B. abgelehnt, weil die Verschlüsselung fehlt).
        self.client = self.chan = self.sock = None
        self.pid = self.fd = None
        self.state = "new"

    def emit(self, data: bytes):
        with self.lock:   # unter der Sperre: Reihenfolge der Rahmen = Reihenfolge der Nonces
            self.out_buf += self.e2e.seal(data) if self.e2e else data
        self.agent.wake_pusher()

    def emit_raw(self, data: bytes):
        with self.lock:
            self.out_buf += data
        self.agent.wake_pusher()

    def feed_wire(self, data: bytes):
        """Daten vom Server: bei E2E erst prüfen/entschlüsseln, dann an die Shell."""
        if self.closed:
            return
        if self.e2e:
            try:
                data = self.e2e.open(data)
            except E2EError as e:
                log.warning("Sitzung %s: %s – Sitzung wird beendet", self.sid[:8], e)
                self.terminate()
                return
        if data:
            self.feed(data)

    def terminate(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        try:
            self._close_backend()
        except Exception:
            log.exception("Sitzung %s: Fehler beim Schließen (ignoriert)", self.sid[:8])
        log.info("Sitzung %s beendet", self.sid[:8])
        self.agent.wake_pusher()   # "closed" an den Server melden – auch nach Fehlern

    # von Unterklassen
    def start(self): ...
    def feed(self, data: bytes): ...
    def resize(self, cols, rows): ...
    def _close_backend(self): ...


class PtySession(BaseSession):
    """Shell direkt als Benutzer des Agenten."""

    def start(self):
        shell = self.agent.cfg.get("shell", "shell", fallback="/bin/bash")
        pid, fd = pty.fork()
        if pid == 0:  # Kindprozess
            try:
                env = dict(os.environ, TERM="xterm-256color")
                os.chdir(os.path.expanduser("~"))
                os.execvpe(shell, [shell, "-l"], env)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.resize(self.cols, self.rows)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while True:
                data = os.read(self.fd, 65536)
                if not data:
                    break
                self.emit(data)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.terminate()

    def feed(self, data):
        if self.closed:
            return
        try:
            while data:
                n = os.write(self.fd, data)
                data = data[n:]
        except OSError:
            self.terminate()

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        if self.fd is None:
            return
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    def _close_backend(self):
        if self.pid is None:
            return
        try:
            os.kill(self.pid, signal.SIGHUP)
        except ProcessLookupError:
            pass


class SshSession(BaseSession):
    """Fragt Benutzer/Passwort im Terminal ab und verbindet per SSH zu localhost."""

    def start(self):
        self.state = "user"   # user -> pass -> connecting -> shell
        self.line = bytearray()
        self.username = ""
        self.attempts = 0
        self.client = None
        self.chan = None
        self.emit(f"\x1b[90mVerbunden mit {socket.gethostname()}\x1b[0m\r\n".encode())
        self._prompt_user()

    def _prompt_user(self):
        self.state = "user"
        self.line.clear()
        self.emit(b"login as: ")

    def feed(self, data):
        if self.closed:
            return
        if self.state == "shell":
            try:
                self.chan.sendall(data)
            except Exception:
                self.terminate()
            return
        if self.state == "connecting" or data.startswith(b"\x1b"):
            return  # Tippen während des Verbindens / Pfeiltasten ignorieren
        for b in data:
            if b in (10, 13):  # Enter
                self._enter()
                if self.state not in ("user", "pass"):
                    return
            elif b in (8, 127):  # Backspace (ein UTF-8-Zeichen löschen)
                if self.line:
                    while self.line and 0x80 <= self.line[-1] < 0xC0:
                        self.line.pop()
                    if self.line:
                        self.line.pop()
                    if self.state == "user":
                        self.emit(b"\b \b")
            elif b == 3:  # Strg+C
                self.emit(b"^C\r\n")
                self._prompt_user()
            elif b == 4:  # Strg+D
                if not self.line:
                    self.emit(b"\r\n")
                    self.terminate()
                    return
            elif b >= 32 and len(self.line) < 256:
                self.line.append(b)
                if self.state == "user":
                    self.emit(bytes([b]))

    def _enter(self):
        text = self.line.decode("utf-8", "replace")
        self.line.clear()
        if self.state == "user":
            if not text.strip():
                self.emit(b"\r\nlogin as: ")
                return
            self.username = text.strip()
            self.state = "pass"
            self.emit(f"\r\n{self.username}@{socket.gethostname()}'s password: ".encode())
        elif self.state == "pass":
            self.state = "connecting"
            self.emit(b"\r\n")
            threading.Thread(target=self._connect, args=(self.username, text), daemon=True).start()

    def _connect(self, username, password):
        c = self.agent.cfg
        host = c.get("shell", "ssh_host", fallback="127.0.0.1")
        port = c.getint("shell", "ssh_port", fallback=22)
        max_attempts = c.getint("shell", "max_login_attempts", fallback=3)
        client = paramiko.SSHClient()
        try:
            load_local_host_keys(client, host, port,
                                 c.get("shell", "host_key_files", fallback="/etc/ssh/ssh_host_*_key.pub"))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(host, port, username=username, password=password,
                           look_for_keys=False, allow_agent=False,
                           timeout=15, auth_timeout=15, banner_timeout=15)
            chan = client.invoke_shell(term="xterm-256color", width=self.cols, height=self.rows)
        except paramiko.AuthenticationException:
            client.close()
            self.attempts += 1
            log.warning("Sitzung %s: SSH-Login fehlgeschlagen für %r", self.sid[:8], username)
            time.sleep(2)
            if self.attempts >= max_attempts:
                self.emit(b"Zugriff verweigert. Zu viele Fehlversuche.\r\n")
                self.terminate()
            else:
                self.emit(b"Zugriff verweigert.\r\n")
                self._prompt_user()
            return
        except Exception as e:
            client.close()
            log.error("Sitzung %s: SSH-Fehler: %s", self.sid[:8], e)
            self.emit(f"\x1b[31mSSH-Fehler: {e}\x1b[0m\r\n".encode())
            self.terminate()
            return
        self.client, self.chan = client, chan
        if self.closed:  # während des Verbindens geschlossen
            client.close()
            return
        log.info("Sitzung %s: SSH-Login als %r", self.sid[:8], username)
        self.state = "shell"
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while True:
                data = self.chan.recv(65536)
                if not data:
                    break
                self.emit(data)
        except Exception:
            pass
        self.terminate()

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        if self.chan is not None:
            try:
                self.chan.resize_pty(width=cols, height=rows)
            except Exception:
                pass

    def _close_backend(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass


class TcpSession(BaseSession):
    """
    Roher TCP-Tunnel für pi_tunnel.py (Mac/PC). Verbindet NUR zum fest
    konfigurierten Ziel ([tunnel] target), damit der Tunnel kein offener Proxy
    ins Heimnetz wird. Die Bytes sind SSH-verschlüsselt (Ende-zu-Ende).
    """

    def start(self):
        c = self.agent.cfg
        self.sock = None
        if not c.getboolean("tunnel", "enabled", fallback=True):
            log.warning("Sitzung %s: Tunnel abgelehnt ([tunnel] enabled = false)", self.sid[:8])
            self.terminate()
            return
        host, port = parse_host_port(c.get("tunnel", "target", fallback="127.0.0.1:22"))
        src = c.get("tunnel", "source_address", fallback="").strip()
        try:
            self.sock = socket.create_connection((host, port), timeout=10,
                                                 source_address=(src, 0) if src else None)
        except OSError as e:
            log.error("Sitzung %s: Tunnel-Ziel %s:%s nicht erreichbar: %s", self.sid[:8], host, port, e)
            self.terminate()
            return
        self.sock.settimeout(None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log.info("Sitzung %s: Tunnel zu %s:%s verbunden", self.sid[:8], host, port)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    break
                self.emit(data)
        except OSError:
            pass
        self.terminate()

    def feed(self, data):
        if self.closed or self.sock is None:
            return
        try:
            self.sock.sendall(data)
        except OSError:
            self.terminate()

    def resize(self, cols, rows):
        pass

    def _close_backend(self):
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass


def parse_host_port(s, default_port=22):
    s = s.strip()
    if s.startswith("["):                      # [::1]:22
        host, _, rest = s[1:].partition("]")
        return host, int(rest.lstrip(":") or default_port)
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, int(port)
    return s, default_port


def load_local_host_keys(client, host, port, pattern):
    """Vertraut genau den eigenen Host-Keys des Pi (aus /etc/ssh) – kein Blind-Accept."""
    name = host if port == 22 else f"[{host}]:{port}"
    keys = client.get_host_keys()
    n = 0
    for path in glob.glob(pattern):
        try:
            with open(path) as f:
                parts = f.read().split()
            entry = paramiko.hostkeys.HostKeyEntry.from_line(f"{name} {parts[0]} {parts[1]}")
            if entry and entry.key:
                keys.add(name, entry.key.get_name(), entry.key)
                n += 1
        except Exception as e:
            log.debug("Host-Key %s nicht lesbar: %s", path, e)
    if not n:
        raise RuntimeError(f"Keine Host-Keys gefunden ({pattern})")


# ============================================================================
#  Agent: Poll-Schleife (Eingaben holen) + Push-Schleife (Ausgabe senden)
# ============================================================================
class Agent:
    def __init__(self, cfg: configparser.ConfigParser):
        self.cfg = cfg
        self.agent_id = secrets.token_urlsafe(12)
        url = cfg.get("server", "url")
        token = cfg.get("server", "token")
        verify = cfg.getboolean("server", "verify_tls", fallback=True)
        self.poll_api = Api(url, token, self.agent_id, verify)
        self.push_api = Api(url, token, self.agent_id, verify)
        self.mode = cfg.get("shell", "mode", fallback="ssh").strip().lower()
        if self.mode not in ("ssh", "pty"):
            raise SystemExit("shell.mode muss 'ssh' oder 'pty' sein")
        if self.mode == "ssh" and paramiko is None:
            raise SystemExit("mode = ssh braucht paramiko:  sudo apt install python3-paramiko")
        self.psk = None
        secret = cfg.get("e2e", "secret", fallback="").strip()
        if not secret or secret.startswith("BITTE-ERSETZEN"):
            log.warning("Kein [e2e] secret in der agent.ini – Web-Terminal ist deaktiviert "
                        "(SSH-Tunnel funktioniert weiter).")
        elif len(secret) < 16:
            raise SystemExit("[e2e] secret ist zu kurz (mind. 16 Zeichen, besser zufällig erzeugt)")
        elif ec is None:
            raise SystemExit("Verschlüsselung braucht das Paket cryptography:  sudo apt install python3-cryptography")
        else:
            t = time.time()
            self.psk = e2e_derive_psk(secret)
            log.info("Terminal-Schlüssel geladen (%.1f s)", time.time() - t)
        self.timing = dict(DEFAULT_TIMING)
        for k in DEFAULT_TIMING:  # lokale Startwerte; der Server überschreibt sie
            if cfg.has_option("timing", k):
                self.timing[k] = cfg.getint("timing", k)
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.push_event = threading.Event()
        self.running = True

    def wake_pusher(self):
        self.push_event.set()

    def _snapshot(self):
        with self.sessions_lock:
            return list(self.sessions.values())

    # ---- Poll ---------------------------------------------------------------
    def poll_loop(self):
        backoff = 1
        while self.running:
            known = {s.sid: {"in_offset": s.in_offset, "resize_seq": s.resize_seq}
                     for s in self._snapshot() if not s.done}
            try:
                r = self.poll_api.call("poll", {"sessions": known, "wait": True},
                                       timeout=self.timing["longpoll_timeout_s"] + 20)
                if backoff > 1:
                    log.info("Server wieder erreichbar")
                backoff = 1
            except ApiError as e:
                log.warning("Poll: %s (neuer Versuch in %d s)", e, backoff)
                time.sleep(backoff)
                backoff = min(30, backoff * 2)
                continue

            if r.get("superseded"):
                log.warning("Ein anderer Pi-Agent mit demselben Token ist aktiv! Läuft er doppelt?")
                time.sleep(5)

            for k, v in (r.get("timing") or {}).items():
                if k in self.timing and v != self.timing[k]:
                    log.info("Timing %s = %s (vom Server)", k, v)
                    self.timing[k] = int(v)

            seen = set()
            for e in r.get("sessions", []):
                sid = str(e.get("id"))
                seen.add(sid)
                try:
                    self._apply(e)
                except Exception:
                    # Ein Fehler in EINER Sitzung darf nie den ganzen Agenten beenden
                    log.exception("Sitzung %s: unerwarteter Fehler – Sitzung wird beendet", sid[:8])
                    with self.sessions_lock:
                        s = self.sessions.get(sid)
                    if s is not None:
                        s.terminate()

            with self.sessions_lock:
                gone = [self.sessions.pop(sid) for sid in list(self.sessions) if sid not in seen]
            for s in gone:
                s.terminate()   # auf dem Server verschwunden

            if self.timing["pi_poll_pause_ms"]:
                time.sleep(self.timing["pi_poll_pause_ms"] / 1000)

    def _apply(self, e):
        """Einen Sitzungseintrag aus der Poll-Antwort verarbeiten."""
        with self.sessions_lock:
            s = self.sessions.get(e["id"])
        if s is None:
            if e["state"] != "open":
                return
            s = self._create(e)
            if s is None:
                return
        if e.get("in"):
            s.feed_wire(base64.b64decode(e["in"]))
        s.in_offset = e["in_offset"]
        if s.resize_seq is None:
            s.resize_seq = e["resize_seq"]
        elif e["resize_seq"] != s.resize_seq:
            s.resize_seq = e["resize_seq"]
            s.resize(e["cols"], e["rows"])
        if e["state"] == "closing":
            s.terminate()

    def _create(self, e):
        kind = e.get("kind", "terminal")
        if kind == "tcp":
            cls = TcpSession
            log.info("Neuer Tunnel %s (%s)", e["id"][:8], e.get("user"))
        elif kind == "terminal":
            cls = SshSession if self.mode == "ssh" else PtySession
            log.info("Neue Sitzung %s (Web-User %s, %sx%s, mode=%s)",
                     e["id"][:8], e.get("user"), e["cols"], e["rows"], self.mode)
        else:
            log.warning("Unbekannte Sitzungsart %r ignoriert", kind)
            return None
        s = cls(self, e["id"], e["cols"], e["rows"], e["out_offset"])
        with self.sessions_lock:
            self.sessions[s.sid] = s
        if kind == "terminal":
            # Web-Terminals NUR verschlüsselt – der Server kann nicht auf Klartext zurückstufen
            err = None
            if self.psk is None:
                err = "Auf dem Pi ist kein Terminal-Schlüssel eingerichtet ([e2e] secret in agent.ini)."
            else:
                try:
                    s.e2e = E2E(self.psk, s.sid, base64.b64decode(e.get("e2e_pub") or ""))
                except Exception as ex:
                    log.warning("Sitzung %s: E2E-Aufbau fehlgeschlagen: %s", s.sid[:8], ex)
                    err = "Verschlüsselung konnte nicht aufgebaut werden (Browser-Schlüssel fehlt oder ist ungültig)."
            if err:
                log.warning("Sitzung %s abgelehnt: %s", s.sid[:8], err)
                s.emit_raw(E2E.error_frame(err))
                s.terminate()
                return s
            s.emit_raw(s.e2e.handshake_frame())
        try:
            s.start()
        except Exception as ex:
            log.exception("Sitzung konnte nicht gestartet werden")
            if kind == "terminal":  # in einen TCP-Tunnel keinen Text schreiben
                s.emit(f"\x1b[31mFehler beim Start: {ex}\x1b[0m\r\n".encode())
            s.terminate()
        return s

    # ---- Push ---------------------------------------------------------------
    def push_loop(self):
        while self.running:
            self.push_event.wait(timeout=5)
            self.push_event.clear()
            if self.timing["pi_push_interval_ms"]:
                time.sleep(self.timing["pi_push_interval_ms"] / 1000)  # Ausgabe sammeln

            payload, closing = {}, set()
            for s in self._snapshot():
                with s.lock:
                    if s.done or (not s.out_buf and not s.closed):
                        continue
                    chunk = bytes(s.out_buf[:MAX_PUSH_BYTES])
                    last = len(s.out_buf) <= MAX_PUSH_BYTES
                    payload[s.sid] = {"offset": s.out_offset,
                                      "data": base64.b64encode(chunk).decode(),
                                      "closed": s.closed and last}
                    if s.closed and last:
                        closing.add(s.sid)
            if not payload:
                continue
            try:
                r = self.push_api.call("push", {"sessions": payload}, timeout=30)
            except ApiError as e:
                log.warning("Push: %s", e)
                time.sleep(2)
                self.wake_pusher()
                continue

            more = False
            for sid, info in (r.get("sessions") or {}).items():
                with self.sessions_lock:
                    s = self.sessions.get(sid)
                if s is None:
                    continue
                if info.get("gone"):
                    s.terminate()
                    s.done = True
                elif "out_offset" in info:
                    with s.lock:
                        n = info["out_offset"] - s.out_offset
                        if n > 0:
                            del s.out_buf[:n]
                            s.out_offset = info["out_offset"]
                        if sid in closing and not s.out_buf:
                            s.done = True
                        more = more or bool(s.out_buf)
                if s.done:
                    with self.sessions_lock:
                        self.sessions.pop(sid, None)
            if more:
                self.wake_pusher()

    def run(self):
        log.info("Pi-Agent startet (mode=%s, Server=%s)", self.mode, self.cfg.get("server", "url"))
        threading.Thread(target=self._forever, args=("Push", self.push_loop), daemon=True).start()
        self._forever("Poll", self.poll_loop)

    def _forever(self, name, loop):
        """Schleife bei unerwarteten Fehlern protokollieren und neu starten statt abzustürzen."""
        while self.running:
            try:
                loop()
                return
            except Exception:
                log.exception("%s-Schleife: unerwarteter Fehler – starte neu", name)
                time.sleep(2)

    def stop(self, *_):
        log.info("Beende …")
        self.running = False
        for s in self._snapshot():
            s.terminate()
        sys.exit(0)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.ini")
    cfg = configparser.ConfigParser()
    if not cfg.read(path):
        raise SystemExit(f"Konfiguration nicht gefunden: {path}")
    logging.basicConfig(level=cfg.get("log", "level", fallback="INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    if os.geteuid() == 0:
        log.warning("Agent läuft als root – bitte einen eigenen, unprivilegierten Benutzer verwenden!")
    agent = Agent(cfg)
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()


if __name__ == "__main__":
    main()
