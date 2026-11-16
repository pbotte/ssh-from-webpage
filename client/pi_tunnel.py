#!/usr/bin/env python3
"""
pi_tunnel.py – SSH zum Raspberry Pi über die Webseite (HTTPS-Polling).

Die SSH-Verbindung läuft Ende-zu-Ende verschlüsselt zwischen deinem ssh-Client
und dem sshd des Pi; der Webspace reicht nur verschlüsselte Bytes durch.
Nur Python-Standardbibliothek nötig.

1) Als ProxyCommand (empfohlen), in ~/.ssh/config:

       Host pi-web
           User pi
           ProxyCommand python3 ~/bin/pi_tunnel.py
           ServerAliveInterval 30

   Danach funktionieren:  ssh pi-web | scp datei pi-web: | rsync | sftp |
   VS Code Remote-SSH | ssh -L 8080:localhost:80 pi-web

2) Als lokaler Port:

       python3 pi_tunnel.py --listen 2222                  # ~/.config/pi-tunnel.ini
       python3 pi_tunnel.py pi-tunnel.ini --listen 2222    # eigene Konfigurationsdatei
       ssh -p 2222 pi@localhost

Konfiguration: erstes Argument, sonst --config, sonst $PI_TUNNEL_CONFIG,
sonst ~/.config/pi-tunnel.ini
"""
import argparse
import base64
import configparser
import http.client
import json
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse

log = logging.getLogger("pi-tunnel")
MAX_SEND = 200_000
DEFAULT_CONFIG = os.path.expanduser("~/.config/pi-tunnel.ini")


class ApiError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


class Api:
    """POST-JSON-Client mit Keep-Alive (spart pro Anfrage einen TLS-Handshake)."""

    def __init__(self, url, token, verify_tls=True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise SystemExit(f"Ungültige URL: {url}")
        self.https = u.scheme == "https"
        self.host, self.port, self.path = u.hostname, u.port, u.path or "/"
        self.token = token
        self.ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self.conn = None

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None

    def call(self, action, payload, timeout=30.0):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "X-Client-Token": self.token,
                   "User-Agent": "pi-tunnel/1.0", "Connection": "keep-alive"}
        for attempt in (1, 2):
            try:
                if self.conn is None:
                    cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
                    kw = {"context": self.ctx} if self.https else {}
                    self.conn = cls(self.host, self.port, timeout=timeout, **kw)
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
                raise ApiError(f"HTTP {resp.status}, keine JSON-Antwort: {data[:200]!r}", resp.status)
            if resp.status != 200 or not j.get("ok"):
                raise ApiError(f"{j.get('error')} (HTTP {resp.status})", resp.status)
            return j
        raise ApiError("unerreichbar")


class Tunnel:
    """
    Eine SSH-Verbindung: liest lokale Bytes über read_fn und schreibt
    empfangene Bytes über write_fn. run() blockiert bis zum Ende.
    """

    def __init__(self, cfg, read_fn, write_fn, label="tunnel"):
        self.cfg = cfg
        self.read_fn, self.write_fn = read_fn, write_fn
        self.label = label
        self.buf = bytearray()
        self.eof = False             # lokale Seite hat nichts mehr zu senden
        self.closed = False          # Tunnel ist zu
        self.lock = threading.Lock()
        self.ev = threading.Event()
        self.in_offset = 0
        self.received = 0

    def api(self):
        s = self.cfg["server"]
        return Api(s["url"], s["token"], s.getboolean("verify_tls", fallback=True))

    def abort(self):
        """
        Sofort beenden (z.B. ssh beendet den ProxyCommand per SIGHUP): noch
        gepufferte Bytes (oft die SSH-Abmeldung) senden und Tunnel schließen,
        damit sshd und die Sitzung auf dem Server nicht bis zum Timeout hängen.
        """
        sid = getattr(self, "id", None)
        if sid is None or self.closed:
            return
        self.closed = True
        api = self.api()
        try:
            with self.lock:
                data, offset = bytes(self.buf), self.in_offset
            if data:   # wiederholbar dank Offset, auch wenn der Sender parallel sendet
                api.call("send", {"id": sid, "offset": offset,
                                  "data": base64.b64encode(data).decode()}, timeout=5)
            api.call("close", {"id": sid}, timeout=5)
        except ApiError as e:
            log.info("[%s] Abbruch: %s", self.label, e)
        api.close()

    def run(self):
        ctl = self.api()
        r = ctl.call("open", {}, timeout=30)
        ctl.close()
        self.id = r["id"]
        self.timing = r.get("timing", {})
        log.info("[%s] Tunnel %s geöffnet", self.label, self.id[:8])
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._sender, daemon=True).start()
        try:
            self._receiver()
        finally:
            self.closed = True
            self.ev.set()
        if self.received == 0:
            log.warning("[%s] Tunnel ohne Daten geschlossen – ist [tunnel] auf dem Pi aktiv "
                        "und sshd unter dem target erreichbar? (siehe Pi-Agent-Log)", self.label)
        log.info("[%s] Tunnel geschlossen (%d Bytes empfangen, %d gesendet)",
                 self.label, self.received, self.in_offset)

    # lokale Daten einlesen ------------------------------------------------------
    def _reader(self):
        while not self.closed:
            try:
                data = self.read_fn(65536)
            except OSError:
                data = b""
            with self.lock:
                if data:
                    self.buf += data
                else:
                    self.eof = True
            self.ev.set()
            if not data:
                return

    # an den Server senden ------------------------------------------------------
    def _sender(self):
        api = self.api()
        errors = 0
        while not self.closed:
            self.ev.wait(5)
            self.ev.clear()
            if self.closed:
                break
            pause = self.timing.get("browser_send_interval_ms", 30)
            if pause:
                time.sleep(pause / 1000)        # Eingaben kurz sammeln
            with self.lock:
                data = bytes(self.buf[:MAX_SEND])
                eof = self.eof and len(self.buf) <= MAX_SEND
            if data:
                try:
                    r = api.call("send", {"id": self.id, "offset": self.in_offset,
                                          "data": base64.b64encode(data).decode()})
                    errors = 0
                except ApiError as e:
                    errors += 1
                    log.warning("[%s] Senden: %s", self.label, e)
                    if errors > 10:
                        self.closed = True
                        break
                    time.sleep(min(5, errors))
                    self.ev.set()
                    continue
                if r.get("gone") or r.get("state") != "open":
                    self.closed = True
                    break
                with self.lock:
                    n = r["offset"] - self.in_offset
                    if n > 0:
                        del self.buf[:n]
                    self.in_offset = r["offset"]
                    if self.buf or self.eof:
                        self.ev.set()
            elif eof:
                log.info("[%s] lokale Seite beendet – schließe Tunnel", self.label)
                try:
                    api.call("close", {"id": self.id})
                except ApiError as e:
                    log.warning("[%s] Schließen: %s", self.label, e)
                break
        api.close()

    # vom Server empfangen -------------------------------------------------------
    def _receiver(self):
        api = self.api()
        offset, errors = 0, 0
        timeout = self.timing.get("longpoll_timeout_s", 20) + 20
        while not self.closed:
            try:
                r = api.call("recv", {"id": self.id, "offset": offset, "wait": True}, timeout=timeout)
                errors = 0
            except ApiError as e:
                errors += 1
                log.warning("[%s] Empfangen: %s", self.label, e)
                if errors > 10 or e.status in (401, 403):
                    break
                time.sleep(min(5, errors))
                continue
            if r.get("gone"):
                break
            data = base64.b64decode(r.get("data") or "")
            if data:
                try:
                    self.write_fn(data)
                except OSError:
                    break
                self.received += len(data)
            offset = r.get("offset", offset)
            if r.get("state") == "closed":
                break
            if not data:
                pause = self.timing.get("browser_poll_pause_ms", 100)
                if pause:
                    time.sleep(pause / 1000)
        api.close()


# ============================================================================
def write_all_stdout(data):
    while data:
        n = os.write(1, data)
        data = data[n:]


def run_proxycommand(cfg):
    """stdin/stdout = SSH-Datenstrom (für ssh -o ProxyCommand=...)."""
    t = Tunnel(cfg, lambda n: os.read(0, n), write_all_stdout, "stdio")

    def on_signal(signum, _frame):
        t.abort()
        os._exit(0)

    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)
    try:
        t.run()
    except ApiError as e:
        log.error("Tunnel konnte nicht geöffnet werden: %s", e)
        os._exit(1)
    os._exit(0)  # blockierendes stdin-Lesen nicht abwarten


def run_listen(cfg, port, bind):
    srv = socket.create_server((bind, port), reuse_port=False)
    log.warning("Lausche auf %s:%d – verbinden mit:  ssh -p %d <user>@localhost", bind, port, port)

    def handle(conn, addr):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        t = Tunnel(cfg, conn.recv, conn.sendall, f"{addr[0]}:{addr[1]}")
        try:
            t.run()
        except ApiError as e:
            log.error("Tunnel konnte nicht geöffnet werden: %s", e)
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(
        description="SSH zum Pi über die Webseite (HTTPS-Polling)",
        epilog="Beispiele:  pi_tunnel.py pi-tunnel.ini --listen 2222   |   "
               "ProxyCommand python3 ~/bin/pi_tunnel.py")
    ap.add_argument("config_file", nargs="?", metavar="CONFIG",
                    help=f"Konfigurationsdatei (alternativ --config; Standard: $PI_TUNNEL_CONFIG "
                         f"oder {DEFAULT_CONFIG})")
    ap.add_argument("--config", help=argparse.SUPPRESS)
    ap.add_argument("--listen", type=int, metavar="PORT",
                    help="lokalen Port öffnen statt stdin/stdout (ProxyCommand) zu nutzen")
    ap.add_argument("--bind", default="127.0.0.1", help="Adresse für --listen (Standard: 127.0.0.1)")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()
    if args.config_file and args.config and args.config_file != args.config:
        ap.error("Konfigurationsdatei bitte nur einmal angeben (Position ODER --config)")
    args.config = os.path.expanduser(args.config_file or args.config
                                     or os.environ.get("PI_TUNNEL_CONFIG") or DEFAULT_CONFIG)

    # Logausgaben IMMER auf stderr – stdout ist im ProxyCommand-Modus der SSH-Datenstrom!
    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)]
    logging.basicConfig(stream=sys.stderr, level=level, format="pi-tunnel: %(message)s")

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        log.error("Konfiguration nicht gefunden: %s (Vorlage: pi-tunnel.ini.example)", args.config)
        sys.exit(2)
    if not cfg.has_option("server", "url") or not cfg.has_option("server", "token"):
        log.error("[server] url und token müssen in %s gesetzt sein", args.config)
        sys.exit(2)
    if os.name == "posix" and os.stat(args.config).st_mode & 0o077:
        log.warning("%s ist für andere lesbar – bitte: chmod 600 %s", args.config, args.config)

    if args.listen:
        try:
            run_listen(cfg, args.listen, args.bind)
        except KeyboardInterrupt:
            pass
    else:
        run_proxycommand(cfg)


if __name__ == "__main__":
    main()
