# Pi-Terminal über Shared Webspace

Ein Browser-Terminal (xterm.js) auf einer PHP-Seite, das per HTTP-Polling mit einem
Python-Agenten auf dem Raspberry Pi verbunden ist. Am Router sind keine Portfreigaben nötig,
WebSockets ebenfalls nicht. Als Zwischenspeicher dienen einfache Dateien.

```
Browser ─────────HTTPS──► api.php    ─┐                 ┌─ pi.php ◄──HTTPS── pi_agent.py ──► sshd (localhost)
Mac: ssh ⇄ pi_tunnel.py ─► client.php ┴► data/sessions/<id>/in.log, out.log ◄┘
```

Es gibt zwei Zugänge:

- **Browser:** ein Terminal mit Login-Prompt, ohne Installation.
- **Mac/PC:** echtes `ssh` mit `client/pi_tunnel.py` als ProxyCommand. Damit gehen auch `scp`,
  `rsync`, `sftp`, VS Code Remote-SSH und Port-Forwarding, Ende-zu-Ende verschlüsselt
  (siehe Abschnitt 4).

## 1. Webspace

1. Geheimnisse in eine eigene Datei, die Git ignoriert:
   `cp server/config.local.php.example server/config.local.php`. Dort eintragen:
   - `users`: Benutzername und Passwort-Hash
     (`php -r 'echo password_hash("MeinPasswort", PASSWORD_DEFAULT), "\n";'`)
   - `pi_token`: langer Zufallswert (`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`)

   [server/config.php](server/config.php) enthält nur Standardwerte und gehört ins Repository.
   Jeder Wert in `config.local.php` überschreibt den gleichnamigen Wert dort, auch einzelne
   `timing`-Einträge.
2. Den Inhalt von `server/` hochladen, **einschließlich `config.local.php`**, z. B. nach
   `https://deine-domain.de/pi-terminal/`.
3. Der Ordner `data/` muss für PHP beschreibbar sein.
   - Besser ist ein Ordner **außerhalb** des Web-Roots, eingestellt über `data_dir` in `config.php`.
   - `data/.htaccess` schützt den Ordner nur bei Apache. Prüfe deshalb im Browser, dass
     `…/data/access.log` mit **403** antwortet.

## 2. Raspberry Pi

```bash
sudo apt install python3-paramiko python3-cryptography
sudo useradd --system --home /opt/pi-agent --shell /usr/sbin/nologin piagent
sudo mkdir -p /opt/pi-agent && sudo cp pi/pi_agent.py pi/agent.ini.example /opt/pi-agent/
cd /opt/pi-agent && sudo cp agent.ini.example agent.ini && sudo nano agent.ini   # url, token, [e2e] secret
sudo chown -R root:piagent /opt/pi-agent && sudo chmod 640 agent.ini

# Test im Vordergrund:
sudo -u piagent python3 /opt/pi-agent/pi_agent.py /opt/pi-agent/agent.ini

# Als Dienst:
sudo cp pi/pi-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now pi-agent
journalctl -u pi-agent -f
```

Im Modus `mode = ssh` braucht der sshd auf dem Pi `PasswordAuthentication yes`
(oder `KbdInteractiveAuthentication yes`). Der Port 22 muss **nicht** nach außen offen sein.

### Ende-zu-Ende-Verschlüsselung des Web-Terminals

Das Web-Terminal ist zwischen Browser und Pi verschlüsselt. Der Webspace reicht nur
Chiffretext weiter und kann die Sitzung weder mitlesen noch unbemerkt verändern.

1. Einen **Terminal-Schlüssel** erzeugen: `python3 -c "import secrets; print(secrets.token_urlsafe(18))"`.
2. Ihn auf dem Pi in `agent.ini` unter `[e2e] secret` eintragen. **Nicht** auf den Webspace kopieren.
3. Im Browser fragt „Neue Sitzung“ einmal nach dem Schlüssel. Mit „Auf diesem Gerät merken“
   wird nur ein abgeleiteter Wert im Browser gespeichert. „Schlüssel vergessen“ löscht ihn.

Ohne `[e2e] secret` lehnt der Pi Web-Sitzungen ab. Einen Rückfall auf Klartext gibt es nicht.
Der SSH-Tunnel braucht den Schlüssel nicht, er ist durch SSH selbst verschlüsselt.

So funktioniert es (Details in [server/assets/e2e.js](server/assets/e2e.js)):
- Browser und Pi handeln pro Sitzung einen Schlüssel per ECDH (P-256) aus.
- Dieser wird per HKDF mit dem Terminal-Schlüssel verknüpft (PBKDF2, 600 000 Runden).
- Der Pi beweist per HMAC, dass er den Terminal-Schlüssel kennt.
- Die Daten sind mit AES-256-GCM verschlüsselt, mit fortlaufender Nonce.
- Dadurch werden ein falscher Schlüssel, ein Server, der sich dazwischenschaltet, und
  veränderte, wiederholte oder umsortierte Daten erkannt.

## 3. Zeitabstände (`timing` in config.php)

Alle Werte stellst du an einer Stelle ein (Standardwerte in `config.php`, eigene Werte am besten in `config.local.php`). Der Pi übernimmt sie bei jedem Poll automatisch.

| Einstellung | Bedeutung |
|---|---|
| `browser_send_interval_ms` | Browser sammelt Tastendrücke so lange und speichert sie dann gemeinsam (→ `in.log`) |
| `pi_poll_pause_ms` | Pause des Pi zwischen zwei Abfragen nach Eingaben bzw. neuen Sitzungen |
| `pi_push_interval_ms` | Pi sammelt Shell-Ausgabe so lange und sendet sie dann gemeinsam (→ `out.log`) |
| `browser_poll_pause_ms` | Pause des Browsers zwischen zwei Abfragen nach neuer Ausgabe |
| `longpoll_timeout_s` | Server hält eine Abfrage bis zu X s offen, bis Daten da sind. `0` = aus |
| `longpoll_check_ms` | So oft prüft der Server während des Long-Polls die Dateien |

**Latenz pro Tastendruck**, ungefähr:

- **Mit Long-Polling:**
  `send_interval + 2 × check_ms + push_interval` plus die Netzlaufzeit.
  Mit den Standardwerten sind das etwa 150–300 ms.
- **Ohne Long-Polling** (`longpoll_timeout_s = 0`):
  Die Pausen bestimmen alles, im Mittel also `pi_poll_pause/2 + browser_poll_pause/2`.
  Dafür kommen viele kurze Anfragen auf den Server.

Long-Polling belegt pro wartendem Client einen PHP-Prozess (Pi + Browser = 2).
Falls dein Hoster Prozesse stark begrenzt oder lange Requests abbricht, setze
`longpoll_timeout_s` auf 5–10 oder auf 0.

## 4. Zugriff vom Mac/PC per SSH-Tunnel

Der Tunnel reicht die **rohen Bytes** der SSH-Verbindung durch. Der Webspace sieht also nur
verschlüsselte Daten, und am Pi meldest du dich ganz normal beim sshd an (am besten per Key).

1. **Server:** In `config.local.php` einen Token pro Gerät eintragen:
   ```php
   'client_tokens' => ['macbook' => '…langer Zufallswert…'],
   ```
2. **Pi:** In `agent.ini` steht der Abschnitt `[tunnel]`. Der Agent verbindet Tunnel **nur** mit
   `target` (Standard `127.0.0.1:22`), also nie mit anderen Geräten im Heimnetz.
3. **Mac:**
   ```bash
   mkdir -p ~/bin ~/.config
   cp client/pi_tunnel.py ~/bin/
   cp client/pi-tunnel.ini.example ~/.config/pi-tunnel.ini
   chmod 600 ~/.config/pi-tunnel.ini   # url (…/client.php) + token eintragen
   ```
   Dann in `~/.ssh/config` eintragen:
   ```
   Host pi-web
       User pi
       ProxyCommand python3 ~/bin/pi_tunnel.py
       ServerAliveInterval 30
   ```
   Nutzung:
   - `ssh pi-web`, `scp datei.txt pi-web:`, `rsync -av ordner/ pi-web:ordner/`
   - VS Code: „Remote-SSH: Connect to Host…“ → `pi-web`
   - Alternativ als lokaler Port: `python3 ~/bin/pi_tunnel.py --listen 2222`, dann `ssh -p 2222 pi@localhost`.
     Mit einer anderen Konfigurationsdatei: `python3 pi_tunnel.py pi-tunnel.ini --listen 2222`.
     Das klappt auch im ProxyCommand: `ProxyCommand python3 ~/bin/pi_tunnel.py ~/pi-zweiter.ini`.
   - Fehlersuche: `ProxyCommand python3 ~/bin/pi_tunnel.py -v`

   Den SSH-Key richtest du einmalig ein: `ssh-copy-id pi-web`.

**Gemessen** (lokal, ohne Internet-Laufzeit):
- Verbindungsaufbau etwa 1,4 s
- Tastendruck etwa 85–225 ms
- `scp` etwa 800 KB/s in beide Richtungen

Auf echtem Webspace kommt die Netzlaufzeit dazu.

### Tunnel nur mit SSH-Key, Web-Terminal weiter mit Passwort

Der Agent verbindet Tunnel von `127.0.0.2` aus (`source_address` in `agent.ini`), das
Web-Terminal von `127.0.0.1`. So kann sshd beide unterscheiden. In `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
KbdInteractiveAuthentication no

Match Address 127.0.0.1
    PasswordAuthentication yes
```

Danach `sudo systemctl restart ssh`. Damit gilt:
- Passwort-Login ist nur noch übers Web-Terminal möglich.
- Tunnel und direkter Zugriff im LAN funktionieren nur per Key.
- **Vorher** den eigenen Key mit `ssh-copy-id` hinterlegen!

## Sicherheit

- Web-Login mit Sperre pro IP und pro Benutzername (`login_max_attempts`, `login_lock_s`)
- CSRF-Token, `SameSite=Strict`-Cookie, CSP, Pi-Token im Header `X-Pi-Token`
- `mode = ssh`: Auch mit Zugriff auf den Webspace ist ohne Linux-Passwort keine Shell möglich.
  Der Host-Key wird gegen `/etc/ssh` geprüft.
- Bereits verarbeitete Ein- und Ausgaben werden sofort aus den Dateien gelöscht,
  getippte Passwörter bleiben also nicht liegen.
- Protokoll: `data/access.log`
- Tunnel: eigener Token pro Gerät, Sperre nach Fehlversuchen, festes Ziel auf dem Pi.
  Die Daten sind Ende-zu-Ende per SSH verschlüsselt.
- Web-Terminal: Ende-zu-Ende verschlüsselt (siehe oben). Der Server kann Sitzungen weder
  mitlesen noch Befehle einschleusen, auch nicht in bereits eingeloggte Sitzungen.
- **Grenze, die jede Verschlüsselung im Browser hat:** Das JavaScript kommt vom Webspace.
  Ein Angreifer, der **die Dateien auf dem Webspace verändert**, könnte eine manipulierte
  `e2e.js` ausliefern und den Terminal-Schlüssel beim Eintippen abgreifen.

  Geschützt bist du gegen:
  - Mitlesen von Daten, Logs und Backups beim Hoster
  - Angreifer, die nur die Datenablage lesen oder schreiben können
  - Einschleusen von Befehlen und Zurückstufen auf Klartext

  Für den höchsten Schutz nutze den **SSH-Tunnel** vom eigenen Rechner. Dort kommt kein
  Code vom Server.
