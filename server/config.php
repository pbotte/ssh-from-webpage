<?php
// ============================================================================
//  Konfiguration (Standardwerte, liegt im Git-Repository).
//
//  GEHEIMNISSE (Benutzer/Passwort-Hash, pi_token) NICHT hier eintragen, sondern
//  in config.local.php (wird von Git ignoriert):
//      cp config.local.php.example config.local.php
//  Jeder Wert aus config.local.php überschreibt den gleichnamigen Wert hier,
//  z.B. auch einzelne 'timing'-Einträge.
// ============================================================================
$config = [

    // ---- Web-Login (feste Werte) -> in config.local.php setzen ---------------
    'users' => [],

    // Sperre nach Fehlversuchen (gilt getrennt pro IP-Adresse und pro Benutzername)
    'login_max_attempts'   => 5,     // so viele Fehlversuche ...
    'login_window_s'       => 900,   // ... innerhalb dieses Zeitraums ...
    'login_lock_s'         => 900,   // ... sperren für diese Dauer (Sekunden)
    // Auch pro Benutzername sperren? Schützt gegen verteiltes Raten, erlaubt aber
    // Fremden, deinen Login vorübergehend zu sperren. false = nur pro IP.
    'login_lock_per_user'  => true,
    'login_lifetime_s'     => 43200, // Web-Login gilt max. 12 h

    // ---- Pi-Agent -> pi_token in config.local.php setzen -----------------------
    'pi_token' => '',

    // ---- Zeitabstände (hier zentral einstellen; der Pi übernimmt sie automatisch)
    'timing' => [
        // Pi: Pause zwischen zwei Abfragen nach Eingaben/neuen Sitzungen ("poll")
        'pi_poll_pause_ms'         => 100,
        // Pi: Shell-Ausgabe so lange sammeln, dann in einem Request senden ("push")
        'pi_push_interval_ms'      => 50,
        // Browser: Tastendrücke so lange sammeln, dann senden (-> in Datei speichern)
        'browser_send_interval_ms' => 30,
        // Browser: Pause zwischen zwei Abfragen nach neuer Ausgabe
        'browser_poll_pause_ms'    => 100,
        // Long-Polling: Server hält eine Anfrage bis zu X s offen, bis Daten da sind.
        // Senkt die Latenz stark. 0 = aus (dann bestimmen nur die Pausen die Latenz).
        // Muss kleiner als max_execution_time des Hosters sein (meist 30 s).
        'longpoll_timeout_s'       => 20,
        // Long-Polling: so oft prüft der Server die Dateien auf Änderungen
        'longpoll_check_ms'        => 40,
    ],

    // ---- SSH-Tunnel für Mac/PC (client/pi_tunnel.py) ----------------------------
    // Name => Token, in config.local.php setzen. Leer = Tunnel deaktiviert.
    'client_tokens'         => [],
    'max_tunnels'           => 4,     // gleichzeitige Tunnel-Verbindungen
    'tunnel_idle_timeout_s' => 7200,  // ohne Daten vom Client so lange -> schließen
                                      // (ssh: ServerAliveInterval hält ihn offen)

    // ---- Sitzungen ------------------------------------------------------------
    'max_sessions'        => 3,     // gleichzeitige Terminal-Sitzungen
    'browser_timeout_s'   => 60,    // Browser meldet sich so lange nicht -> Sitzung schließen
    'idle_timeout_s'      => 1800,  // keine Eingabe so lange -> Sitzung schließen
    'max_chunk_bytes'     => 262144,// max. Datenmenge pro Antwort

    // ---- Ablage ----------------------------------------------------------------
    // Am besten AUSSERHALB des Web-Roots, falls der Hoster das erlaubt, z.B.
    // __DIR__ . '/../ssh-data'. Sonst schützt data/.htaccess den Ordner (nur Apache!).
    'data_dir' => __DIR__ . '/data',
    'timezone' => 'Europe/Berlin',  // für Zeitstempel in data/access.log
];

// Lokale Einstellungen/Geheimnisse einmischen ('users' wird komplett ersetzt).
$local = __DIR__ . '/config.local.php';
if (is_file($local)) {
    $override = require $local;
    if (is_array($override)) {
        $users = $override['users'] ?? null;
        $config = array_replace_recursive($config, $override);
        if (is_array($users)) {
            $config['users'] = $users;
        }
    }
}
return $config;
