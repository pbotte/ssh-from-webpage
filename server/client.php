<?php
declare(strict_types=1);
// ============================================================================
//  Schnittstelle für pi_tunnel.py (SSH-Tunnel vom Mac/PC zum sshd des Pi).
//  Authentifizierung über X-Client-Token (client_tokens in config.local.php).
//    open | send | recv | close
//
//  Die Daten sind die rohen Bytes der SSH-Verbindung, also Ende-zu-Ende
//  verschlüsselt zwischen deinem ssh-Client und dem sshd des Pi.
// ============================================================================
require __DIR__ . '/lib.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_out(['ok' => false, 'error' => 'POST erwartet'], 405);
}
if (!cfg('client_tokens')) {
    json_out(['ok' => false, 'error' => 'Tunnel deaktiviert (client_tokens in config.local.php leer)'], 403);
}

// Sperre nach Fehlversuchen (gleiche Grenzwerte wie beim Web-Login)
$lockKeys = ['client-ip:' . client_ip()];
if (($rem = lockout_remaining($lockKeys)) > 0) {
    json_out(['ok' => false, 'error' => "Zu viele Fehlversuche, gesperrt für $rem s"], 429);
}
$name = client_name_for_token((string)($_SERVER['HTTP_X_CLIENT_TOKEN'] ?? ''));
if ($name === null) {
    lockout_register($lockKeys, false);
    log_event('CLIENT-TOKEN UNGÜLTIG');
    usleep(500000);
    json_out(['ok' => false, 'error' => 'Client-Token ungültig'], 403);
}

$owner = 'client:' . $name;
$in = json_input();
$id = (string)($in['id'] ?? '');

switch ($_GET['action'] ?? '') {

    case 'open':
        sessions_cleanup();
        if (!pi_online()) {
            json_out(['ok' => false, 'error' => 'Pi ist offline'], 503);
        }
        if (count_open_sessions('tcp') >= (int)cfg('max_tunnels')) {
            json_out(['ok' => false, 'error' => 'Zu viele offene Tunnel (max_tunnels)'], 429);
        }
        $sid = session_create($owner, $owner, 'tcp', 80, 24);
        log_event("TUNNEL $sid geöffnet von $owner");
        json_out(['ok' => true, 'id' => $sid, 'timing' => timing()]);

    case 'send':
        json_out(['ok' => true] + op_send($id, $owner, $in));

    case 'recv':
        json_out(['ok' => true] + op_recv($id, $owner, $in));

    case 'close':
        json_out(['ok' => true] + op_close($id, $owner));

    default:
        json_out(['ok' => false, 'error' => 'Unbekannte Aktion'], 400);
}
