<?php
declare(strict_types=1);
// ============================================================================
//  Schnittstelle für das Browser-Terminal (Web-Login + CSRF-Token nötig).
//    status | open | send | recv | resize | close
// ============================================================================
require __DIR__ . '/lib.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_out(['ok' => false, 'error' => 'POST erwartet'], 405);
}
$user = current_user();
if ($user === null) {
    json_out(['ok' => false, 'error' => 'Nicht angemeldet'], 401);
}
$in = json_input();
// CSRF per Header; bei sendBeacon (Tab schließen) geht nur der Body.
if (!check_csrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($in['csrf'] ?? null))) {
    json_out(['ok' => false, 'error' => 'CSRF-Token ungültig'], 403);
}
$owner = session_owner();
// PHP-Sitzung sofort freigeben, sonst blockiert ein Long-Poll alle anderen Anfragen.
session_write_close();

$id = (string)($in['id'] ?? '');

switch ($_GET['action'] ?? '') {

    case 'status':
        sessions_cleanup();
        json_out(['ok' => true, 'pi_online' => pi_online()]);

    case 'open':
        sessions_cleanup();
        if (count_open_sessions('terminal') >= (int)cfg('max_sessions')) {
            json_out(['ok' => false, 'error' => 'Zu viele offene Sitzungen (max_sessions)'], 429);
        }
        $cols = max(20, min(500, (int)($in['cols'] ?? 80)));
        $rows = max(5, min(200, (int)($in['rows'] ?? 24)));
        // Öffentlicher ECDH-Schlüssel des Browsers (P-256, unkomprimiert = 65 Bytes).
        // Der Server reicht ihn nur weiter; der Pi besteht auf Verschlüsselung.
        $pub = b64d($in['e2e_pub'] ?? '');
        if (strlen($pub) !== 65 || $pub[0] !== "\x04") {
            json_out(['ok' => false, 'error' => 'Browser-Schlüssel für die Verschlüsselung fehlt oder ist ungültig'], 400);
        }
        $sid = session_create($user, $owner, 'terminal', $cols, $rows, ['e2e_pub' => base64_encode($pub)]);
        log_event("SITZUNG $sid geöffnet von $user");
        json_out(['ok' => true, 'id' => $sid, 'pi_online' => pi_online()]);

    case 'send':
        json_out(['ok' => true] + op_send($id, $owner, $in));

    case 'recv':
        json_out(['ok' => true] + op_recv($id, $owner, $in));

    case 'resize':
        $r = session_for_owner($id, $owner, function (string $dir, array &$m) use ($in) {
            $cols = max(20, min(500, (int)($in['cols'] ?? 80)));
            $rows = max(5, min(200, (int)($in['rows'] ?? 24)));
            if ($cols !== $m['cols'] || $rows !== $m['rows']) {
                $m['cols'] = $cols;
                $m['rows'] = $rows;
                $m['resize_seq']++;
            }
            return true;
        });
        json_out(['ok' => true] + ($r === null ? SESSION_GONE : []));

    case 'close':
        json_out(['ok' => true] + op_close($id, $owner));

    default:
        json_out(['ok' => false, 'error' => 'Unbekannte Aktion'], 400);
}
