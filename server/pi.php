<?php
declare(strict_types=1);
// ============================================================================
//  Schnittstelle für den Pi-Agenten (Authentifizierung über X-Pi-Token).
//    POST pi.php?action=poll   Eingaben / neue Sitzungen / Resize abholen
//    POST pi.php?action=push   Shell-Ausgabe abliefern
// ============================================================================
require __DIR__ . '/lib.php';

$token = (string)cfg('pi_token');
if (strlen($token) < 16 || str_starts_with($token, 'BITTE-ERSETZEN')) {
    json_out(['ok' => false, 'error' => 'pi_token in config.local.php nicht gesetzt (mind. 16 Zeichen)'], 500);
}
// Eigener Header statt "Authorization", weil manche Shared-Hoster diesen verwerfen.
if (!hash_equals($token, (string)($_SERVER['HTTP_X_PI_TOKEN'] ?? ''))) {
    usleep(500000);
    json_out(['ok' => false, 'error' => 'Token ungültig'], 403);
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    json_out(['ok' => false, 'error' => 'POST erwartet'], 405);
}

pi_heartbeat();
$in = json_input();
$agent = (string)($in['agent_id'] ?? '');
if (!preg_match('/^[A-Za-z0-9_-]{8,64}$/', $agent)) {
    json_out(['ok' => false, 'error' => 'agent_id fehlt'], 400);
}
$max = (int)cfg('max_chunk_bytes');

switch ($_GET['action'] ?? '') {

    // ------------------------------------------------------------------------
    case 'poll':
        sessions_cleanup();
        $known = is_array($in['sessions'] ?? null) ? $in['sessions'] : [];
        $wait = !empty($in['wait']);
        // Der zuletzt pollende Agent ist der aktuelle. Ein noch hängender Long-Poll
        // eines früheren Agent-Laufs (Neustart, Netzabbruch) darf nichts übernehmen.
        $agentFile = data_dir() . '/agent_current';
        if (@file_get_contents($agentFile) !== $agent) {
            file_put_contents($agentFile, $agent, LOCK_EX);
            log_event("Pi-Agent verbunden ($agent)");
        }

        $result = longpoll(function (bool $final) use ($known, $agent, $max, $agentFile) {
            if (@file_get_contents($agentFile) !== $agent) {
                return [];                               // veraltet -> sofort beenden
            }
            $list = [];
            $changed = false;
            $seen = [];
            foreach (session_ids() as $id) {
                $entry = with_session($id, function (string $dir, array &$m) use ($id, $known, $agent, $max, &$changed) {
                    if ($m['state'] === 'closed') {
                        return false;
                    }
                    if ($m['agent'] === null) {
                        if ($m['state'] !== 'open') {    // geschlossen, bevor der Pi sie sah
                            $m['state'] = 'closed';
                            $m['closed_at'] = time();
                            return false;
                        }
                        $m['agent'] = $agent;            // Sitzung übernehmen
                        log_event("SITZUNG $id vom Pi übernommen");
                    } elseif ($m['agent'] !== $agent) {
                        // Gehörte zu einem früheren Lauf des Agenten (Neustart)
                        session_close_with_message($dir, $m, 'Pi-Agent wurde neu gestartet – Sitzung beendet');
                        return false;
                    }
                    $k = is_array($known[$id] ?? null) ? $known[$id] : null;
                    [$data, $newOff] = stream_take($dir, $m, 'in', (int)($k['in_offset'] ?? 0), $max);
                    if ($k === null || $data !== '' || $m['state'] === 'closing'
                        || (int)($k['resize_seq'] ?? -1) !== (int)$m['resize_seq']) {
                        $changed = true;
                    }
                    return [
                        'id' => $id, 'kind' => $m['kind'] ?? 'terminal',
                        'e2e_pub' => $m['e2e_pub'] ?? null,
                        'state' => $m['state'], 'user' => $m['user'],
                        'cols' => $m['cols'], 'rows' => $m['rows'], 'resize_seq' => $m['resize_seq'],
                        'in' => b64e($data), 'in_offset' => $newOff,
                        'out_offset' => stream_size($dir, $m, 'out'),
                    ];
                });
                if ($entry) {
                    $list[] = $entry;
                    $seen[$entry['id']] = true;
                }
            }
            foreach (array_keys($known) as $id) {
                if (!isset($seen[$id])) {
                    $changed = true;                     // Sitzung verschwunden
                }
            }
            return ($changed || $final) ? $list : null;
        }, $wait);

        json_out(['ok' => true, 'timing' => timing(), 'sessions' => $result,
                  'superseded' => @file_get_contents($agentFile) !== $agent]);

    // ------------------------------------------------------------------------
    case 'push':
        $out = [];
        foreach ((array)($in['sessions'] ?? []) as $id => $s) {
            $id = (string)$id;
            $r = with_session($id, function (string $dir, array &$m) use ($s, $agent, $id) {
                if ($m['agent'] !== $agent || $m['state'] === 'closed') {
                    return ['gone' => true];
                }
                $size = stream_append($dir, $m, 'out', (int)($s['offset'] ?? 0), b64d($s['data'] ?? ''));
                $delete = false;
                if (!empty($s['closed'])) {
                    // Tunnel, dessen Client schon "close" geschickt hat: liest niemand mehr -> gleich löschen
                    $delete = ($m['kind'] ?? 'terminal') === 'tcp' && $m['state'] === 'closing';
                    $m['state'] = 'closed';
                    $m['closed_at'] = time();
                    log_event("SITZUNG $id beendet (Pi)");
                }
                return ['out_offset' => $size, 'delete' => $delete];
            });
            if (!empty($r['delete'])) {
                session_delete($id);
            }
            unset($r['delete']);
            $out[$id] = $r ?? ['gone' => true];
        }
        json_out(['ok' => true, 'sessions' => (object)$out]);

    default:
        json_out(['ok' => false, 'error' => 'Unbekannte Aktion'], 400);
}
