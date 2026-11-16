<?php
declare(strict_types=1);

// Direkter Aufruf dieser Datei ist nicht vorgesehen.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    http_response_code(404);
    exit;
}

// ============================================================================
//  Konfiguration & Grundfunktionen
// ============================================================================

function cfg(?string $key = null)
{
    static $c = null;
    if ($c === null) {
        $c = require __DIR__ . '/config.php';
        date_default_timezone_set($c['timezone'] ?? 'Europe/Berlin');
    }
    return $key === null ? $c : ($c[$key] ?? null);
}

function timing(): array
{
    $defaults = [
        'pi_poll_pause_ms' => 100, 'pi_push_interval_ms' => 50,
        'browser_send_interval_ms' => 30, 'browser_poll_pause_ms' => 100,
        'longpoll_timeout_s' => 20, 'longpoll_check_ms' => 40,
    ];
    $t = array_merge($defaults, (array)cfg('timing'));
    foreach ($t as $k => $v) {
        $t[$k] = max(0, (int)$v);
    }
    $t['longpoll_check_ms'] = max(10, $t['longpoll_check_ms']);
    return $t;
}

function data_dir(): string
{
    static $d = null;
    if ($d !== null) {
        return $d;
    }
    $d = rtrim((string)cfg('data_dir'), '/');
    if (!is_dir("$d/sessions") && !@mkdir("$d/sessions", 0700, true) && !is_dir("$d/sessions")) {
        json_out(['ok' => false, 'error' => 'Datenordner nicht beschreibbar: ' . $d], 500);
    }
    if (!is_file("$d/.htaccess")) {
        @file_put_contents("$d/.htaccess",
            "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" .
            "<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n");
        @file_put_contents("$d/index.html", '');
    }
    return $d;
}

function client_ip(): string
{
    // Absichtlich nur REMOTE_ADDR: X-Forwarded-For wäre fälschbar.
    return (string)($_SERVER['REMOTE_ADDR'] ?? '?');
}

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
}

function no_cache_headers(): void
{
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
}

function json_out(array $data, int $code = 200): void
{
    http_response_code($code);
    no_cache_headers();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function json_input(): array
{
    $raw = file_get_contents('php://input');
    $j = json_decode($raw ?: '', true);
    return is_array($j) ? $j : [];
}

function log_event(string $msg): void
{
    $line = sprintf("%s  %-15s  %s\n", date('Y-m-d H:i:s'), client_ip(), $msg);
    @file_put_contents(data_dir() . '/access.log', $line, FILE_APPEND | LOCK_EX);
}

/** Führt $fn exklusiv aus (flock auf $lockfile). */
function with_lock(string $lockfile, callable $fn)
{
    $fh = fopen($lockfile, 'c');
    if (!$fh) {
        throw new RuntimeException("Lock nicht möglich: $lockfile");
    }
    flock($fh, LOCK_EX);
    try {
        return $fn();
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

function read_json(string $file, $default)
{
    $s = @file_get_contents($file);
    if ($s === false || $s === '') {
        return $default;
    }
    $j = json_decode($s, true);
    return is_array($j) ? $j : $default;
}

/** Atomar schreiben (temp + rename), damit Leser nie halbe Dateien sehen. */
function write_json(string $file, array $data): void
{
    $tmp = $file . '.tmp' . bin2hex(random_bytes(4));
    file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES));
    rename($tmp, $file);
}

function b64e(string $s): string { return base64_encode($s); }
function b64d($s): string { return is_string($s) ? (string)base64_decode($s, true) : ''; }

// ============================================================================
//  Web-Login, Sperre nach Fehlversuchen, CSRF
// ============================================================================

function start_web_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $path = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/') . '/';
    session_name('SSHWEB');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => $path, 'secure' => is_https(),
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    ini_set('session.use_strict_mode', '1');
    session_start();
}

function current_user(): ?string
{
    start_web_session();
    $u = $_SESSION['user'] ?? null;
    if (!$u) {
        return null;
    }
    $lifetime = (int)(cfg('login_lifetime_s') ?? 43200);
    if (time() - (int)($_SESSION['login_time'] ?? 0) > $lifetime || !isset(cfg('users')[$u])) {
        $_SESSION = [];
        return null;
    }
    return $u;
}

function csrf_token(): string
{
    start_web_session();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function check_csrf(?string $given): bool
{
    start_web_session();
    return !empty($_SESSION['csrf']) && is_string($given) && hash_equals($_SESSION['csrf'], $given);
}

function verify_user_password(string $user, string $password): bool
{
    $users = (array)cfg('users');
    $stored = $users[$user] ?? null;
    if ($stored === null) {
        // Gleiche Rechenzeit wie bei existierenden Benutzern (kein User-Raten über Timing)
        password_verify($password, '$2y$12$NtoQ/pSHOZsodiq8uxGpJudAFbKxM7S2DX0RLAuGlRKDIEqwmA1XC');
        return false;
    }
    $stored = (string)$stored;
    if (preg_match('/^\$(2[aby]|argon2)/', $stored)) {
        return password_verify($password, $stored);
    }
    return hash_equals($stored, $password); // Klartext (nur für den Anfang)
}

function lockout_keys(string $user): array
{
    $keys = ['ip:' . client_ip()];
    if (cfg('login_lock_per_user') ?? true) {
        $keys[] = 'user:' . strtolower($user);
    }
    return $keys;
}

/** Restliche Sperrzeit in Sekunden (0 = nicht gesperrt). */
function lockout_remaining(array $keys): int
{
    $db = read_json(data_dir() . '/lockout.json', []);
    $rem = 0;
    foreach ($keys as $k) {
        $rem = max($rem, (int)($db[$k]['until'] ?? 0) - time());
    }
    return max(0, $rem);
}

function lockout_register(array $keys, bool $success): void
{
    $dir = data_dir();
    with_lock("$dir/lockout.lock", function () use ($dir, $keys, $success) {
        $db = read_json("$dir/lockout.json", []);
        $now = time();
        $window = (int)cfg('login_window_s');
        foreach ($db as $k => $e) { // Aufräumen
            $e['fails'] = array_values(array_filter($e['fails'] ?? [], fn($t) => $t > $now - $window));
            if (!$e['fails'] && ($e['until'] ?? 0) < $now) {
                unset($db[$k]);
            } else {
                $db[$k] = $e;
            }
        }
        foreach ($keys as $k) {
            if ($success) {
                unset($db[$k]);
                continue;
            }
            $db[$k]['fails'][] = $now;
            if (count($db[$k]['fails']) >= (int)cfg('login_max_attempts')) {
                $db[$k]['until'] = $now + (int)cfg('login_lock_s');
                $db[$k]['fails'] = [];
                log_event("LOGIN GESPERRT $k");
            }
        }
        write_json("$dir/lockout.json", $db);
    });
}

// ============================================================================
//  Terminal-Sitzungen (je Sitzung ein Ordner mit meta.json, in.log, out.log)
//
//  in.log  = Tastatureingaben Browser -> Pi
//  out.log = Bildschirmausgabe Pi -> Browser
//  Beide sind "Streams" mit absoluten Byte-Offsets. Bereits bestätigte Bytes
//  werden aus der Datei entfernt (meta.<name>_base merkt sich, wie viele), damit
//  z.B. eingetippte Passwörter nicht länger als nötig auf dem Webspace liegen.
//  Weil jeder Client mitsendet, ab welchem Offset seine Daten beginnen, sind
//  alle Anfragen wiederholbar, ohne Daten doppelt zu schreiben.
// ============================================================================

function sessions_dir(): string { return data_dir() . '/sessions'; }

function valid_session_id($id): bool
{
    return is_string($id) && preg_match('/^[a-f0-9]{32}$/', $id) === 1;
}

/**
 * Neue Sitzung anlegen.
 *   $kind  'terminal' = Browser-Terminal (Pi zeigt Login-Prompt bzw. Shell)
 *          'tcp'      = roher TCP-Tunnel zum sshd des Pi (pi_tunnel.py)
 *   $owner Wer die Sitzung bedienen darf (Hash der Web-Session bzw. "client:<name>")
 */
function session_create(string $user, string $owner, string $kind, int $cols, int $rows, array $extra = []): string
{
    $id = bin2hex(random_bytes(16));
    $dir = sessions_dir() . "/$id";
    mkdir($dir, 0700);
    touch("$dir/in.log");
    touch("$dir/out.log");
    $now = time();
    write_json("$dir/meta.json", [
        'id' => $id, 'kind' => $kind, 'user' => $user, 'ip' => client_ip(), 'owner' => $owner,
        'created' => $now, 'state' => 'open', 'agent' => null,
        'cols' => $cols, 'rows' => $rows, 'resize_seq' => 0,
        'browser_seen' => $now, 'last_input' => $now, 'closed_at' => null,
        'in_base' => 0, 'out_base' => 0,
    ] + $extra);
    return $id;
}

function session_owner(): string
{
    start_web_session();
    return hash('sha256', session_id());
}

/**
 * Führt $fn(string $dir, array &$meta) unter der Sitzungs-Sperre aus.
 * Änderungen an $meta werden gespeichert. Rückgabe: Ergebnis von $fn,
 * oder null, wenn es die Sitzung nicht (mehr) gibt.
 */
function with_session(string $id, callable $fn)
{
    if (!valid_session_id($id)) {
        return null;
    }
    $dir = sessions_dir() . "/$id";
    if (!is_dir($dir)) {
        return null;
    }
    $fh = @fopen("$dir/lock", 'c');
    if (!$fh) {
        return null;
    }
    flock($fh, LOCK_EX);
    try {
        $meta = read_json("$dir/meta.json", null);
        if (!$meta) {
            return null;
        }
        $orig = $meta;
        $res = $fn($dir, $meta);
        if ($meta !== $orig) {
            write_json("$dir/meta.json", $meta);
        }
        return $res;
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

function session_ids(): array
{
    $ids = [];
    foreach ((array)@scandir(sessions_dir()) as $f) {
        if (valid_session_id($f)) {
            $ids[] = $f;
        }
    }
    return $ids;
}

function session_meta(string $id): ?array
{
    return valid_session_id($id) ? read_json(sessions_dir() . "/$id/meta.json", null) : null;
}

function session_delete(string $id): void
{
    if (!valid_session_id($id)) {
        return;
    }
    $dir = sessions_dir() . "/$id";
    foreach ((array)@scandir($dir) as $f) {
        if ($f !== '.' && $f !== '..') {
            @unlink("$dir/$f");
        }
    }
    @rmdir($dir);
}

function stream_size(string $dir, array $meta, string $name): int
{
    $f = "$dir/$name.log";
    clearstatcache(true, $f);
    return (int)($meta[$name . '_base'] ?? 0) + (is_file($f) ? (int)filesize($f) : 0);
}

/** Hängt $data an, das beim absoluten Offset $offset beginnt. Liefert neue Größe. */
function stream_append(string $dir, array &$meta, string $name, int $offset, string $data): int
{
    $size = stream_size($dir, $meta, $name);
    $skip = $size - $offset;              // schon vorhandene Bytes (Wiederholung)
    if ($skip < 0) {
        $skip = 0;                        // Lücke: Client synchronisiert sich neu
    }
    if ($skip < strlen($data)) {
        $part = substr($data, $skip);
        file_put_contents("$dir/$name.log", $part, FILE_APPEND);
        $size += strlen($part);
    }
    return $size;
}

/**
 * Bestätigt alles bis $ack (löscht es) und liefert Daten ab $ack.
 * Rückgabe: [daten, neuer_offset, gesamtgröße]
 */
function stream_take(string $dir, array &$meta, string $name, int $ack, int $max): array
{
    $f = "$dir/$name.log";
    $base = (int)($meta[$name . '_base'] ?? 0);
    $size = stream_size($dir, $meta, $name);
    $ack = max($base, min($ack, $size));
    if ($ack > $base) {
        $rest = (string)@file_get_contents($f, false, null, $ack - $base);
        file_put_contents($f, $rest);
        $meta[$name . '_base'] = $ack;
    }
    $data = $size > $ack ? (string)@file_get_contents($f, false, null, 0, $max) : '';
    return [$data, $ack + strlen($data), $size];
}

/**
 * Hinweistext ins Terminal schreiben – nur bei unverschlüsselten Terminals.
 * In einen TCP-Tunnel oder einen Ende-zu-Ende-verschlüsselten Datenstrom darf
 * der Server nichts einfügen (das würde ihn verfälschen; der Browser zeigt
 * "Sitzung beendet" dann selbst an).
 */
function session_notice(string $dir, array &$meta, string $msg): void
{
    if (($meta['kind'] ?? 'terminal') === 'terminal' && empty($meta['e2e_pub'])) {
        stream_append($dir, $meta, 'out', stream_size($dir, $meta, 'out'), "\r\n\x1b[33m[$msg]\x1b[0m\r\n");
    }
}

function session_close_with_message(string $dir, array &$meta, string $msg): void
{
    if ($meta['state'] !== 'closed') {
        session_notice($dir, $meta, $msg);
        $meta['state'] = 'closed';
        $meta['closed_at'] = time();
    }
}

/** Räumt verwaiste/abgelaufene Sitzungen auf. */
function sessions_cleanup(): void
{
    $now = time();
    $bt = (int)cfg('browser_timeout_s');
    $idle = (int)cfg('idle_timeout_s');
    foreach (session_ids() as $id) {
        $delete = with_session($id, function (string $dir, array &$m) use ($now, $bt, $idle) {
            if ($m['state'] === 'closed') {
                return $now - (int)$m['closed_at'] > $bt;
            }
            if ($now - (int)$m['browser_seen'] > 2 * $bt) {
                return true;                         // Browser und Pi weg
            }
            $idleLimit = ($m['kind'] ?? 'terminal') === 'tcp' ? (int)cfg('tunnel_idle_timeout_s') : $idle;
            if ($m['state'] === 'open' && $now - (int)$m['browser_seen'] > $bt) {
                $m['state'] = 'closing';             // Browser/Client weg -> Pi soll schließen
                log_event("SITZUNG $m[id] Client-Timeout");
            } elseif ($m['state'] === 'open' && $idleLimit > 0 && $now - (int)$m['last_input'] > $idleLimit) {
                session_notice($dir, $m, 'Zeitüberschreitung wegen Inaktivität');
                $m['state'] = 'closing';
                log_event("SITZUNG $m[id] Inaktivitäts-Timeout");
            }
            return false;
        });
        if ($delete) {
            session_delete($id);
        }
    }
}

// ============================================================================
//  Pi-Status & Long-Polling
// ============================================================================

function pi_heartbeat(): void
{
    @touch(data_dir() . '/pi_seen');
}

function pi_online(): bool
{
    $f = data_dir() . '/pi_seen';
    clearstatcache(true, $f);
    return is_file($f) && time() - filemtime($f) < timing()['longpoll_timeout_s'] + 15;
}

/**
 * Ruft $check() wiederholt auf, bis es etwas anderes als null liefert oder
 * longpoll_timeout_s abgelaufen ist. Ohne $wait bzw. mit Timeout 0: genau einmal.
 */
function longpoll(callable $check, bool $wait = true)
{
    $t = timing();
    $timeout = $wait ? $t['longpoll_timeout_s'] : 0;
    if ($timeout > 0) {
        @set_time_limit($timeout + 15);
    }
    $end = microtime(true) + $timeout;
    while (true) {
        $r = $check(microtime(true) >= $end);
        if ($r !== null) {
            return $r;
        }
        usleep($t['longpoll_check_ms'] * 1000);
        clearstatcache();
    }
}

// ============================================================================
//  Gemeinsame Sitzungs-Operationen für Browser (api.php) und Client (client.php)
// ============================================================================

/** Führt $fn nur aus, wenn die Sitzung $owner gehört; merkt sich "Client lebt noch". */
function session_for_owner(string $id, string $owner, callable $fn)
{
    return with_session($id, function (string $dir, array &$m) use ($owner, $fn) {
        if (!hash_equals((string)$m['owner'], $owner)) {
            return null;
        }
        $m['browser_seen'] = time();
        return $fn($dir, $m);
    });
}

function count_open_sessions(string $kind): int
{
    $n = 0;
    foreach (session_ids() as $sid) {
        $m = session_meta($sid);
        if ($m && $m['state'] !== 'closed' && ($m['kind'] ?? 'terminal') === $kind) {
            $n++;
        }
    }
    return $n;
}

const SESSION_GONE = ['gone' => true, 'state' => 'closed', 'data' => '', 'offset' => 0];

/** Eingabe anhängen (ab absolutem Offset, wiederholbar). */
function op_send(string $id, string $owner, array $in): array
{
    $data = b64d($in['data'] ?? '');
    $r = session_for_owner($id, $owner, function (string $dir, array &$m) use ($in, $data) {
        if ($m['state'] !== 'open') {
            return ['offset' => stream_size($dir, $m, 'in'), 'state' => $m['state']];
        }
        if ($data !== '') {
            $m['last_input'] = time();
        }
        return ['offset' => stream_append($dir, $m, 'in', (int)($in['offset'] ?? 0), $data), 'state' => $m['state']];
    });
    return $r ?? SESSION_GONE;
}

/** Ausgabe abholen (Long-Poll). Bestätigt alles bis $in['offset']. */
function op_recv(string $id, string $owner, array $in): array
{
    $ack = (int)($in['offset'] ?? 0);
    $max = (int)cfg('max_chunk_bytes');
    $first = true;
    $r = longpoll(function (bool $final) use ($id, $owner, $ack, $max, &$first) {
        $fn = function (string $dir, array &$m) use ($ack, $max, $final) {
            [$data, $off, $size] = stream_take($dir, $m, 'out', $ack, $max);
            $done = $m['state'] === 'closed' && $off >= $size;
            if ($data === '' && !$done && !$final) {
                return false;                           // weiter warten
            }
            return ['data' => b64e($data), 'offset' => $off, 'state' => $done ? 'closed' : $m['state'],
                    'pi_seen' => $m['agent'] !== null];
        };
        // "Client lebt" nur beim ersten Durchlauf schreiben (spart Schreibzugriffe)
        $res = $first ? session_for_owner($id, $owner, $fn) : with_session($id, $fn);
        $first = false;
        if ($res === null) {
            return SESSION_GONE;
        }
        return $res === false ? null : $res;
    }, !empty($in['wait']));
    if (empty($r['gone']) && $r['state'] === 'closed') {
        session_delete($id);                            // alles gelesen -> aufräumen
    }
    return $r;
}

function op_close(string $id, string $owner): array
{
    $r = session_for_owner($id, $owner, function (string $dir, array &$m) {
        if ($m['state'] === 'open') {
            $m['state'] = 'closing';
            log_event("SITZUNG $m[id] vom Client geschlossen");
        }
        return true;
    });
    return $r === null ? SESSION_GONE : [];
}

// ============================================================================
//  Client-Token (pi_tunnel.py)
// ============================================================================

/** Liefert den Namen des Clients zum Token oder null. */
function client_name_for_token(string $given): ?string
{
    $found = null;
    foreach ((array)cfg('client_tokens') as $name => $token) {
        $token = (string)$token;
        // Alle Einträge prüfen (gleichbleibende Laufzeit), zu kurze Tokens ignorieren
        if (strlen($token) >= 16 && !str_starts_with($token, 'BITTE-ERSETZEN') && hash_equals($token, $given)) {
            $found = (string)$name;
        }
    }
    return $found;
}
