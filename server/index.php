<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';

start_web_session();
no_cache_headers();
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
// Nur Skripte vom eigenen Server: fremder Code (z.B. ein CDN) könnte sonst den
// Terminal-Schlüssel abgreifen und die Ende-zu-Ende-Verschlüsselung aushebeln.
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    . "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");

$error = null;
$action = $_POST['action'] ?? '';

if ($action === 'login') {
    $u = trim((string)($_POST['user'] ?? ''));
    $p = (string)($_POST['password'] ?? '');
    $keys = lockout_keys($u);
    if (!check_csrf($_POST['csrf'] ?? null)) {
        $error = 'Formular abgelaufen – bitte erneut versuchen.';
    } elseif (($rem = lockout_remaining($keys)) > 0) {
        $error = sprintf('Zu viele Fehlversuche. Gesperrt für %d Min.', (int)ceil($rem / 60));
        log_event("LOGIN ABGELEHNT (gesperrt) $u");
    } elseif (verify_user_password($u, $p)) {
        lockout_register($keys, true);
        session_regenerate_id(true);
        $_SESSION = ['user' => $u, 'login_time' => time(), 'csrf' => bin2hex(random_bytes(32))];
        log_event("LOGIN OK $u");
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'), true, 303);
        exit;
    } else {
        lockout_register($keys, false);
        log_event("LOGIN FEHLER $u");
        sleep(1);
        $error = 'Benutzername oder Passwort falsch.';
    }
} elseif ($action === 'logout' && check_csrf($_POST['csrf'] ?? null)) {
    log_event('LOGOUT ' . ($_SESSION['user'] ?? '?'));
    $_SESSION = [];
    session_regenerate_id(true);
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'), true, 303);
    exit;
}

if (!cfg('users') && $error === null) {
    $error = 'Keine Benutzer konfiguriert: config.local.php anlegen (siehe config.local.php.example).';
}

$user = current_user();
$csrf = csrf_token();
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
// Versionsnummer an Asset-URLs: nach einem Update lädt der Browser die neue Datei statt der aus dem Cache
$asset = fn(string $f) => $h("assets/$f?v=" . (@filemtime(__DIR__ . "/assets/$f") ?: 0));
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Pi Terminal</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="<?= $asset('style.css') ?>">
<?php if ($user): ?>
<link rel="stylesheet" href="<?= $asset('vendor/xterm/xterm.css') ?>">
<?php endif; ?>
</head>
<body>
<?php if (!$user): ?>
  <main class="login">
    <form method="post" autocomplete="on">
      <h1>Pi Terminal</h1>
      <?php if ($error): ?><p class="error"><?= $h($error) ?></p><?php endif; ?>
      <label>Benutzer <input name="user" autocomplete="username" required autofocus></label>
      <label>Passwort <input name="password" type="password" autocomplete="current-password" required></label>
      <input type="hidden" name="action" value="login">
      <input type="hidden" name="csrf" value="<?= $h($csrf) ?>">
      <button type="submit">Anmelden</button>
    </form>
  </main>
<?php else: ?>
  <header class="bar">
    <span class="title">Pi Terminal</span>
    <span id="pi-status" class="status unknown">Pi: ?</span>
    <span id="sess-status" class="status">keine Sitzung</span>
    <span class="spacer"></span>
    <button id="btn-new" type="button">Neue Sitzung</button>
    <button id="btn-close" type="button" disabled>Trennen</button>
    <button id="btn-forget" type="button" title="Gespeicherten Terminal-Schlüssel auf diesem Gerät löschen" disabled>Schlüssel vergessen</button>
    <form method="post" class="inline">
      <input type="hidden" name="action" value="logout">
      <input type="hidden" name="csrf" value="<?= $h($csrf) ?>">
      <button type="submit" title="Angemeldet als <?= $h($user) ?>">Abmelden</button>
    </form>
  </header>
  <div id="terminal"></div>
  <dialog id="keydlg">
    <form method="dialog">
      <h2>Terminal-Schlüssel</h2>
      <p>Der Schlüssel aus <code>[e2e] secret</code> in der <code>agent.ini</code> des Pi.
         Er verlässt diesen Browser nie – der Webserver kann die Sitzung dadurch weder
         mitlesen noch verändern.</p>
      <input id="key-input" type="password" autocomplete="off" spellcheck="false" aria-label="Terminal-Schlüssel">
      <label class="check"><input type="checkbox" id="key-remember"> Auf diesem Gerät merken</label>
      <div class="buttons">
        <button value="ok" class="primary">Verbinden</button>
        <button value="cancel" formnovalidate>Abbrechen</button>
      </div>
    </form>
  </dialog>
  <script id="cfg" type="application/json"><?= json_encode(['csrf' => $csrf, 'timing' => timing()], JSON_HEX_TAG | JSON_HEX_AMP) ?></script>
  <!-- xterm.js 5.5.0 / addon-fit 0.10.0 (MIT), lokal mitgeliefert: assets/vendor/xterm/ -->
  <script src="<?= $asset('vendor/xterm/xterm.js') ?>"></script>
  <script src="<?= $asset('vendor/xterm/addon-fit.js') ?>"></script>
  <script src="<?= $asset('e2e.js') ?>"></script>
  <script src="<?= $asset('terminal.js') ?>"></script>
<?php endif; ?>
</body>
</html>
