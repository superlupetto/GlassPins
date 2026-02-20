<?php
declare(strict_types=1);

/**
 * GlassPins — SINGLE FILE (NO "Pin Tool")
 * - Pinterest-style feed + Liquid Glass UI
 * - Register / Login / Logout
 * - Dashboard (Bacheca) con creazione pin + preview
 * - Ogni utente loggato può creare pin
 * - Ogni utente può eliminare i propri pin; admin può eliminare tutti
 * - SQLite + uploads/
 *
 * URL:
 *   index.php                 -> feed
 *   index.php?register=1      -> crea account
 *   index.php?login=1         -> login
 *   index.php?dashboard=1     -> bacheca account (creazione pin qui)
 *   index.php?admin=1         -> admin panel (solo admin)
 */

session_start();

/* =========================
   CONFIG
========================= */
const UPLOAD_DIR = __DIR__ . '/uploads';
const DB_PATH    = __DIR__ . '/data.sqlite';
const MAX_UPLOAD_BYTES = 8 * 1024 * 1024; // 8MB

/* =========================
   URL HELPERS (ok anche in sottocartelle)
========================= */
function base_path(): string {
  $dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
  return $dir === '' ? '' : $dir;
}
function self_url(array $params = []): string {
  $base = base_path();
  $script = basename($_SERVER['SCRIPT_NAME'] ?? 'index.php');
  $q = http_build_query(array_filter($params, fn($v)=> $v !== null && $v !== ''));
  return ($base ? $base : '') . '/' . $script . ($q ? ('?' . $q) : '');
}

/* =========================
   HELPERS
========================= */
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function now_str(): string { return date('Y-m-d H:i'); }

function ensure_dirs(): void {
  if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0775, true);
}

function db(): PDO {
  static $pdo = null;
  if ($pdo instanceof PDO) return $pdo;

  $pdo = new PDO('sqlite:' . DB_PATH);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS pins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      description TEXT,
      tags TEXT,
      image_path TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  ");

  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pins_created ON pins(created_at);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pins_tags ON pins(tags);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_pins_user ON pins(user_id);");

  return $pdo;
}

function flash_set(string $msg, string $type='info'): void {
  $_SESSION['_flash'] = ['msg'=>$msg, 'type'=>$type];
}
function flash_get(): ?array {
  if (!isset($_SESSION['_flash'])) return null;
  $f = $_SESSION['_flash'];
  unset($_SESSION['_flash']);
  return is_array($f) ? $f : null;
}

function csrf_token(): string {
  if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(16));
  return (string)$_SESSION['_csrf'];
}
function csrf_check(?string $token): bool {
  return is_string($token) && isset($_SESSION['_csrf']) && hash_equals((string)$_SESSION['_csrf'], $token);
}

function normalize_username(string $raw): string {
  $u = trim($raw);
  $u = preg_replace('/\s+/', '', $u) ?? $u;
  return $u;
}

function current_user(): ?array {
  if (empty($_SESSION['uid'])) return null;
  $pdo = db();
  $st = $pdo->prepare("SELECT id, username, is_admin, created_at FROM users WHERE id=?");
  $st->execute([(int)$_SESSION['uid']]);
  $u = $st->fetch(PDO::FETCH_ASSOC);
  return $u ?: null;
}

function require_login(): array {
  $u = current_user();
  if (!$u) {
    flash_set("Devi fare login.", "warn");
    header("Location: " . self_url(['login'=>1]));
    exit;
  }
  return $u;
}

function require_admin(): array {
  $u = require_login();
  if ((int)$u['is_admin'] !== 1) {
    flash_set("Accesso negato: serve admin.", "warn");
    header("Location: " . self_url([]));
    exit;
  }
  return $u;
}

function parse_tags(string $raw): string {
  $parts = preg_split('/[,\s]+/', trim($raw)) ?: [];
  $parts = array_values(array_filter(array_map(fn($t)=> strtolower(trim((string)$t)), $parts)));
  $parts = array_slice(array_unique($parts), 0, 20);
  return implode(',', $parts);
}
function tags_array(?string $tagsCsv): array {
  if (!$tagsCsv) return [];
  $a = array_filter(array_map('trim', explode(',', $tagsCsv)));
  return array_values($a);
}

function safe_unlink_upload(string $publicPath): void {
  $path = __DIR__ . '/' . ltrim($publicPath, '/');
  $real = realpath($path);
  $upl  = realpath(UPLOAD_DIR);
  if ($real && $upl && str_starts_with($real, $upl) && is_file($real)) @unlink($real);
}

function mime_to_ext(string $mime): ?string {
  return match($mime){
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp',
    default      => null
  };
}

/* =========================
   INIT
========================= */
ensure_dirs();
$pdo   = db();
$flash = flash_get();
$u     = current_user();

/* =========================
   READ GET STATE
========================= */
$isRegister  = (($_GET['register'] ?? '') === '1');
$isLogin     = (($_GET['login'] ?? '') === '1');
$isDashboard = (($_GET['dashboard'] ?? '') === '1');
$isAdminPage = (($_GET['admin'] ?? '') === '1');

$q   = isset($_GET['q'])   ? trim((string)$_GET['q']) : '';
$tag = isset($_GET['tag']) ? trim((string)$_GET['tag']) : '';

/* =========================
   ACTIONS (POST)
========================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $action = (string)($_POST['action'] ?? '');
  $token  = (string)($_POST['_csrf'] ?? '');

  if (!csrf_check($token)) {
    flash_set("Sessione scaduta. Riprova.", "warn");
    header("Location: " . self_url([]));
    exit;
  }

  // REGISTER
  if ($action === 'register') {
    $username = normalize_username((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if ($username === '' || strlen($username) < 3) {
      flash_set("Username troppo corto (min 3).", "warn");
      header("Location: " . self_url(['register'=>1]));
      exit;
    }
    if (!preg_match('/^[a-zA-Z0-9_.-]{3,32}$/', $username)) {
      flash_set("Username non valido. Usa solo lettere/numeri/._- (3–32).", "warn");
      header("Location: " . self_url(['register'=>1]));
      exit;
    }
    if (strlen($password) < 6) {
      flash_set("Password troppo corta (min 6).", "warn");
      header("Location: " . self_url(['register'=>1]));
      exit;
    }

    $count = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $isAdminNew = ($count === 0) ? 1 : 0;

    try {
      $hash = password_hash($password, PASSWORD_DEFAULT);
      $st = $pdo->prepare("INSERT INTO users(username, password_hash, is_admin, created_at) VALUES(?,?,?,?)");
      $st->execute([$username, $hash, $isAdminNew, now_str()]);
      $_SESSION['uid'] = (int)$pdo->lastInsertId();

      flash_set($isAdminNew ? "Account creato! Sei ADMIN (primo utente)." : "Account creato! Benvenutə 👋", "ok");
      header("Location: " . self_url(['dashboard'=>1]));
      exit;
    } catch (Throwable $e) {
      flash_set("Username già usato. Prova un altro.", "warn");
      header("Location: " . self_url(['register'=>1]));
      exit;
    }
  }

  // LOGIN
  if ($action === 'login') {
    $username = normalize_username((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $st = $pdo->prepare("SELECT id, password_hash FROM users WHERE username=?");
    $st->execute([$username]);
    $row = $st->fetch(PDO::FETCH_ASSOC);

    if (!$row || !password_verify($password, (string)$row['password_hash'])) {
      flash_set("Login fallito. Controlla credenziali.", "warn");
      header("Location: " . self_url(['login'=>1]));
      exit;
    }

    $_SESSION['uid'] = (int)$row['id'];
    flash_set("Login ok ✨", "ok");
    header("Location: " . self_url(['dashboard'=>1]));
    exit;
  }

  // LOGOUT
  if ($action === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
      $params = session_get_cookie_params();
      setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
      );
    }
    session_destroy();
    session_start();
    flash_set("Logout effettuato.", "ok");
    header("Location: " . self_url([]));
    exit;
  }

  // CREATE PIN (logged users)
  if ($action === 'create_pin') {
    $cu = require_login();

    $title = trim((string)($_POST['title'] ?? ''));
    $desc  = trim((string)($_POST['description'] ?? ''));
    $tags  = parse_tags((string)($_POST['tags'] ?? ''));

    // return destination (dashboard o admin)
    $return = (string)($_POST['return'] ?? 'dashboard');
    $returnUrl = match($return){
      'admin' => self_url(['admin'=>1]),
      default => self_url(['dashboard'=>1]),
    };

    if ($title === '') {
      flash_set("Titolo obbligatorio.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    if (!isset($_FILES['photo']) || $_FILES['photo']['error'] !== UPLOAD_ERR_OK) {
      flash_set("Carica una foto valida.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $tmp  = $_FILES['photo']['tmp_name'];
    $size = (int)($_FILES['photo']['size'] ?? 0);
    if ($size <= 0 || $size > MAX_UPLOAD_BYTES) {
      flash_set("File troppo grande (max 8MB).", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($tmp) ?: '';
    $ext = mime_to_ext($mime);

    if (!$ext) {
      flash_set("Formato non supportato. Usa JPG/PNG/WEBP.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $name = 'pin_' . date('Ymd_His') . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
    $dest = UPLOAD_DIR . '/' . $name;

    if (!move_uploaded_file($tmp, $dest)) {
      flash_set("Upload fallito.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $publicPath = 'uploads/' . $name;

    $st = $pdo->prepare("INSERT INTO pins(user_id, title, author, description, tags, image_path, created_at) VALUES(?,?,?,?,?,?,?)");
    $st->execute([
      (int)$cu['id'],
      $title,
      (string)$cu['username'],
      $desc,
      $tags,
      $publicPath,
      now_str()
    ]);

    flash_set("Pin creato ✨", "ok");
    header("Location: " . $returnUrl);
    exit;
  }

  // DELETE PIN (own pins; admin any)
  if ($action === 'delete_pin') {
    $cu = require_login();
    $id = (int)($_POST['id'] ?? 0);

    $return = (string)($_POST['return'] ?? 'dashboard');
    $returnUrl = match($return){
      'admin' => self_url(['admin'=>1]),
      default => self_url(['dashboard'=>1]),
    };

    if ($id <= 0) {
      flash_set("ID non valido.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $st = $pdo->prepare("SELECT id, user_id, image_path FROM pins WHERE id=?");
    $st->execute([$id]);
    $pin = $st->fetch(PDO::FETCH_ASSOC);

    if (!$pin) {
      flash_set("Pin non trovato.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $isOwner = ((int)$pin['user_id'] === (int)$cu['id']);
    $isAdmin = ((int)$cu['is_admin'] === 1);

    if (!$isOwner && !$isAdmin) {
      flash_set("Non puoi eliminare questo pin.", "warn");
      header("Location: " . $returnUrl);
      exit;
    }

    $pdo->prepare("DELETE FROM pins WHERE id=?")->execute([$id]);
    if (!empty($pin['image_path'])) safe_unlink_upload((string)$pin['image_path']);

    flash_set("Pin eliminato.", "ok");
    header("Location: " . $returnUrl);
    exit;
  }

  flash_set("Azione sconosciuta.", "warn");
  header("Location: " . self_url([]));
  exit;
}

/* =========================
   PAGE GUARDS
========================= */
if ($isDashboard) $u = require_login();
if ($isAdminPage) $u = require_admin();

/* =========================
   FETCH PINS (feed)
========================= */
$where = [];
$params = [];

if ($q !== '') {
  $where[] = "(title LIKE :q OR author LIKE :q OR description LIKE :q OR tags LIKE :q)";
  $params[':q'] = '%' . $q . '%';
}
if ($tag !== '') {
  $where[] = "((',' || tags || ',') LIKE :tag)";
  $params[':tag'] = '%,' . $tag . ',%';
}

$sql = "SELECT * FROM pins";
if ($where) $sql .= " WHERE " . implode(" AND ", $where);
$sql .= " ORDER BY id DESC LIMIT 250";

$st = $pdo->prepare($sql);
$st->execute($params);
$pins = $st->fetchAll(PDO::FETCH_ASSOC);

// tag chips
$tagsUnique = [];
$all = $pdo->query("SELECT tags FROM pins")->fetchAll(PDO::FETCH_ASSOC);
foreach ($all as $r) foreach (tags_array($r['tags'] ?? '') as $t) $tagsUnique[$t] = true;
$allTags = array_keys($tagsUnique);
sort($allTags);

// dashboard: miei pin + stats
$myPins = [];
$myCount = 0;
$allCount = (int)$pdo->query("SELECT COUNT(*) FROM pins")->fetchColumn();
if ($u) {
  $st2 = $pdo->prepare("SELECT * FROM pins WHERE user_id=? ORDER BY id DESC LIMIT 250");
  $st2->execute([(int)$u['id']]);
  $myPins = $st2->fetchAll(PDO::FETCH_ASSOC);

  $stC = $pdo->prepare("SELECT COUNT(*) FROM pins WHERE user_id=?");
  $stC->execute([(int)$u['id']]);
  $myCount = (int)$stC->fetchColumn();
}

/* =========================
   RENDER HELPERS
========================= */
function pin_card(array $p, string $ctx = 'feed', ?array $user = null): void {
  $tags = tags_array($p['tags'] ?? '');
  $pinJson = json_encode([
    "id" => (int)$p['id'],
    "title" => (string)$p['title'],
    "author" => (string)$p['author'],
    "desc" => (string)($p['description'] ?? ''),
    "tags" => $tags,
    "image" => (string)$p['image_path'],
    "created_at" => (string)$p['created_at'],
  ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);

  $canDelete = false;
  if ($user) {
    $canDelete = ((int)$user['is_admin'] === 1) || ((int)$p['user_id'] === (int)$user['id']);
  }
  ?>
  <article class="pin glass" data-pin='<?= e($pinJson) ?>' tabindex="0" role="button" aria-label="Apri pin: <?= e((string)$p['title']) ?>">
    <div class="pinActions">
      <button class="iconBtn" type="button" data-action="open" aria-label="Apri">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M14 4h6v6m0-6l-7 7M10 20H4v-6m0 6l7-7" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </button>

      <?php if ($canDelete && ($ctx === 'dashboard' || $ctx === 'admin')): ?>
        <form method="post" class="miniForm" onsubmit="return confirm('Eliminare questo pin?');">
          <input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="delete_pin">
          <input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
          <input type="hidden" name="return" value="<?= e($ctx === 'admin' ? 'admin' : 'dashboard') ?>">
          <button class="iconBtn danger" type="submit" aria-label="Elimina">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M6 7h12M10 11v7m4-7v7M9 7l1-2h4l1 2M7 7l1 14h8l1-14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </button>
        </form>
      <?php endif; ?>
    </div>

    <div class="pinMedia">
      <img loading="lazy" src="<?= e((string)$p['image_path']) ?>" alt="<?= e((string)$p['title']) ?>">
      <div class="pinOverlay" aria-hidden="true"></div>
    </div>

    <div class="pinBody">
      <h3 class="pinTitle"><?= e((string)$p['title']) ?></h3>
      <div class="pinMeta">
        <span>di <strong style="font-weight:900; color: rgba(255,255,255,.86);"><?= e((string)$p['author']) ?></strong></span>
        <span style="color: rgba(255,255,255,.55); font-size: 11px;"><?= e((string)$p['created_at']) ?></span>
      </div>

      <?php if (!empty($tags)): ?>
        <div class="tagRow" aria-label="Tag">
          <?php foreach ($tags as $t): ?>
            <a class="tag" href="<?= e(self_url(['q'=>($_GET['q'] ?? ''), 'tag'=>$t])) ?>">#<?= e($t) ?></a>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </div>
  </article>
  <?php
}

?>
<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GlassPins</title>

  <style>
    :root{
      --bg0:#070A12; --bg1:#0B1020;
      --stroke: rgba(255,255,255,.16);
      --stroke2: rgba(255,255,255,.22);
      --txt: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.65);
      --muted2: rgba(255,255,255,.45);
      --shadow: 0 18px 55px rgba(0,0,0,.55);
      --glow: 0 0 0 1px rgba(255,255,255,.08), 0 12px 40px rgba(0,0,0,.55);
      --accent: rgba(160,196,255,1);
      --accent2: rgba(255,180,204,1);
      --ok: rgba(142,255,214,.95);
      --warn: rgba(255,208,122,.95);
      --bad: rgba(255,120,120,.95);
      --r: 20px; --r2: 26px;
      --blur: 18px; --blur2: 26px;
      --max: 1180px;
      --gap: 14px;
    }
    *{ box-sizing:border-box; }
    html,body{ height:100%; }
    body{
      margin:0; color:var(--txt);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      background:
        radial-gradient(1200px 800px at 20% -10%, rgba(160,196,255,.25), transparent 60%),
        radial-gradient(1000px 700px at 110% 10%, rgba(255,180,204,.18), transparent 60%),
        radial-gradient(900px 650px at 50% 120%, rgba(142,255,214,.12), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      overflow-x:hidden;
    }
    .bgFX{
      position:fixed; inset:0; pointer-events:none;
      background:
        radial-gradient(800px 500px at 30% 15%, rgba(255,255,255,.08), transparent 60%),
        radial-gradient(700px 420px at 80% 30%, rgba(255,255,255,.05), transparent 60%),
        radial-gradient(500px 340px at 50% 75%, rgba(255,255,255,.04), transparent 60%);
      mix-blend-mode: screen; opacity:.8;
      animation: floaty 14s ease-in-out infinite alternate;
    }
    @keyframes floaty{ 0%{transform:translate3d(0,0,0) scale(1);opacity:.70} 100%{transform:translate3d(0,-10px,0) scale(1.02);opacity:.95} }

    .wrap{ max-width:var(--max); margin:0 auto; padding:18px 14px 40px; }

    .glass{
      background: linear-gradient(180deg, rgba(255,255,255,.10), rgba(255,255,255,.06));
      border:1px solid var(--stroke);
      box-shadow: var(--glow);
      backdrop-filter: blur(var(--blur));
      -webkit-backdrop-filter: blur(var(--blur));
      border-radius: var(--r);
    }
    .glassStrong{
      background: linear-gradient(180deg, rgba(255,255,255,.14), rgba(255,255,255,.07));
      border:1px solid var(--stroke2);
      box-shadow: var(--shadow);
      backdrop-filter: blur(var(--blur2));
      -webkit-backdrop-filter: blur(var(--blur2));
      border-radius: var(--r2);
    }

    header{ position:sticky; top:0; z-index:30; margin:10px 0 16px; }
    .topbar{ display:grid; grid-template-columns:1fr; gap:10px; padding:12px; }
    @media(min-width:640px){ .topbar{ grid-template-columns: 1.1fr 1.4fr; align-items:center; } }

    .brand{ display:flex; align-items:center; gap:10px; padding:10px 12px; }
    .logo{
      width:38px; height:38px; border-radius:14px;
      background:
        radial-gradient(16px 16px at 30% 30%, rgba(255,255,255,.55), transparent 60%),
        radial-gradient(18px 18px at 70% 60%, rgba(255,255,255,.25), transparent 65%),
        linear-gradient(135deg, rgba(160,196,255,.95), rgba(255,180,204,.85));
      box-shadow:0 14px 40px rgba(0,0,0,.35);
      border:1px solid rgba(255,255,255,.22);
    }
    .brand h1{ margin:0; font-size:16px; letter-spacing:.3px; }
    .brand .sub{ display:block; font-size:12px; color:var(--muted); margin-top:2px; }

    .actionsRow{ display:grid; gap:10px; }
    @media(min-width:640px){ .actionsRow{ grid-template-columns: 1fr auto; align-items:center; } }
    .authRow{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:flex-end; }

    .searchRow{ display:flex; gap:10px; align-items:center; padding:10px 12px; flex-wrap: wrap; margin:0; }
    .search{
      display:flex; align-items:center; gap:10px; width:100%;
      padding:10px 12px; border-radius:16px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.22);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.06);
    }
    .search input{ width:100%; border:0; outline:none; color:var(--txt); background:transparent; font-size:14px; }

    .btn{
      border:0; cursor:pointer; color:var(--txt); font-weight:800;
      padding:10px 12px; border-radius:16px;
      background: rgba(255,255,255,.10);
      border:1px solid rgba(255,255,255,.16);
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
      transition: transform .15s ease, background .15s ease, border-color .15s ease;
      white-space:nowrap;
      text-decoration: none;
      display:inline-flex;
      align-items:center;
      gap:8px;
    }
    .btn:hover{ transform:translateY(-1px); background: rgba(255,255,255,.13); border-color: rgba(255,255,255,.22); }
    .btn:active{ transform:translateY(0) scale(.99); }
    .btnPrimary{
      background: linear-gradient(135deg, rgba(160,196,255,.85), rgba(255,180,204,.75));
      border:1px solid rgba(255,255,255,.24);
      color: rgba(10,12,18,.92);
    }
    .btnDanger{
      background: rgba(255,120,120,.12);
      border-color: rgba(255,120,120,.22);
    }

    .chips{
      display:flex; gap:10px; padding:0 12px 12px;
      overflow-x:auto; -webkit-overflow-scrolling:touch; scrollbar-width:none;
    }
    .chips::-webkit-scrollbar{ display:none; }
    .chip{
      flex:0 0 auto;
      padding:9px 12px; border-radius:999px;
      font-size:13px; color:var(--txt);
      background: rgba(0,0,0,.18);
      border:1px solid rgba(255,255,255,.14);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.06);
      text-decoration:none;
      transition: transform .15s ease, border-color .15s ease, background .15s ease;
      white-space: nowrap;
    }
    .chip:hover{ transform:translateY(-1px); border-color: rgba(255,255,255,.22); background: rgba(255,255,255,.08); }
    .chip.active{ background: linear-gradient(135deg, rgba(160,196,255,.35), rgba(255,180,204,.28)); border-color: rgba(255,255,255,.26); }

    .hero{ display:flex; justify-content:space-between; gap:14px; margin:14px 0; padding:14px; flex-wrap: wrap; }
    .hero h2{ margin:0 0 6px; font-size:18px; }
    .hero p{ margin:0; color:var(--muted); font-size:13px; line-height:1.35; max-width: 75ch; }

    .notice{
      padding: 12px 14px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(0,0,0,.18);
      color: rgba(255,255,255,.84);
      font-size: 13px;
      display:flex; align-items:center; gap:10px;
    }
    .badge{
      width:10px; height:10px; border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      box-shadow: 0 0 0 3px rgba(255,255,255,.08);
      flex: 0 0 auto;
    }
    .badge.ok{ background: var(--ok); }
    .badge.warn{ background: var(--warn); }
    .badge.bad{ background: var(--bad); }

    .masonry{ column-count:2; column-gap: var(--gap); width:100%; }
    @media(min-width:640px){ .masonry{ column-count:3; } }
    @media(min-width:980px){ .masonry{ column-count:4; } }

    .pin{ break-inside:avoid; margin:0 0 var(--gap); overflow:hidden; position:relative; transform:translateZ(0); transition: transform .18s ease, border-color .18s ease; }
    .pin:hover{ transform: translateY(-2px); border-color: rgba(255,255,255,.24); }
    .pinMedia{ position:relative; width:100%; aspect-ratio: 1/1.35; background: rgba(0,0,0,.24); overflow:hidden; border-bottom:1px solid rgba(255,255,255,.10); }
    .pinMedia img{ width:100%; height:100%; object-fit:cover; display:block; transform:scale(1.02); transition: transform .35s ease; filter:saturate(1.08) contrast(1.02); }
    .pin:hover .pinMedia img{ transform: scale(1.06); }
    .pinOverlay{ position:absolute; inset:0; background: linear-gradient(180deg, rgba(0,0,0,0) 55%, rgba(0,0,0,.55)); opacity:.95; pointer-events:none; }
    .pinBody{ padding:12px; display:flex; flex-direction:column; gap:8px; }
    .pinTitle{ margin:0; font-size:14px; line-height:1.2; }
    .pinMeta{ display:flex; align-items:center; justify-content:space-between; gap:10px; color:var(--muted); font-size:12px; }
    .tagRow{ display:flex; gap:8px; flex-wrap:wrap; }
    .tag{
      font-size:11px; color: rgba(255,255,255,.78);
      background: rgba(255,255,255,.08);
      border:1px solid rgba(255,255,255,.12);
      padding:6px 9px; border-radius:999px;
      text-decoration:none;
      transition: background .15s ease, border-color .15s ease, transform .15s ease;
    }
    .tag:hover{ background: rgba(255,255,255,.12); border-color: rgba(255,255,255,.20); transform: translateY(-1px); }

    .pinActions{ position:absolute; top:10px; right:10px; z-index:2; display:flex; gap:8px; align-items:center; }
    .iconBtn{
      width:40px; height:40px; border-radius:16px;
      border:1px solid rgba(255,255,255,.18);
      background: rgba(0,0,0,.20);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      display:grid; place-items:center;
      cursor:pointer;
      transition: transform .15s ease, background .15s ease, border-color .15s ease;
      box-shadow: 0 12px 30px rgba(0,0,0,.28);
      color: var(--txt);
    }
    .iconBtn:hover{ transform:translateY(-1px); border-color: rgba(255,255,255,.24); background: rgba(255,255,255,.10); }
    .iconBtn.danger{ background: rgba(255,120,120,.10); border-color: rgba(255,120,120,.20); }
    .miniForm{ margin:0; }

    .panel{ padding:14px; }
    .field{ display:flex; flex-direction:column; gap:6px; }
    .field label{ font-size:12px; color:var(--muted); }
    .field input, .field textarea{
      padding:10px 12px;
      border-radius: 16px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.22);
      color: var(--txt);
      outline:none;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.06);
      font-size: 14px;
    }
    .field textarea{ min-height: 96px; resize: vertical; }
    .row{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .mini{ font-size: 12px; color: var(--muted2); }
    .kv{ padding:8px 10px; border-radius:999px; background: rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.12); color: rgba(255,255,255,.74); }

    .grid2{ display:grid; grid-template-columns: 1fr; gap:14px; }
    @media(min-width:980px){ .grid2{ grid-template-columns: 1.1fr .9fr; } }

    .masonryTitle{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin: 8px 2px 10px; }
    .masonryTitle h3{ margin:0; font-size:14px; color: rgba(255,255,255,.86); }

    /* Modal */
    .modal{ position:fixed; inset:0; display:none; z-index:80; padding:14px; }
    .modal.open{ display:block; }
    .modalBg{ position:absolute; inset:0; background: rgba(0,0,0,.55); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); }
    .modalCard{ position:relative; margin:60px auto 0; max-width: 980px; overflow:hidden; display:grid; grid-template-columns:1fr; }
    @media(min-width:860px){ .modalCard{ grid-template-columns:1.2fr .9fr; margin-top:70px; } }
    .modalMedia{ background: rgba(0,0,0,.25); min-height:260px; border-bottom:1px solid rgba(255,255,255,.10); }
    @media(min-width:860px){ .modalMedia{ border-bottom:0; border-right:1px solid rgba(255,255,255,.10); } }
    .modalMedia img{ width:100%; height:100%; object-fit:cover; display:block; }
    .modalSide{ padding:14px; display:flex; flex-direction:column; gap:10px; }
    .modalTop{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px; }
    .modalTop h3{ margin:0; font-size:18px; line-height:1.15; }
    .modalClose{ width:44px; height:44px; border-radius:18px; border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.20); display:grid; place-items:center; cursor:pointer; transition: transform .15s ease, background .15s ease; color: var(--txt);}
    .modalClose:hover{ transform: translateY(-1px); background: rgba(255,255,255,.10); }
    .modalDesc{ margin:0; color: var(--muted); font-size:14px; line-height:1.45; }

    /* Preview */
    .previewBox{
      border-radius: 20px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.18);
      overflow:hidden;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.06);
    }
    .previewImg{
      width:100%;
      aspect-ratio: 1/1.1;
      background: rgba(0,0,0,.25);
      display:grid;
      place-items:center;
      color: rgba(255,255,255,.55);
      font-weight:800;
      border-bottom:1px solid rgba(255,255,255,.10);
    }
    .previewImg img{ width:100%; height:100%; object-fit:cover; display:block; }
    .previewBody{ padding:12px; display:flex; flex-direction:column; gap:8px; }

    @media (prefers-reduced-motion: reduce){
      *{ animation:none !important; transition:none !important; scroll-behavior:auto !important; }
    }
  </style>
</head>

<body>
  <div class="bgFX" aria-hidden="true"></div>

  <div class="wrap">
    <header class="glassStrong">
      <div class="topbar">
        <div class="brand">
          <div class="logo" aria-hidden="true"></div>
          <div>
            <h1>GlassPins <span class="sub">Bacheca • Liquid Glass • No Pin Tool</span></h1>
          </div>
        </div>

        <div class="actionsRow">
          <!-- SEARCH -->
          <form class="searchRow" method="get" action="<?= e(self_url([])) ?>">
            <?php if ($tag !== ''): ?><input type="hidden" name="tag" value="<?= e($tag) ?>"><?php endif; ?>
            <div class="search" role="search">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M21 21l-4.35-4.35m1.35-5.15a7 7 0 11-14 0 7 7 0 0114 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              </svg>
              <input name="q" value="<?= e($q) ?>" placeholder="Cerca titolo, tag, autore…" autocomplete="off" />
            </div>
            <button class="btn btnPrimary" type="submit">Cerca</button>
            <a class="btn" href="<?= e(self_url([])) ?>">Reset</a>
          </form>

          <!-- NAV / AUTH -->
          <div class="authRow">
            <a class="btn" href="<?= e(self_url([])) ?>">Feed</a>

            <?php if ($u): ?>
              <a class="btn btnPrimary" href="<?= e(self_url(['dashboard'=>1])) ?>">Bacheca</a>

              <?php if ((int)$u['is_admin']===1): ?>
                <a class="btn" href="<?= e(self_url(['admin'=>1])) ?>">Admin</a>
              <?php endif; ?>

              <form method="post" style="margin:0;">
                <input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="logout">
                <button class="btn btnDanger" type="submit">Logout (<?= e($u['username']) ?>)</button>
              </form>
            <?php else: ?>
              <a class="btn" href="<?= e(self_url(['login'=>1])) ?>">Login</a>
              <a class="btn btnPrimary" href="<?= e(self_url(['register'=>1])) ?>">Crea account</a>
            <?php endif; ?>
          </div>
        </div>

        <div class="chips" aria-label="Filtri tag">
          <a class="chip <?= $tag==="" ? "active" : "" ?>" href="<?= e(self_url(['q'=>$q])) ?>">Tutto</a>
          <?php foreach ($allTags as $t): ?>
            <a class="chip <?= ($tag===$t) ? "active" : "" ?>" href="<?= e(self_url(['q'=>$q,'tag'=>$t])) ?>">#<?= e($t) ?></a>
          <?php endforeach; ?>
        </div>
      </div>
    </header>

    <?php if ($flash): ?>
      <?php
        $type = $flash['type'] ?? 'info';
        $badge = 'ok';
        if ($type === 'warn') $badge = 'warn';
        if ($type === 'bad')  $badge = 'bad';
      ?>
      <div class="notice glassStrong" style="margin-bottom:14px;">
        <span class="badge <?= e($badge) ?>"></span>
        <div><?= e((string)$flash['msg']) ?></div>
      </div>
    <?php endif; ?>

    <?php if ($isRegister || $isLogin): ?>

      <section class="hero glass">
        <div>
          <h2><?= $isRegister ? "Crea nuovo account" : "Login" ?></h2>
          <p><?= $isRegister ? "Il primo account creato diventa automaticamente ADMIN." : "Accedi con le tue credenziali." ?></p>
        </div>
        <div class="row">
          <a class="btn" href="<?= e(self_url([])) ?>">Torna al feed</a>
          <?php if ($isRegister): ?>
            <a class="btn" href="<?= e(self_url(['login'=>1])) ?>">Ho già un account</a>
          <?php else: ?>
            <a class="btn btnPrimary" href="<?= e(self_url(['register'=>1])) ?>">Crea account</a>
          <?php endif; ?>
        </div>
      </section>

      <section class="glassStrong panel" style="max-width: 560px; margin: 0 auto;">
        <form method="post" style="display:flex; flex-direction:column; gap:12px;">
          <input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="<?= $isRegister ? 'register' : 'login' ?>">

          <div class="field">
            <label>Username (3–32, solo lettere/numeri/._-)</label>
            <input name="username" required placeholder="es. luna_nera" autocomplete="username">
          </div>

          <div class="field">
            <label>Password (min 6)</label>
            <input type="password" name="password" required placeholder="••••••••"
                   autocomplete="<?= $isRegister ? 'new-password' : 'current-password' ?>">
          </div>

          <div class="row" style="justify-content: space-between;">
            <button class="btn btnPrimary" type="submit"><?= $isRegister ? "Crea account" : "Login" ?></button>
            <span class="mini">Tip: primo account = admin.</span>
          </div>
        </form>
      </section>

    <?php elseif ($isAdminPage): ?>

      <section class="hero glass">
        <div>
          <h2>Admin</h2>
          <p>Gestione totale. Puoi eliminare qualsiasi pin. Sei admin: <strong><?= e((string)$u['username']) ?></strong>.</p>
        </div>
        <div class="row">
          <a class="btn btnPrimary" href="<?= e(self_url(['dashboard'=>1])) ?>">Bacheca</a>
          <a class="btn" href="<?= e(self_url([])) ?>">Feed</a>
        </div>
      </section>

      <section class="glassStrong panel">
        <div class="masonryTitle">
          <h3>Tutti i pin (<?= count($pins) ?>)</h3>
          <span class="kv">Admin power</span>
        </div>
        <main class="masonry" id="grid">
          <?php foreach ($pins as $p) pin_card($p, 'admin', $u); ?>
        </main>
      </section>

    <?php elseif ($isDashboard): ?>

      <section class="hero glass">
        <div>
          <h2>Bacheca: <?= e((string)$u['username']) ?></h2>
          <p>Qui crei e gestisci i tuoi pin (preview live incluso).</p>
        </div>
        <div class="row">
          <span class="kv">I tuoi pin: <?= (int)$myCount ?></span>
          <span class="kv">Pin totali: <?= (int)$allCount ?></span>
          <?php if ((int)$u['is_admin']===1): ?>
            <a class="btn" href="<?= e(self_url(['admin'=>1])) ?>">Admin</a>
          <?php endif; ?>
          <a class="btn" href="<?= e(self_url([])) ?>">Feed</a>
        </div>
      </section>

      <div class="grid2">
        <section class="glassStrong panel">
          <h3 style="margin:0 0 10px; font-size:16px;">Crea Pin</h3>

          <form id="quickForm" method="post" enctype="multipart/form-data" style="display:flex; flex-direction:column; gap:12px;">
            <input type="hidden" name="_csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="create_pin">
            <input type="hidden" name="return" value="dashboard">

            <div class="field">
              <label>Foto *</label>
              <input id="q_photo" type="file" name="photo" accept="image/jpeg,image/png,image/webp" required>
              <div class="mini">JPG/PNG/WEBP • Max 8MB</div>
            </div>

            <div class="field">
              <label>Titolo *</label>
              <input id="q_title" name="title" required placeholder="Titolo…">
            </div>

            <div class="field">
              <label>Descrizione</label>
              <textarea id="q_desc" name="description" placeholder="Descrizione…"></textarea>
            </div>

            <div class="field">
              <label>Tag</label>
              <input id="q_tags" name="tags" placeholder="tag1, tag2, tag3">
            </div>

            <div class="row">
              <button class="btn btnPrimary" type="submit">Pubblica</button>
              <a class="btn" href="<?= e(self_url([])) ?>">Torna al feed</a>
            </div>
          </form>
        </section>

        <section class="glassStrong panel">
          <h3 style="margin:0 0 10px; font-size:16px;">Preview</h3>
          <div class="previewBox">
            <div class="previewImg" id="q_prevImg">Carica una foto ✨</div>
            <div class="previewBody">
              <div style="font-weight:900;" id="q_prevTitle">Titolo</div>
              <div class="mini" id="q_prevDesc">Descrizione…</div>
              <div class="tagRow" id="q_prevTags"></div>
              <div class="mini">Autore: <strong style="color: rgba(255,255,255,.86)"><?= e((string)$u['username']) ?></strong></div>
            </div>
          </div>
        </section>
      </div>

      <section class="glassStrong panel" style="margin-top:14px;">
        <div class="masonryTitle">
          <h3>I tuoi pin</h3>
          <span class="mini">Elimina con l’icona cestino</span>
        </div>
        <main class="masonry" id="grid">
          <?php foreach ($myPins as $p) pin_card($p, 'dashboard', $u); ?>
        </main>

        <?php if (empty($myPins)): ?>
          <div class="notice glassStrong" style="margin-top:14px;">
            <span class="badge warn"></span>
            <div>Nessun pin ancora. Pubblica il primo ✨</div>
          </div>
        <?php endif; ?>
      </section>

    <?php else: ?>

      <section class="hero glass">
        <div>
          <h2><?= ($q!=='' || $tag!=='') ? "Risultati" : "Esplora" ?>
            <span style="color: var(--muted); font-weight:800; font-size:12px;">(<?= count($pins) ?>)</span>
          </h2>
          <p>
            Feed stile Pinterest con UI “liquid glass”.
            <?php if ($u): ?>
              Vai nella tua <a class="tag" href="<?= e(self_url(['dashboard'=>1])) ?>" style="display:inline-flex;">Bacheca</a> per creare pin.
            <?php else: ?>
              Fai <a class="tag" href="<?= e(self_url(['login'=>1])) ?>" style="display:inline-flex;">login</a> o <a class="tag" href="<?= e(self_url(['register'=>1])) ?>" style="display:inline-flex;">crea account</a> per pubblicare.
            <?php endif; ?>
          </p>
        </div>
        <div class="row">
          <span class="kv">DB: SQLite</span>
          <span class="kv">Foto: uploads/</span>
          <?php if ($u): ?>
            <a class="btn btnPrimary" href="<?= e(self_url(['dashboard'=>1])) ?>">Bacheca</a>
          <?php endif; ?>
        </div>
      </section>

      <main class="masonry" id="grid">
        <?php foreach ($pins as $p) pin_card($p, 'feed', $u); ?>
      </main>

      <?php if (empty($pins)): ?>
        <div class="notice glassStrong" style="margin-top:14px;">
          <span class="badge warn"></span>
          <div>Nessun pin ancora. Crea un account e pubblica il primo ✨</div>
        </div>
      <?php endif; ?>

    <?php endif; ?>

  </div>

  <!-- Modal dettaglio pin -->
  <div class="modal" id="modal" aria-hidden="true">
    <div class="modalBg" data-close="1"></div>
    <section class="modalCard glassStrong" role="dialog" aria-modal="true" aria-label="Dettaglio pin">
      <div class="modalMedia" id="modalMedia"></div>
      <div class="modalSide">
        <div class="modalTop">
          <h3 id="modalTitle">Titolo</h3>
          <button class="modalClose" type="button" data-close="1" aria-label="Chiudi">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
        <p class="modalDesc" id="modalDesc"></p>
        <div class="row" id="modalMeta"></div>
        <div class="tagRow" id="modalTags"></div>
        <div class="row" style="margin-top:6px;">
          <button class="btn btnPrimary" id="modalCopy" type="button">Copia link immagine</button>
        </div>
      </div>
    </section>
  </div>

  <script>
    // Modal pin
    const modal = document.getElementById('modal');
    const modalMedia = document.getElementById('modalMedia');
    const modalTitle = document.getElementById('modalTitle');
    const modalDesc  = document.getElementById('modalDesc');
    const modalMeta  = document.getElementById('modalMeta');
    const modalTags  = document.getElementById('modalTags');
    const modalCopy  = document.getElementById('modalCopy');

    let currentPin = null;

    function openPin(pin){
      currentPin = pin;
      modalTitle.textContent = pin.title || '';
      modalDesc.textContent  = pin.desc || '';
      modalMedia.innerHTML = `<img src="${pin.image}" alt="${escapeHtml(pin.title||'')}">`;
      modalMeta.innerHTML = `
        <span class="kv">Autore: <strong style="color: rgba(255,255,255,.88)">${escapeHtml(pin.author||'')}</strong></span>
        <span class="kv">ID: ${pin.id ?? ''}</span>
        <span class="kv">${escapeHtml(pin.created_at || '')}</span>
      `;
      modalTags.innerHTML = '';
      (pin.tags || []).forEach(t => {
        const a = document.createElement('a');
        a.className = 'tag';
        a.href = `?${new URLSearchParams({ tag: t }).toString()}`;
        a.textContent = '#' + t;
        modalTags.appendChild(a);
      });
      modal.setAttribute('aria-hidden','false');
      modal.classList.add('open');
      document.body.style.overflow = 'hidden';
    }
    function closeModal(){
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden','true');
      document.body.style.overflow = '';
      currentPin = null;
    }

    const grid = document.getElementById('grid');
    if (grid){
      grid.addEventListener('click', (e)=>{
        const pinEl = e.target.closest('.pin');
        if (!pinEl) return;

        // evita che il click su delete submit apra modal
        const isDelete = e.target.closest('form.miniForm');
        if (isDelete) return;

        const pin = JSON.parse(pinEl.getAttribute('data-pin') || '{}');
        openPin(pin);
      });

      grid.addEventListener('keydown', (e)=>{
        const pinEl = e.target.closest('.pin');
        if (!pinEl) return;
        if (e.key === 'Enter'){
          const pin = JSON.parse(pinEl.getAttribute('data-pin') || '{}');
          openPin(pin);
        }
      });
    }

    modal?.addEventListener('click', (e)=>{
      if (e.target && e.target.getAttribute('data-close') === '1') closeModal();
      if (e.target && e.target.closest && e.target.closest('[data-close="1"]')) closeModal();
    });
    window.addEventListener('keydown', (e)=>{
      if (e.key === 'Escape' && modal.classList.contains('open')) closeModal();
    });

    modalCopy?.addEventListener('click', async ()=>{
      if (!currentPin) return;
      try{
        await navigator.clipboard.writeText(currentPin.image);
        modalCopy.textContent = 'Copiato ✓';
        setTimeout(()=> modalCopy.textContent = 'Copia link immagine', 1200);
      } catch(err){
        modalCopy.textContent = 'Non posso copiare';
        setTimeout(()=> modalCopy.textContent = 'Copia link immagine', 1200);
      }
    });

    function escapeHtml(str){
      return String(str)
        .replaceAll('&','&amp;')
        .replaceAll('<','&lt;')
        .replaceAll('>','&gt;')
        .replaceAll('"','&quot;')
        .replaceAll("'","&#039;");
    }

    // Preview dashboard (live)
    function setupPreview(){
      const file = document.getElementById('q_photo');
      const title = document.getElementById('q_title');
      const desc = document.getElementById('q_desc');
      const tags = document.getElementById('q_tags');

      const prevImg = document.getElementById('q_prevImg');
      const prevTitle = document.getElementById('q_prevTitle');
      const prevDesc = document.getElementById('q_prevDesc');
      const prevTags = document.getElementById('q_prevTags');

      if (!file || !title || !desc || !tags || !prevImg || !prevTitle || !prevDesc || !prevTags) return;

      file.addEventListener('change', ()=>{
        const f = file.files && file.files[0];
        if (!f) return;
        const url = URL.createObjectURL(f);
        prevImg.innerHTML = `<img src="${url}" alt="preview">`;
      });

      function renderTags(){
        const raw = tags.value || '';
        const parts = raw.split(/[\s,]+/).map(s=>s.trim()).filter(Boolean).slice(0, 12);
        prevTags.innerHTML = '';
        parts.forEach(t=>{
          const a = document.createElement('span');
          a.className = 'tag';
          a.textContent = '#' + t.toLowerCase();
          prevTags.appendChild(a);
        });
      }

      title.addEventListener('input', ()=> prevTitle.textContent = title.value || 'Titolo');
      desc.addEventListener('input', ()=> prevDesc.textContent = desc.value || 'Descrizione…');
      tags.addEventListener('input', renderTags);
      renderTags();
    }
    setupPreview();
  </script>
</body>
</html>