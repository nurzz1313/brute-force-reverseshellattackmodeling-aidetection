<?php
/**
 * Local Laboratory Web Service for ML Dataset Collection
 * -----------------------------------------------------
 * Purpose: collect raw AUTH / UPLOAD / SESSION / FILE_ACCESS events.
 * This app is intended for an isolated VirtualBox lab environment.
 */

/* =========================================================
 *  BLOCKLIST ENFORCEMENT (must be first)
 * ========================================================= */

$blocklistPath = __DIR__ . '/blocked_ips.json';

function get_client_ip_for_blocking(): string
{
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }

    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function enforce_blocklist_or_exit(string $blocklistPath): void
{
    $clientIp = get_client_ip_for_blocking();

    if (!file_exists($blocklistPath)) {
        return;
    }

    $raw = file_get_contents($blocklistPath);
    $data = json_decode($raw, true);

    if (!is_array($data) || !isset($data[$clientIp])) {
        return;
    }

    $untilRaw = $data[$clientIp]['until'] ?? '';
    $untilTs = strtotime($untilRaw);

    if ($untilTs === false) {
        return;
    }

    if (time() >= $untilTs) {
        unset($data[$clientIp]);
        file_put_contents(
            $blocklistPath,
            json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
            LOCK_EX
        );
        return;
    }

    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('Access denied due to suspicious activity.');
}

enforce_blocklist_or_exit($blocklistPath);

/* =========================================================
 *  APPLICATION
 * ========================================================= */

session_start();

const VALID_USERNAME = 'student';
const VALID_PASSWORD = 'Password123!';

const BASE_DIR = __DIR__;
const UPLOAD_DIR = BASE_DIR . DIRECTORY_SEPARATOR . 'uploads';
const LOG_DIR = BASE_DIR . DIRECTORY_SEPARATOR . 'logs';
const RAW_TEXT_LOG = LOG_DIR . DIRECTORY_SEPARATOR . 'raw_events.txt';
const RAW_CSV_LOG = LOG_DIR . DIRECTORY_SEPARATOR . 'raw_events.csv';
const UPLOAD_HTACCESS = UPLOAD_DIR . DIRECTORY_SEPARATOR . '.htaccess';

const ALLOWED_EXTENSIONS = [
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv', 'doc', 'docx',
    'php', 'aspx', 'py', 'sh', 'exe', 'bat', 'js'
];

const CSV_FIELDS = [
    'event_id',
    'timestamp',
    'event_type',
    'source_ip',
    'username',
    'session_id',
    'status',
    'http_status',
    'user_agent',
    'resource',
    'filename',
    'file_ext',
    'file_size',
    'mime_type',
    'sha256',
];

function ensure_directories(): void
{
    if (!is_dir(UPLOAD_DIR)) {
        mkdir(UPLOAD_DIR, 0755, true);
    }

    if (!is_dir(LOG_DIR)) {
        mkdir(LOG_DIR, 0755, true);
    }

    ensure_upload_directory_policy();
}

function ensure_upload_directory_policy(): void
{
    $htaccess = <<<'HTACCESS'
Options +Indexes -ExecCGI
Require all granted

RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .cgi .pl .py .sh .asp .aspx .jsp .exe .bat .js
RemoveType .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .cgi .pl .py .sh .asp .aspx .jsp .exe .bat .js
AddType text/plain .php .phtml .php3 .php4 .php5 .php7 .php8 .phar .cgi .pl .py .sh .asp .aspx .jsp .exe .bat .js

<FilesMatch "\.(php|phtml|php3|php4|php5|php7|php8|phar|cgi|pl|py|sh|asp|aspx|jsp|exe|bat|js)$">
    SetHandler None
    ForceType text/plain
</FilesMatch>
HTACCESS;

    if (!file_exists(UPLOAD_HTACCESS) || file_get_contents(UPLOAD_HTACCESS) !== $htaccess . PHP_EOL) {
        file_put_contents(UPLOAD_HTACCESS, $htaccess . PHP_EOL, LOCK_EX);
    }
}

function ensure_csv_header(): void
{
    ensure_directories();

    if (!file_exists(RAW_CSV_LOG) || filesize(RAW_CSV_LOG) === 0) {
        $fp = fopen(RAW_CSV_LOG, 'w');
        if ($fp !== false) {
            fputcsv($fp, CSV_FIELDS);
            fclose($fp);
        }
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect_to(string $path, array $params = []): never
{
    if ($params) {
        $path .= '?' . http_build_query($params);
    }

    header('Location: ' . $path, true, 302);
    exit;
}

function app_client_ip(): string
{
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }

    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function current_user(): string
{
    return (string)($_SESSION['username'] ?? '');
}

function session_identifier(): string
{
    return (string)($_SESSION['session_id'] ?? '');
}

function require_login(): void
{
    if (current_user() === '') {
        redirect_to('/', ['message' => 'Please log in first.', 'success' => '0']);
    }
}

function safe_filename(string $name): string
{
    $name = basename($name);
    $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
    return trim((string)$name, '._');
}

function file_extension(string $filename): string
{
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    return strtolower((string)$ext);
}

function allowed_file(string $filename): bool
{
    $ext = file_extension($filename);
    return $ext !== '' && in_array($ext, ALLOWED_EXTENSIONS, true);
}

function detect_mime_type(string $tmpPath, string $fallback = ''): string
{
    if ($tmpPath !== '' && file_exists($tmpPath)) {
        if (function_exists('mime_content_type')) {
            $mime = mime_content_type($tmpPath);
            if (is_string($mime) && $mime !== '') {
                return $mime;
            }
        }

        if (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo !== false) {
                $mime = finfo_file($finfo, $tmpPath);
                finfo_close($finfo);
                if (is_string($mime) && $mime !== '') {
                    return $mime;
                }
            }
        }
    }

    return $fallback !== '' ? $fallback : 'application/octet-stream';
}

function next_unique_path(string $filename): string
{
    $target = UPLOAD_DIR . DIRECTORY_SEPARATOR . $filename;
    if (!file_exists($target)) {
        return $target;
    }

    $stem = pathinfo($filename, PATHINFO_FILENAME);
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $suffix = $ext !== '' ? '.' . $ext : '';
    $counter = 1;

    while (true) {
        $candidate = UPLOAD_DIR . DIRECTORY_SEPARATOR . $stem . '_' . $counter . $suffix;
        if (!file_exists($candidate)) {
            return $candidate;
        }
        $counter++;
    }
}

function uploaded_files(): array
{
    ensure_directories();
    $result = [];

    $items = scandir(UPLOAD_DIR);
    if ($items === false) {
        return [];
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..' || $item === '.htaccess') {
            continue;
        }

        $path = UPLOAD_DIR . DIRECTORY_SEPARATOR . $item;
        if (is_file($path)) {
            $result[] = [
                'name' => $item,
                'size' => filesize($path) ?: 0,
            ];
        }
    }

    usort($result, static function ($a, $b) {
        return strcmp($a['name'], $b['name']);
    });

    return $result;
}

function write_raw_event(array $event): void
{
    ensure_csv_header();

    $record = [
        'event_id' => bin2hex(random_bytes(16)),
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => (string)($event['event_type'] ?? ''),
        'source_ip' => app_client_ip(),
        'username' => (string)($event['username'] ?? current_user()),
        'session_id' => (string)($event['session_id'] ?? session_identifier()),
        'status' => (string)($event['status'] ?? ''),
        'http_status' => (int)($event['http_status'] ?? 0),
        'user_agent' => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'resource' => (string)($event['resource'] ?? ''),
        'filename' => (string)($event['filename'] ?? ''),
        'file_ext' => (string)($event['file_ext'] ?? ''),
        'file_size' => (int)($event['file_size'] ?? 0),
        'mime_type' => (string)($event['mime_type'] ?? ''),
        'sha256' => (string)($event['sha256'] ?? ''),
    ];

    $textLine = implode(' | ', [
        $record['timestamp'],
        $record['event_type'],
        $record['source_ip'],
        $record['username'],
        $record['status'],
        (string)$record['http_status'],
        $record['resource'],
        $record['filename'],
        $record['file_ext'],
        (string)$record['file_size'],
        $record['mime_type'],
        $record['sha256'],
    ]) . PHP_EOL;

    file_put_contents(RAW_TEXT_LOG, $textLine, FILE_APPEND | LOCK_EX);

    $fp = fopen(RAW_CSV_LOG, 'a');
    if ($fp !== false) {
        fputcsv($fp, $record);
        fclose($fp);
    }
}

function render_header(string $title): void
{
    echo '<!doctype html>';
    echo '<html lang="en"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . h($title) . '</title>';
    echo '<style>
        body { font-family: Arial, sans-serif; background:#f4f6f8; margin:0; color:#1f2937; }
        .wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px; }
        .card { background:#fff; border:1px solid #d1d5db; border-radius:14px; padding:24px; box-shadow:0 4px 10px rgba(0,0,0,0.05); }
        .topbar { display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:20px; }
        h1,h2 { margin-top:0; }
        label { display:block; font-weight:600; margin-top:14px; margin-bottom:6px; }
        input[type=text], input[type=password] { width:100%; padding:10px 12px; border:1px solid #cbd5e1; border-radius:10px; box-sizing:border-box; }
        input[type=file] { margin-top:12px; }
        button, .btn { display:inline-block; background:#1d4ed8; color:#fff; border:none; border-radius:10px; padding:10px 16px; cursor:pointer; text-decoration:none; }
        button:hover, .btn:hover { background:#1e40af; }
        .danger { background:#b91c1c; }
        .danger:hover { background:#991b1b; }
        .msg { padding:10px 12px; border-radius:10px; margin-bottom:12px; }
        .ok { background:#dcfce7; color:#166534; }
        .bad { background:#fee2e2; color:#991b1b; }
        .muted { color:#6b7280; font-size:14px; }
        .note { margin-top:18px; background:#f8fafc; border:1px solid #e5e7eb; border-radius:10px; padding:12px; }
        .warn { margin-top:14px; background:#fef3c7; color:#92400e; padding:10px 12px; border-radius:10px; }
        table { width:100%; border-collapse: collapse; margin-top: 18px; }
        th, td { border:1px solid #e5e7eb; padding:8px 10px; text-align:left; font-size:14px; }
        th { background:#f9fafb; }
        .actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
    </style>';
    echo '</head><body><div class="wrap">';
}

function render_footer(): void
{
    echo '</div></body></html>';
}

function render_message(): void
{
    $message = $_GET['message'] ?? '';
    if ($message !== '') {
        $success = ($_GET['success'] ?? '') === '1';
        echo '<div class="msg ' . ($success ? 'ok' : 'bad') . '">' . h($message) . '</div>';
    }
}

function render_login_page(): void
{
    render_header('Local Authentication Test Environment');
    echo '<div class="card">';
    echo '<h1>Local Authentication Test Environment</h1>';
    echo '<p class="muted">This local laboratory web service collects authentication and upload events for offline ML-based security analysis.</p>';
    render_message();
    echo '<form method="post" action="/login">';
    echo '<label>Username</label><input type="text" name="username" required>';
    echo '<label>Password</label><input type="password" name="password" required>';
    echo '<button type="submit">Sign In</button>';
    echo '</form>';
    echo '<div class="note"><strong>Dataset focus:</strong> repeated login attempts create AUTH records in raw_events.csv and raw_events.txt.</div>';
    echo '</div>';
    render_footer();
}

function render_upload_page(): void
{
    require_login();

    render_header('Authenticated Upload Portal');
    echo '<div class="topbar"><div>';
    echo '<h1>Authenticated Upload Portal</h1>';
    echo '<p class="muted">Signed in as: <strong>' . h(current_user()) . '</strong></p>';
    echo '</div><div><a class="btn" href="/logout">Logout</a></div></div>';

    echo '<div class="card">';
    render_message();

    echo '<h2>Upload a File</h2>';
    echo '<form method="post" action="/upload" enctype="multipart/form-data">';
    echo '<input type="file" name="file" required><br>';
    echo '<button type="submit">Upload</button>';
    echo '</form>';

    echo '<div class="warn">Uploaded files are stored for research logging only. Raw events are saved locally in the logs directory.</div>';
    echo '<p class="muted" style="margin-top:14px;">Raw events are saved locally to <code>logs/raw_events.csv</code> and <code>logs/raw_events.txt</code>. Log export from the web interface is disabled.</p>';

    echo '<h2>Uploaded Files</h2>';
    echo '<table><thead><tr><th>File Name</th><th>Size (bytes)</th></tr></thead><tbody>';
    $files = uploaded_files();
    if (!$files) {
        echo '<tr><td colspan="2">No files uploaded yet.</td></tr>';
    } else {
        foreach ($files as $f) {
            echo '<tr>';
            echo '<td>' . h($f['name']) . '</td>';
            echo '<td>' . h((string)$f['size']) . '</td>';
            echo '</tr>';
        }
    }
    echo '</tbody></table>';

    echo '<div class="actions">';
    echo '<a class="btn danger" href="/lab/clear" onclick="return confirm(\'Clear logs, sessions and uploads?\')">Clear Lab Data</a>';
    echo '</div>';

    echo '</div>';
    render_footer();
}

function handle_login(): void
{
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === VALID_USERNAME && $password === VALID_PASSWORD) {
        session_regenerate_id(true);
        $_SESSION['username'] = $username;
        $_SESSION['session_id'] = bin2hex(random_bytes(16));

        write_raw_event([
            'event_type' => 'AUTH',
            'username' => $username,
            'session_id' => session_identifier(),
            'status' => 'SUCCESS',
            'http_status' => 200,
            'resource' => '/login',
        ]);

        redirect_to('/upload', ['message' => 'Login successful.', 'success' => '1']);
    }

    write_raw_event([
        'event_type' => 'AUTH',
        'username' => $username,
        'session_id' => $_SESSION['session_id'] ?? '',
        'status' => 'FAILED',
        'http_status' => 401,
        'resource' => '/login',
    ]);

    redirect_to('/', ['message' => 'Login failed.', 'success' => '0']);
}

function handle_upload(): void
{
    require_login();

    if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
        write_raw_event([
            'event_type' => 'UPLOAD',
            'status' => 'FAILED',
            'http_status' => 400,
            'resource' => '/upload',
        ]);
        redirect_to('/upload', ['message' => 'No file selected.', 'success' => '0']);
    }

    $file = $_FILES['file'];

    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        write_raw_event([
            'event_type' => 'UPLOAD',
            'status' => 'FAILED',
            'http_status' => 400,
            'resource' => '/upload',
        ]);
        redirect_to('/upload', ['message' => 'Upload failed.', 'success' => '0']);
    }

    $originalName = safe_filename((string)$file['name']);
    if ($originalName === '') {
        write_raw_event([
            'event_type' => 'UPLOAD',
            'status' => 'FAILED',
            'http_status' => 400,
            'resource' => '/upload',
        ]);
        redirect_to('/upload', ['message' => 'Invalid file name.', 'success' => '0']);
    }

    $fileExt = file_extension($originalName);
    $tmpPath = (string)$file['tmp_name'];
    $mimeType = detect_mime_type($tmpPath, (string)($file['type'] ?? ''));

    if (!allowed_file($originalName)) {
        write_raw_event([
            'event_type' => 'UPLOAD',
            'status' => 'FAILED',
            'http_status' => 415,
            'resource' => '/upload',
            'filename' => $originalName,
            'file_ext' => $fileExt,
            'file_size' => (int)($file['size'] ?? 0),
            'mime_type' => $mimeType,
        ]);
        redirect_to('/upload', ['message' => 'File type not allowed.', 'success' => '0']);
    }

    $savePath = next_unique_path($originalName);
    if (!move_uploaded_file($tmpPath, $savePath)) {
        write_raw_event([
            'event_type' => 'UPLOAD',
            'status' => 'FAILED',
            'http_status' => 500,
            'resource' => '/upload',
            'filename' => $originalName,
            'file_ext' => $fileExt,
            'file_size' => (int)($file['size'] ?? 0),
            'mime_type' => $mimeType,
        ]);
        redirect_to('/upload', ['message' => 'File could not be saved.', 'success' => '0']);
    }

    $savedName = basename($savePath);
    $fileSize = filesize($savePath) ?: 0;
    $sha256 = hash_file('sha256', $savePath) ?: '';

    write_raw_event([
        'event_type' => 'UPLOAD',
        'status' => 'SUCCESS',
        'http_status' => 200,
        'resource' => '/upload',
        'filename' => $savedName,
        'file_ext' => $fileExt,
        'file_size' => $fileSize,
        'mime_type' => $mimeType,
        'sha256' => $sha256,
    ]);

    redirect_to('/upload', ['message' => 'File uploaded successfully.', 'success' => '1']);
}

function handle_logout(): void
{
    if (current_user() !== '') {
        write_raw_event([
            'event_type' => 'SESSION',
            'username' => current_user(),
            'session_id' => session_identifier(),
            'status' => 'SUCCESS',
            'http_status' => 200,
            'resource' => '/logout',
        ]);
    }

    $_SESSION = [];
    if (session_id() !== '') {
        session_destroy();
    }

    redirect_to('/', ['message' => 'Logged out successfully.', 'success' => '1']);
}

function handle_clear_lab_data(): void
{
    $_SESSION = [];
    if (session_id() !== '') {
        session_destroy();
    }

    ensure_directories();

    if (file_exists(RAW_TEXT_LOG)) {
        file_put_contents(RAW_TEXT_LOG, '', LOCK_EX);
    }

    if (file_exists(RAW_CSV_LOG)) {
        file_put_contents(RAW_CSV_LOG, '', LOCK_EX);
    }

    ensure_csv_header();

    $items = scandir(UPLOAD_DIR);
    if ($items !== false) {
        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item === '.htaccess') {
                continue;
            }
            $path = UPLOAD_DIR . DIRECTORY_SEPARATOR . $item;
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    redirect_to('/', ['message' => 'Laboratory data cleared.', 'success' => '1']);
}

function route(): void
{
    ensure_csv_header();

    $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($uri === '/' && $method === 'GET') {
        render_login_page();
        return;
    }

    if ($uri === '/login' && $method === 'POST') {
        handle_login();
        return;
    }

    if ($uri === '/upload' && $method === 'GET') {
        render_upload_page();
        return;
    }

    if ($uri === '/upload' && $method === 'POST') {
        handle_upload();
        return;
    }

    if ($uri === '/logout' && $method === 'GET') {
        handle_logout();
        return;
    }

    if ($uri === '/lab/clear' && $method === 'GET') {
        handle_clear_lab_data();
        return;
    }

    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Not Found';
}

route();