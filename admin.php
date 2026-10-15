<?php
// ============================================================
// CONFIGURATION
// ============================================================
define('DATA_FILE', __DIR__ . '/licenses.json');
define('LOG_FILE', __DIR__ . '/logs.json');
define('ACCESS_LOG_FILE', __DIR__ . '/access_logs.json');
define('FAILED_LOGIN_FILE', __DIR__ . '/failed_logins.json');
define('WEBHOOK_TIMEOUT', 5);
define('CONFIG_SELECTION_MODE', 'client_side_latency_preferred_static_quality_fallback');
define('CONFIG_PRIORITY_VERSION', '2026-06-02-client-side-latency-static-fallback');
define('SESSION_TIMEOUT', 3600);
define('MAX_LOGIN_ATTEMPTS', 5);
define('BLOCK_TIME', 900);
define('ALLOWED_IPS', []);
define('SETTINGS_FILE', __DIR__ . '/settings.json');
define('ADMIN_PASSWORD_HASH_FILE', __DIR__ . '/.symex_admin_password_hash');
define('ADMIN_INITIAL_PASSWORD_FILE', __DIR__ . '/.symex_initial_admin_password');
require_once __DIR__ . '/symex_subscription_core.php';

// Fix: Check if session is already active
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_samesite' => 'Strict'
    ]);
}

// Prevent browser/proxy caching stale admin POST results. This fixes toggles that
// appear stuck until several manual refreshes on some mobile browsers/proxies.
if (!headers_sent()) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

// ============================================================
// CORE FUNCTIONS
// ============================================================

function getUserIP(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($forwarded && filter_var(explode(',', $forwarded)[0], FILTER_VALIDATE_IP)) {
        $ip = explode(',', $forwarded)[0];
    }
    return $ip;
}

function getUserLocation(string $ip): array {
    // Fix: Return early for local IPs
    if ($ip === '127.0.0.1' || $ip === '::1' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0) {
        return ['country' => 'Local', 'city' => 'Local', 'isp' => 'Local Network', 'error' => null];
    }

    $settings = function_exists('load_settings') ? load_settings() : [];
    if (empty($settings['external_geo_lookup_enabled'])) {
        return ['country' => 'Unknown', 'city' => 'Unknown', 'isp' => 'Unknown', 'error' => 'geo_lookup_disabled'];
    }
    
    if (!extension_loaded('curl')) {
        return ['country' => 'Unknown', 'city' => 'Unknown', 'isp' => 'Unknown', 'error' => 'curl extension missing'];
    }
    // Fix: Add timeout and error handling
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => "http://ip-api.com/json/{$ip}?fields=status,country,city,isp,lat,lon,timezone,query",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_CONNECTTIMEOUT => 2,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($response && !$error) {
        $data = json_decode($response, true);
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            return [
                'country' => $data['country'] ?? 'Unknown',
                'city' => $data['city'] ?? 'Unknown',
                'isp' => $data['isp'] ?? 'Unknown',
                'lat' => $data['lat'] ?? 0,
                'lon' => $data['lon'] ?? 0,
                'timezone' => $data['timezone'] ?? 'Unknown',
                'ip' => $data['query'] ?? $ip,
                'error' => null
            ];
        }
    }
    return ['country' => 'Unknown', 'city' => 'Unknown', 'isp' => 'Unknown', 'error' => 'Geo lookup failed'];
}

function getUserDeviceInfo(): array {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    $os = 'Unknown';
    $osPatterns = [
        'Windows' => '/Windows NT/',
        'Mac' => '/Macintosh|Mac OS X/',
        'Linux' => '/Linux|X11/',
        'Android' => '/Android/',
        'iOS' => '/iPhone|iPad|iPod/'
    ];
    foreach ($osPatterns as $name => $pattern) {
        if (preg_match($pattern, $userAgent)) {
            $os = $name;
            break;
        }
    }
    
    $browser = 'Unknown';
    $browserPatterns = [
        'Chrome' => '/Chrome\//',
        'Firefox' => '/Firefox\//',
        'Safari' => '/Safari\//',
        'Edge' => '/Edg\//',
        'Opera' => '/Opera|OPR\//'
    ];
    foreach ($browserPatterns as $name => $pattern) {
        if (preg_match($pattern, $userAgent)) {
            $browser = $name;
            break;
        }
    }
    
    return [
        'user_agent' => $userAgent,
        'os' => $os,
        'browser' => $browser,
        'screen_resolution' => $_COOKIE['screen_resolution'] ?? 'Unknown',
        'language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'Unknown'
    ];
}

function logAccess(string $status, string $message = ''): void {
    $ip = getUserIP();
    $device = getUserDeviceInfo();
    $location = getUserLocation($ip);
    
    $log = [
        'timestamp' => date('Y-m-d H:i:s'),
        'status' => $status,
        'ip' => $ip,
        'location' => $location,
        'device' => $device,
        'message' => $message,
        'session_id' => session_id()
    ];
    
    $logs = [];
    if (file_exists(ACCESS_LOG_FILE)) {
        $content = file_get_contents(ACCESS_LOG_FILE);
        if ($content !== false) {
            $logs = json_decode($content, true);
            if (!is_array($logs)) $logs = [];
        }
    }
    $logs[] = $log;
    
    if (count($logs) > 2000) {
        $logs = array_slice($logs, -2000);
    }
    
    file_put_contents(ACCESS_LOG_FILE, json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function isIPBlocked(): bool {
    $ip = getUserIP();
    if (!file_exists(FAILED_LOGIN_FILE)) return false;
    
    $content = file_get_contents(FAILED_LOGIN_FILE);
    if ($content === false) return false;
    
    $failedLogs = json_decode($content, true);
    if (!is_array($failedLogs)) return false;
    
    if (!isset($failedLogs[$ip])) return false;
    
    $attempts = $failedLogs[$ip]['attempts'] ?? 0;
    $lastAttempt = $failedLogs[$ip]['last_attempt'] ?? 0;
    
    if ($attempts >= MAX_LOGIN_ATTEMPTS && (time() - $lastAttempt) < BLOCK_TIME) {
        return true;
    }
    
    if ((time() - $lastAttempt) >= BLOCK_TIME) {
        unset($failedLogs[$ip]);
        file_put_contents(FAILED_LOGIN_FILE, json_encode($failedLogs, JSON_PRETTY_PRINT), LOCK_EX);
    }
    
    return false;
}

function recordFailedLogin(): void {
    $ip = getUserIP();
    $failedLogs = [];
    if (file_exists(FAILED_LOGIN_FILE)) {
        $content = file_get_contents(FAILED_LOGIN_FILE);
        if ($content !== false) {
            $failedLogs = json_decode($content, true);
            if (!is_array($failedLogs)) $failedLogs = [];
        }
    }
    
    if (!isset($failedLogs[$ip])) {
        $failedLogs[$ip] = ['attempts' => 1, 'last_attempt' => time()];
    } else {
        $failedLogs[$ip]['attempts']++;
        $failedLogs[$ip]['last_attempt'] = time();
    }
    
    file_put_contents(FAILED_LOGIN_FILE, json_encode($failedLogs, JSON_PRETTY_PRINT), LOCK_EX);
}

function resetFailedLogins(): void {
    $ip = getUserIP();
    if (!file_exists(FAILED_LOGIN_FILE)) return;
    
    $content = file_get_contents(FAILED_LOGIN_FILE);
    if ($content === false) return;
    
    $failedLogs = json_decode($content, true);
    if (is_array($failedLogs)) {
        unset($failedLogs[$ip]);
        file_put_contents(FAILED_LOGIN_FILE, json_encode($failedLogs, JSON_PRETTY_PRINT), LOCK_EX);
    }
}

function checkIPAllowed(): bool {
    $ip = getUserIP();
    $allowed = ALLOWED_IPS;
    if (empty($allowed)) return true;
    return in_array($ip, $allowed);
}

function symex_env(string $name): string {
    $value = getenv($name);
    return is_string($value) ? trim($value) : '';
}

function symex_generate_initial_admin_password(): string {
    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%';
    $password = '';
    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < 24; $i++) {
        $password .= $alphabet[random_int(0, $max)];
    }
    return $password;
}

function symex_admin_password_hash(): string {
    $envHash = symex_env('SYMEX_ADMIN_PASSWORD_HASH');
    if ($envHash !== '') return $envHash;

    $envPassword = symex_env('SYMEX_ADMIN_PASSWORD');
    if ($envPassword !== '') return password_hash($envPassword, PASSWORD_DEFAULT);

    if (file_exists(ADMIN_PASSWORD_HASH_FILE)) {
        $hash = trim((string)@file_get_contents(ADMIN_PASSWORD_HASH_FILE));
        if ($hash !== '') return $hash;
    }

    $initialPassword = symex_generate_initial_admin_password();
    $hash = password_hash($initialPassword, PASSWORD_DEFAULT);
    $hashSaved = @file_put_contents(ADMIN_PASSWORD_HASH_FILE, $hash . PHP_EOL, LOCK_EX) !== false;
    if ($hashSaved) {
        @chmod(ADMIN_PASSWORD_HASH_FILE, 0600);
        @file_put_contents(
            ADMIN_INITIAL_PASSWORD_FILE,
            "Initial SYMEX admin password: {$initialPassword}" . PHP_EOL .
            "Set SYMEX_ADMIN_PASSWORD_HASH or change this password, then delete this file." . PHP_EOL,
            LOCK_EX
        );
        @chmod(ADMIN_INITIAL_PASSWORD_FILE, 0600);
        return $hash;
    }

    return '';
}

function verifyAdminPassword(string $password): bool {
    $hash = symex_admin_password_hash();
    return $hash !== '' && password_verify($password, $hash);
}

function saveAdminPassword(string $password): bool {
    if (strlen($password) < 12) return false;
    $hash = password_hash($password, PASSWORD_DEFAULT);
    if (@file_put_contents(ADMIN_PASSWORD_HASH_FILE, $hash . PHP_EOL, LOCK_EX) === false) {
        return false;
    }
    @chmod(ADMIN_PASSWORD_HASH_FILE, 0600);
    @unlink(ADMIN_INITIAL_PASSWORD_FILE);
    return true;
}

function checkSessionTimeout(): bool {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        return false;
    }
    $_SESSION['last_activity'] = time();
    return true;
}

function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken(): bool {
    // Fix: Only verify for POST requests
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return true;
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function addLog(string $type, string $message): void {
    $logs = [];
    if (file_exists(LOG_FILE)) {
        $content = file_get_contents(LOG_FILE);
        if ($content !== false) {
            $logs = json_decode($content, true);
            if (!is_array($logs)) $logs = [];
        }
    }
    $logs[] = [
        'timestamp' => date('Y-m-d H:i:s'),
        'type' => $type,
        'message' => $message,
        'ip' => getUserIP()
    ];
    if (count($logs) > 1000) {
        $logs = array_slice($logs, -1000);
    }
    file_put_contents(LOG_FILE, json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function symex_json_decode_db(string $content): array {
    $content = trim($content);
    if ($content === '') return [];
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

function db_load(): array {
    if (!file_exists(DATA_FILE)) {
        @file_put_contents(DATA_FILE, '{}', LOCK_EX);
        return [];
    }
    $fp = @fopen(DATA_FILE, 'rb');
    if (!$fp) return [];
    $content = '';
    if (flock($fp, LOCK_SH)) {
        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    return symex_json_decode_db((string)$content);
}

function db_save(array $data): void {
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        throw new RuntimeException('Failed to encode license database JSON.');
    }
    $dir = dirname(DATA_FILE);
    if (!is_dir($dir) || !is_writable($dir)) {
        throw new RuntimeException('Data directory is not writable.');
    }
    $lockFile = DATA_FILE . '.lock';
    $lock = @fopen($lockFile, 'c');
    if (!$lock) {
        throw new RuntimeException('Unable to open database lock file.');
    }
    if (!flock($lock, LOCK_EX)) {
        fclose($lock);
        throw new RuntimeException('Unable to lock database for writing.');
    }
    $tmp = DATA_FILE . '.tmp.' . getmypid();
    $ok = @file_put_contents($tmp, $json, LOCK_EX);
    if ($ok === false) {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($tmp);
        throw new RuntimeException('Unable to write temporary database file.');
    }
    @chmod($tmp, 0644);
    if (!@rename($tmp, DATA_FILE)) {
        flock($lock, LOCK_UN);
        fclose($lock);
        @unlink($tmp);
        throw new RuntimeException('Unable to replace database file atomically.');
    }
    flock($lock, LOCK_UN);
    fclose($lock);
}

function symex_admin_redirect_after_post(string $message = ''): void {
    if ($message !== '') {
        $_SESSION['flash_msg'] = $message;
    }
    $target = strtok($_SERVER['REQUEST_URI'] ?? 'admin.php', '?') ?: 'admin.php';
    if (!headers_sent()) {
        header('Location: ' . $target, true, 303);
        exit;
    }
}

function get_logs(): array {
    if (!file_exists(LOG_FILE)) return [];
    $content = file_get_contents(LOG_FILE);
    if ($content === false) return [];
    $logs = json_decode($content, true);
    return is_array($logs) ? array_reverse($logs) : [];
}

function get_access_logs(): array {
    if (!file_exists(ACCESS_LOG_FILE)) return [];
    $content = file_get_contents(ACCESS_LOG_FILE);
    if ($content === false) return [];
    $logs = json_decode($content, true);
    return is_array($logs) ? array_reverse($logs) : [];
}

function formatBytes(int $bytes): string {
    if ($bytes <= 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    $bytes_float = (float)$bytes;
    while ($bytes_float >= 1024 && $i < count($units) - 1) {
        $bytes_float /= 1024;
        $i++;
    }
    return round($bytes_float, 2) . ' ' . $units[$i];
}

function parseBandwidthInput(float $gb): int {
    if ($gb <= 0) return 0;
    return (int)round($gb * 1024 * 1024 * 1024);
}

function get_statistics(array $db): array {
    $total = count($db);
    $active = 0;
    $expired = 0;
    $disabled = 0;
    $total_devices = 0;
    $expiring_soon = 0;
    $total_bandwidth_used = 0;
    $total_bandwidth_limit = 0;
    $today = time();
    
    foreach ($db as $license) {
        $total_devices += count($license['devices'] ?? []);
        $total_bandwidth_used += $license['bandwidth_used'] ?? 0;
        $total_bandwidth_limit += $license['bandwidth_limit'] ?? 0;
        
        if (isset($license['active']) && $license['active']) {
            $active++;
            
            if (!empty($license['expires_at'])) {
                $expire_time = strtotime($license['expires_at'] . ' 23:59:59');
                if ($expire_time && $today > $expire_time) {
                    $expired++;
                } elseif ($expire_time && $today > $expire_time - (3 * 86400)) {
                    $expiring_soon++;
                }
            }
        } else {
            $disabled++;
        }
    }
    
    return [
        'total' => $total,
        'active' => $active,
        'expired' => $expired,
        'disabled' => $disabled,
        'total_devices' => $total_devices,
        'expiring_soon' => $expiring_soon,
        'total_bandwidth_used' => $total_bandwidth_used,
        'total_bandwidth_limit' => $total_bandwidth_limit
    ];
}

function is_expired(string $date): bool {
    if ($date === '') return false;
    $expire_time = strtotime($date . ' 23:59:59');
    return $expire_time ? time() > $expire_time : false;
}

function get_days_remaining(string $expires_at): string {
    if ($expires_at === '') return '∞';
    $now = time();
    $exp = strtotime($expires_at . ' 23:59:59');
    if (!$exp) return '∞';
    $diff = $exp - $now;
    if ($diff <= 0) return 'Expired';
    $days = ceil($diff / 86400);
    return "{$days} day" . ($days != 1 ? 's' : '') . " left";
}

function symex_normalize_subscription_url(string $url): string {
    if (function_exists('symex_sub_normalize_url')) return symex_sub_normalize_url($url);
    $url = html_entity_decode(trim($url), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $url = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $url);
    $url = preg_replace('/\s+/u', '', $url);
    if (strpos($url, '//') === 0) $url = 'https:' . $url;
    return $url;
}

function symex_extract_subscription_urls_from_text(string $text): array {
    if (function_exists('symex_sub_extract_urls')) return symex_sub_extract_urls($text, 10);
    $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if (!preg_match_all('/https?:\/\/[^\s<>"\'`]+/iu', $text, $matches)) {
        return [];
    }
    $urls = [];
    foreach ($matches[0] as $url) {
        $url = symex_normalize_subscription_url(trim($url, " \t\n\r\0\x0B,;)]}"));
        $parts = @parse_url($url);
        if (!is_array($parts)) continue;
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = trim((string)($parts['host'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') continue;
        $urls[$url] = true;
        if (count($urls) >= 5) break;
    }
    return array_keys($urls);
}

function symex_body_has_config_marker(string $body): bool {
    $sample = substr($body, 0, 1048576);
    $schemes = implode('|', array_map('preg_quote', get_supported_config_schemes()));
    if (preg_match('/(?:' . $schemes . '):\/\//iu', $sample)) return true;
    if (preg_match('/(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|socks5?)%3A%2F%2F/iu', $sample)) return true;
    $decoded = rawurldecode($sample);
    if ($decoded !== $sample && preg_match('/(?:' . $schemes . '):\/\//iu', $decoded)) return true;
    $compact = preg_replace('/\s+/', '', trim($sample));
    if (strlen($compact) > 24 && preg_match('/^[A-Za-z0-9+\/_-]+={0,3}$/', $compact)) {
        $b64 = strtr($compact, '-_', '+/');
        $b64 .= str_repeat('=', (4 - strlen($b64) % 4) % 4);
        $plain = base64_decode($b64, true);
        if (is_string($plain) && preg_match('/(?:' . $schemes . '):\/\//iu', $plain)) return true;
    }
    // JSON/YAML subscriptions sometimes need the full parser after fetch.
    $trim = ltrim($sample);
    if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[' || stripos($trim, 'proxies:') !== false)) return true;
    return false;
}

function symex_decode_http_body_if_needed(string $body): string {
    // cURL normally decompresses when CURLOPT_ENCODING is used, but stream fallback can still receive gzip.
    if ($body !== '' && substr($body, 0, 2) === "\x1f\x8b" && function_exists('gzdecode')) {
        $decoded = @gzdecode($body);
        if (is_string($decoded) && $decoded !== '') return $decoded;
    }
    return $body;
}

function symex_subscription_fetch_error(string $message, array $attempts = []): string {
    $message = trim($message) !== '' ? trim($message) : 'unknown_fetch_error';
    if (!empty($attempts)) {
        $tail = array_slice($attempts, -6);
        $message .= ' | attempts: ' . implode(' || ', $tail);
    }
    return function_exists('mb_substr') ? mb_substr($message, 0, 1800, 'UTF-8') : substr($message, 0, 1800);
}

function symex_allow_insecure_subscription_fetch(): bool {
    $settings = function_exists('load_settings') ? load_settings() : [];
    return !empty($settings['allow_insecure_subscription_fetch']);
}

function symex_ssl_context_options(): array {
    if (symex_allow_insecure_subscription_fetch()) {
        return [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'SNI_enabled' => true,
            'disable_compression' => false,
        ];
    }
    return [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'allow_self_signed' => false,
        'SNI_enabled' => true,
        'disable_compression' => false,
    ];
}

function symex_stream_fetch_subscription(string $url) {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 12,
            'ignore_errors' => true,
            'header' => "User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36\r\n" .
                        "Accept: text/plain, application/octet-stream, application/json, application/yaml, text/yaml, text/html, */*\r\n" .
                        "Accept-Language: fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7\r\n" .
                        "Accept-Encoding: gzip, deflate\r\n" .
                        "Cache-Control: no-cache\r\n" .
                        "Pragma: no-cache\r\n" .
                        "Connection: close\r\n"
        ],
        'ssl' => symex_ssl_context_options()
    ]);
    $content = @file_get_contents($url, false, $ctx);
    if (is_string($content) && trim($content) !== '') return symex_decode_http_body_if_needed($content);
    return false;
}

function symex_subscription_url_candidates(string $url): array {
    $url = symex_normalize_subscription_url($url);
    $candidates = [$url];
    if (stripos($url, 'https://') === 0 && symex_allow_insecure_subscription_fetch()) {
        // Some Marzban/subscription servers behind non-standard ports have broken TLS on PHP/cURL,
        // while browsers silently recover. Try plain HTTP only when the admin explicitly allows it.
        $candidates[] = 'http://' . substr($url, 8);
    }
    return array_values(array_unique(array_filter($candidates)));
}

function symex_curl_fetch_once(string $attemptUrl, array $opts): array {
    $ch = curl_init();
    if ($ch === false) {
        return ['ok' => false, 'body' => false, 'error' => 'curl_init_failed', 'http' => 0, 'effective' => $attemptUrl];
    }

    $headers = [
        'Accept: text/plain, application/octet-stream, application/json, application/yaml, text/yaml, text/html, */*',
        'Accept-Language: fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cache-Control: no-cache',
        'Pragma: no-cache',
        'Connection: close',
    ];

    $insecureTls = symex_allow_insecure_subscription_fetch();

    curl_setopt_array($ch, [
        CURLOPT_URL => $attemptUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_TIMEOUT => (int)($opts['timeout'] ?? 12),
        CURLOPT_CONNECTTIMEOUT => (int)($opts['connect_timeout'] ?? 6),
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_SSL_VERIFYPEER => !$insecureTls,
        CURLOPT_SSL_VERIFYHOST => $insecureTls ? 0 : 2,
        CURLOPT_USERAGENT => (string)($opts['ua'] ?? 'Mozilla/5.0'),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_ENCODING => '',
        CURLOPT_FAILONERROR => false,
        CURLOPT_FORBID_REUSE => true,
        CURLOPT_FRESH_CONNECT => true,
        CURLOPT_NOSIGNAL => true,
        CURLOPT_DNS_CACHE_TIMEOUT => 0,
    ]);

    if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
        @curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
        @curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    if (defined('CURLOPT_SSL_ENABLE_ALPN')) @curl_setopt($ch, CURLOPT_SSL_ENABLE_ALPN, false);
    if (defined('CURLOPT_SSL_ENABLE_NPN')) @curl_setopt($ch, CURLOPT_SSL_ENABLE_NPN, false);
    if (!empty($opts['ipresolve']) && defined('CURLOPT_IPRESOLVE')) @curl_setopt($ch, CURLOPT_IPRESOLVE, $opts['ipresolve']);
    if (!empty($opts['http_version']) && defined('CURLOPT_HTTP_VERSION')) @curl_setopt($ch, CURLOPT_HTTP_VERSION, $opts['http_version']);
    if (!empty($opts['doh']) && defined('CURLOPT_DOH_URL')) @curl_setopt($ch, CURLOPT_DOH_URL, $opts['doh']);
    if (!empty($opts['dns_servers']) && defined('CURLOPT_DNS_SERVERS')) @curl_setopt($ch, CURLOPT_DNS_SERVERS, $opts['dns_servers']);

    $body = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $effective = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $error = curl_error($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if (is_string($body)) $body = symex_decode_http_body_if_needed($body);
    return ['ok' => is_string($body) && trim($body) !== '', 'body' => $body, 'error' => $error ?: ('curl_errno_' . $errno), 'http' => $http, 'effective' => $effective ?: $attemptUrl];
}


function symex_http_post_json(string $url, array $payload, int $timeout = 18) {
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false) return ['ok' => false, 'body' => false, 'http' => 0, 'error' => 'json_encode_failed'];
    if (extension_loaded('curl')) {
        $ch = curl_init($url);
        if ($ch === false) return ['ok' => false, 'body' => false, 'http' => 0, 'error' => 'curl_init_failed'];
        $insecureTls = symex_allow_insecure_subscription_fetch();
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $json,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(8, $timeout),
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_SSL_VERIFYPEER => !$insecureTls,
            CURLOPT_SSL_VERIFYHOST => $insecureTls ? 0 : 2,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json, text/plain, */*'],
            CURLOPT_USERAGENT => 'SYMEX-Panel-Relay/2.0',
            CURLOPT_ENCODING => '',
            CURLOPT_NOSIGNAL => true,
        ]);
        $body = curl_exec($ch);
        $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch) ?: ('curl_errno_' . curl_errno($ch));
        curl_close($ch);
        return ['ok' => is_string($body) && trim($body) !== '', 'body' => is_string($body) ? symex_decode_http_body_if_needed($body) : false, 'http' => $http, 'error' => $error];
    }
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'timeout' => $timeout,
            'ignore_errors' => true,
            'header' => "Content-Type: application/json\r\nAccept: application/json, text/plain, */*\r\nUser-Agent: SYMEX-Panel-Relay/2.0\r\n",
            'content' => $json,
        ],
        'ssl' => symex_ssl_context_options(),
    ]);
    $body = @file_get_contents($url, false, $ctx);
    return ['ok' => is_string($body) && trim($body) !== '', 'body' => is_string($body) ? symex_decode_http_body_if_needed($body) : false, 'http' => 0, 'error' => 'stream_empty_or_failed'];
}

function symex_extract_relay_body($body) {
    if (!is_string($body) || trim($body) === '') return false;
    $trim = trim($body);
    $json = json_decode($trim, true);
    if (is_array($json)) {
        foreach (['content', 'body', 'data', 'subscription', 'raw'] as $k) {
            if (isset($json[$k]) && is_string($json[$k]) && trim($json[$k]) !== '') return $json[$k];
        }
        if (isset($json['configs']) && is_array($json['configs'])) {
            $configs = [];
            foreach ($json['configs'] as $c) if (is_string($c) && trim($c) !== '') $configs[] = trim($c);
            if (!empty($configs)) return implode("\n", $configs);
        }
        if (isset($json['ok']) && !$json['ok']) return false;
    }
    return $body;
}

function symex_fetch_subscription_via_relay(string $url) {
    $settings = function_exists('load_settings') ? load_settings() : [];
    if (empty($settings['subscription_relay_enabled'])) return false;
    $relayUrl = trim((string)($settings['subscription_relay_url'] ?? ''));
    if ($relayUrl === '' || !preg_match('/^https?:\/\//i', $relayUrl)) return false;
    $secret = (string)($settings['subscription_relay_secret'] ?? '');
    $payload = [
        'url' => $url,
        'secret' => $secret,
        'ua' => 'Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36',
        'timeout' => 18,
    ];
    $result = symex_http_post_json($relayUrl, $payload, 22);
    $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'][] = 'relay_post:http' . (int)($result['http'] ?? 0) . ':' . (($result['ok'] ?? false) ? 'body' : ($result['error'] ?? 'failed'));
    if (!empty($result['ok'])) {
        $content = symex_extract_relay_body($result['body']);
        if (is_string($content) && trim($content) !== '') {
            return $content;
        }
    }
    // Optional GET fallback for very small relay scripts.
    $sep = strpos($relayUrl, '?') === false ? '?' : '&';
    $getUrl = $relayUrl . $sep . 'url=' . rawurlencode($url) . '&secret=' . rawurlencode($secret);
    if (extension_loaded('curl')) {
        $r = symex_curl_fetch_once($getUrl, ['ua' => 'SYMEX-Panel-Relay/2.0', 'timeout' => 18, 'connect_timeout' => 8]);
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'][] = 'relay_get:http' . (int)($r['http'] ?? 0) . ':' . (($r['ok'] ?? false) ? 'body' : ($r['error'] ?? 'failed'));
        if (!empty($r['ok'])) {
            $content = symex_extract_relay_body($r['body']);
            if (is_string($content) && trim($content) !== '') return $content;
        }
    }
    return false;
}

function fetch_subscription_content(string $url) {
    if (function_exists('symex_sub_fetch_url')) {
        $result = symex_sub_fetch_url($url, symex_sub_settings_options());
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'] = $result['attempts'] ?? [];
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] = empty($result['ok'])
            ? symex_subscription_fetch_error((string)($result['error'] ?? 'fetch_failed'), $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'])
            : '';
        return !empty($result['ok']) && is_string($result['content'] ?? null) ? $result['content'] : false;
    }
    // Iran-friendly, bounded, no-hang subscription loader.
    // The previous loader tried a very large cartesian product of UA/IP/HTTP/DNS modes and could time out/500 on shared hosting.
    // This version uses ordered browser/client attempts with a hard deadline, relaxed TLS/SNI, IPv4 preference,
    // optional c-ares DNS servers, DoH fallback, stream fallback, gzip decode, and safe error reporting.
    $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] = '';
    $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'] = [];
    $url = symex_normalize_subscription_url($url);
    if ($url === '') {
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] = 'empty_url';
        return false;
    }
    if (!preg_match('/^https?:\/\//i', $url)) {
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] = 'invalid_url_scheme';
        return false;
    }

    @set_time_limit(75);
    $started = microtime(true);
    $deadlineSeconds = 42;
    $attemptLogs = [];
    $lastError = 'unknown_fetch_error';
    $urls = symex_subscription_url_candidates($url);

    // If the hosting provider cannot reach Iranian/mobile-accessible subscription hosts, use an optional relay.
    // This is the correct fix for timeout-only cases: the panel server has no route, while the user's browser/mobile network does.
    $relayContent = symex_fetch_subscription_via_relay($url);
    if (is_string($relayContent) && trim($relayContent) !== '') {
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'][] = 'relay:ok';
        return $relayContent;
    }

    if (!extension_loaded('curl')) {
        foreach ($urls as $u) {
            if ((microtime(true) - $started) > $deadlineSeconds) break;
            $content = symex_stream_fetch_subscription($u);
            if (is_string($content) && trim($content) !== '') return $content;
            $attemptLogs[] = 'stream:' . parse_url($u, PHP_URL_SCHEME) . ':empty';
        }
        $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] = symex_subscription_fetch_error('curl_missing_and_stream_fetch_failed', $attemptLogs);
        return false;
    }

    $uaChromeAndroid = 'Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36';
    $uaChromeDesktop = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
    $uaHapp = 'Happ/2.0 okhttp/4.12.0';
    $uaV2ray = 'v2rayNG/1.9.30 okhttp/4.12.0';
    $uaSingbox = 'sing-box/1.9.0';

    $v4 = defined('CURL_IPRESOLVE_V4') ? CURL_IPRESOLVE_V4 : null;
    $v6 = defined('CURL_IPRESOLVE_V6') ? CURL_IPRESOLVE_V6 : null;
    $h11 = defined('CURL_HTTP_VERSION_1_1') ? CURL_HTTP_VERSION_1_1 : null;
    $h2 = defined('CURL_HTTP_VERSION_2TLS') ? CURL_HTTP_VERSION_2TLS : null;

    $baseAttempts = [
        ['name' => 'chrome_android_ipv4_http11', 'ua' => $uaChromeAndroid, 'ipresolve' => $v4, 'http_version' => $h11],
        ['name' => 'happ_ipv4_http11', 'ua' => $uaHapp, 'ipresolve' => $v4, 'http_version' => $h11],
        ['name' => 'v2rayng_ipv4_http11', 'ua' => $uaV2ray, 'ipresolve' => $v4, 'http_version' => $h11],
        ['name' => 'chrome_default_http11', 'ua' => $uaChromeDesktop, 'http_version' => $h11],
        ['name' => 'singbox_default_http11', 'ua' => $uaSingbox, 'http_version' => $h11],
        ['name' => 'chrome_ipv4_http2', 'ua' => $uaChromeDesktop, 'ipresolve' => $v4, 'http_version' => $h2],
    ];
    if ($v6 !== null) $baseAttempts[] = ['name' => 'chrome_ipv6_http11', 'ua' => $uaChromeAndroid, 'ipresolve' => $v6, 'http_version' => $h11];

    $dnsAttempts = [];
    if (defined('CURLOPT_DNS_SERVERS')) {
        // Some Iranian/mobile-resolvable domains fail on hosting-provider DNS. Try common public + Iranian DNS if libcurl supports it.
        $dnsAttempts[] = ['name' => 'dns_google', 'ua' => $uaChromeAndroid, 'ipresolve' => $v4, 'http_version' => $h11, 'dns_servers' => '8.8.8.8,8.8.4.4'];
        $dnsAttempts[] = ['name' => 'dns_cloudflare', 'ua' => $uaChromeAndroid, 'ipresolve' => $v4, 'http_version' => $h11, 'dns_servers' => '1.1.1.1,1.0.0.1'];
        $dnsAttempts[] = ['name' => 'dns_iran_shecan', 'ua' => $uaChromeAndroid, 'ipresolve' => $v4, 'http_version' => $h11, 'dns_servers' => '178.22.122.100,185.51.200.2'];
    }
    if (defined('CURLOPT_DOH_URL')) {
        $dnsAttempts[] = ['name' => 'doh_cloudflare_ip', 'ua' => $uaChromeAndroid, 'ipresolve' => $v4, 'http_version' => $h11, 'doh' => 'https://1.1.1.1/dns-query'];
        $dnsAttempts[] = ['name' => 'doh_google', 'ua' => $uaChromeAndroid, 'ipresolve' => $v4, 'http_version' => $h11, 'doh' => 'https://dns.google/dns-query'];
    }

    $attempts = array_merge($baseAttempts, $dnsAttempts);
    foreach ($urls as $attemptUrl) {
        foreach ($attempts as $opts) {
            if ((microtime(true) - $started) > $deadlineSeconds) {
                $lastError = 'subscription_fetch_deadline_reached';
                break 2;
            }
            $opts['timeout'] = 10;
            $opts['connect_timeout'] = 5;
            $result = symex_curl_fetch_once($attemptUrl, $opts);
            $log = ($opts['name'] ?? 'attempt') . ':http' . $result['http'] . ':' . ($result['ok'] ? 'body' : $result['error']);
            $attemptLogs[] = $log;

            if ($result['ok']) {
                $body = (string)$result['body'];
                // Return any non-empty 2xx/3xx body. If it is an HTML/text wrapper, parser will decide.
                // Also accept non-2xx bodies when they visibly contain configs, because some panels send wrong status codes.
                if (($result['http'] >= 200 && $result['http'] < 400) || $result['http'] === 0 || symex_body_has_config_marker($body)) {
                    $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'] = $attemptLogs;
                    return $body;
                }
                $lastError = 'http_' . $result['http'] . '_body_without_config_marker';
            } else {
                $lastError = $result['error'] ?: ('http_' . $result['http'] . '_empty_body');
            }
        }
    }

    // Last chance with streams. This is intentionally after cURL attempts because some hosts behave differently.
    foreach ($urls as $u) {
        if ((microtime(true) - $started) > $deadlineSeconds) break;
        $content = symex_stream_fetch_subscription($u);
        if (is_string($content) && trim($content) !== '') {
            $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'] = $attemptLogs;
            return $content;
        }
        $attemptLogs[] = 'stream:' . parse_url($u, PHP_URL_SCHEME) . ':empty';
    }

    $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'] = $attemptLogs;
    $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] = symex_subscription_fetch_error($lastError, $attemptLogs);
    return false;
}

function get_supported_config_schemes(): array {
    if (function_exists('symex_sub_supported_schemes')) return symex_sub_supported_schemes();
    return ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'socks', 'socks5', 'wireguard', 'warp', 'anytls', 'snell'];
}

function clean_extracted_config(string $candidate): string {
    if (function_exists('symex_sub_clean_config')) return symex_sub_clean_config($candidate);
    $candidate = html_entity_decode($candidate, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $candidate = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $candidate);
    $candidate = str_replace(["\r\n", "\r"], "\n", $candidate);
    $candidate = trim($candidate);
    return trim($candidate, " \t\n\r\0\x0B\"'`<>[]{}،؛,");
}

function is_valid_config_uri(string $config): bool {
    if (function_exists('symex_sub_is_valid_config_uri')) return symex_sub_is_valid_config_uri($config);
    $config = clean_extracted_config($config);
    if ($config === '' || preg_match('/[\r\n]/', $config)) return false;
    if (!preg_match('/^([a-z][a-z0-9+.-]*):\/\/(.+)$/iu', $config, $m)) return false;

    $scheme = strtolower($m[1]);
    if (!in_array($scheme, get_supported_config_schemes(), true)) return false;

    $body = trim($m[2]);
    if (strlen($body) < 4) return false;

    if ($scheme === 'vmess') {
        $payload = preg_split('/\s+/u', $body)[0] ?? '';
        $payload = strtr($payload, '-_', '+/');
        $payload .= str_repeat('=', (4 - strlen($payload) % 4) % 4);
        $decoded = base64_decode($payload, true);
        if ($decoded !== false) {
            $json = json_decode($decoded, true);
            if (is_array($json) && (!empty($json['add']) || !empty($json['host'])) && (!empty($json['port']) || !empty($json['ps']))) {
                return true;
            }
        }
        return strlen($body) > 16;
    }

    if (in_array($scheme, ['vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'socks', 'socks5', 'wireguard', 'warp', 'anytls', 'snell'], true)) {
        if (preg_match('/^[a-z][a-z0-9+.-]*:\/\/(?:[^@\s\/?#]+@)?(\[[^\]]+\]|[^\/\s:?#]+):(\d{1,5})(?:[\/?#]|$)/iu', $config, $pm)) {
            $port = (int)$pm[2];
            return $port > 0 && $port <= 65535;
        }
        $parts = @parse_url($config);
        if (is_array($parts) && !empty($parts['host']) && !empty($parts['port'])) {
            $port = (int)$parts['port'];
            return $port > 0 && $port <= 65535;
        }
        return !in_array($scheme, ['vless', 'trojan'], true);
    }

    return true;
}

function symex_encoded_scheme_exists(string $text): bool {
    return (bool)preg_match('/(?:vless|vmess|trojan|ssr?|hysteria2?|hy2|tuic|socks5?|wireguard|warp|anytls|snell)%3A%2F%2F/iu', $text);
}

function symex_strip_non_uri_tail(string $candidate): string {
    $candidate = preg_split('/[\r\n]+/u', $candidate)[0] ?? $candidate;
    $candidate = preg_split('/<\/?(?:br|pre|div|span|p|body|html|code|textarea)\b[^>]*>/iu', $candidate)[0] ?? $candidate;
    $candidate = clean_extracted_config($candidate);

    // If there is no fragment, URI cannot contain raw whitespace.
    if (strpos($candidate, '#') === false && preg_match('/\s/u', $candidate)) {
        $candidate = preg_split('/\s+/u', $candidate)[0] ?? $candidate;
        $candidate = clean_extracted_config($candidate);
    }
    return $candidate;
}

function extract_configs_from_plain_text(string $text): array {
    $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    // Some panels/API wrappers encode line breaks as literal \n or \r\n. Convert them before URI boundary detection.
    $text = str_replace(["\\r\\n", "\\n", "\\r"], "\n", $text);
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $text = preg_replace('/<br\s*\/?>/iu', "\n", $text);
    $text = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $text);

    $schemes = array_map('preg_quote', get_supported_config_schemes());
    $schemePattern = implode('|', $schemes);
    $startPattern = '/(?:' . $schemePattern . '):\/\//iu';

    $starts = [];
    if (!preg_match_all($startPattern, $text, $m, PREG_OFFSET_CAPTURE)) {
        return [];
    }
    foreach ($m[0] as $hit) {
        $starts[] = $hit[1]; // byte offset, safe for substr
    }
    $starts = array_values(array_unique($starts));
    sort($starts, SORT_NUMERIC);

    $configs = [];
    $length = strlen($text);
    foreach ($starts as $i => $start) {
        $end = $starts[$i + 1] ?? $length;
        if ($end <= $start) continue;
        $candidate = substr($text, $start, $end - $start);
        $candidate = symex_strip_non_uri_tail($candidate);
        if (is_valid_config_uri($candidate)) {
            $configs[config_dedupe_key_for_parser($candidate)] = $candidate;
        }
    }

    return array_values($configs);
}

function config_dedupe_key_for_parser(string $config): string {
    $config = clean_extracted_config($config);
    if ($config === '') return sha1('');
    if (function_exists('config_dedupe_key')) {
        $key = config_dedupe_key($config);
        if ($key !== '') return $key;
    }
    return strtolower(preg_replace('/\s+/', '', rawurldecode($config)));
}

function decode_subscription_content_if_needed(string $raw): string {
    if (function_exists('symex_sub_extract_configs')) {
        $configs = symex_sub_extract_configs($raw);
        if (!empty($configs)) return implode("\n", $configs);
    }
    $trimmed = trim($raw);
    if ($trimmed === '') return '';

    $compact = preg_replace('/\s+/', '', $trimmed);
    if (strlen($compact) > 20 && preg_match('/^[A-Za-z0-9+\/_-]+={0,3}$/', $compact)) {
        $base64 = strtr($compact, '-_', '+/');
        $base64 .= str_repeat('=', (4 - strlen($base64) % 4) % 4);
        $decoded = base64_decode($base64, true);
        if ($decoded !== false && $decoded !== '') {
            $decodedConfigs = extract_configs_from_plain_text($decoded);
            if (!empty($decodedConfigs)) return $decoded;
            $urlDecoded = rawurldecode($decoded);
            if ($urlDecoded !== $decoded) {
                $decodedConfigs = extract_configs_from_plain_text($urlDecoded);
                if (!empty($decodedConfigs)) return $urlDecoded;
            }
        }
    }

    return $raw;
}

function collect_strings_from_json_value($value, array &$strings, int $depth = 0): void {
    if ($depth > 10) return;
    if (is_string($value)) {
        if (trim($value) !== '') $strings[] = $value;
        return;
    }
    if (is_array($value)) {
        foreach ($value as $k => $v) {
            if (is_string($k) && trim($k) !== '') $strings[] = $k;
            collect_strings_from_json_value($v, $strings, $depth + 1);
        }
    }
}

function symex_scalar_to_string($value): string {
    if (is_bool($value)) return $value ? 'true' : 'false';
    if (is_scalar($value)) return trim((string)$value);
    return '';
}

function symex_proxy_flatten_value($value, array &$out, string $prefix = '', int $depth = 0): void {
    if ($depth > 8 || !is_array($value)) return;
    foreach ($value as $k => $v) {
        $key = strtolower(str_replace('_', '-', trim((string)$k)));
        if ($key === '') continue;
        $fullKey = $prefix === '' ? $key : $prefix . '.' . $key;
        if (is_array($v)) {
            symex_proxy_flatten_value($v, $out, $fullKey, $depth + 1);
            continue;
        }
        $stringValue = symex_scalar_to_string($v);
        if ($stringValue === '') continue;
        $out[$fullKey] = $stringValue;
        if (!isset($out[$key])) $out[$key] = $stringValue;
    }
}

function symex_proxy_flatten_map(array $proxy): array {
    $out = [];
    symex_proxy_flatten_value($proxy, $out);
    return $out;
}

function symex_proxy_get(array $map, array $keys, string $default = ''): string {
    foreach ($keys as $key) {
        $key = strtolower(str_replace('_', '-', $key));
        if (isset($map[$key]) && trim((string)$map[$key]) !== '') {
            return trim((string)$map[$key]);
        }
    }
    return $default;
}

function symex_truthy($value): bool {
    if (is_bool($value)) return $value;
    $value = strtolower(trim((string)$value));
    return in_array($value, ['1', 'true', 'yes', 'on', 'enable', 'enabled', 'tls', 'reality'], true);
}

function symex_endpoint_host(string $server): string {
    $server = trim($server);
    if ($server !== '' && $server[0] !== '[' && strpos($server, ':') !== false) {
        return '[' . trim($server, '[]') . ']';
    }
    return $server;
}

function symex_query_string(array $params): string {
    $clean = [];
    foreach ($params as $key => $value) {
        if ($value === null) continue;
        $value = trim((string)$value);
        if ($value === '') continue;
        $clean[$key] = $value;
    }
    return http_build_query($clean, '', '&', PHP_QUERY_RFC3986);
}

function symex_proxy_fragment(string $name): string {
    $name = trim($name);
    return $name === '' ? '' : '#' . rawurlencode($name);
}

function symex_proxy_security(array $map): string {
    $security = strtolower(symex_proxy_get($map, ['security', 'security-type', 'tls-type']));
    if ($security === 'reality') return 'reality';
    if ($security === 'tls' || symex_truthy(symex_proxy_get($map, ['tls']))) return 'tls';
    return '';
}

function symex_proxy_network(array $map): string {
    $network = strtolower(symex_proxy_get($map, ['network', 'net', 'transport', 'transport.type']));
    if ($network === 'websocket') return 'ws';
    if ($network === 'h2') return 'http';
    return $network;
}

function symex_proxy_array_to_uri(array $proxy): string {
    $map = symex_proxy_flatten_map($proxy);
    $type = strtolower(symex_proxy_get($map, ['type', 'protocol']));
    if ($type === 'shadowsocks') $type = 'ss';
    if ($type === 'hysteria2') $type = 'hy2';
    if ($type === 'socks5') $type = 'socks';

    $server = symex_proxy_get($map, ['server', 'address', 'add', 'remote-address']);
    $port = (int)symex_proxy_get($map, ['port', 'server-port', 'remote-port']);
    if ($type === '' || $server === '' || $port <= 0 || $port > 65535) return '';

    $host = symex_endpoint_host($server);
    $endpoint = $host . ':' . $port;
    $name = symex_proxy_get($map, ['name', 'ps', 'remark', 'remarks'], $type . '-' . $server);
    $network = symex_proxy_network($map);
    $security = symex_proxy_security($map);
    $sni = symex_proxy_get($map, ['sni', 'servername', 'server-name', 'server-name', 'tls.servername', 'reality-opts.servername']);
    $path = symex_proxy_get($map, ['path', 'ws-path', 'ws-opts.path', 'grpc-opts.grpc-service-name', 'service-name']);
    $hostHeader = symex_proxy_get($map, ['ws-host', 'host', 'headers.host', 'ws-opts.headers.host', 'plugin-opts.host']);

    if ($type === 'vless') {
        $uuid = symex_proxy_get($map, ['uuid', 'id', 'user', 'username']);
        if ($uuid === '') return '';
        $params = [
            'encryption' => symex_proxy_get($map, ['encryption'], 'none'),
            'security' => $security === '' ? 'none' : $security,
            'type' => $network,
            'sni' => $sni,
            'host' => $hostHeader,
            'path' => $path,
            'flow' => symex_proxy_get($map, ['flow']),
            'fp' => symex_proxy_get($map, ['client-fingerprint', 'fingerprint', 'fp']),
            'pbk' => symex_proxy_get($map, ['public-key', 'reality-opts.public-key', 'pbk']),
            'sid' => symex_proxy_get($map, ['short-id', 'reality-opts.short-id', 'sid']),
            'spx' => symex_proxy_get($map, ['spider-x', 'reality-opts.spider-x', 'spx']),
        ];
        return 'vless://' . rawurlencode($uuid) . '@' . $endpoint . '?' . symex_query_string($params) . symex_proxy_fragment($name);
    }

    if ($type === 'vmess') {
        $uuid = symex_proxy_get($map, ['uuid', 'id', 'user', 'username']);
        if ($uuid === '') return '';
        $payload = [
            'v' => '2',
            'ps' => $name,
            'add' => $server,
            'port' => (string)$port,
            'id' => $uuid,
            'aid' => symex_proxy_get($map, ['alterid', 'alter-id', 'aid'], '0'),
            'scy' => symex_proxy_get($map, ['cipher', 'scy'], 'auto'),
            'net' => $network === '' ? 'tcp' : $network,
            'type' => symex_proxy_get($map, ['header-type'], 'none'),
            'host' => $hostHeader,
            'path' => $path,
            'tls' => $security === 'tls' ? 'tls' : '',
            'sni' => $sni,
        ];
        return 'vmess://' . base64_encode(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    if ($type === 'trojan') {
        $password = symex_proxy_get($map, ['password', 'passwd', 'uuid', 'id']);
        if ($password === '') return '';
        $params = [
            'security' => $security === '' ? 'tls' : $security,
            'type' => $network,
            'sni' => $sni,
            'host' => $hostHeader,
            'path' => $path,
        ];
        return 'trojan://' . rawurlencode($password) . '@' . $endpoint . '?' . symex_query_string($params) . symex_proxy_fragment($name);
    }

    if ($type === 'ss') {
        $method = symex_proxy_get($map, ['cipher', 'method']);
        $password = symex_proxy_get($map, ['password', 'passwd']);
        if ($method === '' || $password === '') return '';
        $userinfo = rtrim(strtr(base64_encode($method . ':' . $password), '+/', '-_'), '=');
        $plugin = symex_proxy_get($map, ['plugin']);
        $pluginParams = [];
        if ($plugin !== '') {
            $pluginValue = $plugin;
            $pluginHost = symex_proxy_get($map, ['plugin-opts.host', 'host']);
            $pluginPath = symex_proxy_get($map, ['plugin-opts.path', 'path']);
            if ($pluginHost !== '') $pluginValue .= ';host=' . $pluginHost;
            if ($pluginPath !== '') $pluginValue .= ';path=' . $pluginPath;
            if (symex_truthy(symex_proxy_get($map, ['plugin-opts.tls', 'tls']))) $pluginValue .= ';tls';
            $pluginParams['plugin'] = $pluginValue;
        }
        $query = symex_query_string($pluginParams);
        return 'ss://' . $userinfo . '@' . $endpoint . ($query === '' ? '' : '?' . $query) . symex_proxy_fragment($name);
    }

    if (in_array($type, ['hy2', 'hysteria'], true)) {
        $password = symex_proxy_get($map, ['password', 'auth', 'auth-str', 'auth-strs']);
        if ($password === '') return '';
        $params = [
            'sni' => $sni,
            'insecure' => symex_truthy(symex_proxy_get($map, ['skip-cert-verify', 'insecure'])) ? '1' : '',
            'obfs' => symex_proxy_get($map, ['obfs', 'obfs-password']),
        ];
        return ($type === 'hy2' ? 'hy2' : 'hysteria') . '://' . rawurlencode($password) . '@' . $endpoint . '?' . symex_query_string($params) . symex_proxy_fragment($name);
    }

    if ($type === 'tuic') {
        $uuid = symex_proxy_get($map, ['uuid', 'id']);
        $password = symex_proxy_get($map, ['password', 'passwd']);
        if ($uuid === '' || $password === '') return '';
        $params = [
            'sni' => $sni,
            'congestion_control' => symex_proxy_get($map, ['congestion-controller', 'congestion-control']),
            'udp_relay_mode' => symex_proxy_get($map, ['udp-relay-mode']),
        ];
        return 'tuic://' . rawurlencode($uuid) . ':' . rawurlencode($password) . '@' . $endpoint . '?' . symex_query_string($params) . symex_proxy_fragment($name);
    }

    if ($type === 'socks') {
        $user = symex_proxy_get($map, ['username', 'user']);
        $password = symex_proxy_get($map, ['password', 'passwd']);
        $auth = $user === '' ? '' : rawurlencode($user) . ($password === '' ? '' : ':' . rawurlencode($password)) . '@';
        return 'socks://' . $auth . $endpoint . symex_proxy_fragment($name);
    }

    return '';
}

function symex_yaml_unquote(string $value): string {
    $value = trim($value);
    $value = preg_replace('/\s+#.*$/u', '', $value);
    $value = trim($value, " \t\n\r\0\x0B,");
    if (strlen($value) >= 2) {
        $first = $value[0];
        $last = $value[strlen($value) - 1];
        if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
            $value = substr($value, 1, -1);
        }
    }
    return stripcslashes($value);
}

function symex_find_top_level_colon(string $text) {
    $quote = '';
    $depth = 0;
    $len = strlen($text);
    for ($i = 0; $i < $len; $i++) {
        $ch = $text[$i];
        if ($quote !== '') {
            if ($ch === $quote && ($i === 0 || $text[$i - 1] !== '\\')) $quote = '';
            continue;
        }
        if ($ch === '"' || $ch === "'") {
            $quote = $ch;
            continue;
        }
        if ($ch === '{' || $ch === '[' || $ch === '(') $depth++;
        if ($ch === '}' || $ch === ']' || $ch === ')') $depth = max(0, $depth - 1);
        if ($ch === ':' && $depth === 0) return $i;
    }
    return false;
}

function symex_split_top_level_commas(string $text): array {
    $parts = [];
    $buf = '';
    $quote = '';
    $depth = 0;
    $len = strlen($text);
    for ($i = 0; $i < $len; $i++) {
        $ch = $text[$i];
        if ($quote !== '') {
            $buf .= $ch;
            if ($ch === $quote && ($i === 0 || $text[$i - 1] !== '\\')) $quote = '';
            continue;
        }
        if ($ch === '"' || $ch === "'") {
            $quote = $ch;
            $buf .= $ch;
            continue;
        }
        if ($ch === '{' || $ch === '[' || $ch === '(') $depth++;
        if ($ch === '}' || $ch === ']' || $ch === ')') $depth = max(0, $depth - 1);
        if ($ch === ',' && $depth === 0) {
            $parts[] = trim($buf);
            $buf = '';
            continue;
        }
        $buf .= $ch;
    }
    if (trim($buf) !== '') $parts[] = trim($buf);
    return $parts;
}

function symex_parse_inline_yaml_map_into(string $text, array &$out, string $prefix = ''): void {
    $text = trim($text);
    if ($text !== '' && $text[0] === '{' && substr($text, -1) === '}') {
        $text = substr($text, 1, -1);
    }
    foreach (symex_split_top_level_commas($text) as $part) {
        $pos = symex_find_top_level_colon($part);
        if ($pos === false) continue;
        $key = strtolower(str_replace('_', '-', trim(substr($part, 0, $pos), " \t\n\r\0\x0B\"'")));
        $value = trim(substr($part, $pos + 1));
        if ($key === '') continue;
        $fullKey = $prefix === '' ? $key : $prefix . '.' . $key;
        if ($value !== '' && $value[0] === '{' && substr($value, -1) === '}') {
            symex_parse_inline_yaml_map_into($value, $out, $fullKey);
            continue;
        }
        $out[$fullKey] = symex_yaml_unquote($value);
        if (!isset($out[$key])) $out[$key] = $out[$fullKey];
    }
}

function symex_extract_yaml_proxy_arrays(string $text): array {
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $lines = preg_split('/\n/u', $text) ?: [];
    $proxies = [];
    $current = null;
    $section = '';

    foreach ($lines as $line) {
        $line = rtrim($line);
        if (trim($line) === '' || preg_match('/^\s*#/u', $line)) continue;

        if (preg_match('/^\s*-\s*(.+)$/u', $line, $m)) {
            if (is_array($current) && !empty($current)) $proxies[] = $current;
            $current = [];
            $section = '';
            $rest = trim($m[1]);
            if ($rest !== '' && $rest[0] === '{') {
                symex_parse_inline_yaml_map_into($rest, $current);
            } else {
                $pos = symex_find_top_level_colon($rest);
                if ($pos !== false) {
                    $key = strtolower(str_replace('_', '-', trim(substr($rest, 0, $pos))));
                    $value = symex_yaml_unquote(substr($rest, $pos + 1));
                    if ($key !== '') $current[$key] = $value;
                }
            }
            continue;
        }

        if (!is_array($current)) continue;
        if (preg_match('/^\s*([A-Za-z0-9_.-]+)\s*:\s*(.*)$/u', $line, $m)) {
            $key = strtolower(str_replace('_', '-', trim($m[1])));
            $value = trim($m[2]);
            if ($value === '') {
                $section = $key;
                continue;
            }
            $value = symex_yaml_unquote($value);
            $fullKey = $section === '' ? $key : $section . '.' . $key;
            $current[$fullKey] = $value;
            if (!isset($current[$key])) $current[$key] = $value;
        }
    }

    if (is_array($current) && !empty($current)) $proxies[] = $current;
    return $proxies;
}

function symex_collect_proxy_arrays_from_json($value, array &$out, int $depth = 0): void {
    if ($depth > 10 || !is_array($value)) return;
    $map = symex_proxy_flatten_map($value);
    $type = strtolower(symex_proxy_get($map, ['type', 'protocol']));
    $server = symex_proxy_get($map, ['server', 'address', 'add', 'remote-address']);
    $port = (int)symex_proxy_get($map, ['port', 'server-port', 'remote-port']);
    if ($type !== '' && $server !== '' && $port > 0) {
        $out[] = $value;
    }
    foreach ($value as $child) {
        if (is_array($child)) symex_collect_proxy_arrays_from_json($child, $out, $depth + 1);
    }
}

function symex_extract_structured_proxy_configs(string $text): array {
    $items = [];
    $json = json_decode(trim($text), true);
    if (is_array($json)) {
        symex_collect_proxy_arrays_from_json($json, $items);
    }
    foreach (symex_extract_yaml_proxy_arrays($text) as $proxy) {
        $items[] = $proxy;
    }

    $configs = [];
    foreach ($items as $proxy) {
        if (!is_array($proxy)) continue;
        $uri = symex_proxy_array_to_uri($proxy);
        if ($uri !== '' && is_valid_config_uri($uri)) {
            $configs[config_dedupe_key_for_parser($uri)] = $uri;
        }
    }
    return array_values($configs);
}

function maybe_decode_base64_text(string $text) {
    $candidate = preg_replace('/\s+/', '', trim($text));
    if ($candidate === '' || strlen($candidate) < 16) return false;
    if (!preg_match('/^[A-Za-z0-9+\/_-]+={0,3}$/', $candidate)) return false;
    $candidate = strtr($candidate, '-_', '+/');
    $candidate .= str_repeat('=', (4 - strlen($candidate) % 4) % 4);
    $decoded = base64_decode($candidate, true);
    if ($decoded === false || trim($decoded) === '') return false;
    if (preg_match('/[\x00-\x08\x0E-\x1F]/', $decoded)) return false;
    return $decoded;
}

function extract_configs_from_text(string $text): array {
    if (function_exists('symex_sub_extract_configs')) return symex_sub_extract_configs($text);
    // Strict recursive extractor for raw URI lists, glued configs, Base64 subscriptions,
    // URL-encoded subscriptions, JSON wrappers, simple YAML/HTML pages, and mixed plain text.
    $queue = [$text];
    $seenText = [];
    $configs = [];
    $rounds = 0;

    while (!empty($queue) && $rounds < 80) {
        $rounds++;
        $current = array_shift($queue);
        if (!is_string($current)) continue;
        $current = html_entity_decode($current, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $current = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $current);
        $current = str_replace('\\/', '/', $current);
        $current = str_ireplace(['\\u003a', '\\u002f', '\\u003f', '\\u0026', '\\u003d'], [':', '/', '?', '&', '='], $current);
        $hash = sha1($current);
        if (isset($seenText[$hash])) continue;
        $seenText[$hash] = true;

        $plainConfigs = extract_configs_from_plain_text($current);
        foreach ($plainConfigs as $config) {
            $configs[config_dedupe_key_for_parser($config)] = $config;
        }

        $structuredConfigs = symex_extract_structured_proxy_configs($current);
        foreach ($structuredConfigs as $config) {
            $configs[config_dedupe_key_for_parser($config)] = $config;
        }
        $foundPlain = !empty($plainConfigs) || !empty($structuredConfigs);

        // Decode the entire body only when it is a real subscription wrapper, not a raw config list.
        // This prevents duplicate/extra fake configs from query parameters like pbk/extra.
        $decodedWholeBase64 = false;
        if (!$foundPlain) {
            $decodedFull = maybe_decode_base64_text($current);
            if (is_string($decodedFull)) {
                $decodedWholeBase64 = true;
                if (!isset($seenText[sha1($decodedFull)])) {
                    $queue[] = $decodedFull;
                }
            }
        }

        // URL-decode only when there are no raw configs or when encoded protocol markers exist.
        if (!$foundPlain || symex_encoded_scheme_exists($current)) {
            $urlDecoded = rawurldecode($current);
            if ($urlDecoded !== $current && !isset($seenText[sha1($urlDecoded)])) {
                $queue[] = $urlDecoded;
            }
        }

        $stripped = trim(strip_tags($current));
        if ($stripped !== '' && $stripped !== $current && !isset($seenText[sha1($stripped)])) {
            $queue[] = $stripped;
        }

        $json = json_decode(trim($current), true);
        if (is_array($json)) {
            $strings = [];
            collect_strings_from_json_value($json, $strings);
            foreach ($strings as $s) {
                if (!isset($seenText[sha1($s)])) $queue[] = $s;
            }
        }

        // Decode embedded Base64 blobs only when no raw configs were found in this text.
        // This avoids decoding random base64-like values inside VLESS query parameters.
        if (!$foundPlain && !$decodedWholeBase64 && preg_match_all('/(?<![A-Za-z0-9+\/_-])([A-Za-z0-9+\/_-]{48,}={0,3})(?![A-Za-z0-9+\/_-])/u', $current, $m)) {
            foreach ($m[1] as $blob) {
                $decodedBlob = maybe_decode_base64_text($blob);
                if (is_string($decodedBlob) && !isset($seenText[sha1($decodedBlob)])) {
                    $queue[] = $decodedBlob;
                }
            }
        }
    }

    return array_values($configs);
}

function config_dedupe_key(string $config): string {
    $config = clean_extracted_config($config);
    if ($config === '') return '';
    if (!preg_match('/^([a-z][a-z0-9+.-]*):\/\/(.+)$/iu', $config, $m)) {
        return sha1($config);
    }
    $scheme = strtolower($m[1]);
    if ($scheme === 'vmess') {
        $payload = preg_split('/[#?\s]/u', $m[2])[0] ?? $m[2];
        $payload = strtr($payload, '-_', '+/');
        $payload .= str_repeat('=', (4 - strlen($payload) % 4) % 4);
        $decoded = base64_decode($payload, true);
        if ($decoded !== false) {
            $json = json_decode($decoded, true);
            if (is_array($json)) {
                ksort($json);
                return 'vmess:' . sha1(json_encode($json, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
        }
        return 'vmess:' . sha1(preg_replace('/\s+/', '', $m[2]));
    }
    if ($scheme === 'ss') {
        return 'ss:' . sha1(rawurldecode(preg_replace('/\s+/', '', $m[2])));
    }
    $parts = @parse_url($config);
    if (!is_array($parts)) return $scheme . ':' . sha1(rawurldecode($m[2]));
    $host = strtolower(trim((string)($parts['host'] ?? ''), '[]'));
    $port = (int)($parts['port'] ?? 0);
    $user = rawurldecode((string)($parts['user'] ?? ''));
    $path = rawurldecode((string)($parts['path'] ?? ''));
    $fragment = rawurldecode((string)($parts['fragment'] ?? ''));
    $query = [];
    parse_str((string)($parts['query'] ?? ''), $query);
    if (is_array($query)) ksort($query);
    return $scheme . '://' . $user . '@' . $host . ':' . $port . $path . '?' . json_encode($query, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . '#' . $fragment;
}

function normalize_config_list(array $items): array {
    if (function_exists('symex_sub_normalize_config_list')) return symex_sub_normalize_config_list($items);
    $configs = [];
    foreach ($items as $item) {
        if (!is_string($item)) continue;
        $found = extract_configs_from_text($item);
        if (empty($found) && is_valid_config_uri($item)) {
            $found = [clean_extracted_config($item)];
        }
        foreach ($found as $config) {
            $config = clean_extracted_config($config);
            if (!is_valid_config_uri($config)) continue;
            $key = config_dedupe_key($config);
            if ($key === '') $key = $config;
            if (!isset($configs[$key])) $configs[$key] = $config;
        }
    }
    return array_values($configs);
}

function append_configs_to_license(array &$licenseRow, array $newConfigs): array {
    if (!isset($licenseRow['configs']) || !is_array($licenseRow['configs'])) {
        $licenseRow['configs'] = [];
    }

    $existing = normalize_config_list($licenseRow['configs']);
    $seen = [];
    foreach ($existing as $existingConfig) {
        $seen[config_dedupe_key($existingConfig)] = true;
    }
    $added = 0;

    foreach ($newConfigs as $config) {
        $config = clean_extracted_config((string)$config);
        $key = config_dedupe_key($config);
        if (!is_valid_config_uri($config) || isset($seen[$key])) continue;
        $licenseRow['configs'][] = $config;
        $seen[$key] = true;
        $added++;
    }

    return ['added' => $added, 'duplicates' => max(0, count($newConfigs) - $added)];
}

function symex_subscription_log_message(string $level, string $message, string $licenseKey = ''): void {
    if (function_exists('add_log')) {
        add_log($level, $message, $licenseKey);
    } elseif (function_exists('addLog')) {
        addLog('subscription', $message);
    }
}

function symex_log_subscription_event(array &$licenseRow, string $event, array $data = []): void {
    if (!isset($licenseRow['subscription_logs']) || !is_array($licenseRow['subscription_logs'])) {
        $licenseRow['subscription_logs'] = [];
    }
    $entry = array_merge([
        'timestamp' => date('Y-m-d H:i:s'),
        'event' => $event,
    ], $data);
    $licenseRow['subscription_logs'][] = $entry;
    if (count($licenseRow['subscription_logs']) > 80) {
        $licenseRow['subscription_logs'] = array_slice($licenseRow['subscription_logs'], -80);
    }
}


function symex_clear_subscription_cache(array &$licenseRow, string $reason = 'cleared', bool $clearUrl = true): void {
    if ($clearUrl) $licenseRow['subscription_url'] = '';
    $licenseRow['subscription_content'] = '';
    $licenseRow['subscription_last_good_content'] = '';
    $licenseRow['subscription_last_good_update'] = null;
    $licenseRow['subscription_last_good_count'] = 0;
    $licenseRow['last_subscription_update'] = null;
    $licenseRow['last_subscription_attempt'] = null;
    $licenseRow['last_subscription_status'] = 'no_url';
    $licenseRow['last_subscription_error'] = '';
    $licenseRow['subscription_config_count'] = 0;
    $licenseRow['subscription_cache_used'] = false;
    $licenseRow['last_subscription_cache_used_at'] = null;
    $licenseRow['last_subscription_test'] = [];
    $licenseRow['last_delivery_source'] = 'manual';
    symex_log_subscription_event($licenseRow, 'subscription_cache_cleared', [
        'status' => 'no_url',
        'configs_found' => 0,
        'cache_used' => false,
        'message' => $reason,
    ]);
}

function symex_subscription_fetch_meta(string $url, $content = false): array {
    return [
        'url' => $url,
        'content_bytes' => is_string($content) ? strlen($content) : 0,
        'fetch_error' => $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] ?? '',
        'fetch_attempts' => $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ATTEMPTS'] ?? [],
        'checked_at' => date('Y-m-d H:i:s'),
    ];
}

function symex_get_last_good_subscription_configs(array $licenseRow): array {
    $lastGood = (string)($licenseRow['subscription_last_good_content'] ?? '');
    if ($lastGood === '') {
        $lastGood = (string)($licenseRow['subscription_content'] ?? '');
    }
    $configs = $lastGood !== '' ? extract_configs_from_text($lastGood) : [];
    return normalize_config_list($configs);
}

function symex_use_last_good_subscription_cache(array &$licenseRow, string $status, string $message, string $licenseKey = '', array $meta = []): array {
    $cachedConfigs = symex_get_last_good_subscription_configs($licenseRow);
    if (empty($cachedConfigs)) {
        $licenseRow['subscription_content'] = '';
        $licenseRow['last_subscription_status'] = $status;
        $licenseRow['last_subscription_error'] = $message;
        $licenseRow['subscription_config_count'] = 0;
        $licenseRow['subscription_cache_used'] = false;
        symex_log_subscription_event($licenseRow, $status, array_merge($meta, [
            'status' => $status,
            'configs_found' => 0,
            'cache_used' => false,
            'message' => $message,
        ]));
        return ['status' => $status, 'count' => 0, 'message' => $message . '; manual configs will be used', 'cache_used' => false];
    }

    $licenseRow['subscription_content'] = implode("
", $cachedConfigs);
    $licenseRow['last_subscription_status'] = $status . '_using_cache';
    $licenseRow['last_subscription_error'] = $message . ' Last healthy subscription cache is being used.';
    $licenseRow['subscription_config_count'] = count($cachedConfigs);
    $licenseRow['subscription_cache_used'] = true;
    $licenseRow['last_subscription_cache_used_at'] = date('Y-m-d H:i:s');
    symex_log_subscription_event($licenseRow, $status . '_using_cache', array_merge($meta, [
        'status' => $status . '_using_cache',
        'configs_found' => 0,
        'cache_used' => true,
        'cache_count' => count($cachedConfigs),
        'message' => $message,
    ]));
    return ['status' => $status . '_using_cache', 'count' => count($cachedConfigs), 'message' => $message . '; using last healthy subscription cache', 'cache_used' => true];
}

function update_subscription_cache_for_license(array &$licenseRow, string $licenseKey = ''): array {
    if (empty($licenseRow['subscription_url'])) {
        symex_clear_subscription_cache($licenseRow, 'No subscription URL; subscription cache cleared so manual configs are used.', false);
        return ['status' => 'no_url', 'count' => 0, 'message' => 'No subscription URL; cache cleared', 'cache_used' => false];
    }

    $url = trim((string)$licenseRow['subscription_url']);
    $licenseRow['last_subscription_attempt'] = date('Y-m-d H:i:s');
    $licenseRow['subscription_cache_used'] = false;

    if (function_exists('symex_sub_fetch_and_parse')) {
        $result = symex_sub_fetch_and_parse($url, symex_sub_settings_options());
        $meta = [
            'url' => $url,
            'content_bytes' => (int)($result['content_bytes'] ?? 0),
            'fetch_error' => (string)($result['fetch_error'] ?? ''),
            'attempts' => array_slice((array)($result['attempts'] ?? []), -8),
        ];
        if (!empty($result['ok']) && !empty($result['configs'])) {
            $configs = normalize_config_list((array)$result['configs']);
            $cleanContent = implode("\n", $configs);
            $licenseRow['subscription_content'] = $cleanContent;
            $licenseRow['subscription_last_good_content'] = $cleanContent;
            $licenseRow['subscription_last_good_update'] = date('Y-m-d H:i:s');
            $licenseRow['subscription_last_good_count'] = count($configs);
            $licenseRow['last_subscription_update'] = date('Y-m-d H:i:s');
            $licenseRow['last_subscription_status'] = 'ok';
            $licenseRow['last_subscription_error'] = '';
            $licenseRow['subscription_config_count'] = count($configs);
            $licenseRow['subscription_cache_used'] = false;
            symex_log_subscription_event($licenseRow, 'ok', array_merge($meta, [
                'status' => 'ok',
                'configs_found' => count($configs),
                'cache_used' => false,
                'message' => 'Subscription updated by v2 parser and saved as last healthy cache',
            ]));
            if ($licenseKey !== '') symex_subscription_log_message('info', "Subscription updated for $licenseKey (" . count($configs) . " configs) with v2 parser", $licenseKey);
            return ['status' => 'ok', 'count' => count($configs), 'message' => 'Subscription updated: ' . count($configs) . ' configs', 'cache_used' => false];
        }

        $status = (string)($result['status'] ?? 'invalid_content');
        $message = (string)($result['message'] ?? 'Subscription could not be parsed.');
        $fallback = symex_use_last_good_subscription_cache($licenseRow, $status, $message, $licenseKey, $meta);
        if ($licenseKey !== '') {
            symex_subscription_log_message('error', "Subscription update failed for $licenseKey; " . (!empty($fallback['cache_used']) ? 'last healthy cache is being used' : 'manual configs will be used'), $licenseKey);
        }
        return $fallback;
    }

    $content = fetch_subscription_content($url);
    $meta = symex_subscription_fetch_meta($url, $content);

    if ($content === false) {
        $message = 'Subscription URL did not return valid content: ' . ($GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] ?? 'unknown_fetch_error');
        $result = symex_use_last_good_subscription_cache($licenseRow, 'fetch_failed', $message, $licenseKey, $meta);
        if ($licenseKey !== '') {
            symex_subscription_log_message('error', "Subscription fetch failed for $licenseKey; " . ($result['cache_used'] ? 'last healthy cache is being used' : 'manual configs will be used'), $licenseKey);
        }
        return $result;
    }

    $configs = normalize_config_list(extract_configs_from_text($content));
    if (empty($configs)) {
        $message = 'Subscription content did not contain any supported config URI.';
        $result = symex_use_last_good_subscription_cache($licenseRow, 'invalid_content', $message, $licenseKey, $meta);
        if ($licenseKey !== '') {
            symex_subscription_log_message('error', "Subscription content invalid for $licenseKey; " . ($result['cache_used'] ? 'last healthy cache is being used' : 'manual configs will be used'), $licenseKey);
        }
        return $result;
    }

    $cleanContent = implode("
", $configs);
    $licenseRow['subscription_content'] = $cleanContent;
    $licenseRow['subscription_last_good_content'] = $cleanContent;
    $licenseRow['subscription_last_good_update'] = date('Y-m-d H:i:s');
    $licenseRow['subscription_last_good_count'] = count($configs);
    $licenseRow['last_subscription_update'] = date('Y-m-d H:i:s');
    $licenseRow['last_subscription_status'] = 'ok';
    $licenseRow['last_subscription_error'] = '';
    $licenseRow['subscription_config_count'] = count($configs);
    $licenseRow['subscription_cache_used'] = false;
    symex_log_subscription_event($licenseRow, 'ok', array_merge($meta, [
        'status' => 'ok',
        'configs_found' => count($configs),
        'cache_used' => false,
        'message' => 'Subscription updated and saved as last healthy cache',
    ]));
    if ($licenseKey !== '') symex_subscription_log_message('info', "Subscription updated for $licenseKey (" . count($configs) . " configs) and saved as last healthy cache", $licenseKey);
    return ['status' => 'ok', 'count' => count($configs), 'message' => 'Subscription updated', 'cache_used' => false];
}





function get_combined_configs(array &$licenseRow): array {
    // Subscription and manual configs must not be merged. Manual configs are fallback only.
    // Priority: current parsed subscription -> last healthy subscription cache -> manual configs.
    $subscriptionConfigs = [];
    if (!empty($licenseRow['subscription_content'])) {
        $subscriptionConfigs = normalize_config_list(extract_configs_from_text((string)$licenseRow['subscription_content']));
    }
    if (!empty($subscriptionConfigs)) {
        $licenseRow['last_delivery_source'] = !empty($licenseRow['subscription_cache_used']) ? 'subscription_cache' : 'subscription';
        return $subscriptionConfigs;
    }

    $lastGoodConfigs = [];
    if (!empty($licenseRow['subscription_last_good_content'])) {
        $lastGoodConfigs = normalize_config_list(extract_configs_from_text((string)$licenseRow['subscription_last_good_content']));
    }
    if (!empty($lastGoodConfigs)) {
        $licenseRow['subscription_content'] = implode("
", $lastGoodConfigs);
        $licenseRow['subscription_config_count'] = count($lastGoodConfigs);
        $licenseRow['subscription_cache_used'] = true;
        $licenseRow['last_delivery_source'] = 'subscription_last_good_cache';
        return $lastGoodConfigs;
    }

    $licenseRow['last_delivery_source'] = 'manual_fallback';
    return normalize_config_list(isset($licenseRow['configs']) && is_array($licenseRow['configs']) ? $licenseRow['configs'] : []);
}

// ============================================================
// CONFIG QUALITY, DEDUPLICATION & BEST SERVER SELECTION
// Live speed/delay tests and server-side ping are intentionally removed. Selection is deterministic,
// safe for shared hosting, and does not require core/Sing-box/proc_open.
// ============================================================

function config_hash(string $config): string {
    return hash('sha256', clean_extracted_config($config));
}

function configs_delivery_hash(array $configs): string {
    $clean = [];
    foreach (normalize_config_list($configs) as $config) {
        $clean[] = clean_extracted_config($config);
    }
    return empty($clean) ? '' : hash('sha256', implode("\n", $clean));
}


// ============================================================
// SYMEX MODE ROLE HELPERS (Smart / Gaming / Browsing)
// ============================================================

function symex_mode_keys(): array {
    return ['gaming', 'browsing'];
}

function symex_normalize_mode_name(string $mode): string {
    $mode = strtolower(trim($mode));
    $aliases = [
        'game' => 'gaming',
        'gaming' => 'gaming',
        'gamer' => 'gaming',
        'web' => 'browsing',
        'browse' => 'browsing',
        'browser' => 'browsing',
        'browsing' => 'browsing',
        'surf' => 'browsing',
        'smart' => 'smart',
        'auto' => 'smart',
    ];
    return $aliases[$mode] ?? $mode;
}

function symex_bool_from_post_value($value): bool {
    if (is_bool($value)) return $value;
    if (is_int($value) || is_float($value)) return ((int)$value) === 1;
    $value = strtolower(trim((string)$value));
    return in_array($value, ['1', 'true', 'yes', 'on', 'checked'], true);
}

function symex_ensure_config_roles(array &$licenseRow): array {
    if (!isset($licenseRow['config_roles']) || !is_array($licenseRow['config_roles'])) {
        $licenseRow['config_roles'] = [];
    }

    $allowedHashes = [];
    $sources = [];
    if (isset($licenseRow['configs']) && is_array($licenseRow['configs'])) {
        $sources = array_merge($sources, normalize_config_list($licenseRow['configs']));
    }
    foreach (['subscription_content', 'subscription_last_good_content'] as $field) {
        if (!empty($licenseRow[$field])) {
            $sources = array_merge($sources, normalize_config_list(extract_configs_from_text((string)$licenseRow[$field])));
        }
    }
    foreach ($sources as $cfg) {
        if (is_valid_config_uri($cfg)) $allowedHashes[config_hash($cfg)] = true;
    }

    $clean = [];
    foreach ($licenseRow['config_roles'] as $hash => $roles) {
        $hash = preg_replace('/[^a-f0-9]/i', '', (string)$hash);
        if ($hash === '') continue;
        if (!empty($allowedHashes) && !isset($allowedHashes[$hash])) continue;
        if (!is_array($roles)) $roles = [];
        $row = [];
        foreach (symex_mode_keys() as $mode) {
            $row[$mode] = !empty($roles[$mode]);
        }
        if ($row['gaming'] || $row['browsing']) $clean[$hash] = $row;
    }
    $licenseRow['config_roles'] = $clean;
    return $clean;
}

function symex_set_config_roles_for_hash(array &$licenseRow, string $hash, array $roles): void {
    $hash = preg_replace('/[^a-f0-9]/i', '', $hash);
    if ($hash === '') return;
    symex_ensure_config_roles($licenseRow);
    $row = [];
    foreach (symex_mode_keys() as $mode) {
        $row[$mode] = !empty($roles[$mode]);
    }
    if ($row['gaming'] || $row['browsing']) {
        $licenseRow['config_roles'][$hash] = $row;
    } else {
        unset($licenseRow['config_roles'][$hash]);
    }
}

function symex_set_config_roles_for_config(array &$licenseRow, string $config, array $roles): void {
    if (!is_valid_config_uri($config)) return;
    symex_set_config_roles_for_hash($licenseRow, config_hash($config), $roles);
}

function symex_remove_config_roles_for_config(array &$licenseRow, string $config): void {
    if (!is_valid_config_uri($config)) return;
    symex_ensure_config_roles($licenseRow);
    unset($licenseRow['config_roles'][config_hash($config)]);
}

function symex_get_config_roles(array $licenseRow, string $config): array {
    $hash = is_valid_config_uri($config) ? config_hash($config) : '';
    $roles = ($hash !== '' && isset($licenseRow['config_roles'][$hash]) && is_array($licenseRow['config_roles'][$hash]))
        ? $licenseRow['config_roles'][$hash]
        : [];
    return [
        'gaming' => !empty($roles['gaming']),
        'browsing' => !empty($roles['browsing']),
    ];
}

function symex_config_has_mode(array $licenseRow, string $config, string $mode): bool {
    $mode = symex_normalize_mode_name($mode);
    if ($mode === 'smart') return true;
    if (!in_array($mode, symex_mode_keys(), true)) return false;
    $roles = symex_get_config_roles($licenseRow, $config);
    return !empty($roles[$mode]);
}

function symex_rank_config_subset_for_mode(array &$licenseRow, array $configs, string $mode): array {
    $mode = symex_normalize_mode_name($mode);
    $configs = normalize_config_list($configs);
    if ($mode !== 'smart') {
        $configs = array_values(array_filter($configs, function ($cfg) use ($licenseRow, $mode) {
            return symex_config_has_mode($licenseRow, $cfg, $mode);
        }));
    }
    if (empty($configs)) return ['configs' => [], 'best_config' => '', 'best_config_hash' => ''];

    $ranked = [];
    foreach ($configs as $idx => $config) {
        $ranked[] = [
            'config' => $config,
            'quality' => strip_server_ping_fields(config_static_quality_score($config, $idx)),
            'index' => $idx,
        ];
    }
    usort($ranked, function ($a, $b) {
        $sa = $a['quality']['score'] ?? 0;
        $sb = $b['quality']['score'] ?? 0;
        if ($sa != $sb) return $sb <=> $sa;
        return $a['index'] <=> $b['index'];
    });
    $sorted = array_map(function ($item) { return $item['config']; }, $ranked);
    $best = $sorted[0] ?? '';
    return [
        'configs' => $sorted,
        'best_config' => $best,
        'best_config_hash' => $best !== '' ? config_hash($best) : '',
    ];
}

function symex_build_mode_delivery_meta(array &$licenseRow, array $allConfigs): array {
    symex_ensure_config_roles($licenseRow);
    $smart = symex_rank_config_subset_for_mode($licenseRow, $allConfigs, 'smart');
    $gaming = symex_rank_config_subset_for_mode($licenseRow, $allConfigs, 'gaming');
    $browsing = symex_rank_config_subset_for_mode($licenseRow, $allConfigs, 'browsing');

    $roleMap = [];
    foreach (normalize_config_list($allConfigs) as $config) {
        $hash = config_hash($config);
        $roles = symex_get_config_roles($licenseRow, $config);
        if ($roles['gaming'] || $roles['browsing']) {
            $roleMap[$hash] = $roles;
        }
    }

    return [
        'smart_config' => $smart['best_config'],
        'gaming_config' => $gaming['best_config'],
        'browsing_config' => $browsing['best_config'],
        'smart_configs' => $smart['configs'],
        'gaming_configs' => $gaming['configs'],
        'browsing_configs' => $browsing['configs'],
        'mode_configs' => [
            'smart' => $smart['configs'],
            'gaming' => $gaming['configs'],
            'browsing' => $browsing['configs'],
        ],
        'mode_config_hashes' => [
            'smart' => array_values(array_map('config_hash', $smart['configs'])),
            'gaming' => array_values(array_map('config_hash', $gaming['configs'])),
            'browsing' => array_values(array_map('config_hash', $browsing['configs'])),
        ],
        'config_roles' => $roleMap,
        'mode_selection_version' => '2026-06-21-panel-tagged-modes-v1',
    ];
}

function preview_text_safe(string $text, int $length = 90): string {
    return function_exists('mb_substr') ? mb_substr($text, 0, $length, 'UTF-8') : substr($text, 0, $length);
}

function decode_base64_urlsafe_payload(string $payload) {
    $payload = trim($payload);
    $payload = preg_split('/[#?\s]/u', $payload)[0] ?? $payload;
    $payload = strtr($payload, '-_', '+/');
    $payload .= str_repeat('=', (4 - strlen($payload) % 4) % 4);
    $decoded = base64_decode($payload, true);
    return $decoded === false ? false : $decoded;
}

function parse_host_port_from_authority(string $authority): array {
    $authority = trim($authority);
    if ($authority === '') return [];
    if (strpos($authority, '@') !== false) {
        $parts = explode('@', $authority);
        $authority = end($parts);
    }
    $authority = preg_replace('/[\/?#].*$/', '', $authority);
    if (preg_match('/^\[([^\]]+)\]:(\d{1,5})$/', $authority, $m)) {
        return ['host' => $m[1], 'port' => (int)$m[2]];
    }
    if (preg_match('/^(.+):(\d{1,5})$/', $authority, $m)) {
        return ['host' => trim($m[1], '[]'), 'port' => (int)$m[2]];
    }
    return [];
}

function parse_config_endpoint(string $config): array {
    $config = clean_extracted_config($config);
    if (!is_valid_config_uri($config)) {
        return ['ok' => false, 'error' => 'invalid_config_format'];
    }

    if (!preg_match('/^([a-z][a-z0-9+.-]*):\/\/(.+)$/iu', $config, $m)) {
        return ['ok' => false, 'error' => 'missing_scheme'];
    }

    $scheme = strtolower($m[1]);
    $body = trim($m[2]);
    $host = '';
    $port = 0;
    $query = [];
    $fragment = '';

    if ($scheme === 'vmess') {
        $decoded = decode_base64_urlsafe_payload($body);
        if ($decoded !== false) {
            $json = json_decode($decoded, true);
            if (is_array($json)) {
                $host = trim((string)($json['add'] ?? $json['host'] ?? ''));
                $port = (int)($json['port'] ?? 0);
                $query = [
                    'security' => (string)($json['tls'] ?? ''),
                    'type' => (string)($json['net'] ?? ''),
                    'sni' => (string)($json['sni'] ?? ''),
                    'host' => (string)($json['host'] ?? ''),
                ];
                $fragment = (string)($json['ps'] ?? '');
            }
        }
    } elseif ($scheme === 'ss') {
        $withoutFragment = preg_split('/#/u', $body)[0] ?? $body;
        $withoutQuery = preg_split('/\?/u', $withoutFragment)[0] ?? $withoutFragment;
        if (strpos($withoutQuery, '@') === false) {
            $decoded = decode_base64_urlsafe_payload($withoutQuery);
            if ($decoded !== false && strpos($decoded, '@') !== false) {
                $withoutQuery = $decoded;
            }
        }
        $hp = parse_host_port_from_authority($withoutQuery);
        $host = $hp['host'] ?? '';
        $port = (int)($hp['port'] ?? 0);
        if (strpos($body, '?') !== false) {
            parse_str(parse_url('ss://' . $body, PHP_URL_QUERY) ?: '', $query);
        }
        $fragment = rawurldecode((string)(parse_url('ss://' . $body, PHP_URL_FRAGMENT) ?: ''));
    } else {
        $parts = @parse_url($config);
        if (is_array($parts)) {
            $host = trim((string)($parts['host'] ?? ''));
            $port = (int)($parts['port'] ?? 0);
            parse_str((string)($parts['query'] ?? ''), $query);
            $fragment = rawurldecode((string)($parts['fragment'] ?? ''));
        }
    }

    $host = trim($host, '[]');
    if ($host === '' || $port < 1 || $port > 65535) {
        return ['ok' => false, 'error' => 'missing_or_invalid_endpoint', 'scheme' => $scheme, 'host' => $host, 'port' => $port];
    }

    return [
        'ok' => true,
        'scheme' => $scheme,
        'host' => $host,
        'port' => $port,
        'query' => $query,
        'fragment' => $fragment,
    ];
}

function is_ip_address_host(string $host): bool {
    return filter_var($host, FILTER_VALIDATE_IP) !== false;
}

function config_static_quality_score(string $config, int $index = 0): array {
    $endpoint = parse_config_endpoint($config);
    $checkedAt = date('Y-m-d H:i:s');
    if (empty($endpoint['ok'])) {
        return [
            'status' => 'invalid',
            'score' => 0,
            'scheme' => $endpoint['scheme'] ?? null,
            'host' => $endpoint['host'] ?? null,
            'port' => $endpoint['port'] ?? null,
            'method' => CONFIG_SELECTION_MODE,
            'checked_at' => $checkedAt,
            'error' => $endpoint['error'] ?? 'invalid_config',
            'reasons' => ['invalid_or_unreadable_config'],
        ];
    }

    $scheme = strtolower((string)$endpoint['scheme']);
    $host = (string)$endpoint['host'];
    $port = (int)$endpoint['port'];
    $query = is_array($endpoint['query'] ?? null) ? $endpoint['query'] : [];
    $fragment = (string)($endpoint['fragment'] ?? '');

    $score = 100;
    $reasons = ['valid_endpoint'];

    $schemeWeight = [
        'vless' => 34, 'trojan' => 30, 'vmess' => 22, 'hysteria2' => 28, 'hy2' => 28,
        'hysteria' => 24, 'tuic' => 23, 'ss' => 16, 'ssr' => 11, 'wireguard' => 15,
        'warp' => 15, 'socks' => 6, 'socks5' => 6, 'anytls' => 24, 'snell' => 10,
    ];
    $score += $schemeWeight[$scheme] ?? 8;
    $reasons[] = 'scheme_' . $scheme;

    $security = strtolower((string)($query['security'] ?? $query['tls'] ?? ''));
    if ($security === 'reality') { $score += 36; $reasons[] = 'reality_security'; }
    elseif ($security === 'tls') { $score += 28; $reasons[] = 'tls_security'; }
    elseif ($security === 'xtls') { $score += 24; $reasons[] = 'xtls_security'; }
    elseif ($security === 'none' || $security === '') { $score += 2; $reasons[] = 'no_tls_or_unspecified_security'; }

    $network = strtolower((string)($query['type'] ?? $query['net'] ?? $query['network'] ?? ''));
    $networkWeight = ['xhttp' => 30, 'grpc' => 24, 'ws' => 22, 'h2' => 18, 'httpupgrade' => 20, 'tcp' => 18, 'quic' => 14, 'kcp' => 4];
    if ($network !== '') { $score += $networkWeight[$network] ?? 8; $reasons[] = 'network_' . $network; }

    if (in_array($port, [443, 8443, 2096, 2087, 2053], true)) { $score += 16; $reasons[] = 'tls_friendly_port'; }
    elseif (in_array($port, [80, 8080, 8880, 2052, 2082], true)) { $score += 8; $reasons[] = 'http_friendly_port'; }
    else { $score += 4; $reasons[] = 'custom_port'; }

    $sni = trim((string)($query['sni'] ?? $query['peer'] ?? ''));
    $hostHeader = trim((string)($query['host'] ?? ''));
    if ($sni !== '') { $score += 10; $reasons[] = 'has_sni'; }
    if ($hostHeader !== '') { $score += 7; $reasons[] = 'has_host_header'; }
    if (!is_ip_address_host($host)) { $score += 8; $reasons[] = 'domain_host'; }
    elseif ($security === 'reality') { $score += 3; $reasons[] = 'ip_host_with_reality'; }
    else { $score -= 4; $reasons[] = 'ip_host'; }

    if ($fragment !== '') { $score += 2; $reasons[] = 'named_config'; }

    // Keep original order as final tie-breaker.
    $score -= min(20, max(0, $index) * 0.001);

    return [
        'status' => 'valid',
        'score' => round($score, 3),
        'scheme' => $scheme,
        'host' => $host,
        'port' => $port,
        'method' => CONFIG_SELECTION_MODE,
        'checked_at' => $checkedAt,
        'error' => '',
        'reasons' => array_values(array_unique($reasons)),
    ];
}


function config_quality_has_latency(array $quality): bool {
    return false;
}

function config_quality_is_online(array $quality): bool {
    return false;
}

function strip_server_ping_fields(array $quality): array {
    foreach (['ping_status','latency_ms','ping_ms','ping_error','ping_method','ping_checked_at','manual_score_version'] as $field) {
        unset($quality[$field]);
    }
    return $quality;
}

function update_config_scores_for_license(array &$licenseRow, array $configs = []): array {
    // Server-side ping is removed. This function now refreshes deterministic static quality only.
    if (empty($configs)) $configs = get_combined_configs($licenseRow);
    $configs = normalize_config_list($configs);
    $qualityRows = [];
    $valid = 0; $invalid = 0; $tested = 0;
    foreach ($configs as $idx => $config) {
        $quality = config_static_quality_score($config, $idx);
        $quality = strip_server_ping_fields($quality);
        $quality['hash'] = config_hash($config);
        $quality['preview'] = preview_text_safe(clean_extracted_config($config), 90);
        $qualityRows[$quality['hash']] = $quality;
        $tested++;
        if (($quality['status'] ?? '') === 'valid') $valid++; else $invalid++;
    }
    $licenseRow['config_quality'] = $qualityRows;
    $licenseRow['last_score_update'] = date('Y-m-d H:i:s');
    $licenseRow['last_score_summary'] = ['tested' => $tested, 'valid' => $valid, 'invalid' => $invalid, 'mode' => 'static_quality_only_no_server_ping'];
    $licenseRow['last_best_latency_ms'] = null;
    unset($licenseRow['last_best_ping_status']);
    rank_configs_for_license($licenseRow, $configs);
    return $licenseRow['last_score_summary'];
}

function rank_configs_for_license(array &$licenseRow, array $configs): array {
    $configs = array_values(array_unique(normalize_config_list($configs)));
    $ranked = [];
    foreach ($configs as $idx => $config) {
        $hash = config_hash($config);
        $quality = strip_server_ping_fields(config_static_quality_score($config, $idx));
        $quality['hash'] = $hash;
        $quality['preview'] = preview_text_safe(clean_extracted_config($config), 90);
        $ranked[] = ['config' => $config, 'quality' => $quality, 'index' => $idx];
    }

    usort($ranked, function ($a, $b) {
        $sa = $a['quality']['score'] ?? 0;
        $sb = $b['quality']['score'] ?? 0;
        if ($sa != $sb) return $sb <=> $sa;
        return $a['index'] <=> $b['index'];
    });

    $sorted = array_map(function ($item) { return $item['config']; }, $ranked);
    $best = $sorted[0] ?? '';
    $bestQuality = $ranked[0]['quality'] ?? [];

    $qualityRows = [];
    foreach ($ranked as $item) {
        $qualityRows[$item['quality']['hash']] = $item['quality'];
    }

    $licenseRow['config_quality'] = $qualityRows;
    $licenseRow['last_best_config'] = $best;
    $licenseRow['last_best_config_hash'] = $best !== '' ? config_hash($best) : '';
    $licenseRow['last_fastest_score'] = $bestQuality['score'] ?? null;
    $licenseRow['last_best_latency_ms'] = null;
    unset($licenseRow['last_best_ping_status']);
    $licenseRow['last_selection_method'] = CONFIG_SELECTION_MODE;
    $licenseRow['last_selection_update'] = date('Y-m-d H:i:s');
    unset($licenseRow['config_health'], $licenseRow['last_best_test_method'], $licenseRow['last_delay_test_target'], $licenseRow['last_health_check']);

    return [
        'configs' => $sorted,
        'best_config' => $best,
        'best_quality' => $bestQuality,
        'quality' => array_values($qualityRows),
    ];
}

function prepare_configs_for_delivery(array &$licenseRow, array $configs): array {
    $ranked = rank_configs_for_license($licenseRow, $configs);
    $modeMeta = symex_build_mode_delivery_meta($licenseRow, $ranked['configs']);
    $deliverySource = $licenseRow['last_delivery_source'] ?? 'unknown';
    $configsHash = configs_delivery_hash($ranked['configs']);
    return [
        'configs' => $ranked['configs'],
        'meta' => array_merge([
            'configs_hash' => $configsHash,
            'configs_revision' => $configsHash,
            'configs_count' => count($ranked['configs']),
            'configs_updated_at' => $licenseRow['last_subscription_update'] ?? $licenseRow['subscription_last_good_update'] ?? date('c'),
            'sync_server_time' => date('c'),
            'subscription_cache_used' => !empty($licenseRow['subscription_cache_used']),
            'subscription_last_good_update' => $licenseRow['subscription_last_good_update'] ?? null,
            'subscription_last_error' => $licenseRow['last_subscription_error'] ?? '',
            'best_config' => $ranked['best_config'],
            'fastest_config' => $ranked['best_config'],
            'best_config_hash' => $ranked['best_config'] !== '' ? config_hash($ranked['best_config']) : '',
            'best_config_quality' => $ranked['best_quality'],
            'fastest_latency_ms' => null,
            'live_speed_test' => false,
            'manual_latency_test' => false,
            'client_side_latency_test' => true,
            'selection_score' => $ranked['best_quality']['score'] ?? null,
            'config_quality' => $ranked['quality'],
            'config_selection' => 'smart_lowest_client_latency_gaming_browsing_panel_tag_preferred',
            'selection_method' => CONFIG_SELECTION_MODE,
            'delivery_source' => $deliverySource,
        ], $modeMeta)
    ];
}

function summarize_license_quality(array $licenseRow): array {
    $summary = ['valid' => 0, 'invalid' => 0, 'unknown' => 0, 'best_score' => $licenseRow['last_fastest_score'] ?? null, 'last_update' => $licenseRow['last_selection_update'] ?? null, 'last_score_update' => $licenseRow['last_score_update'] ?? null];
    $rows = isset($licenseRow['config_quality']) && is_array($licenseRow['config_quality']) ? $licenseRow['config_quality'] : [];
    foreach ($rows as $quality) {
        $status = $quality['status'] ?? 'unknown';
        if (!array_key_exists($status, $summary)) $status = 'unknown';
        $summary[$status]++;
    }
    return $summary;
}

function summarize_license_health(array $licenseRow): array {
    return summarize_license_quality($licenseRow);
}

function import_configs_to_license(array &$licenseRow, array $newConfigs): array {
    if (!isset($licenseRow['configs']) || !is_array($licenseRow['configs'])) $licenseRow['configs'] = [];
    $licenseRow['configs'] = normalize_config_list($licenseRow['configs']);
    $seen = [];
    foreach ($licenseRow['configs'] as $existingConfig) {
        $seen[config_dedupe_key($existingConfig)] = true;
    }
    $result = ['added' => 0, 'duplicates' => 0, 'invalid' => 0, 'quality' => [], 'added_configs' => []];

    foreach ($newConfigs as $rawConfig) {
        $config = clean_extracted_config((string)$rawConfig);
        if (!is_valid_config_uri($config)) { $result['invalid']++; continue; }
        $key = config_dedupe_key($config);
        if (isset($seen[$key])) { $result['duplicates']++; continue; }
        $licenseRow['configs'][] = $config;
        $result['added_configs'][] = $config;
        $seen[$key] = true;
        $result['added']++;
    }

    $licenseRow['configs'] = normalize_config_list($licenseRow['configs']);
    $ranked = rank_configs_for_license($licenseRow, $licenseRow['configs']);
    $result['quality'] = $ranked['quality'];
    return $result;
}

function sanitize_license_row(array &$licenseRow): int {
    $before = isset($licenseRow['configs']) && is_array($licenseRow['configs']) ? count($licenseRow['configs']) : 0;
    $licenseRow['configs'] = normalize_config_list($licenseRow['configs'] ?? []);
    $after = count($licenseRow['configs']);
    if (!isset($licenseRow['config_quality']) || !is_array($licenseRow['config_quality'])) $licenseRow['config_quality'] = [];
    unset($licenseRow['config_health'], $licenseRow['last_health_check'], $licenseRow['last_best_test_method'], $licenseRow['last_delay_test_target']);
    if (!isset($licenseRow['last_subscription_status'])) $licenseRow['last_subscription_status'] = empty($licenseRow['subscription_url']) ? 'no_url' : 'unknown';
    if (!isset($licenseRow['subscription_last_good_content'])) $licenseRow['subscription_last_good_content'] = '';
    if (!isset($licenseRow['subscription_last_good_update'])) $licenseRow['subscription_last_good_update'] = null;
    if (!isset($licenseRow['subscription_last_good_count'])) $licenseRow['subscription_last_good_count'] = 0;
    if (!isset($licenseRow['subscription_cache_used'])) $licenseRow['subscription_cache_used'] = false;
    if (!isset($licenseRow['last_subscription_cache_used_at'])) $licenseRow['last_subscription_cache_used_at'] = null;
    if (!isset($licenseRow['last_subscription_test']) || !is_array($licenseRow['last_subscription_test'])) $licenseRow['last_subscription_test'] = [];
    if (!isset($licenseRow['subscription_logs']) || !is_array($licenseRow['subscription_logs'])) $licenseRow['subscription_logs'] = [];
    symex_ensure_config_roles($licenseRow);
    if (!empty($licenseRow['configs'])) rank_configs_for_license($licenseRow, $licenseRow['configs']);
    return max(0, $before - $after);
}

function sanitize_all_licenses(array &$db): int {
    $removed = 0;
    foreach ($db as &$row) {
        if (is_array($row)) $removed += sanitize_license_row($row);
    }
    unset($row);
    return $removed;
}

function badge_for_quality_status(string $status): string {
    if ($status === 'valid') return 'badge-success';
    if ($status === 'invalid') return 'badge-danger';
    return 'badge-info';
}

function badge_for_health_status(string $status): string {
    return badge_for_quality_status($status);
}





function symex_store_good_subscription_from_configs(array &$licenseRow, string $url, array $configs, string $rawContent = '', string $event = 'manual_test_saved'): void {
    $configs = normalize_config_list($configs);
    if (empty($configs)) return;
    $cleanContent = implode("\n", $configs);
    $licenseRow['subscription_url'] = $url;
    $licenseRow['subscription_content'] = $cleanContent;
    $licenseRow['subscription_last_good_content'] = $cleanContent;
    $licenseRow['subscription_last_good_update'] = date('Y-m-d H:i:s');
    $licenseRow['subscription_last_good_count'] = count($configs);
    $licenseRow['last_subscription_update'] = date('Y-m-d H:i:s');
    $licenseRow['last_subscription_status'] = 'ok';
    $licenseRow['last_subscription_error'] = '';
    $licenseRow['subscription_config_count'] = count($configs);
    $licenseRow['subscription_cache_used'] = false;
    $licenseRow['last_delivery_source'] = 'subscription';
    symex_log_subscription_event($licenseRow, $event, [
        'status' => 'ok',
        'configs_found' => count($configs),
        'content_bytes' => strlen($rawContent),
        'cache_used' => false,
        'message' => 'Healthy subscription content stored for app delivery',
        'url' => $url,
    ]);
}

function test_subscription_url_for_panel(string $url): array {
    $url = trim($url);
    $out = [
        'timestamp' => date('Y-m-d H:i:s'),
        'url' => $url,
        'status' => 'invalid_url',
        'configs_found' => 0,
        'content_bytes' => 0,
        'message' => 'Invalid or empty subscription URL',
    ];
    if ($url === '' || !preg_match('#^https?://#i', $url)) return $out;
    if (function_exists('symex_sub_fetch_and_parse')) {
        $result = symex_sub_fetch_and_parse($url, symex_sub_settings_options());
        $out['content_bytes'] = (int)($result['content_bytes'] ?? 0);
        $out['fetch_error'] = (string)($result['fetch_error'] ?? '');
        $out['attempts'] = array_slice((array)($result['attempts'] ?? []), -8);
        $out['configs_found'] = (int)($result['configs_found'] ?? 0);
        if (empty($result['ok'])) {
            $out['status'] = (string)($result['status'] ?? 'invalid_content');
            $out['message'] = (string)($result['message'] ?? 'Subscription could not be parsed.');
            return $out;
        }
        $configs = normalize_config_list((array)$result['configs']);
        $out['status'] = 'ok';
        $out['message'] = 'Subscription fetched and parsed successfully by v2 parser. This healthy result was also saved for app delivery.';
        $out['configs_found'] = count($configs);
        $out['configs_preview'] = array_slice(array_map('preview_text_safe', $configs), 0, 5);
        $out['_configs'] = $configs;
        $out['_raw_content'] = (string)($result['raw_content'] ?? '');
        return $out;
    }
    $content = fetch_subscription_content($url);
    $out['content_bytes'] = is_string($content) ? strlen($content) : 0;
    $out['fetch_error'] = $GLOBALS['SYMEX_LAST_SUBSCRIPTION_FETCH_ERROR'] ?? '';
    if ($content === false || trim((string)$content) === '') {
        $out['status'] = 'fetch_failed';
        $out['message'] = 'Could not fetch subscription: ' . ($out['fetch_error'] ?: 'empty response');
        return $out;
    }
    $configs = normalize_config_list(extract_configs_from_text((string)$content));
    $out['configs_found'] = count($configs);
    if (empty($configs)) {
        $out['status'] = 'invalid_content';
        $out['message'] = 'Fetched content, but no supported config URI was found.';
        return $out;
    }
    $out['status'] = 'ok';
    $out['message'] = 'Subscription fetched and parsed successfully. This healthy result was also saved for app delivery.';
    $out['configs_preview'] = array_slice(array_map('preview_text_safe', $configs), 0, 5);
    $out['_configs'] = $configs;
    $out['_raw_content'] = (string)$content;
    return $out;
}

function symex_block_device(array &$licenseRow, string $deviceId, string $reason = 'blocked_by_admin'): void {
    $deviceId = trim($deviceId);
    if ($deviceId === '') return;
    if (!isset($licenseRow['revoked_devices']) || !is_array($licenseRow['revoked_devices'])) $licenseRow['revoked_devices'] = [];
    $licenseRow['revoked_devices'][$deviceId] = [
        'blocked_at' => date('Y-m-d H:i:s'),
        'reason' => $reason,
        'hard_block' => true,
    ];
}

function symex_clear_soft_device_resets(array &$licenseRow, ?string $deviceId = null): void {
    if (!isset($licenseRow['revoked_devices']) || !is_array($licenseRow['revoked_devices'])) {
        $licenseRow['revoked_devices'] = [];
        return;
    }
    foreach (array_keys($licenseRow['revoked_devices']) as $id) {
        if ($deviceId !== null && $id !== $deviceId) continue;
        $info = $licenseRow['revoked_devices'][$id];
        $reason = is_array($info) ? (string)($info['reason'] ?? '') : '';
        $hard = !empty($info['hard_block']) || in_array($reason, ['blocked_by_admin', 'blacklisted_by_admin', 'manual_block'], true);
        if (!$hard) unset($licenseRow['revoked_devices'][$id]);
    }
}

function get_system_status(array $db): array {
    $manualConfigs = 0;
    $subOk = 0; $subWarn = 0; $subNoUrl = 0;
    $quality = ['valid' => 0, 'invalid' => 0, 'unknown' => 0];
    foreach ($db as $row) {
        $manualConfigs += count(normalize_config_list($row['configs'] ?? []));
        $status = $row['last_subscription_status'] ?? (empty($row['subscription_url']) ? 'no_url' : 'unknown');
        if ($status === 'ok') $subOk++;
        elseif ($status === 'no_url') $subNoUrl++;
        else $subWarn++;
        foreach (($row['config_quality'] ?? []) as $q) {
            $s = $q['status'] ?? 'unknown';
            if (!isset($quality[$s])) $s = 'unknown';
            $quality[$s]++;
        }
    }
    $files = [];
    foreach ([DATA_FILE, LOG_FILE, ACCESS_LOG_FILE, SETTINGS_FILE] as $file) {
        $files[] = [
            'file' => basename($file),
            'exists' => file_exists($file),
            'readable' => file_exists($file) ? is_readable($file) : is_readable(dirname($file)),
            'writable' => file_exists($file) ? is_writable($file) : is_writable(dirname($file)),
            'size' => file_exists($file) ? filesize($file) : 0,
        ];
    }
    return [
        'php_version' => PHP_VERSION,
        'server_time' => date('Y-m-d H:i:s'),
        'timezone' => date_default_timezone_get(),
        'extensions' => [
            'curl' => extension_loaded('curl'),
            'json' => extension_loaded('json'),
            'mbstring' => extension_loaded('mbstring'),
            'openssl' => extension_loaded('openssl'),
        ],
        'files' => $files,
        'manual_configs' => $manualConfigs,
        'subscription_ok' => $subOk,
        'subscription_warning' => $subWarn,
        'subscription_no_url' => $subNoUrl,
        'quality' => $quality,
        'selection_method' => CONFIG_SELECTION_MODE,
    ];
}

function should_update_subscription($last_update) {
    if (empty($last_update)) return true;
    $last = strtotime($last_update);
    if (!$last) return true;
    $now = time();
    return ($now - $last) >= (3 * 3600);
}

function trigger_webhook(array $licenseData, string $event): void {
    // Panel-only stability build: external webhooks are disabled intentionally.
    // Leaving slow/dead webhook URLs active was a common cause of delayed/stuck
    // license actions such as enable/disable. Keep this function as a safe no-op
    // so older stored data cannot block admin actions.
    return;
}



function load_settings(): array {
    $defaults = [
        'external_alerts_enabled' => false,
        'subscription_relay_enabled' => false,
        'subscription_relay_url' => '',
        'subscription_relay_secret' => '',
        'allow_insecure_subscription_fetch' => false,
        'external_geo_lookup_enabled' => false,
        'app_latest_version_code' => 0,
        'app_latest_version_name' => '',
        'app_update_apk_url' => '',
        'app_update_sha256' => '',
        'app_update_notes' => '',
        'app_update_required' => false,
        'network_dns_servers' => '1.1.1.1,8.8.8.8',
        'network_mtu' => 1400,
        'network_routing_mode' => 'FULL_TUNNEL',
    ];
    if (!file_exists(SETTINGS_FILE)) return $defaults;
    $content = file_get_contents(SETTINGS_FILE);
    $data = json_decode($content ?: '{}', true);
    if (!is_array($data)) return $defaults;
    // Keep older settings.json compatible, but external messenger fields are ignored in this panel-only build.
    return array_merge($defaults, $data);
}

function save_settings(array $settings): void {
    file_put_contents(SETTINGS_FILE, json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}


function symex_alert_enabled(string $category): bool {
    return false;
}


// ============================================================
// AUTHENTICATION - Fix header order
// ============================================================

if (!checkIPAllowed()) {
    logAccess('blocked', 'IP not allowed');
    die('Access denied. Your IP is not authorized.');
}

if (isset($_SESSION['auth']) && $_SESSION['auth'] === true) {
    if (!checkSessionTimeout()) {
        header('Location: admin.php');
        exit;
    }
}

if (isIPBlocked() && !isset($_SESSION['auth'])) {
    logAccess('blocked', 'Too many failed attempts');
    die('Too many failed login attempts. Please try again later.');
}

if (isset($_POST['password'])) {
    $password = $_POST['password'] ?? '';
    
    if (verifyAdminPassword($password)) {
        $_SESSION['auth'] = true;
        $_SESSION['last_activity'] = time();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        resetFailedLogins();
        logAccess('success', 'Login successful');
        addLog('auth', 'Admin logged in from ' . getUserIP());
        if (symex_alert_enabled('login')) {
        }
        
        $_SESSION['login_info'] = [
            'ip' => getUserIP(),
            'location' => getUserLocation(getUserIP()),
            'device' => getUserDeviceInfo(),
            'login_time' => date('Y-m-d H:i:s')
        ];
        
        header('Location: admin.php');
        exit;
    } else {
        recordFailedLogin();
        $err = 'Wrong password.';
        logAccess('failed', 'Invalid password attempt');
        addLog('auth', 'Failed login attempt from ' . getUserIP());
        if (symex_alert_enabled('failed_login')) {
        }
    }
}

if (isset($_GET['logout'])) {
    addLog('auth', 'Admin logged out');
    logAccess('success', 'Logout');
    session_destroy();
    header('Location: admin.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['theme']) && count($_POST) === 1) {
    $_SESSION['theme'] = ($_POST['theme'] === 'light') ? 'light' : 'dark';
    http_response_code(204);
    exit;
}

$authed = !empty($_SESSION['auth']) && $_SESSION['auth'] === true;
$msg = $_SESSION['flash_msg'] ?? '';
unset($_SESSION['flash_msg']);
$theme = $_SESSION['theme'] ?? 'dark';

// ============================================================
// POST HANDLERS - Fix CSRF verification
// ============================================================

if ($authed && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken()) {
        $msg = 'Security token mismatch. Please refresh the page.';
    } else {
        $db = db_load();
        sanitize_all_licenses($db);

        if (isset($_POST['change_admin_password'])) {
            $newPassword = (string)($_POST['new_admin_password'] ?? '');
            $confirmPassword = (string)($_POST['confirm_admin_password'] ?? '');
            if ($newPassword !== $confirmPassword) {
                $msg = 'Admin password confirmation does not match.';
            } elseif (!saveAdminPassword($newPassword)) {
                $msg = 'Admin password must be at least 12 characters and writable by PHP.';
            } else {
                $msg = 'Admin password updated.';
                addLog('auth', 'Admin password changed from ' . getUserIP());
            }
            redirectWithFlash($msg);
        }

        // Subscription network settings: relay is optional and useful when this host cannot reach a sub URL that opens on mobile/browser.
        if (isset($_POST['update_subscription_network_settings'])) {
            $settings = load_settings();
            $settings['subscription_relay_enabled'] = !empty($_POST['subscription_relay_enabled']);
            $settings['subscription_relay_url'] = trim((string)($_POST['subscription_relay_url'] ?? ''));
            $settings['subscription_relay_secret'] = trim((string)($_POST['subscription_relay_secret'] ?? ''));
            $settings['allow_insecure_subscription_fetch'] = !empty($_POST['allow_insecure_subscription_fetch']);
            $settings['external_geo_lookup_enabled'] = !empty($_POST['external_geo_lookup_enabled']);
            if (array_key_exists('app_latest_version_code', $_POST)) {
                $settings['app_latest_version_code'] = max(0, (int)($_POST['app_latest_version_code'] ?? 0));
                $settings['app_latest_version_name'] = trim((string)($_POST['app_latest_version_name'] ?? ''));
                $settings['app_update_apk_url'] = trim((string)($_POST['app_update_apk_url'] ?? ''));
                $settings['app_update_sha256'] = strtolower(trim((string)($_POST['app_update_sha256'] ?? '')));
                $settings['app_update_notes'] = trim((string)($_POST['app_update_notes'] ?? ''));
                $settings['app_update_required'] = !empty($_POST['app_update_required']);
            }
            if (array_key_exists('network_dns_servers', $_POST)) {
                $settings['network_dns_servers'] = trim((string)($_POST['network_dns_servers'] ?? '1.1.1.1,8.8.8.8'));
                $settings['network_mtu'] = max(1280, min(1500, (int)($_POST['network_mtu'] ?? 1400)));
                $routingMode = strtoupper(trim((string)($_POST['network_routing_mode'] ?? 'FULL_TUNNEL')));
                $settings['network_routing_mode'] = in_array($routingMode, ['FULL_TUNNEL', 'BYPASS_LAN'], true) ? $routingMode : 'FULL_TUNNEL';
            }
            save_settings($settings);
            addLog('settings', 'Client update and network settings updated');
            $msg = 'Client update and network settings saved.';
        }

        // Add License
        if (!empty($_POST['add_license'])) {
            $key = strtoupper(trim($_POST['add_license']));
            $days = max(0, (int) ($_POST['expires_days'] ?? 0));
            $exp = $days > 0 ? date('Y-m-d', strtotime("+{$days} days")) : '';
            $max_devices = max(1, (int) ($_POST['max_devices'] ?? 1));
            $bandwidth_limit_gb = (float) ($_POST['bandwidth_limit'] ?? 0);
            $bandwidth_limit_bytes = parseBandwidthInput($bandwidth_limit_gb);
            if ($key === '') {
                $msg = 'License key cannot be empty.';
            } elseif (isset($db[$key])) {
                $msg = 'That key already exists.';
            } else {
                $db[$key] = [
                    'license_key' => $key,
                    'active' => true,
                    'expires_at' => $exp,
                    'devices' => [],
                    'device_bandwidth' => [],
                    'device_upload' => [],
                    'device_download' => [],
                    'max_devices' => $max_devices,
                    'bandwidth_limit' => $bandwidth_limit_bytes,
                    'bandwidth_used' => 0,
                    'upload_used' => 0,
                    'download_used' => 0,
                    'traffic_events' => [],
                    'created_at' => date('Y-m-d H:i:s'),
                    'configs' => [],
                    'config_roles' => [],
                    'subscription_url' => '',
                    'last_subscription_update' => null,
                    'subscription_content' => '',
                    'last_subscription_attempt' => null,
                    'last_subscription_status' => 'no_url',
                    'last_subscription_error' => '',
                    'subscription_config_count' => 0,
                    'subscription_last_good_content' => '',
                    'subscription_last_good_update' => null,
                    'subscription_last_good_count' => 0,
                    'subscription_cache_used' => false,
                    'last_subscription_cache_used_at' => null,
                    'last_subscription_test' => [],
                    'subscription_logs' => [],
                    'config_quality' => [],
                    'last_best_config' => '',
                    'last_fastest_score' => null,
                    'last_best_latency_ms' => null,
                    'last_best_ping_status' => null,
                    'last_score_update' => null,
                    'last_score_summary' => [],
                    'last_selection_method' => CONFIG_SELECTION_MODE,
                ];
                db_save($db);
                addLog('license', "License created: $key (max_devices: $max_devices, bandwidth: {$bandwidth_limit_gb}GB)");
                $msg = "Added: $key";
            }
        }

        // Toggle License
        if (!empty($_POST['toggle'])) {
            $key = $_POST['toggle'];
            if (isset($db[$key])) {
                $db[$key]['active'] = !$db[$key]['active'];
                db_save($db);
                addLog('license', "License toggled: $key (" . ($db[$key]['active'] ? 'active' : 'disabled') . ")");
                $msg = "Toggled: $key";
            }
        }

        // Reset Device (kick current device/session out, but DO NOT blacklist it)
        if (!empty($_POST['reset_device'])) {
            $key = $_POST['reset_device'];
            $device_id = $_POST['reset_device_id'] ?? null;
            if (isset($db[$key])) {
                if ($device_id) {
                    // Reset means remove from the active devices list only.
                    // It must NOT add the device to revoked_devices, otherwise the user cannot re-activate with the same phone.
                    symex_clear_soft_device_resets($db[$key], $device_id);
                    $db[$key]['devices'] = array_values(array_filter($db[$key]['devices'] ?? [], fn($d) => ($d['device_id'] ?? '') !== $device_id));
                    unset($db[$key]['device_bandwidth'][$device_id]);
                    unset($db[$key]['device_upload'][$device_id], $db[$key]['device_download'][$device_id]);
                    $db[$key]['bandwidth_used'] = array_sum(array_map('intval', $db[$key]['device_bandwidth'] ?? []));
                    $db[$key]['upload_used'] = array_sum(array_map('intval', $db[$key]['device_upload'] ?? []));
                    $db[$key]['download_used'] = array_sum(array_map('intval', $db[$key]['device_download'] ?? []));
                    addLog('device', "Device reset without blacklist: $device_id from $key");
                    $msg = "Device reset for $key. It can be activated again by entering the license.";
                } else {
                    // Reset all removes active devices and bandwidth only. It does not blacklist phones.
                    symex_clear_soft_device_resets($db[$key]);
                    $db[$key]['devices'] = [];
                    $db[$key]['device_bandwidth'] = [];
                    $db[$key]['device_upload'] = [];
                    $db[$key]['device_download'] = [];
                    $db[$key]['bandwidth_used'] = 0;
                    $db[$key]['upload_used'] = 0;
                    $db[$key]['download_used'] = 0;
                    addLog('device', "All devices reset for $key, bandwidth reset to 0 (no blacklist)");
                    $msg = "All devices reset for $key. Devices can activate again by entering the license.";
                }
                db_save($db);
            }
        }

        // Block Device (separate from reset; prevents this device from using the license)
        if (!empty($_POST['block_device'])) {
            $key = $_POST['block_device'];
            $device_id = trim($_POST['block_device_id'] ?? '');
            if (isset($db[$key]) && $device_id !== '') {
                symex_block_device($db[$key], $device_id, 'blocked_by_admin');
                $db[$key]['devices'] = array_values(array_filter($db[$key]['devices'] ?? [], fn($d) => ($d['device_id'] ?? '') !== $device_id));
                unset($db[$key]['device_bandwidth'][$device_id]);
                unset($db[$key]['device_upload'][$device_id], $db[$key]['device_download'][$device_id]);
                $db[$key]['bandwidth_used'] = array_sum(array_map('intval', $db[$key]['device_bandwidth'] ?? []));
                $db[$key]['upload_used'] = array_sum(array_map('intval', $db[$key]['device_upload'] ?? []));
                $db[$key]['download_used'] = array_sum(array_map('intval', $db[$key]['device_download'] ?? []));
                db_save($db);
                addLog('device', "Device blocked by admin: $device_id from $key");
                $msg = "Device blocked for $key.";
            }
        }

        // Clear blocked/revoked device list for a license
        if (!empty($_POST['clear_device_blocks'])) {
            $key = $_POST['clear_device_blocks'];
            if (isset($db[$key])) {
                $count = count($db[$key]['revoked_devices'] ?? []);
                $db[$key]['revoked_devices'] = [];
                db_save($db);
                addLog('device', "Cleared $count device block(s) for $key");
                $msg = "Device blocks cleared for $key.";
            }
        }

        // Delete License
        if (!empty($_POST['delete'])) {
            $key = $_POST['delete'];
            if (isset($db[$key])) {
                addLog('license', "License deleted: $key");
                unset($db[$key]);
                db_save($db);
                $msg = "Deleted: $key";
            }
        }

        // Update Settings
        if (isset($_POST['update_settings_key'])) {
            $key = $_POST['update_settings_key'];
            if (isset($db[$key])) {
                $db[$key]['max_devices'] = max(1, (int) ($_POST['max_devices'] ?? 1));
                $bandwidth_limit_gb = (float) ($_POST['bandwidth_limit'] ?? 0);
                $db[$key]['bandwidth_limit'] = parseBandwidthInput($bandwidth_limit_gb);
                db_save($db);
                addLog('settings', "Settings updated for $key");
                $msg = "Settings updated for $key";
            }
        }

        // Reset Bandwidth for license
        if (isset($_POST['reset_bandwidth'])) {
            $key = $_POST['reset_bandwidth'];
            if (isset($db[$key])) {
                $old_used = $db[$key]['bandwidth_used'];
                $db[$key]['bandwidth_used'] = 0;
                $db[$key]['upload_used'] = 0;
                $db[$key]['download_used'] = 0;
                $db[$key]['device_bandwidth'] = [];
                $db[$key]['device_upload'] = [];
                $db[$key]['device_download'] = [];
                db_save($db);
                addLog('bandwidth', "Bandwidth reset for $key (was " . formatBytes($old_used) . ")");
                $msg = "Bandwidth reset for $key";
            }
        }

        // Reset bandwidth for specific device
        if (isset($_POST['reset_device_bandwidth'])) {
            $key = $_POST['reset_device_bandwidth'];
            $device_id = $_POST['reset_device_id'] ?? '';
            if (isset($db[$key]) && isset($db[$key]['device_bandwidth'][$device_id])) {
                $old_used = $db[$key]['device_bandwidth'][$device_id];
                unset($db[$key]['device_bandwidth'][$device_id]);
                unset($db[$key]['device_upload'][$device_id], $db[$key]['device_download'][$device_id]);
                // Recalculate total bandwidth
                $total = 0;
                foreach ($db[$key]['device_bandwidth'] as $used) {
                    $total += $used;
                }
                $db[$key]['bandwidth_used'] = $total;
                $db[$key]['upload_used'] = array_sum(array_map('intval', $db[$key]['device_upload'] ?? []));
                $db[$key]['download_used'] = array_sum(array_map('intval', $db[$key]['device_download'] ?? []));
                db_save($db);
                addLog('bandwidth', "Device bandwidth reset for $device_id on $key (was " . formatBytes($old_used) . ")");
                $msg = "Device bandwidth reset for $device_id";
            }
        }

        // Config management - supports bulk pasted configs with extra text, validation, and automatic dedupe
        if (!empty($_POST['add_config']) && !empty($_POST['config_key'])) {
            $key = $_POST['config_key'];
            $val = trim($_POST['add_config']);
            if (isset($db[$key]) && $val !== '') {
                $configsToAdd = extract_configs_from_text($val);
                $subscriptionUrls = symex_extract_subscription_urls_from_text($val);
                $subImportMessages = [];
                foreach ($subscriptionUrls as $subUrl) {
                    $test = test_subscription_url_for_panel($subUrl);
                    $found = isset($test['_configs']) && is_array($test['_configs']) ? normalize_config_list($test['_configs']) : [];
                    if (!empty($found)) {
                        $configsToAdd = array_merge($configsToAdd, $found);
                        symex_store_good_subscription_from_configs(
                            $db[$key],
                            $subUrl,
                            $found,
                            (string)($test['_raw_content'] ?? ''),
                            'add_config_subscription_url_saved'
                        );
                        $subImportMessages[] = 'subscription ok: ' . count($found);
                    } else {
                        $subImportMessages[] = 'subscription failed: ' . ($test['message'] ?? 'no configs found');
                    }
                }
                $configsToAdd = normalize_config_list($configsToAdd);
                if (empty($configsToAdd)) {
                    $msg = "No valid supported config was found in the pasted text.";
                    if (!empty($subImportMessages)) {
                        $msg .= ' ' . implode(' | ', $subImportMessages);
                    }
                } else {
                    $result = import_configs_to_license($db[$key], $configsToAdd);
                    $newRoles = [
                        'gaming' => in_array('gaming', (array)($_POST['add_config_roles'] ?? []), true),
                        'browsing' => in_array('browsing', (array)($_POST['add_config_roles'] ?? []), true),
                    ];
                    if (!empty($result['added_configs'])) {
                        foreach ($result['added_configs'] as $addedConfig) {
                            symex_set_config_roles_for_config($db[$key], $addedConfig, $newRoles);
                        }
                    }
                    symex_ensure_config_roles($db[$key]);
                    db_save($db);
                    addLog('config', "Smart config import for $key: {$result['added']} added, {$result['duplicates']} duplicate, {$result['invalid']} invalid");
                    $msg = "{$result['added']} config(s) added to $key" .
                        " | duplicates: {$result['duplicates']}" .
                        " | invalid: {$result['invalid']}";
                    if (!empty($subImportMessages)) {
                        $msg .= ' | ' . implode(' | ', $subImportMessages);
                    }
                }
            }
        }

        if (isset($_POST['edit_config_key'], $_POST['edit_config_index'], $_POST['edit_config_value'])) {
            $key = $_POST['edit_config_key'];
            $idx = (int) $_POST['edit_config_index'];
            $val = trim($_POST['edit_config_value']);
            if (isset($db[$key]['configs'][$idx]) && $val !== '') {
                $parsed = extract_configs_from_text($val);
                if (empty($parsed)) {
                    $msg = "Edited value does not contain a valid supported config.";
                } else {
                    $oldConfig = $db[$key]['configs'][$idx];
                    $oldRoles = symex_get_config_roles($db[$key], $oldConfig);
                    array_splice($db[$key]['configs'], $idx, 1);
                    symex_remove_config_roles_for_config($db[$key], $oldConfig);
                    $result = import_configs_to_license($db[$key], array_values(array_unique($parsed)));
                    if ($result['added'] <= 0) {
                        array_splice($db[$key]['configs'], $idx, 0, [$oldConfig]);
                        symex_set_config_roles_for_config($db[$key], $oldConfig, $oldRoles);
                        $msg = "Edit rejected: no valid config was found.";
                    } else {
                        if (!empty($result['added_configs'])) {
                            foreach ($result['added_configs'] as $addedConfig) {
                                symex_set_config_roles_for_config($db[$key], $addedConfig, $oldRoles);
                            }
                        }
                        addLog('config', "Config updated for $key ({$result['added']} replacement configs saved)");
                        $msg = $result['added'] > 1 ? "Config updated and split into {$result['added']} configs." : "Config updated.";
                    }
                    $db[$key]['configs'] = normalize_config_list($db[$key]['configs']);
                    symex_ensure_config_roles($db[$key]);
                    db_save($db);
                }
            }
        }

        if (isset($_POST['delete_config_key'], $_POST['delete_config_index'])) {
            $key = $_POST['delete_config_key'];
            $idx = (int) $_POST['delete_config_index'];
            if (isset($db[$key]['configs'][$idx])) {
                $deletedConfig = $db[$key]['configs'][$idx];
                array_splice($db[$key]['configs'], $idx, 1);
                symex_remove_config_roles_for_config($db[$key], $deletedConfig);
                symex_ensure_config_roles($db[$key]);
                db_save($db);
                addLog('config', "Config deleted from $key");
                $msg = "Config deleted.";
            }
        }

        if (isset($_POST['clear_configs_key'])) {
            $key = $_POST['clear_configs_key'];
            if (isset($db[$key])) {
                $db[$key]['configs'] = [];
                $db[$key]['config_roles'] = [];
                db_save($db);
                addLog('config', "All configs cleared for $key");
                $msg = "All configs cleared for $key";
            }
        }


        // Config mode roles: mark manual configs for Gaming and/or Browsing app modes.
        if (isset($_POST['set_config_roles_key'], $_POST['set_config_roles_hash'])) {
            $key = $_POST['set_config_roles_key'];
            $hash = preg_replace('/[^a-f0-9]/i', '', (string)($_POST['set_config_roles_hash'] ?? ''));
            if (isset($db[$key]) && $hash !== '') {
                $roles = [
                    'gaming' => !empty($_POST['role_gaming']),
                    'browsing' => !empty($_POST['role_browsing']),
                ];
                symex_set_config_roles_for_hash($db[$key], $hash, $roles);
                symex_ensure_config_roles($db[$key]);
                db_save($db);
                addLog('config', "Mode roles updated for $key / $hash: gaming=" . ($roles['gaming'] ? '1' : '0') . ', browsing=' . ($roles['browsing'] ? '1' : '0'));
                $msg = "Config mode roles updated.";
            }
        }

        // Import/paste subscription content manually. Use this when the URL opens in a browser/mobile network but the hosting server times out.
        if (isset($_POST['import_subscription_content_key'])) {
            $key = $_POST['import_subscription_content_key'];
            if (isset($db[$key])) {
                $urlToStore = trim($_POST['subscription_url'] ?? ($db[$key]['subscription_url'] ?? ''));
                $rawContent = (string)($_POST['subscription_pasted_content'] ?? '');
                $configs = normalize_config_list(extract_configs_from_text($rawContent));
                $subscriptionUrls = symex_extract_subscription_urls_from_text($rawContent);
                $fetchMessages = [];
                foreach ($subscriptionUrls as $subUrl) {
                    $test = test_subscription_url_for_panel($subUrl);
                    $found = isset($test['_configs']) && is_array($test['_configs']) ? normalize_config_list($test['_configs']) : [];
                    if (!empty($found)) {
                        $configs = array_merge($configs, $found);
                        if ($urlToStore === '') $urlToStore = $subUrl;
                        $fetchMessages[] = 'subscription url ok: ' . count($found);
                    } else {
                        $fetchMessages[] = 'subscription url failed: ' . ($test['message'] ?? 'no configs found');
                    }
                }
                $configs = normalize_config_list($configs);
                if (empty($configs)) {
                    $msg = 'No valid configs were found in the pasted subscription content.';
                    if (!empty($fetchMessages)) {
                        $msg .= ' ' . implode(' | ', $fetchMessages);
                    }
                    $db[$key]['last_subscription_test'] = [
                        'timestamp' => date('Y-m-d H:i:s'),
                        'url' => $urlToStore,
                        'status' => 'paste_invalid_content',
                        'configs_found' => 0,
                        'content_bytes' => strlen($rawContent),
                        'message' => $msg,
                        'source' => !empty($subscriptionUrls) ? 'pasted_subscription_url' : 'pasted_content',
                    ];
                    symex_log_subscription_event($db[$key], 'paste_invalid_content', [
                        'status' => 'paste_invalid_content',
                        'configs_found' => 0,
                        'content_bytes' => strlen($rawContent),
                        'message' => $msg,
                        'url' => $urlToStore,
                        'source' => !empty($subscriptionUrls) ? 'pasted_subscription_url' : 'pasted_content',
                    ]);
                } else {
                    symex_store_good_subscription_from_configs($db[$key], $urlToStore, $configs, $rawContent, 'pasted_subscription_saved');
                    $db[$key]['last_subscription_test'] = [
                        'timestamp' => date('Y-m-d H:i:s'),
                        'url' => $urlToStore,
                        'status' => 'ok',
                        'configs_found' => count($configs),
                        'content_bytes' => strlen($rawContent),
                        'message' => 'Pasted subscription parsed and saved for app delivery.' . (!empty($fetchMessages) ? ' ' . implode(' | ', $fetchMessages) : ''),
                        'source' => !empty($subscriptionUrls) ? 'pasted_subscription_url' : 'pasted_content',
                    ];
                    $msg = 'Pasted subscription imported for ' . $key . ': ' . count($configs) . ' config(s).';
                    addLog('subscription', 'Pasted subscription imported for ' . $key . ': ' . count($configs) . ' configs');
                }
                db_save($db);
            }
        }

        // Manual subscription test from panel - does not have to save/update cache.
        if (isset($_POST['test_subscription_key'])) {
            $key = $_POST['test_subscription_key'];
            if (isset($db[$key])) {
                $urlToTest = trim($_POST['subscription_url'] ?? ($db[$key]['subscription_url'] ?? ''));
                $test = test_subscription_url_for_panel($urlToTest);
                if (($test['status'] ?? '') === 'ok' && !empty($test['_configs'])) {
                    symex_store_good_subscription_from_configs($db[$key], $urlToTest, $test['_configs'], (string)($test['_raw_content'] ?? ''), 'manual_test_saved');
                }
                $publicTest = $test;
                unset($publicTest['_configs'], $publicTest['_raw_content']);
                $db[$key]['last_subscription_test'] = $publicTest;
                symex_log_subscription_event($db[$key], 'manual_test_' . ($test['status'] ?? 'unknown'), [
                    'status' => $test['status'] ?? 'unknown',
                    'configs_found' => (int)($test['configs_found'] ?? 0),
                    'content_bytes' => (int)($test['content_bytes'] ?? 0),
                    'cache_used' => false,
                    'message' => $test['message'] ?? '',
                    'url' => $urlToTest,
                ]);
                db_save($db);
                addLog('subscription', "Manual subscription test for $key: " . ($test['status'] ?? 'unknown') . " / " . (int)($test['configs_found'] ?? 0) . " configs");
                $msg = "Subscription test for $key: " . ($test['message'] ?? 'done');
            }
        }

        // Subscription management - validates content and falls back to last healthy cache/manual configs on failure
        if (isset($_POST['subscription_key'], $_POST['subscription_url']) && !isset($_POST['test_subscription_key'])) {
            $key = $_POST['subscription_key'];
            $url = trim($_POST['subscription_url']);
            if (isset($db[$key])) {
                $db[$key]['subscription_url'] = $url;
                if (!empty($url)) {
                    $result = update_subscription_cache_for_license($db[$key], $key);
                    if ($result['status'] === 'ok') {
                        $msg = "Subscription URL saved and {$result['count']} config(s) fetched for $key";
                    } else {
                        $msg = "Subscription URL saved, but {$result['message']} for $key";
                    }
                } else {
                    symex_clear_subscription_cache($db[$key], 'Subscription URL was cleared by admin; last healthy cache deleted.', true);
                    $msg = "Subscription URL and its healthy cache were cleared for $key";
                }
                db_save($db);
            }
        }

        if (isset($_POST['delete_subscription_key'])) {
            $key = $_POST['delete_subscription_key'];
            if (isset($db[$key])) {
                symex_clear_subscription_cache($db[$key], 'Subscription URL and last healthy cache deleted by admin.', true);
                db_save($db);
                addLog('subscription', "Subscription URL and cache deleted for $key");
                $msg = "Subscription and cache deleted for $key. Manual configs will be used now.";
            }
        }

        if (isset($_POST['force_update_subscription'])) {
            $key = $_POST['force_update_subscription'];
            if (isset($db[$key]) && !empty($db[$key]['subscription_url'])) {
                $result = update_subscription_cache_for_license($db[$key], $key);
                if ($result['status'] === 'ok') {
                    $msg = "Subscription content manually updated for $key ({$result['count']} configs)";
                } else {
                    $msg = "Failed to update subscription for $key: {$result['message']}";
                }
                db_save($db);
            }
        }
        // Server-side ping/score actions are disabled. Clients should test latency locally.

        if (isset($_POST['dedupe_all'])) {
            $removed = sanitize_all_licenses($db);
            db_save($db);
            $msg = "Automatic deduplication completed. Removed {$removed} duplicate/invalid stored item(s).";
            addLog('config', "Global deduplication completed. Removed {$removed} items");
        }
        // External messenger settings are removed in this panel-only build.

        // Clear logs
        if (isset($_POST['clear_logs'])) {
            file_put_contents(LOG_FILE, json_encode([], JSON_PRETTY_PRINT), LOCK_EX);
            addLog('system', 'Logs cleared by admin');
            $msg = "Logs cleared successfully";
        }
        
        if (isset($_POST['clear_access_logs'])) {
            file_put_contents(ACCESS_LOG_FILE, json_encode([], JSON_PRETTY_PRINT), LOCK_EX);
            addLog('system', 'Access logs cleared by admin');
            $msg = "Access logs cleared successfully";
        }

        // Export data
        if (isset($_POST['export_data'])) {
            $export = [
                'licenses' => db_load(),
                'logs' => file_exists(LOG_FILE) ? json_decode(file_get_contents(LOG_FILE), true) : [],
                'export_date' => date('Y-m-d H:i:s')
            ];
            header('Content-Type: application/json');
            header('Content-Disposition: attachment; filename="backup_' . date('Y-m-d') . '.json"');
            echo json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            exit;
        }

        // Import data
        if (isset($_FILES['import_file']) && $_FILES['import_file']['error'] === UPLOAD_ERR_OK) {
            $content = file_get_contents($_FILES['import_file']['tmp_name']);
            if ($content !== false) {
                $data = json_decode($content, true);
                if (isset($data['licenses']) && is_array($data['licenses'])) {
                    db_save($data['licenses']);
                    addLog('system', 'Data imported from backup');
                    $msg = "Data imported successfully";
                } else {
                    $msg = "Invalid backup file";
                }
            } else {
                $msg = "Failed to read backup file";
            }
        }
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        symex_admin_redirect_after_post($msg);
    }
}

$db = $authed ? db_load() : [];
$logs = $authed ? get_logs() : [];
$access_logs = $authed ? get_access_logs() : [];
$stats = $authed ? get_statistics($db) : [];
$system_status = $authed ? get_system_status($db) : [];
$settings = $authed ? load_settings() : load_settings();
$csrf_token = generateCSRFToken();

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Symex VPN | Secure Admin Panel</title>
<script>
document.cookie = "screen_resolution=" + screen.width + "x" + screen.height + "; path=/";
</script>
<style>
/* ============================================================
   SYMEX VPN — Admin Panel Design System (v2)
   Modern security-ops aesthetic. All original class hooks kept.
   ============================================================ */
*{box-sizing:border-box}
html{scroll-behavior:smooth}

:root{
  color-scheme:dark;
  --bg:#070b16; --bg-2:#0a1020;
  --surface:#0e1626; --surface2:#131f33; --card:#111b2e; --soft:#18243a;
  --text:#eef3fb; --muted:#90a2bd; --border:#21304a;
  --accent:#7c6bff; --accent2:#19c2ff;
  --success:#22c55e; --warning:#f59e0b; --danger:#f43f5e; --info:#38bdf8;
  --shadow:0 18px 40px -18px rgba(0,0,0,.65);
  --shadow-sm:0 6px 18px -10px rgba(0,0,0,.55);
  --ring:0 0 0 3px color-mix(in srgb,var(--accent) 32%,transparent);
  --radius:20px; --radius-sm:14px;
  /* aliases for legacy inline references */
  --text-muted:var(--muted); --bg-primary:var(--surface2);
}
[data-theme="light"]{
  color-scheme:light;
  --bg:#eef2f9; --bg-2:#e6ecf6;
  --surface:#ffffff; --surface2:#f5f8fc; --card:#ffffff; --soft:#eef3fb;
  --text:#0f1b2d; --muted:#5b6b85; --border:#dde6f2;
  --accent:#6354f4; --accent2:#0696d7;
  --success:#16a34a; --warning:#d97706; --danger:#e11d48; --info:#0284c7;
  --shadow:0 18px 38px -22px rgba(15,23,42,.28);
  --shadow-sm:0 6px 16px -10px rgba(15,23,42,.18);
  --text-muted:var(--muted); --bg-primary:var(--surface2);
}

body{
  margin:0;
  background:
    radial-gradient(1100px 540px at 12% -8%,color-mix(in srgb,var(--accent) 16%,transparent),transparent 60%),
    radial-gradient(900px 500px at 100% 0%,color-mix(in srgb,var(--accent2) 13%,transparent),transparent 55%),
    linear-gradient(180deg,var(--bg),var(--bg-2));
  background-attachment:fixed;
  font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
  font-size:13.5px; color:var(--text); line-height:1.55; min-height:100vh;
  padding:18px; transition:background .25s,color .25s;
  -webkit-font-smoothing:antialiased;
}
.container{max-width:1520px;margin:auto}
::selection{background:color-mix(in srgb,var(--accent) 40%,transparent)}

/* Scrollbars */
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-track{background:transparent}
*::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--muted) 35%,transparent);border-radius:99px;border:2px solid transparent;background-clip:padding-box}
*::-webkit-scrollbar-thumb:hover{background:color-mix(in srgb,var(--muted) 55%,transparent);background-clip:padding-box}

/* Header */
.header{
  position:sticky;top:12px;z-index:30;display:flex;justify-content:space-between;align-items:center;gap:14px;
  margin:0 0 18px;padding:14px 18px;border-radius:var(--radius);
  background:color-mix(in srgb,var(--surface) 78%,transparent);
  border:1px solid var(--border);box-shadow:var(--shadow-sm);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
}
h1{
  font-size:clamp(1.2rem,2.1vw,1.85rem);letter-spacing:-.03em;margin:0;font-weight:850;
  background:linear-gradient(120deg,var(--text),var(--accent2) 130%);
  -webkit-background-clip:text;background-clip:text;color:transparent;
  display:flex;align-items:center;gap:8px;
}

/* Surfaces */
.security-bar,.card,.stat-card{background:var(--card);border:1px solid var(--border);box-shadow:var(--shadow-sm)}
.security-bar{
  border-radius:var(--radius);padding:14px 16px;margin-bottom:16px;
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;
}
.security-item{min-width:0;border-left:2px solid color-mix(in srgb,var(--accent) 40%,transparent);padding-left:12px}
.security-label{display:block;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}
.security-value{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;font-size:.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* Tabs */
.top-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;padding:6px;border-radius:var(--radius);background:var(--card);border:1px solid var(--border);box-shadow:var(--shadow-sm)}
.top-tabs a{
  flex:0 1 auto;text-decoration:none;color:var(--muted);font-weight:750;font-size:.78rem;
  padding:9px 15px;border-radius:12px;transition:.16s;border:1px solid transparent;white-space:nowrap;
}
.top-tabs a:hover{color:var(--text);background:color-mix(in srgb,var(--accent) 10%,transparent)}
.top-tabs a.active{color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 8px 20px -10px color-mix(in srgb,var(--accent) 80%,transparent)}

/* Hero */
.hero-grid{display:grid;grid-template-columns:1.6fr 1fr;gap:14px;margin-bottom:16px}
.hero-card{position:relative;overflow:hidden;background:linear-gradient(150deg,var(--surface2),var(--card));border:1px solid var(--border);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow-sm)}
.hero-card::before{content:"";position:absolute;inset:0 0 auto auto;width:180px;height:180px;background:radial-gradient(circle,color-mix(in srgb,var(--accent) 26%,transparent),transparent 70%);transform:translate(40%,-40%);pointer-events:none}
.hero-kicker{font-size:.68rem;text-transform:uppercase;letter-spacing:.14em;font-weight:800;color:var(--accent2)}
.hero-title{font-size:1.05rem;font-weight:800;letter-spacing:-.02em;margin:6px 0 8px;line-height:1.35}
.hero-text{color:var(--muted);max-width:720px;font-size:.82rem}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:12px;margin-bottom:16px}
.stat-card{position:relative;overflow:hidden;border-radius:var(--radius);padding:15px;min-height:96px;transition:transform .15s,border-color .15s,box-shadow .15s}
.stat-card::after{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:.85}
.stat-card:hover{transform:translateY(-3px);border-color:color-mix(in srgb,var(--accent) 45%,var(--border));box-shadow:var(--shadow)}
.stat-title{font-size:.66rem;text-transform:uppercase;color:var(--muted);letter-spacing:.05em;font-weight:700}
.stat-value{font-size:clamp(1.2rem,2vw,1.7rem);font-weight:850;margin-top:10px;letter-spacing:-.02em;line-height:1.1}
.stat-unit{font-size:.68rem;color:var(--muted);margin-top:4px}

/* Cards */
.card{border-radius:var(--radius);padding:18px;margin-bottom:16px}
.card-header{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.card-title{font-weight:850;font-size:.8rem;text-transform:uppercase;letter-spacing:.09em;color:var(--text);display:flex;align-items:center;gap:7px}

/* Forms */
input,textarea,select{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;color:var(--text);font-size:.82rem;font-family:inherit;outline:none;width:100%;min-height:42px;transition:border-color .15s,box-shadow .15s}
textarea{resize:vertical;min-height:74px;line-height:1.5}
input::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--muted) 80%,transparent)}
input:hover,textarea:hover,select:hover{border-color:color-mix(in srgb,var(--accent) 30%,var(--border))}
input:focus,textarea:focus,select:focus{border-color:var(--accent);box-shadow:var(--ring)}
.input-group{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.input-field{flex:1;min-width:160px}
.input-field label{display:block;font-size:.66rem;text-transform:uppercase;font-weight:800;color:var(--muted);margin-bottom:6px;letter-spacing:.05em}

/* Buttons */
.btn{
  border:1px solid var(--border);background:var(--soft);padding:10px 15px;border-radius:var(--radius-sm);
  font-weight:800;font-size:.74rem;cursor:pointer;color:var(--text);
  display:inline-flex;align-items:center;justify-content:center;gap:6px;text-decoration:none;
  min-height:40px;line-height:1;white-space:nowrap;
  transition:transform .12s,filter .12s,box-shadow .15s,border-color .15s,background .15s;
}
.btn:hover{transform:translateY(-1px);filter:brightness(1.06);box-shadow:var(--shadow-sm)}
.btn:active{transform:translateY(0);filter:brightness(.97)}
.btn:focus-visible{outline:none;box-shadow:var(--ring)}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border-color:transparent}
.btn-danger{background:linear-gradient(135deg,var(--danger),#b91c3c);color:#fff;border-color:transparent}
.btn-warning{background:linear-gradient(135deg,var(--warning),#d97706);color:#1c1300;border-color:transparent}
.btn-success{background:linear-gradient(135deg,var(--success),#0f9d58);color:#04140b;border-color:transparent}
.btn-info{background:linear-gradient(135deg,var(--info),#0ea5e9);color:#04131f;border-color:transparent}
.btn-secondary{background:var(--soft);border-color:var(--border);color:var(--text)}
.btn-secondary:hover{border-color:color-mix(in srgb,var(--accent) 40%,var(--border))}

/* Table */
.table-wrapper{overflow:auto;border-radius:var(--radius);border:1px solid var(--border);max-height:74vh;box-shadow:var(--shadow-sm)}
table{width:100%;border-collapse:separate;border-spacing:0;min-width:980px}
th{position:sticky;top:0;z-index:5;text-align:left;padding:13px 12px;font-size:.66rem;font-weight:900;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:color-mix(in srgb,var(--surface2) 96%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
td{padding:12px;border-top:1px solid var(--border);vertical-align:middle;font-size:.78rem}
tbody tr{transition:background .12s}
tr:hover td{background:color-mix(in srgb,var(--accent) 7%,transparent)}

/* Badges */
.badge{display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;font-size:.66rem;font-weight:800;text-transform:uppercase;letter-spacing:.02em;gap:4px;border:1px solid transparent;line-height:1.4}
.badge-success{background:color-mix(in srgb,var(--success) 16%,transparent);color:var(--success);border-color:color-mix(in srgb,var(--success) 40%,transparent)}
.badge-danger{background:color-mix(in srgb,var(--danger) 16%,transparent);color:var(--danger);border-color:color-mix(in srgb,var(--danger) 40%,transparent)}
.badge-warning{background:color-mix(in srgb,var(--warning) 18%,transparent);color:var(--warning);border-color:color-mix(in srgb,var(--warning) 44%,transparent)}
.badge-info{background:color-mix(in srgb,var(--info) 16%,transparent);color:var(--info);border-color:color-mix(in srgb,var(--info) 40%,transparent)}

/* Drawers */
.cfg-drawer,.sub-drawer,.settings-drawer{display:none;background:linear-gradient(180deg,var(--surface2),var(--card));border-radius:var(--radius-sm);margin:6px 0 14px;padding:16px;border:1px solid var(--border);box-shadow:inset 0 1px 0 color-mix(in srgb,#fff 4%,transparent)}
.cfg-drawer.open,.sub-drawer.open,.settings-drawer.open{display:block;animation:drawerIn .22s ease}
@keyframes drawerIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}

/* Logs */
.logs-container{max-height:62vh;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.75rem;border:1px solid var(--border);border-radius:var(--radius-sm);background:color-mix(in srgb,var(--surface2) 60%,transparent)}
.log-entry,.access-log-entry{padding:11px 12px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:160px 110px 1fr;gap:12px;align-items:center}
.log-entry:hover,.access-log-entry:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
.log-time,.access-time{color:var(--muted);font-size:.72rem}
.log-message{color:var(--text);word-break:break-word}
.log-type,.access-status{font-weight:900;font-size:.7rem}
.log-type.auth,.access-status.success{color:var(--success)}
.log-type.license{color:var(--info)}
.log-type.device,.access-status.failed{color:var(--warning)}
.log-type.error,.access-status.blocked{color:var(--danger)}

/* Bandwidth */
.bandwidth-bar{width:110px;height:7px;background:var(--border);border-radius:99px;margin-top:6px;overflow:hidden}
.bandwidth-fill{height:100%;border-radius:99px;transition:width .3s}

/* Devices */
.device-item{background:var(--card);border-radius:var(--radius-sm);padding:14px;margin-bottom:10px;border:1px solid var(--border);transition:border-color .15s}
.device-item:hover{border-color:color-mix(in srgb,var(--accent) 35%,var(--border))}
.device-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.74rem;color:var(--accent2);word-break:break-all;font-weight:600}
.device-info{font-size:.7rem;color:var(--muted);margin-top:3px}

/* Notice */
.notice{background:color-mix(in srgb,var(--info) 11%,transparent);border:1px solid color-mix(in srgb,var(--info) 34%,transparent);padding:12px 14px;border-radius:var(--radius-sm);margin-bottom:14px}

/* Status pills */
.status-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.status-pill{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px}
.status-line{height:9px;background:var(--border);border-radius:999px;overflow:hidden;margin-top:10px}
.status-line span{display:block;height:100%;border-radius:999px;transition:width .4s}

/* System / config cards */
.system-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.system-file{display:grid;grid-template-columns:1fr auto auto auto;gap:8px;align-items:center;padding:11px;border-bottom:1px solid var(--border);font-size:.76rem}
.config-health-card,.config-quality-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;margin:8px 0}
.mode-role-box{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:8px;padding:8px;border:1px dashed color-mix(in srgb,var(--accent) 28%,var(--border));border-radius:12px;background:color-mix(in srgb,var(--accent) 6%,transparent);font-size:.72rem;color:var(--text)}
.mode-role-box label{display:inline-flex;align-items:center;gap:5px;cursor:pointer}
.mode-role-box input{accent-color:var(--accent)}
.config-quality-card:hover{border-color:color-mix(in srgb,var(--accent) 30%,var(--border))}
.mini-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.64rem;word-break:break-all;color:var(--muted)}
.health-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.muted,.text-muted{color:var(--muted)}

/* Login */
.login-container{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 36px)}
.login-container .card{position:relative;overflow:hidden}
.login-container .card::before{content:"";position:absolute;inset:-2px;border-radius:inherit;padding:1px;background:linear-gradient(135deg,color-mix(in srgb,var(--accent) 60%,transparent),transparent 45%,color-mix(in srgb,var(--accent2) 55%,transparent));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}

@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
@media (max-width:1200px){.stats-grid{grid-template-columns:repeat(4,1fr)}.security-bar{grid-template-columns:repeat(2,1fr)}}
@media (max-width:920px){.hero-grid{grid-template-columns:1fr}.system-grid{grid-template-columns:repeat(2,1fr)}}
@media (max-width:760px){
  body{padding:12px;font-size:12.5px}
  .header{top:8px;padding:12px;flex-wrap:wrap}
  .header>div{width:100%;display:grid!important;grid-template-columns:1fr 1fr;gap:8px}
  .security-bar{grid-template-columns:1fr}
  .stats-grid{grid-template-columns:repeat(2,1fr);gap:10px}
  .card{padding:14px}
  .input-field{min-width:100%;max-width:100%!important}
  .input-group>.btn,.input-group form,.input-group button{width:100%}
  .table-wrapper{max-height:none}
  .log-entry,.access-log-entry{grid-template-columns:1fr;gap:3px}
  .status-grid{grid-template-columns:1fr}
  .btn{width:auto}
  h1{font-size:1.15rem}
}
@media (max-width:560px){.system-grid{grid-template-columns:1fr}.top-tabs a{flex:1;text-align:center}}
@media (max-width:420px){.stats-grid{grid-template-columns:1fr}.header>div{grid-template-columns:1fr}.stat-card{min-height:auto}}

/* ============================================================
   Single-panel app shell
   ============================================================ */
.app{display:grid;grid-template-columns:264px 1fr;min-height:100vh;margin:-18px}
.sidebar{position:sticky;top:0;align-self:start;height:100vh;display:flex;flex-direction:column;gap:5px;padding:20px 15px;background:color-mix(in srgb,var(--surface) 84%,transparent);border-right:1px solid var(--border);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);z-index:40}
.brand{display:flex;align-items:center;gap:9px;font-size:1.18rem;font-weight:850;letter-spacing:-.02em}
.brand span{background:linear-gradient(120deg,var(--text),var(--accent2) 135%);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand-sub{font-size:.62rem;text-transform:uppercase;letter-spacing:.18em;color:var(--muted);margin:3px 0 18px 3px}
.nav{display:flex;flex-direction:column;gap:4px}
.nav-item{display:flex;align-items:center;gap:10px;width:100%;text-align:left;justify-content:flex-start;background:transparent;border:1px solid transparent;color:var(--muted);font-weight:750;font-size:.82rem;padding:11px 13px;border-radius:13px;cursor:pointer;transition:.15s;font-family:inherit}
.nav-item:hover{background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--text)}
.nav-item.active{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;box-shadow:0 12px 24px -12px color-mix(in srgb,var(--accent) 90%,transparent)}
.nav-count{margin-left:auto;font-size:.64rem;font-weight:800;background:color-mix(in srgb,var(--muted) 22%,transparent);color:var(--text);padding:2px 8px;border-radius:999px}
.nav-item.active .nav-count{background:rgba(255,255,255,.26);color:#fff}
.sidebar-foot{margin-top:auto;display:flex;flex-direction:column;gap:9px;padding-top:14px;border-top:1px solid var(--border)}
.session-mini{font-size:.68rem;color:var(--muted);line-height:1.75;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:11px}
.session-mini b{color:var(--text);font-weight:700}
.session-mini .mono{font-family:ui-monospace,Menlo,monospace;font-size:.7rem}
.foot-actions{display:flex;gap:8px}
.foot-actions .btn{flex:1;padding:9px 10px}
.main{min-width:0;padding:18px;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:12px;margin:-18px -18px 18px;padding:14px 18px;background:color-mix(in srgb,var(--surface) 78%,transparent);border-bottom:1px solid var(--border);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.topbar-title{font-size:1.05rem;font-weight:850;letter-spacing:-.02em;display:flex;align-items:center;gap:8px}
.topbar-right{margin-left:auto;display:flex;gap:16px;flex-wrap:wrap}
.chip{display:flex;flex-direction:column;line-height:1.25}
.chip small{font-size:.58rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.chip span{font-size:.76rem;font-weight:700;font-family:ui-monospace,Menlo,monospace}
.hamburger{display:none;background:var(--soft);border:1px solid var(--border);color:var(--text);width:40px;height:40px;border-radius:12px;font-size:1.1rem;cursor:pointer;flex:none}
.view{animation:viewIn .25s ease}
.view[hidden]{display:none!important}
@keyframes viewIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.scrim{display:none}
@media (max-width:980px){
  .app{grid-template-columns:1fr}
  .sidebar{position:fixed;top:0;left:0;width:284px;height:100vh;transform:translateX(-100%);transition:transform .25s ease;box-shadow:var(--shadow)}
  .sidebar.open{transform:translateX(0)}
  .hamburger{display:inline-flex;align-items:center;justify-content:center}
  .scrim{display:block;position:fixed;inset:0;background:rgba(0,0,0,.55);opacity:0;pointer-events:none;transition:opacity .25s;z-index:39}
  .scrim.open{opacity:1;pointer-events:auto}
  .topbar-right .chip{display:none}
  .topbar-right .chip.keep{display:flex}
}
@media (max-width:760px){.app{margin:-12px}.main{padding:12px}.topbar{margin:-12px -12px 14px;padding:12px}}


/* Inline SVG icons */
.nav-ic{width:18px;height:18px;flex:none}
.brand-ic{width:21px;height:21px;flex:none;color:var(--accent2)}
.brand{display:flex;align-items:center;gap:9px}
.view-ic{width:20px;height:20px}
#view-icon{display:inline-flex;align-items:center;color:var(--accent2)}
#view-icon svg{width:20px;height:20px}
.topbar-title{gap:9px}

/* Adaptive inline icons (scale to surrounding text) */
.ic{width:1em;height:1em;display:inline-block;vertical-align:-0.14em;flex:none}
.btn .ic{width:1.05em;height:1.05em}
.stat-title,.card-title,.security-label,.hero-kicker{display:inline-flex;align-items:center;gap:6px}
.card-title{display:flex}
</style>
</head>
<body data-theme="<?= $theme ?>">

<div class="app-root">

<?php if (!$authed): ?>
<div class="login-container" style="display: flex; align-items: center; justify-content: center; min-height: 90vh;">
  <div class="card" style="max-width: 360px; width: 100%; text-align: center;">
    <div class="card-header" style="justify-content: center;">
      <span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Symex VPN | Secure Login</span>
    </div>
    <div class="security-bar" style="margin-bottom:1rem;grid-template-columns:1fr;">
      <div class="security-item" style="text-align:left;">
        <span class="security-label"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg> Your IP</span>
        <span class="security-value" style="white-space:normal;"><?= htmlspecialchars(getUserIP()) ?></span>
      </div>
    </div>
    <?php if (!empty($err)): ?>
      <div class="notice" style="background:color-mix(in srgb,var(--danger) 12%,transparent);border-color:color-mix(in srgb,var(--danger) 38%,transparent);color:var(--danger);font-size:.8rem;margin-bottom:1rem;display:flex;gap:8px;align-items:center;">
        <span><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg></span><span><?= htmlspecialchars($err) ?></span>
      </div>
    <?php endif ?>
    <?php if (file_exists(ADMIN_INITIAL_PASSWORD_FILE)): ?>
      <div class="notice" style="background:color-mix(in srgb,var(--warning) 12%,transparent);border-color:color-mix(in srgb,var(--warning) 38%,transparent);color:var(--warning);font-size:.74rem;margin-bottom:1rem;text-align:left;line-height:1.6;">
        Initial password was generated in <b>.symex_initial_admin_password</b>. Delete that file after setting your permanent admin password.
      </div>
    <?php endif ?>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
      <div class="input-field" style="margin-bottom: 20px;">
        <label>Administrator Password</label>
        <input type="password" name="password" placeholder="••••••••" autofocus>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> Unlock Panel</button>
    </form>
    <div style="margin-top: 1rem; font-size: 0.6rem; color: var(--text-muted);">All login attempts are logged</div>
  </div>
</div>
<?php else: ?>
<?php $deviceInfo = getUserDeviceInfo(); ?>
<div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><svg class="brand-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/></svg><span>Symex VPN</span></div>
    <div class="brand-sub">Secure Admin Console</div>
    <nav class="nav">
      <button type="button" class="nav-item active" data-target="overview"><svg class="nav-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg><span>Overview</span></button>
      <button type="button" class="nav-item" data-target="licenses"><svg class="nav-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg><span>Licenses</span><span class="nav-count"><?= count($db) ?></span></button>
      <button type="button" class="nav-item" data-target="status"><svg class="nav-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg><span>System Status</span></button>
      <button type="button" class="nav-item" data-target="logs"><svg class="nav-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/></svg><span>System Logs</span></button>
      <button type="button" class="nav-item" data-target="access"><svg class="nav-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg><span>Access Logs</span></button>
      <button type="button" class="nav-item" data-target="settings"><svg class="nav-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg><span>Settings</span></button>
    </nav>
    <div class="sidebar-foot">
      <div class="session-mini">
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg> <b>IP</b> <span class="mono"><?= htmlspecialchars(getUserIP()) ?></span><br>
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg> <b>Device</b> <?= htmlspecialchars($deviceInfo['os']) ?> / <?= htmlspecialchars($deviceInfo['browser']) ?><br>
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> <b>Login</b> <span class="mono"><?= htmlspecialchars($_SESSION['login_info']['login_time'] ?? 'N/A') ?></span><br>
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2h4"/><path d="M12 14l3-3"/><circle cx="12" cy="14" r="8"/></svg> <b>Timeout</b> <?= SESSION_TIMEOUT / 60 ?> min
      </div>
      <div class="foot-actions">
        <button type="button" class="btn btn-secondary" onclick="toggleTheme()"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 18a6 6 0 0 0 0-12z" fill="currentColor" stroke="none"/></svg> Theme</button>
        <a href="?logout=1" class="btn btn-danger" onclick="return confirm('Logout?')"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></svg> Sign out</a>
      </div>
    </div>
  </aside>
  <div class="scrim" id="scrim" onclick="toggleSidebar()"></div>

  <main class="main">
    <header class="topbar">
      <button type="button" class="hamburger" onclick="toggleSidebar()"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/></svg></button>
      <div class="topbar-title"><span id="view-icon"><svg class="view-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg></span><span id="view-title">Overview</span></div>
      <div class="topbar-right">
        <div class="chip keep"><small>IP</small><span><?= htmlspecialchars(getUserIP()) ?></span></div>
        <div class="chip"><small>Device</small><span><?= htmlspecialchars($deviceInfo['os']) ?>/<?= htmlspecialchars($deviceInfo['browser']) ?></span></div>
        <div class="chip"><small>Session</small><span><?= SESSION_TIMEOUT / 60 ?> min</span></div>
      </div>
    </header>

    <?php if ($msg): ?>
      <div class="notice" style="display:flex;align-items:center;gap:8px;font-size:.82rem;">
        <span style="font-size:1rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/></svg></span><span><?= htmlspecialchars($msg) ?></span>
      </div>
    <?php endif ?>

    <!-- OVERVIEW -->
    <section class="view" data-view="overview">
<div class="hero-grid">
  <div class="hero-card">
    <div class="hero-kicker">Smart Subscription Gateway</div>
    <div class="hero-title">Best server is selected automatically without live speed tests.</div>
    <div class="hero-text">Every successful app entry refreshes the subscription, removes duplicate configs, falls back to manual configs when the sub is broken, and returns validated configs sorted by deterministic quality. The Android app should test latency locally and choose the fastest config for each user network.</div>
  </div>
  <div class="hero-card">
    <div class="hero-kicker">System Snapshot</div>
    <div class="health-row">
      <span class="badge badge-success">Valid Configs: <?= (int)($system_status['quality']['valid'] ?? 0) ?></span>
      <span class="badge badge-danger">Invalid: <?= (int)($system_status['quality']['invalid'] ?? 0) ?></span>
      <span class="badge badge-warning">Sub Warnings: <?= (int)($system_status['subscription_warning'] ?? 0) ?></span>
      <span class="badge badge-info">Manual Configs: <?= (int)($system_status['manual_configs'] ?? 0) ?></span>
    </div>
    <div class="muted" style="margin-top:10px;">Last server render: <?= htmlspecialchars($system_status['server_time'] ?? date('Y-m-d H:i:s')) ?></div>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4"/><path d="M12 16h4"/><path d="M8 11h.01"/><path d="M8 16h.01"/></svg> Total Licenses</div><div class="stat-value"><?= number_format($stats['total']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.801 10A10 10 0 1 1 17 3.335"/><path d="m9 11 3 3L22 4"/></svg> Active</div><div class="stat-value" style="color: var(--success);"><?= number_format($stats['active']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Expired</div><div class="stat-value" style="color: var(--danger);"><?= number_format($stats['expired']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg> Disabled</div><div class="stat-value" style="color: var(--warning);"><?= number_format($stats['disabled']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/></svg> Connected Devices</div><div class="stat-value"><?= number_format($stats['total_devices']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg> Expiring Soon</div><div class="stat-value" style="color: var(--warning);"><?= number_format($stats['expiring_soon']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Total Used</div><div class="stat-value" style="color: var(--info);"><?= formatBytes($stats['total_bandwidth_used']) ?></div></div>
  <div class="stat-card"><div class="stat-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg> Total Limit</div><div class="stat-value" style="color: var(--info);"><?= formatBytes($stats['total_bandwidth_limit']) ?></div></div>
</div>


      <div class="card">
        <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg> License Status Distribution</span><span class="badge badge-info">Lightweight CSS chart</span></div>
  <?php $totalForChart = max(1, (int)$stats['total']); $activePct = round(($stats['active'] / $totalForChart) * 100); $expiredPct = round(($stats['expired'] / $totalForChart) * 100); $disabledPct = round(($stats['disabled'] / $totalForChart) * 100); ?>
  <div class="status-grid">
    <div class="status-pill"><div class="stat-title">Active</div><div class="stat-value" style="color:var(--success)"><?= $activePct ?>%</div><div class="status-line"><span style="width:<?= $activePct ?>%;background:var(--success)"></span></div></div>
    <div class="status-pill"><div class="stat-title">Expired</div><div class="stat-value" style="color:var(--danger)"><?= $expiredPct ?>%</div><div class="status-line"><span style="width:<?= $expiredPct ?>%;background:var(--danger)"></span></div></div>
    <div class="status-pill"><div class="stat-title">Disabled</div><div class="stat-value" style="color:var(--warning)"><?= $disabledPct ?>%</div><div class="status-line"><span style="width:<?= $disabledPct ?>%;background:var(--warning)"></span></div></div>
  </div>
</div>
    </section>

    <!-- LICENSES -->
    <section class="view" data-view="licenses" hidden>
<div class="card">
  <div class="card-header">
    <span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/></svg> + New License</span>
  </div>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
    <div class="input-group">
      <div class="input-field"><label>License key</label><input type="text" name="add_license" placeholder="XXXX-XXXX-XXXX-XXXX" style="text-transform: uppercase;"></div>
      <div class="input-field" style="max-width: 80px;"><label>Days</label><input type="number" name="expires_days" placeholder="30" step="1"></div>
      <div class="input-field" style="max-width: 90px;"><label>Max Devices</label><input type="number" name="max_devices" value="1" min="1" step="1"></div>
      <div class="input-field" style="max-width: 100px;"><label>Bandwidth (GB)</label><input type="number" name="bandwidth_limit" value="0" step="0.01" min="0" placeholder="0=unlimited"></div>
      <div><button type="submit" class="btn btn-primary" style="margin-top: 22px;">+ Create</button></div>
    </div>
  </form>
</div>
      <?php if (empty($db)): ?>
        <div class="card"><div style="text-align:center;color:var(--muted);padding:2rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .962 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.962 0z"/></svg> No licenses yet. Create the first one above.</div></div>
      <?php else: ?>
      <div class="card">
        <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg> All Licenses</span><span class="badge badge-info"><?= count($db) ?> total</span></div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr><th>Key</th><th>Status</th><th>Expires</th><th>Devices</th><th>Bandwidth</th><th>Configs</th><th>Best</th><th>Sub</th><th>Actions</th></tr>
        </thead>
        <tbody>
        <?php foreach ($db as $key => $row):
            $active = (bool) ($row['active'] ?? false);
            $expired = !empty($row['expires_at']) && is_expired($row['expires_at']);
            $daysRemaining = !empty($row['expires_at']) && !$expired ? get_days_remaining($row['expires_at']) : ($expired ? 'Expired' : '∞');
            $deviceCount = count($row['devices'] ?? []);
            $maxDevices = $row['max_devices'] ?? 1;
            $cfgCount = count(normalize_config_list($row['configs'] ?? []));
            $hasSubUrl = !empty($row['subscription_url']);
            $subStatus = $row['last_subscription_status'] ?? ($hasSubUrl ? 'unknown' : 'no_url');
            $subConfigCount = (int)($row['subscription_config_count'] ?? 0);
            $qualitySummary = summarize_license_quality($row);
            $bestScore = $qualitySummary['best_score'] ?? null;
            $bandwidthLimit = $row['bandwidth_limit'] ?? 0;
            $bandwidthUsed = $row['bandwidth_used'] ?? 0;
            $bandwidthPercent = $bandwidthLimit > 0 ? min(100, round(($bandwidthUsed / $bandwidthLimit) * 100)) : 0;
            $safeKey = htmlspecialchars($key);
            $bandwidthColor = $bandwidthPercent > 90 ? 'var(--danger)' : ($bandwidthPercent > 70 ? 'var(--warning)' : 'var(--success)');
        ?>
          <tr>
            <td style="font-family: monospace; font-size: 0.65rem;"><?= htmlspecialchars(substr($safeKey, 0, 16)) ?>..</td>
            <td><?= $expired ? '<span class="badge badge-danger">Expired</span>' : ($active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-warning">Disabled</span>') ?></td>
            <td><?= $expired ? '<span class="badge badge-danger">' . $daysRemaining . '</span>' : ($row['expires_at'] !== '' ? '<span class="badge badge-warning">' . $daysRemaining . '</span>' : '<span class="badge badge-info">∞</span>') ?></td>
            <td><button class="btn btn-secondary" onclick="toggleSettings('<?= $safeKey ?>')"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/></svg> <?= $deviceCount ?>/<?= $maxDevices ?> ▾</button></td>
            <td>
              <?php if ($bandwidthLimit > 0): ?>
                <div style="min-width: 100px;">
                  <span class="badge badge-info" style="font-size: 0.55rem;"><?= formatBytes($bandwidthUsed) ?> / <?= formatBytes($bandwidthLimit) ?></span>
                  <div class="bandwidth-bar"><div class="bandwidth-fill" style="width: <?= $bandwidthPercent ?>%; background: <?= $bandwidthColor ?>;"></div></div>
                </div>
              <?php else: ?>
                <span class="badge badge-info">∞ Unlimited</span>
              <?php endif; ?>
            </td>
            <td><button class="btn btn-secondary" onclick="toggleCfg('<?= $safeKey ?>')"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z"/><path d="M12 22V12"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="m7.5 4.27 9 5.15"/></svg> <?= $cfgCount ?> ▾</button></td>
            <td>
              <span class="badge badge-success" title="Server fallback recommendation. The app should test latency locally and select the fastest config for this user."><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/></svg> <?= $bestScore !== null ? htmlspecialchars((string)round((float)$bestScore, 1)) : 'N/A' ?></span>
            </td>
            <td><button class="btn btn-secondary" onclick="toggleSub('<?= $safeKey ?>')"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg> <?= $hasSubUrl ? ($subStatus === 'ok' ? '✓ ' . $subConfigCount : '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>') : '✗' ?> ▾</button></td>
            <td>
              <div style="display: flex; gap: 3px; flex-wrap: wrap;">
                <form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="toggle" value="<?= $safeKey ?>"><button class="btn <?= $active ? 'btn-warning' : 'btn-success' ?>" style="padding: 0.2rem 0.5rem;"><?= $active ? '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>' : '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.801 10A10 10 0 1 1 17 3.335"/><path d="m9 11 3 3L22 4"/></svg>' ?></button></form>
                <form method="post" onsubmit="return confirm('Reset bandwidth for <?= $safeKey ?>?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="reset_bandwidth" value="<?= $safeKey ?>"><button class="btn btn-info" style="padding: 0.2rem 0.5rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg></button></form>
                <form method="post" onsubmit="return confirm('Reset all active devices for <?= $safeKey ?>? This will NOT block them; they can activate again with the license.')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="reset_device" value="<?= $safeKey ?>"><button class="btn btn-secondary" title="Reset devices without blocking" style="padding: 0.2rem 0.5rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg></button></form>
                <form method="post" onsubmit="return confirm('Delete license?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="delete" value="<?= $safeKey ?>"><button class="btn btn-danger" style="padding: 0.2rem 0.5rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></form>
              </div>
            </td>
          </tr>
          
          <!-- Settings Drawer with device bandwidth -->
          <tr id="settings-row-<?= $safeKey ?>"><td colspan="9" style="padding:0;"><div class="settings-drawer" id="settings-drawer-<?= $safeKey ?>">
            <form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="update_settings_key" value="<?= $safeKey ?>">
            <div class="input-group">
              <div class="input-field" style="max-width:100px;"><label>Max Devices</label><input type="number" name="max_devices" value="<?= $maxDevices ?>" min="1" step="1"></div>
              <div class="input-field" style="max-width:120px;"><label>Bandwidth (GB)</label><input type="number" name="bandwidth_limit" value="<?= $bandwidthLimit > 0 ? round($bandwidthLimit / 1073741824, 2) : 0 ?>" step="0.01" min="0" placeholder="0=unlimited"></div>
              <button type="submit" class="btn btn-primary"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Save</button>
            </div></form>
            
            <div style="margin-top: 1rem;">
              <strong><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/></svg> Connected Devices & Bandwidth Usage:</strong>
              <?php if (!empty($row['devices'])): ?>
                <?php foreach ($row['devices'] as $dev): 
                  $devId = $dev['device_id'];
                  $devBandwidth = $row['device_bandwidth'][$devId] ?? 0;
                  $devPercent = $bandwidthLimit > 0 ? min(100, round(($devBandwidth / $bandwidthLimit) * 100)) : 0;
                ?>
                  <div class="device-item">
                    <div class="device-id"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg> <?= htmlspecialchars(substr($devId, 0, 30)) ?>...</div>
                    <div class="device-info">
                      Registered: <?= $dev['registered_at'] ?? 'N/A' ?> | 
                      Last seen: <?= $dev['last_seen'] ?? 'N/A' ?>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 5px; flex-wrap: wrap; gap: 5px;">
                      <div>
                        <span class="badge badge-info"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Used: <?= formatBytes($devBandwidth) ?></span>
                        <?php if ($bandwidthLimit > 0): ?>
                          <div class="bandwidth-bar" style="width: 100px;"><div class="bandwidth-fill" style="width: <?= $devPercent ?>%; background: <?= $devPercent > 90 ? 'var(--danger)' : ($devPercent > 70 ? 'var(--warning)' : 'var(--success)') ?>;"></div></div>
                        <?php endif; ?>
                      </div>
                      <form method="post" onsubmit="return confirm('Reset bandwidth for this device?')">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <input type="hidden" name="reset_device_bandwidth" value="<?= $safeKey ?>">
                        <input type="hidden" name="reset_device_id" value="<?= htmlspecialchars($devId) ?>">
                        <button class="btn btn-warning" style="padding: 0.2rem 0.5rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Reset Device Bandwidth</button>
                      </form>
                      <form method="post" onsubmit="return confirm('Reset this device? This removes it from the active list but does NOT block it. The user can enter the license again.')">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <input type="hidden" name="reset_device" value="<?= $safeKey ?>">
                        <input type="hidden" name="reset_device_id" value="<?= htmlspecialchars($devId) ?>">
                        <button class="btn btn-secondary" style="padding: 0.2rem 0.5rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg> Reset Device</button>
                      </form>
                      <form method="post" onsubmit="return confirm('Block this device completely? It will not be able to use this license until you clear device blocks.')">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <input type="hidden" name="block_device" value="<?= $safeKey ?>">
                        <input type="hidden" name="block_device_id" value="<?= htmlspecialchars($devId) ?>">
                        <button class="btn btn-danger" style="padding: 0.2rem 0.5rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg> Block Device</button>
                      </form>
                    </div>
                  </div>
                <?php endforeach; ?>
              <?php else: ?>
                <div style="margin-top: 0.5rem; color: var(--text-muted);">No devices connected.</div>
              <?php endif; ?>
              <?php if (!empty($row['revoked_devices'])): ?>
                <div style="margin-top: 10px; padding: 10px; border: 1px solid var(--border); border-radius: 12px; background: var(--surface2);">
                  <strong><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg> Blocked Devices:</strong> <?= count($row['revoked_devices']) ?>
                  <form method="post" style="display:inline-block; margin-left:8px;" onsubmit="return confirm('Clear all blocked/reset device markers for <?= $safeKey ?>?')">
                    <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                    <input type="hidden" name="clear_device_blocks" value="<?= $safeKey ?>">
                    <button class="btn btn-warning" style="padding: 0.2rem 0.5rem;">Clear Blocks</button>
                  </form>
                  <div style="margin-top:6px;color:var(--muted);font-size:.72rem;">Reset Device is not a block anymore. Use Block Device only when you want to prevent that phone from using the license.</div>
                </div>
              <?php endif; ?>
            </div>
          </div></td></tr>
          
          <!-- Config Drawer -->
          <tr id="cfg-row-<?= $safeKey ?>"><td colspan="9" style="padding:0;"><div class="cfg-drawer" id="cfg-drawer-<?= $safeKey ?>">
            <form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="config_key" value="<?= $safeKey ?>">
            <div class="input-group"><div class="input-field"><textarea name="add_config" rows="4" placeholder="Paste configs or subscription URLs here. Valid vless/vmess/trojan/ss/etc. links will be detected automatically."></textarea><div style="font-size:0.68rem;color:var(--text-muted);margin-top:4px;">Bulk import enabled: multiple configs and subscription URLs are fetched, parsed, validated, deduplicated, and sorted automatically. Smart mode uses the lowest client latency. Optional tags below force Gaming/Browsing buttons to prefer these configs.</div><div class="mode-role-box"><label><input type="checkbox" name="add_config_roles[]" value="gaming"> Gaming</label><label><input type="checkbox" name="add_config_roles[]" value="browsing"> Browsing / Web</label></div></div><button type="submit" class="btn btn-primary">Add</button></div></form>
            <?php if ($cfgCount > 0): ?>
              <?php $manualConfigText = implode("\n", normalize_config_list($row['configs'] ?? [])); ?>
              <div style="display:flex; justify-content:space-between; margin-bottom:8px; gap:8px; flex-wrap:wrap;"><span class="badge badge-info">Total: <?= $cfgCount ?></span>
              <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;"><button type="button" class="btn btn-success" style="padding:0.2rem 0.6rem;" onclick="copyManualConfigs('<?= $safeKey ?>')"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4"/><path d="M12 16h4"/><path d="M8 11h.01"/><path d="M8 16h.01"/></svg> Copy All Manual</button><textarea id="manual-configs-<?= $safeKey ?>" readonly style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;"><?= htmlspecialchars($manualConfigText) ?></textarea>
              <form method="post" onsubmit="return confirm('Clear all configs?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="clear_configs_key" value="<?= $safeKey ?>"><button class="btn btn-danger" style="padding:0.2rem 0.6rem;">Clear All</button></form></div></div>
              <?php foreach ($row['configs'] as $ci => $cval): $ch = $row['config_quality'][config_hash($cval)] ?? config_static_quality_score($cval, $ci); $cHash = config_hash($cval); $cRoles = symex_get_config_roles($row, $cval); ?>
                <div class="config-quality-card">
                  <div class="mini-code"><?= htmlspecialchars(substr($cval, 0, 120)) ?>...</div>
                  <div class="health-row"><span class="badge <?= badge_for_quality_status($ch['status'] ?? 'unknown') ?>"><?= htmlspecialchars($ch['status'] ?? 'unknown') ?></span><span class="badge badge-info">score: <?= htmlspecialchars((string)($ch['score'] ?? 'N/A')) ?></span><?php if (!empty($ch['scheme'])): ?><span class="badge badge-info"><?= htmlspecialchars($ch['scheme']) ?></span><?php endif; ?><?php if (!empty($ch['host'])): ?><span class="badge badge-info"><?= htmlspecialchars($ch['host']) ?>:<?= (int)($ch['port'] ?? 0) ?></span><?php endif; ?><?php if ($cRoles['gaming']): ?><span class="badge badge-warning">Gaming</span><?php endif; ?><?php if ($cRoles['browsing']): ?><span class="badge badge-info">Browsing</span><?php endif; ?></div>
                  <form method="post" class="mode-role-box"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="set_config_roles_key" value="<?= $safeKey ?>"><input type="hidden" name="set_config_roles_hash" value="<?= htmlspecialchars($cHash) ?>"><label><input type="checkbox" name="role_gaming" value="1" <?= $cRoles['gaming'] ? 'checked' : '' ?>> Gaming</label><label><input type="checkbox" name="role_browsing" value="1" <?= $cRoles['browsing'] ? 'checked' : '' ?>> Browsing / Web</label><button type="submit" class="btn btn-success" style="padding:0.2rem 0.6rem;">Save mode</button></form>
                  <div style="display:flex; gap:4px; margin-top:8px;">
                    <button type="button" class="btn btn-secondary" onclick="toggleCEdit('<?= $safeKey ?>',<?= $ci ?>)"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/></svg> Edit</button>
                    <form method="post" onsubmit="return confirm('Delete config?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="delete_config_key" value="<?= $safeKey ?>"><input type="hidden" name="delete_config_index" value="<?= $ci ?>"><button class="btn btn-danger"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></button></form>
                  </div>
                  <div id="cedit-<?= $safeKey ?>-<?= $ci ?>" style="display:none; margin-top:4px;">
                    <form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="edit_config_key" value="<?= $safeKey ?>"><input type="hidden" name="edit_config_index" value="<?= $ci ?>"><textarea name="edit_config_value" rows="2" style="width:100%;"><?= htmlspecialchars($cval) ?></textarea><div style="display:flex; gap:4px; margin-top:4px;"><button type="submit" class="btn btn-success">Save</button><button type="button" class="btn btn-secondary" onclick="toggleCEdit('<?= $safeKey ?>',<?= $ci ?>)">Cancel</button></div></form>
                  </div>
                </div>
              <?php endforeach; ?>
            <?php else: ?><div style="color:var(--text-muted);">No configs.</div><?php endif; ?>
          </div></td></tr>
          
          <!-- Subscription Drawer -->
          <tr id="sub-row-<?= $safeKey ?>"><td colspan="9" style="padding:0;"><div class="sub-drawer" id="sub-drawer-<?= $safeKey ?>">
            <form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="subscription_key" value="<?= $safeKey ?>"><div class="input-group"><div class="input-field"><label>Subscription URL</label><input type="text" name="subscription_url" value="<?= htmlspecialchars($row['subscription_url'] ?? '') ?>" placeholder="Subscription URL"></div><button type="submit" class="btn btn-primary"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Save</button><button type="submit" name="test_subscription_key" value="<?= $safeKey ?>" class="btn btn-info"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2v6a2 2 0 0 0 .245.96l5.51 10.04A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.04A2 2 0 0 0 10 8V2"/><path d="M8.5 2h7"/><path d="M7 16h10"/></svg> Test Link</button></div></form>
            <form method="post" style="margin-top:10px;"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="import_subscription_content_key" value="<?= $safeKey ?>"><input type="hidden" name="subscription_url" value="<?= htmlspecialchars($row['subscription_url'] ?? '') ?>"><div class="input-group"><div class="input-field"><label>Paste Subscription Content / Browser Fallback</label><textarea name="subscription_pasted_content" rows="4" placeholder="خود لینک ساب یا محتوای باز شده را اینجا Paste کن. Base64، متن ساده، JSON، Clash/YAML و کانفیگ‌های vless/vmess/trojan/ss/ws پشتیبانی می‌شود."></textarea><div style="font-size:0.68rem;color:var(--muted);margin-top:4px;">این محتوا به‌عنوان آخرین ساب سالم ذخیره می‌شود و اپ دقیقاً همین کانفیگ‌ها را دریافت می‌کند.</div></div><button type="submit" class="btn btn-success"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg> Import Pasted Sub</button></div></form>
            <?php if (!empty($row['subscription_url'])): ?>
              <div style="margin-top:0.5rem;"><div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;"><div style="display:flex;gap:6px;flex-wrap:wrap;"><span class="badge badge-info">Last success: <?= $row['last_subscription_update'] ?? 'Never' ?></span><span class="badge <?= ($row['last_subscription_status'] ?? '') === 'ok' ? 'badge-success' : 'badge-warning' ?>">Status: <?= htmlspecialchars($row['last_subscription_status'] ?? 'unknown') ?><?= !empty($row['subscription_config_count']) ? ' / ' . (int)$row['subscription_config_count'] . ' configs' : '' ?></span></div><div style="display:flex;gap:6px;flex-wrap:wrap;"><form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="force_update_subscription" value="<?= $safeKey ?>"><button class="btn btn-info" style="padding:0.2rem 0.6rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg> Force</button></form><form method="post" onsubmit="return confirm('Delete subscription URL and cached subscription configs for <?= $safeKey ?>? Manual configs will be used after this.');"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="delete_subscription_key" value="<?= $safeKey ?>"><button class="btn btn-danger" style="padding:0.2rem 0.6rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m13.4 7.4 3.2 3.2"/><path d="M19 5 11.5 12.5"/><path d="M5.5 14.5 9 18s-1 3-4 3c0 0-1.5 0-3-1.5 2-1 1.5-3 1.5-3l2-2"/><path d="m14 6 4 4 2.5-2.5a2.83 2.83 0 0 0-4-4Z"/></svg> Delete Sub + Cache</button></form></div></div>
              <?php if (!empty($row['last_subscription_error'])): ?><div style="font-size:0.68rem;color:var(--warning);margin-top:6px;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg> <?= htmlspecialchars($row['last_subscription_error']) ?> <?= !empty($row['subscription_cache_used']) ? 'Last healthy cache is being used.' : 'Manual configs are used as fallback if no cache exists.' ?></div><?php endif; ?>
              <div class="health-row" style="margin-top:8px;"><span class="badge badge-info">Last good: <?= htmlspecialchars($row['subscription_last_good_update'] ?? 'Never') ?></span><span class="badge badge-info">Good cache: <?= (int)($row['subscription_last_good_count'] ?? 0) ?></span><?php if (!empty($row['subscription_cache_used'])): ?><span class="badge badge-warning">Using cached sub</span><?php endif; ?><?php if (!empty($row['last_subscription_cache_used_at'])): ?><span class="badge badge-warning">Cache used at: <?= htmlspecialchars($row['last_subscription_cache_used_at']) ?></span><?php endif; ?></div>
              <?php if (!empty($row['last_subscription_test']) && is_array($row['last_subscription_test'])): $t = $row['last_subscription_test']; ?><div style="margin-top:8px;padding:10px;border:1px solid var(--border);border-radius:14px;background:var(--surface);"><strong><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2v6a2 2 0 0 0 .245.96l5.51 10.04A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.04A2 2 0 0 0 10 8V2"/><path d="M8.5 2h7"/><path d="M7 16h10"/></svg> Last manual test</strong><div class="health-row" style="margin-top:6px;"><span class="badge <?= ($t['status'] ?? '') === 'ok' ? 'badge-success' : 'badge-warning' ?>"><?= htmlspecialchars($t['status'] ?? 'unknown') ?></span><span class="badge badge-info">configs: <?= (int)($t['configs_found'] ?? 0) ?></span><span class="badge badge-info">bytes: <?= (int)($t['content_bytes'] ?? 0) ?></span><span class="badge badge-info"><?= htmlspecialchars($t['timestamp'] ?? '') ?></span></div><div style="font-size:.72rem;color:var(--muted);margin-top:6px;"><?= htmlspecialchars($t['message'] ?? '') ?></div></div><?php endif; ?>
              <?php $subLogs = array_reverse(array_slice($row['subscription_logs'] ?? [], -8)); if (!empty($subLogs)): ?><div style="margin-top:8px;padding:10px;border:1px solid var(--border);border-radius:14px;background:var(--surface);"><strong><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/></svg> Subscription Log</strong><?php foreach ($subLogs as $sl): ?><div style="display:grid;grid-template-columns:140px 140px 1fr;gap:8px;border-top:1px solid var(--border);padding-top:6px;margin-top:6px;font-size:.68rem;"><span><?= htmlspecialchars($sl['timestamp'] ?? '') ?></span><span class="badge <?= (($sl['status'] ?? $sl['event'] ?? '') === 'ok') ? 'badge-success' : (!empty($sl['cache_used']) ? 'badge-warning' : 'badge-info') ?>"><?= htmlspecialchars($sl['event'] ?? $sl['status'] ?? 'event') ?></span><span><?= htmlspecialchars(($sl['message'] ?? '') . ' | configs=' . (string)($sl['configs_found'] ?? $sl['cache_count'] ?? 0) . ' | bytes=' . (string)($sl['content_bytes'] ?? 0)) ?></span></div><?php endforeach; ?></div><?php endif; ?>
              <div style="background:var(--bg-primary); border-radius:8px; padding:0.4rem; margin-top:0.5rem; max-height:120px; overflow:auto;"><pre style="font-family:monospace; font-size:0.55rem; white-space:pre-wrap;"><?= htmlspecialchars(substr($row['subscription_content'] ?? '', 0, 400)) ?></pre></div></div>
            <?php else: ?>
              <div style="color:var(--text-muted);">No subscription URL.</div>
              <?php if (!empty($row['subscription_last_good_content']) || !empty($row['subscription_content'])): ?>
                <div class="health-row" style="margin-top:8px;"><span class="badge badge-warning">Stale subscription cache exists</span><span class="badge badge-info">Good cache: <?= (int)($row['subscription_last_good_count'] ?? 0) ?></span></div>
                <form method="post" style="margin-top:8px;" onsubmit="return confirm('Delete stale subscription cache for <?= $safeKey ?>? Manual configs will be used after this.');"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden" name="delete_subscription_key" value="<?= $safeKey ?>"><button class="btn btn-danger" style="padding:0.2rem 0.6rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m13.4 7.4 3.2 3.2"/><path d="M19 5 11.5 12.5"/><path d="M5.5 14.5 9 18s-1 3-4 3c0 0-1.5 0-3-1.5 2-1 1.5-3 1.5-3l2-2"/><path d="m14 6 4 4 2.5-2.5a2.83 2.83 0 0 0-4-4Z"/></svg> Delete Stale Sub Cache</button></form>
              <?php endif; ?>
            <?php endif; ?>
          </div></td></tr>
        <?php endforeach; ?>
        </tbody>
       </table>
    </div>
      </div>
      <?php endif; ?>
    </section>

    <!-- SYSTEM STATUS -->
    <section class="view" data-view="status" hidden>
      <div class="card">
        <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg> System Status</span><span class="badge badge-info">Live server snapshot</span></div>
    <div class="system-grid">
      <div class="stat-card"><div class="stat-title">PHP Version</div><div class="stat-value"><?= htmlspecialchars($system_status['php_version']) ?></div><div class="stat-unit"><?= htmlspecialchars($system_status['timezone']) ?></div></div>
      <div class="stat-card"><div class="stat-title">Subscription OK</div><div class="stat-value" style="color:var(--success)"><?= (int)$system_status['subscription_ok'] ?></div><div class="stat-unit">Warnings: <?= (int)$system_status['subscription_warning'] ?> / No URL: <?= (int)$system_status['subscription_no_url'] ?></div></div>
      <div class="stat-card"><div class="stat-title">Config Quality</div><div class="stat-value" style="color:var(--success)"><?= (int)($system_status['quality']['valid'] ?? 0) ?></div><div class="stat-unit">Invalid: <?= (int)($system_status['quality']['invalid'] ?? 0) ?> / Method: <?= htmlspecialchars($system_status['selection_method']) ?></div></div>
      <div class="stat-card"><div class="stat-title">Manual Configs</div><div class="stat-value"><?= (int)$system_status['manual_configs'] ?></div><div class="stat-unit">After normalization and dedupe</div></div>
    </div>
    <div class="card" style="margin-top:16px;">
      <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15.39 4.39a1 1 0 0 0 1.68-.474 2.5 2.5 0 1 1 3.014 3.015 1 1 0 0 0-.474 1.68l1.683 1.682a2.414 2.414 0 0 1 0 3.414L19.61 19.39a1 1 0 0 1-1.68-.474 2.5 2.5 0 1 0-3.014 3.015 1 1 0 0 1 .474 1.68l-1.683 1.682a2.414 2.414 0 0 1-3.414 0l-1.682-1.683a1 1 0 0 0-1.68.474 2.5 2.5 0 1 1-3.015-3.014 1 1 0 0 0 .474-1.68L2.61 12.7a2.414 2.414 0 0 1 0-3.414L4.293 7.6a1 1 0 0 1 1.68.474A2.5 2.5 0 1 0 8.987 5.06a1 1 0 0 1-.474-1.68L10.196 1.7a2.414 2.414 0 0 1 3.414 0z"/></svg> Required PHP Extensions</span></div>
      <div class="health-row">
        <?php foreach ($system_status['extensions'] as $ext => $enabled): ?>
          <span class="badge <?= $enabled ? 'badge-success' : 'badge-danger' ?>"><?= htmlspecialchars($ext) ?>: <?= $enabled ? 'OK' : 'Missing' ?></span>
        <?php endforeach; ?>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></svg> Storage Health</span></div>
      <?php foreach ($system_status['files'] as $file): ?>
        <div class="system-file">
          <strong><?= htmlspecialchars($file['file']) ?></strong>
          <span class="badge <?= $file['exists'] ? 'badge-success' : 'badge-warning' ?>"><?= $file['exists'] ? 'exists' : 'new' ?></span>
          <span class="badge <?= $file['readable'] ? 'badge-success' : 'badge-danger' ?>">read</span>
          <span class="badge <?= $file['writable'] ? 'badge-success' : 'badge-danger' ?>">write</span>
        </div>
      <?php endforeach; ?>
    </div>
      </div>
    </section>

    <!-- SYSTEM LOGS -->
    <section class="view" data-view="logs" hidden>
      <div class="card">
        <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/></svg> System Logs</span>
          <form method="post" onsubmit="return confirm('Clear system logs?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><button type="submit" name="clear_logs" value="1" class="btn btn-warning" style="padding:.3rem .7rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Clear Logs</button></form>
        </div>
    <div class="logs-container">
      <?php if (empty($logs)): ?><div style="text-align: center; color: var(--text-muted); padding: 2rem;">No logs yet.</div>
      <?php else: foreach ($logs as $log): ?>
        <div class="log-entry">
          <span class="log-time"><?= htmlspecialchars($log['timestamp']) ?></span>
          <span class="log-type <?= htmlspecialchars($log['type']) ?>">[<?= strtoupper(htmlspecialchars($log['type'])) ?>]</span>
          <span class="log-message"><?= htmlspecialchars($log['message']) ?></span>
        </div>
      <?php endforeach; endif; ?>
    </div>
      </div>
    </section>

    <!-- ACCESS LOGS -->
    <section class="view" data-view="access" hidden>
      <div class="card">
        <div class="card-header"><span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Access Logs</span>
          <form method="post" onsubmit="return confirm('Clear access logs?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><button type="submit" name="clear_access_logs" value="1" class="btn btn-danger" style="padding:.3rem .7rem;"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Clear Access Logs</button></form>
        </div>
    <div class="logs-container">
      <?php if (empty($access_logs)): ?><div style="text-align: center; color: var(--text-muted); padding: 2rem;">No access logs yet.</div>
      <?php else: foreach ($access_logs as $log): ?>
        <div class="access-log-entry">
          <span class="access-time"><?= htmlspecialchars($log['timestamp']) ?></span>
          <span class="access-status <?= htmlspecialchars($log['status']) ?>">[<?= strtoupper(htmlspecialchars($log['status'])) ?>]</span>
          <span class="log-message"><?= htmlspecialchars($log['ip']) ?> | <?= htmlspecialchars($log['location']['city'] ?? 'Unknown') ?>, <?= htmlspecialchars($log['location']['country'] ?? 'Unknown') ?> | <?= htmlspecialchars($log['device']['os'] ?? 'Unknown') ?>/<?= htmlspecialchars($log['device']['browser'] ?? 'Unknown') ?></span>
        </div>
      <?php endforeach; endif; ?>
    </div>
      </div>
    </section>

    <!-- SETTINGS -->
    <section class="view" data-view="settings" hidden>
<div class="card">
  <div class="card-header">
    <span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg> Subscription Network Fix</span>
    <span class="badge badge-info">Relay / Browser fallback</span>
  </div>
  <div class="notice" style="font-size:.78rem;">
    اگر لینک ساب در مرورگر/ایرانسل/همراه اول باز می‌شود ولی روی هاست پنل timeout می‌دهد، مشکل از مسیر شبکه هاست است. اینجا می‌توانی یک Relay خارجی تنظیم کنی یا از داخل هر لایسنس محتوای ساب را Paste/Import کنی.
  </div>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
    <input type="hidden" name="update_subscription_network_settings" value="1">
    <div class="input-group">
      <div class="input-field" style="max-width:140px;"><label>Relay Enabled</label><select name="subscription_relay_enabled"><option value="0" <?= empty($settings['subscription_relay_enabled']) ? 'selected' : '' ?>>Off</option><option value="1" <?= !empty($settings['subscription_relay_enabled']) ? 'selected' : '' ?>>On</option></select></div>
      <div class="input-field"><label>Subscription Relay URL</label><input type="text" name="subscription_relay_url" value="<?= htmlspecialchars($settings['subscription_relay_url'] ?? '') ?>" placeholder="https://your-foreign-host.com/symex_subscription_relay.php"></div>
      <div class="input-field" style="max-width:240px;"><label>Relay Secret</label><input type="text" name="subscription_relay_secret" value="<?= htmlspecialchars($settings['subscription_relay_secret'] ?? '') ?>" placeholder="optional-secret"></div>
      <div class="input-field" style="max-width:190px;"><label>Insecure TLS Fetch</label><select name="allow_insecure_subscription_fetch"><option value="0" <?= empty($settings['allow_insecure_subscription_fetch']) ? 'selected' : '' ?>>Off</option><option value="1" <?= !empty($settings['allow_insecure_subscription_fetch']) ? 'selected' : '' ?>>On</option></select></div>
      <div class="input-field" style="max-width:170px;"><label>External Geo IP</label><select name="external_geo_lookup_enabled"><option value="0" <?= empty($settings['external_geo_lookup_enabled']) ? 'selected' : '' ?>>Off</option><option value="1" <?= !empty($settings['external_geo_lookup_enabled']) ? 'selected' : '' ?>>On</option></select></div>
      <button type="submit" class="btn btn-primary"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Save Relay</button>
    </div>
  </form>
  <div style="font-size:.72rem;color:var(--muted);margin-top:8px;">فایل آماده Relay داخل ZIP هست: <b>symex_subscription_relay.php</b>. آن را روی یک هاست/سرور خارجی بگذار و آدرسش را اینجا وارد کن. اگر Relay نداری، از قسمت Paste Subscription Content داخل هر لایسنس استفاده کن.</div>
</div>
<div class="card">
  <div class="card-header">
    <span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></svg> App v2 Controls</span>
    <span class="badge badge-success">Update / DNS / MTU</span>
  </div>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
    <input type="hidden" name="update_subscription_network_settings" value="1">
    <input type="hidden" name="subscription_relay_enabled" value="<?= !empty($settings['subscription_relay_enabled']) ? '1' : '0' ?>">
    <input type="hidden" name="subscription_relay_url" value="<?= htmlspecialchars($settings['subscription_relay_url'] ?? '') ?>">
    <input type="hidden" name="subscription_relay_secret" value="<?= htmlspecialchars($settings['subscription_relay_secret'] ?? '') ?>">
    <input type="hidden" name="allow_insecure_subscription_fetch" value="<?= !empty($settings['allow_insecure_subscription_fetch']) ? '1' : '0' ?>">
    <input type="hidden" name="external_geo_lookup_enabled" value="<?= !empty($settings['external_geo_lookup_enabled']) ? '1' : '0' ?>">
    <div class="input-group">
      <div class="input-field" style="max-width:150px;"><label>Latest Code</label><input type="number" name="app_latest_version_code" value="<?= (int)($settings['app_latest_version_code'] ?? 0) ?>" min="0" step="1"></div>
      <div class="input-field" style="max-width:180px;"><label>Latest Name</label><input type="text" name="app_latest_version_name" value="<?= htmlspecialchars($settings['app_latest_version_name'] ?? '') ?>" placeholder="2.0"></div>
      <div class="input-field"><label>APK URL</label><input type="url" name="app_update_apk_url" value="<?= htmlspecialchars($settings['app_update_apk_url'] ?? '') ?>" placeholder="https://revmamad.lol/app_updates/symex-v2.apk"></div>
      <div class="input-field"><label>APK SHA-256</label><input type="text" name="app_update_sha256" value="<?= htmlspecialchars($settings['app_update_sha256'] ?? '') ?>" maxlength="64" placeholder="64 lowercase hex chars"></div>
      <div class="input-field" style="max-width:160px;"><label>Required</label><select name="app_update_required"><option value="0" <?= empty($settings['app_update_required']) ? 'selected' : '' ?>>No</option><option value="1" <?= !empty($settings['app_update_required']) ? 'selected' : '' ?>>Yes</option></select></div>
      <div class="input-field"><label>Update Notes</label><input type="text" name="app_update_notes" value="<?= htmlspecialchars($settings['app_update_notes'] ?? '') ?>" placeholder="Short release note shown in app"></div>
    </div>
    <div class="input-group" style="margin-top:10px;">
      <div class="input-field"><label>DNS Servers</label><input type="text" name="network_dns_servers" value="<?= htmlspecialchars($settings['network_dns_servers'] ?? '1.1.1.1,8.8.8.8') ?>" placeholder="1.1.1.1,8.8.8.8"></div>
      <div class="input-field" style="max-width:140px;"><label>MTU</label><input type="number" name="network_mtu" value="<?= (int)($settings['network_mtu'] ?? 1400) ?>" min="1280" max="1500" step="1"></div>
      <div class="input-field" style="max-width:190px;"><label>Routing</label><select name="network_routing_mode"><option value="FULL_TUNNEL" <?= (($settings['network_routing_mode'] ?? 'FULL_TUNNEL') === 'FULL_TUNNEL') ? 'selected' : '' ?>>Full Tunnel</option><option value="BYPASS_LAN" <?= (($settings['network_routing_mode'] ?? '') === 'BYPASS_LAN') ? 'selected' : '' ?>>Bypass LAN</option></select></div>
      <button type="submit" class="btn btn-primary"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Save v2 Controls</button>
    </div>
  </form>
  <div style="font-size:.72rem;color:var(--muted);margin-top:8px;">APK update links must be HTTPS. The Android app only opens the allowed production domain, and SHA-256 is sent to users for verification.</div>
</div>
<div class="card">
  <div class="card-header">
    <span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Admin Password</span>
    <span class="badge badge-success">Hashed storage</span>
  </div>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
    <input type="hidden" name="change_admin_password" value="1">
    <div class="input-group">
      <div class="input-field"><label>New Password</label><input type="password" name="new_admin_password" autocomplete="new-password" minlength="12" placeholder="At least 12 characters"></div>
      <div class="input-field"><label>Confirm Password</label><input type="password" name="confirm_admin_password" autocomplete="new-password" minlength="12" placeholder="Repeat password"></div>
      <button type="submit" class="btn btn-warning"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15.5 7.5 19 4"/><path d="m21 2-2 2"/><path d="M9 11a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z"/><path d="M11.5 13.5 15 10"/></svg> Update Password</button>
    </div>
  </form>
</div>
<div class="card">
  <div class="card-header">
    <span class="card-title"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/></svg> Backup & Security</span>
  </div>
  <div class="input-group">
    <form method="post"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><button type="submit" name="export_data" value="1" class="btn btn-primary"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg> Export Data</button></form>
    <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="file" name="import_file" accept=".json" style="display: inline; width: auto;"><button type="submit" class="btn btn-secondary"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg> Import</button></form>
    <form method="post" onsubmit="return confirm('Clear system logs?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><button type="submit" name="clear_logs" value="1" class="btn btn-warning"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Clear Logs</button></form>
    <form method="post" onsubmit="return confirm('Clear access logs?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><button type="submit" name="clear_access_logs" value="1" class="btn btn-danger"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Clear Access Logs</button></form>
    <form method="post" onsubmit="return confirm('Remove duplicate/invalid stored config rows from all licenses?')"><input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><button type="submit" name="dedupe_all" value="1" class="btn btn-info"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m13.4 7.4 3.2 3.2"/><path d="M19 5 11.5 12.5"/><path d="M5.5 14.5 9 18s-1 3-4 3c0 0-1.5 0-3-1.5 2-1 1.5-3 1.5-3l2-2"/><path d="m14 6 4 4 2.5-2.5a2.83 2.83 0 0 0-4-4Z"/></svg> Deduplicate All</button></form>
  </div>
</div>
    </section>
  </main>
</div>
<?php endif; ?>

</div>

<script>
function toggleCfg(key) {
    let drawer = document.getElementById('cfg-drawer-' + key);
    let subDrawer = document.getElementById('sub-drawer-' + key);
    let settingsDrawer = document.getElementById('settings-drawer-' + key);
    if(drawer) { drawer.classList.toggle('open'); if(subDrawer) subDrawer.classList.remove('open'); if(settingsDrawer) settingsDrawer.classList.remove('open'); }
}
function toggleSub(key) {
    let subDrawer = document.getElementById('sub-drawer-' + key);
    let cfgDrawer = document.getElementById('cfg-drawer-' + key);
    let settingsDrawer = document.getElementById('settings-drawer-' + key);
    if(subDrawer) { subDrawer.classList.toggle('open'); if(cfgDrawer) cfgDrawer.classList.remove('open'); if(settingsDrawer) settingsDrawer.classList.remove('open'); }
}
function toggleSettings(key) {
    let settingsDrawer = document.getElementById('settings-drawer-' + key);
    let cfgDrawer = document.getElementById('cfg-drawer-' + key);
    let subDrawer = document.getElementById('sub-drawer-' + key);
    if(settingsDrawer) { settingsDrawer.classList.toggle('open'); if(cfgDrawer) cfgDrawer.classList.remove('open'); if(subDrawer) subDrawer.classList.remove('open'); }
}
function toggleCEdit(key, idx) {
    let editBox = document.getElementById('cedit-' + key + '-' + idx);
    if(editBox) editBox.style.display = editBox.style.display === 'none' ? 'block' : 'none';
}
function copyManualConfigs(key) {
    const box = document.getElementById('manual-configs-' + key);
    if (!box) { alert('No manual config box found.'); return; }
    const text = box.value || box.textContent || '';
    if (!text.trim()) { alert('No manual configs to copy.'); return; }
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function(){ alert('Manual configs copied.'); }).catch(function(){ fallbackCopyText(box); });
    } else {
        fallbackCopyText(box);
    }
}
function fallbackCopyText(box) {
    try {
        box.style.position = 'fixed';
        box.style.left = '0';
        box.style.top = '0';
        box.style.opacity = '0.01';
        box.focus();
        box.select();
        document.execCommand('copy');
        box.style.position = 'absolute';
        box.style.left = '-9999px';
        box.style.opacity = '0';
        alert('Manual configs copied.');
    } catch(e) {
        alert('Copy failed. Select and copy manually.');
    }
}
function toggleTheme() {
    const body = document.body;
    const current = body.getAttribute('data-theme') || 'dark';
    const newTheme = current === 'dark' ? 'light' : 'dark';
    body.setAttribute('data-theme', newTheme);
    try { localStorage.setItem('symex_theme', newTheme); } catch(e) {}
    if (window.fetch) {
        fetch('?', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'theme=' + encodeURIComponent(newTheme), keepalive: true }).catch(function(){});
    }
}
(function(){
  try {
    const saved = localStorage.getItem('symex_theme');
    if (saved === 'light' || saved === 'dark') document.body.setAttribute('data-theme', saved);
  } catch(e) {}
})();

</script>

<script>
// Prevent accidental double-click/double-submit that can toggle a license twice.
document.addEventListener('submit', function(e) {
  const form = e.target;
  if (!form || form.dataset.symexSubmitting === '1') {
    e.preventDefault();
    return false;
  }
  form.dataset.symexSubmitting = '1';
  const btn = form.querySelector('button[type="submit"], button:not([type])');
  if (btn && !btn.dataset.keepEnabled) {
    btn.disabled = true;
    btn.style.opacity = '0.65';
    btn.style.pointerEvents = 'none';
  }
}, true);
</script>

<script>
(function(){
  var titles={overview:'Overview',licenses:'Licenses',status:'System Status',logs:'System Logs',access:'Access Logs',settings:'Settings'};
  function showView(name){
    if(!titles[name]) name='overview';
    document.querySelectorAll('.view').forEach(function(v){ v.hidden=(v.dataset.view!==name); });
    document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.toggle('active', b.dataset.target===name); });
    var t=document.getElementById('view-title'), ic=document.getElementById('view-icon');
    if(t) t.textContent=titles[name];
    var act=document.querySelector('.nav-item[data-target="'+name+'"] svg');
    if(ic&&act){ ic.innerHTML=act.outerHTML; }
    try{ localStorage.setItem('symex_view', name); }catch(e){}
    if(history.replaceState) history.replaceState(null,'','#'+name);
    closeSidebar();
  }
  window.symexShowView=showView;
  document.querySelectorAll('.nav-item').forEach(function(b){ b.addEventListener('click', function(){ showView(b.dataset.target); }); });
  var initial='overview';
  try{
    var h=(location.hash||'').replace('#','');
    var qs=location.search||'';
    if(titles[h]) initial=h;
    else if(/view_logs=1/.test(qs)) initial='logs';
    else if(/view_access_logs=1/.test(qs)) initial='access';
    else if(/system_status=1/.test(qs)) initial='status';
    else { var sv=localStorage.getItem('symex_view'); if(titles[sv]) initial=sv; }
  }catch(e){}
  showView(initial);
})();
function toggleSidebar(){ var s=document.getElementById('sidebar'), c=document.getElementById('scrim'); if(s)s.classList.toggle('open'); if(c)c.classList.toggle('open'); }
function closeSidebar(){ var s=document.getElementById('sidebar'), c=document.getElementById('scrim'); if(s)s.classList.remove('open'); if(c)c.classList.remove('open'); }
</script>
</body>
</html>
