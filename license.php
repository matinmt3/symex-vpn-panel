<?php
// ============================================================
// LICENSE API - PANEL-ONLY DEBUGGED VERSION
// ============================================================

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send('error', 'method_not_allowed');
}

define('DATA_FILE', __DIR__ . '/licenses.json');
define('LOG_FILE', __DIR__ . '/logs.json');
define('SETTINGS_FILE', __DIR__ . '/settings.json');
define('WEBHOOK_TIMEOUT', 5);
define('CONFIG_SELECTION_MODE', 'client_side_latency_preferred_static_quality_fallback');
define('CONFIG_PRIORITY_VERSION', '2026-06-02-client-side-latency-static-fallback');
require_once __DIR__ . '/symex_subscription_core.php';

// Create files if not exist
if (!file_exists(DATA_FILE)) {
    file_put_contents(DATA_FILE, json_encode(new stdClass(), JSON_PRETTY_PRINT), LOCK_EX);
}

if (!file_exists(LOG_FILE)) {
    file_put_contents(LOG_FILE, json_encode([], JSON_PRETTY_PRINT), LOCK_EX);
}

$body = json_decode(file_get_contents('php://input'), true);
if (!is_array($body)) {
    $body = $_POST;
}
$license = isset($body['license']) ? trim($body['license']) : '';
$device_id = isset($body['device_id']) ? trim($body['device_id']) : '';
$bandwidth_add = symex_request_bandwidth_delta($body);
$fresh_login = !empty($body['fresh_login']) || !empty($body['reauth']) || !empty($body['manual_login']) || !empty($body['license_reentered']) || (($body['action'] ?? '') === 'activate') || (($body['event'] ?? '') === 'activate');

if ($license === '' || $device_id === '') {
    send('invalid', 'missing_params');
}

$db = db_load();

if (!isset($db[$license]) && isset($db[strtoupper($license)])) {
    $license = strtoupper($license);
}
if (!isset($db[$license])) {
    add_log('error', "Invalid license attempt: $license", $license, $device_id);
    send('invalid', 'not_found');
}

$row = &$db[$license];

// Normalize and deduplicate stored configs on every successful app entry path.
$dedupe_removed = sanitize_license_row($row);
if ($dedupe_removed > 0) {
    add_log('info', "Automatic duplicate cleanup for $license removed $dedupe_removed item(s)", $license, $device_id);
    db_save($db);
}

// ============================================================
// DEVICE LOGOUT / RELEASE SLOT
// App sends action=logout before local session cleanup so this device is removed
// from active devices and another phone can use the freed slot immediately.
// ============================================================
$action = isset($body['action']) ? strtolower(trim((string)$body['action'])) : '';
if (in_array($action, ['logout', 'release_device', 'signout'], true)) {
    $devices = isset($row['devices']) && is_array($row['devices']) ? $row['devices'] : [];
    $beforeCount = count($devices);
    $devices = array_values(array_filter($devices, function ($dev) use ($device_id) {
        return !is_array($dev) || (($dev['device_id'] ?? '') !== $device_id);
    }));
    $row['devices'] = $devices;

    db_save($db);
    $removed = $beforeCount - count($devices);
    add_log('info', $removed > 0 ? 'Device released by app logout' : 'Logout requested; device was not registered', $license, $device_id);
    send('ok', 'device_released', [], [
        'device_released' => $removed > 0,
        'max_devices' => isset($row['max_devices']) ? (int)$row['max_devices'] : 1,
        'current_devices' => count($devices),
        'logout_action_supported' => true,
    ]);
}

// Check if license is active
if (!isset($row['active']) || !$row['active']) {
    add_log('error', "Disabled license attempt: $license", $license, $device_id);
    send('disabled', 'license_disabled');
}

// Check expiration
if (!empty($row['expires_at'])) {
    $expire_time = strtotime($row['expires_at'] . ' 23:59:59');
    if ($expire_time && time() > $expire_time) {
        add_log('error', "Expired license attempt: $license", $license, $device_id);
        send('expired', 'expired_on_' . $row['expires_at']);
    }
}

// ============================================================
// BANDWIDTH TRACKING
// ============================================================
if ($bandwidth_add > 0) {
    $traffic_result = symex_apply_traffic_event($row, $device_id, $body);
    db_save($db);
    
    // Check if bandwidth limit exceeded
    $bandwidth_limit = isset($row['bandwidth_limit']) ? $row['bandwidth_limit'] : 0;
    if ($bandwidth_limit > 0 && $row['bandwidth_used'] >= $bandwidth_limit) {
        add_log('error', "Bandwidth exceeded for $license", $license, $device_id);
        send('bandwidth_exceeded', 'Bandwidth limit reached. Used: ' . formatBytes($row['bandwidth_used']) . ' / ' . formatBytes($bandwidth_limit), [], array_merge(
            symex_usage_extra($row, $device_id),
            [
                'traffic_event_id' => $traffic_result['traffic_event_id'] ?? null,
                'traffic_duplicate' => !empty($traffic_result['duplicate']),
            ]
        ));
    }
}

// ============================================================
// DEVICE MANAGEMENT
// ============================================================
$devices = isset($row['devices']) ? $row['devices'] : [];
if (!isset($row['revoked_devices']) || !is_array($row['revoked_devices'])) $row['revoked_devices'] = [];
if (isset($row['revoked_devices'][$device_id])) {
    $revokedInfo = is_array($row['revoked_devices'][$device_id]) ? $row['revoked_devices'][$device_id] : [];
    $reason = (string)($revokedInfo['reason'] ?? '');
    $hardBlock = !empty($revokedInfo['hard_block']) || in_array($reason, ['blocked_by_admin', 'blacklisted_by_admin', 'manual_block'], true);

    if ($hardBlock) {
        add_log('info', "Blocked device rejected", $license, $device_id);
        db_save($db);
        send('device_blocked', 'device_blocked_by_admin', [], [
            'requires_admin_unblock' => true,
            'clear_cached_session' => true,
            'reason' => 'device_blocked_by_admin',
        ]);
    }

    // Backward compatibility fix:
    // Older panel builds used revoked_devices for normal Reset Device. That made a reset behave like a permanent block.
    // Soft reset markers are now automatically cleared, so the user can enter the license again on the same phone.
    unset($row['revoked_devices'][$device_id]);
    add_log('info', "Soft device reset marker cleared; device can activate again", $license, $device_id);
}

// Check if device already exists
$device_exists = false;
$device_index = -1;
foreach ($devices as $idx => $dev) {
    if (isset($dev['device_id']) && $dev['device_id'] === $device_id) {
        $device_exists = true;
        $device_index = $idx;
        break;
    }
}

$max_devices = isset($row['max_devices']) ? $row['max_devices'] : 1;

if (!$device_exists) {
    // Check device limit
    if (count($devices) >= $max_devices) {
        add_log('error', "Device limit exceeded for $license (max: $max_devices)", $license, $device_id);
        send('device_limit', "Maximum devices reached ($max_devices). Please remove another device first.");
    }
    
    // Add new device
    $new_device = [
        'device_id' => $device_id,
        'registered_at' => date('Y-m-d H:i:s'),
        'last_seen' => date('Y-m-d H:i:s'),
        'ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown',
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown'
    ];
    $devices[] = $new_device;
    $row['devices'] = $devices;
    
    // Initialize bandwidth for this device if not exists
    if (!isset($row['device_bandwidth'])) {
        $row['device_bandwidth'] = [];
    }
    if (!isset($row['device_bandwidth'][$device_id])) {
        $row['device_bandwidth'][$device_id] = 0;
    }
    
    db_save($db);
    
    add_log('info', "New device registered: " . substr($device_id, 0, 30), $license, $device_id);
    
    // Update subscription on every successful app entry before returning configs.
    $subscription_update = update_subscription_cache_for_license($row, $license);
    db_save($db);

    $configs = get_combined_configs($row);
    $delivery = prepare_configs_for_delivery($row, $configs);
    db_save($db);
    symex_send_ok_or_current_status($license, 'device_registered', $delivery['configs'], array_merge([
        'max_devices' => $max_devices,
        'current_devices' => count($devices),
        'subscription_status' => $subscription_update['status'],
        'subscription_config_count' => $subscription_update['count'],
        'subscription_cache_used' => !empty($row['subscription_cache_used']),
        'subscription_last_good_update' => $row['subscription_last_good_update'] ?? null,
        'subscription_last_good_count' => (int)($row['subscription_last_good_count'] ?? 0),
        'subscription_last_error' => $row['last_subscription_error'] ?? ''
    ], symex_usage_extra($row, $device_id), $delivery['meta']));
}

// Update last seen for existing device
foreach ($devices as &$dev) {
    if (isset($dev['device_id']) && $dev['device_id'] === $device_id) {
        $dev['last_seen'] = date('Y-m-d H:i:s');
        break;
    }
}
$row['devices'] = $devices;

// ============================================================
// UPDATE SUBSCRIPTION ON EVERY SUCCESSFUL APP ENTRY
// If the link fails or its content is invalid, subscription_content is cleared
// and get_combined_configs() falls back to manual configs only.
// ============================================================
$subscription_update = update_subscription_cache_for_license($row, $license);
db_save($db);

$configs = get_combined_configs($row);
$delivery = prepare_configs_for_delivery($row, $configs);
db_save($db);

// Get device bandwidth
$device_bandwidth = isset($row['device_bandwidth'][$device_id]) ? $row['device_bandwidth'][$device_id] : 0;

symex_send_ok_or_current_status($license, 'authorized', $delivery['configs'], array_merge([
    'max_devices' => $max_devices,
    'current_devices' => count($devices),
    'subscription_status' => $subscription_update['status'],
    'subscription_config_count' => $subscription_update['count'],
    'subscription_cache_used' => !empty($row['subscription_cache_used']),
    'subscription_last_good_update' => $row['subscription_last_good_update'] ?? null,
    'subscription_last_good_count' => (int)($row['subscription_last_good_count'] ?? 0),
    'subscription_last_error' => $row['last_subscription_error'] ?? ''
], symex_usage_extra($row, $device_id), $delivery['meta']));

// ============================================================
// HELPER FUNCTIONS
// ============================================================



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

function symex_write_db_atomic(array $data): void {
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) return;
    $lockFile = DATA_FILE . '.lock';
    $lock = @fopen($lockFile, 'c');
    if (!$lock) return;
    if (!flock($lock, LOCK_EX)) { fclose($lock); return; }
    $tmp = DATA_FILE . '.tmp.' . getmypid();
    $ok = @file_put_contents($tmp, $json, LOCK_EX);
    if ($ok !== false) {
        @chmod($tmp, 0644);
        @rename($tmp, DATA_FILE);
    } else {
        @unlink($tmp);
    }
    flock($lock, LOCK_UN);
    fclose($lock);
}

function db_save(array $data): void {
    // license.php must not overwrite admin changes with an older full copy of
    // licenses.json. App requests can run while the admin toggles a license;
    // save only runtime fields for the current license and preserve admin-owned
    // fields such as active, limits, manual configs and subscription URL.
    global $license, $device_id, $fresh_login;
    if (isset($license) && $license !== '' && isset($data[$license]) && is_array($data[$license])) {
        $lockFile = DATA_FILE . '.lock';
        $lock = @fopen($lockFile, 'c');
        if (!$lock || !flock($lock, LOCK_EX)) { if ($lock) fclose($lock); return; }
        $current = [];
        if (file_exists(DATA_FILE)) {
            $current = symex_json_decode_db((string)@file_get_contents(DATA_FILE));
        }
        if (!isset($current[$license]) || !is_array($current[$license])) {
            $current[$license] = [];
        }
        $incoming = $data[$license];
        $merged = $current[$license];
        $runtimeFields = [
            'devices','device_bandwidth','device_upload','device_download','bandwidth_used','upload_used','download_used','traffic_events',
            'last_subscription_update','subscription_content','last_subscription_attempt','last_subscription_status','last_subscription_error','subscription_config_count',
            'subscription_last_good_content','subscription_last_good_update','subscription_last_good_count','subscription_cache_used','last_subscription_cache_used_at','last_subscription_test','subscription_logs',
            'config_quality','last_best_config','last_fastest_score','last_best_latency_ms','last_score_update','last_score_summary','last_selection_method'
        ];
        foreach ($runtimeFields as $field) {
            if (array_key_exists($field, $incoming)) {
                if (strpos($field, 'subscription') === 0 || in_array($field, ['last_subscription_update','last_subscription_attempt','last_subscription_status','last_subscription_error','last_subscription_cache_used_at'], true)) {
                    // Do not save subscription runtime data if admin changed/cleared the URL during this request.
                    if (($current[$license]['subscription_url'] ?? '') !== ($incoming['subscription_url'] ?? ($current[$license]['subscription_url'] ?? ''))) {
                        continue;
                    }
                }
                $merged[$field] = $incoming[$field];
            }
        }
        if (!isset($merged['revoked_devices']) || !is_array($merged['revoked_devices'])) $merged['revoked_devices'] = [];
        if (!empty($fresh_login) && !empty($device_id)) {
            unset($merged['revoked_devices'][$device_id]);
        }
        $current[$license] = $merged;
        $json = json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if ($json !== false) {
            $tmp = DATA_FILE . '.tmp.' . getmypid();
            if (@file_put_contents($tmp, $json, LOCK_EX) !== false) {
                @chmod($tmp, 0644);
                @rename($tmp, DATA_FILE);
            } else {
                @unlink($tmp);
            }
        }
        flock($lock, LOCK_UN);
        fclose($lock);
        return;
    }
    symex_write_db_atomic($data);
}

function symex_latest_license_row(string $key): array {
    $latest = db_load();
    return (isset($latest[$key]) && is_array($latest[$key])) ? $latest[$key] : [];
}

function symex_send_ok_or_current_status(string $key, string $okMessage, array $configs, array $extra): void {
    $latest = symex_latest_license_row($key);
    if ($latest && (empty($latest['active']))) {
        send('disabled', 'license_disabled');
    }
    if (!empty($latest['expires_at'])) {
        $expire_time = strtotime($latest['expires_at'] . ' 23:59:59');
        if ($expire_time && time() > $expire_time) {
            send('expired', 'expired_on_' . $latest['expires_at']);
        }
    }
    send('ok', $okMessage, $configs, $extra);
}

function add_log(string $type, string $message, string $license = '', string $device_id = ''): void {
    if (!file_exists(LOG_FILE)) {
        file_put_contents(LOG_FILE, json_encode([], JSON_PRETTY_PRINT), LOCK_EX);
    }
    
    $content = file_get_contents(LOG_FILE);
    if ($content === false) {
        $logs = [];
    } else {
        $logs = json_decode($content, true);
        if (!is_array($logs)) $logs = [];
    }
    
    $logs[] = [
        'timestamp' => date('Y-m-d H:i:s'),
        'type' => $type,
        'message' => $message,
        'license' => $license,
        'device_id' => substr($device_id, 0, 30),
        'ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown'
    ];
    
    // Keep last 2000 logs
    if (count($logs) > 2000) {
        $logs = array_slice($logs, -2000);
    }
    
    file_put_contents(LOG_FILE, json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
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

function symex_int_from_body(array $body, array $keys): int {
    foreach ($keys as $key) {
        if (!array_key_exists($key, $body)) continue;
        if (is_numeric($body[$key])) {
            return max(0, (int)$body[$key]);
        }
    }
    return 0;
}

function symex_request_bandwidth_delta(array $body): int {
    $total = symex_int_from_body($body, ['bandwidth_used', 'bandwidth_delta_bytes', 'total_delta_bytes']);
    if ($total > 0) return $total;
    $upload = symex_int_from_body($body, ['upload_delta_bytes']);
    $download = symex_int_from_body($body, ['download_delta_bytes']);
    return max(0, $upload + $download);
}

function symex_normalize_split(int $total, int $upload, int $download): array {
    $total = max(0, $total);
    $upload = max(0, $upload);
    $download = max(0, $download);
    if ($total <= 0) return ['total' => 0, 'upload' => 0, 'download' => 0];
    $reported = $upload + $download;
    if ($reported <= 0) return ['total' => $total, 'upload' => 0, 'download' => $total];
    if ($reported === $total) return ['total' => $total, 'upload' => $upload, 'download' => $download];
    $normalizedUpload = (int)round(($total * $upload) / $reported);
    $normalizedUpload = max(0, min($total, $normalizedUpload));
    return ['total' => $total, 'upload' => $normalizedUpload, 'download' => $total - $normalizedUpload];
}

function symex_clean_event_key($value): string {
    $value = trim((string)$value);
    if ($value === '') return '';
    if (strlen($value) > 128) $value = substr($value, 0, 128);
    return preg_replace('/[^A-Za-z0-9_.:-]/', '_', $value);
}

function symex_ensure_traffic_fields(array &$row): void {
    if (!isset($row['device_bandwidth']) || !is_array($row['device_bandwidth'])) $row['device_bandwidth'] = [];
    if (!isset($row['device_upload']) || !is_array($row['device_upload'])) $row['device_upload'] = [];
    if (!isset($row['device_download']) || !is_array($row['device_download'])) $row['device_download'] = [];
    if (!isset($row['traffic_events']) || !is_array($row['traffic_events'])) $row['traffic_events'] = [];
    $row['bandwidth_used'] = max(0, (int)($row['bandwidth_used'] ?? 0));
    $row['upload_used'] = max(0, (int)($row['upload_used'] ?? 0));
    $row['download_used'] = max(0, (int)($row['download_used'] ?? 0));
}

function symex_prune_traffic_events(array &$row, int $maxEvents = 4000): void {
    if (!isset($row['traffic_events']) || !is_array($row['traffic_events'])) {
        $row['traffic_events'] = [];
        return;
    }
    if (count($row['traffic_events']) <= $maxEvents) return;
    $row['traffic_events'] = array_slice($row['traffic_events'], -$maxEvents, $maxEvents, true);
}

function symex_apply_traffic_event(array &$row, string $device_id, array $body): array {
    symex_ensure_traffic_fields($row);

    $total = symex_request_bandwidth_delta($body);
    $upload = symex_int_from_body($body, ['upload_delta_bytes']);
    $download = symex_int_from_body($body, ['download_delta_bytes']);
    $charge = symex_normalize_split($total, $upload, $download);
    if ($charge['total'] <= 0) {
        return ['applied' => false, 'duplicate' => false, 'traffic_event_id' => null];
    }

    $eventId = symex_clean_event_key($body['traffic_event_id'] ?? '');
    $sessionId = symex_clean_event_key($body['session_id'] ?? '');
    if ($eventId !== '' && isset($row['traffic_events'][$eventId])) {
        return ['applied' => false, 'duplicate' => true, 'traffic_event_id' => $eventId];
    }

    $row['device_bandwidth'][$device_id] = max(0, (int)($row['device_bandwidth'][$device_id] ?? 0)) + $charge['total'];
    $row['device_upload'][$device_id] = max(0, (int)($row['device_upload'][$device_id] ?? 0)) + $charge['upload'];
    $row['device_download'][$device_id] = max(0, (int)($row['device_download'][$device_id] ?? 0)) + $charge['download'];
    $row['bandwidth_used'] += $charge['total'];
    $row['upload_used'] += $charge['upload'];
    $row['download_used'] += $charge['download'];

    if ($eventId !== '') {
        $row['traffic_events'][$eventId] = [
            'device_id' => substr($device_id, 0, 80),
            'session_id' => $sessionId,
            'total_bytes' => $charge['total'],
            'upload_bytes' => $charge['upload'],
            'download_bytes' => $charge['download'],
            'applied_at' => date('Y-m-d H:i:s'),
        ];
        symex_prune_traffic_events($row);
    }

    return ['applied' => true, 'duplicate' => false, 'traffic_event_id' => $eventId !== '' ? $eventId : null];
}

function symex_usage_extra(array $row, string $device_id): array {
    symex_ensure_traffic_fields($row);
    $total = max(0, (int)($row['bandwidth_used'] ?? 0));
    $limit = max(0, (int)($row['bandwidth_limit'] ?? 0));
    $upload = max(0, (int)($row['upload_used'] ?? 0));
    $download = max(0, (int)($row['download_used'] ?? 0));
    $deviceTotal = max(0, (int)($row['device_bandwidth'][$device_id] ?? 0));
    $deviceUpload = max(0, (int)($row['device_upload'][$device_id] ?? 0));
    $deviceDownload = max(0, (int)($row['device_download'][$device_id] ?? 0));
    return [
        'bandwidth_used' => formatBytes($total),
        'bandwidth_limit' => formatBytes($limit),
        'upload_used' => formatBytes($upload),
        'download_used' => formatBytes($download),
        'device_bandwidth_used' => formatBytes($deviceTotal),
        'device_upload_used' => formatBytes($deviceUpload),
        'device_download_used' => formatBytes($deviceDownload),
        'bandwidth_used_bytes' => $total,
        'bandwidth_limit_bytes' => $limit,
        'upload_used_bytes' => $upload,
        'download_used_bytes' => $download,
        'device_bandwidth_used_bytes' => $deviceTotal,
        'device_upload_used_bytes' => $deviceUpload,
        'device_download_used_bytes' => $deviceDownload,
    ];
}

function trigger_webhook(array $licenseData, string $event, string $device_id = ''): void {
    // Panel-only stability build: external webhooks are disabled. Older stored
    // webhook URLs must never delay or break app authorization requests.
    return;
}


function symex_normalize_subscription_url(string $url): string {
    if (function_exists('symex_sub_normalize_url')) return symex_sub_normalize_url($url);
    $url = html_entity_decode(trim($url), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $url = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $url);
    $url = preg_replace('/\s+/u', '', $url);
    if (strpos($url, '//') === 0) $url = 'https:' . $url;
    return $url;
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
// Server-side ping is intentionally disabled. Each client app should test latency locally
// and select the fastest config for that user's own network. The panel only provides
// validated configs sorted by deterministic static quality as a safe fallback.
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
    $serverHealth = symex_build_server_health($ranked['quality']);
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
            'server_health' => $serverHealth,
            'server_health_mode' => 'static_quality_client_latency_preferred',
            'config_selection' => 'smart_lowest_client_latency_gaming_browsing_panel_tag_preferred',
            'selection_method' => CONFIG_SELECTION_MODE,
            'delivery_source' => $deliverySource,
        ], $modeMeta)
    ];
}

function symex_build_server_health(array $qualityRows): array {
    $health = [];
    foreach ($qualityRows as $idx => $quality) {
        if (!is_array($quality)) continue;
        $score = isset($quality['score']) ? (float)$quality['score'] : 0.0;
        $status = (string)($quality['status'] ?? 'unknown');
        if ($status === 'invalid') {
            $serverStatus = 'broken';
        } elseif ($score > 0 && $score < 145) {
            $serverStatus = 'slow';
        } elseif ($status === 'valid') {
            $serverStatus = 'online';
        } else {
            $serverStatus = 'unknown';
        }
        $name = trim((string)($quality['host'] ?? ''));
        if ($name === '') $name = 'server-' . ($idx + 1);
        $health[] = [
            'name' => $name,
            'status' => $serverStatus,
            'latency_ms' => null,
            'jitter_ms' => null,
            'packet_loss_percent' => $serverStatus === 'broken' ? 100 : 0,
            'score' => (int)round($score),
        ];
    }
    return $health;
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

function getClientIP(): string {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $candidate = trim($parts[0]);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) $ip = $candidate;
    }
    return $ip;
}

function load_settings(): array {
    $defaults = [
        'external_alerts_enabled' => false,
        'subscription_relay_enabled' => false,
        'subscription_relay_url' => '',
        'subscription_relay_secret' => '',
        'allow_insecure_subscription_fetch' => false,
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
    return array_merge($defaults, $data);
}

function symex_valid_sha256(string $value): string {
    $value = strtolower(trim($value));
    return preg_match('/^[a-f0-9]{64}$/', $value) ? $value : '';
}

function symex_valid_https_url(string $url): string {
    $url = trim($url);
    if ($url === '') return '';
    $parts = @parse_url($url);
    if (!is_array($parts)) return '';
    if (strtolower((string)($parts['scheme'] ?? '')) !== 'https') return '';
    if (trim((string)($parts['host'] ?? '')) === '') return '';
    return $url;
}

function symex_parse_dns_servers($value): array {
    $raw = is_array($value) ? $value : preg_split('/[\s,;]+/', (string)$value);
    $servers = [];
    foreach ($raw ?: [] as $item) {
        $item = trim((string)$item);
        if ($item === '') continue;
        if (strlen($item) > 253) continue;
        if (filter_var($item, FILTER_VALIDATE_IP) || preg_match('/^[A-Za-z0-9.-]+$/', $item)) {
            $servers[] = $item;
        }
        if (count($servers) >= 4) break;
    }
    return $servers ?: ['1.1.1.1', '8.8.8.8'];
}

function symex_public_client_settings(): array {
    global $body;
    $settings = load_settings();
    $latestCode = max(0, (int)($settings['app_latest_version_code'] ?? 0));
    $clientCode = isset($body['app_version_code']) && is_numeric($body['app_version_code']) ? (int)$body['app_version_code'] : 0;
    $apkUrl = symex_valid_https_url((string)($settings['app_update_apk_url'] ?? ''));
    $sha256 = symex_valid_sha256((string)($settings['app_update_sha256'] ?? ''));
    $updateAvailable = $latestCode > 0 && $apkUrl !== '' && ($clientCode <= 0 || $clientCode < $latestCode);
    $mtu = max(1280, min(1500, (int)($settings['network_mtu'] ?? 1400)));
    $routingMode = strtoupper(trim((string)($settings['network_routing_mode'] ?? 'FULL_TUNNEL')));
    if (!in_array($routingMode, ['FULL_TUNNEL', 'BYPASS_LAN'], true)) $routingMode = 'FULL_TUNNEL';

    return [
        'app_update_available' => $updateAvailable,
        'app_update_required' => $updateAvailable && !empty($settings['app_update_required']),
        'app_latest_version_code' => $latestCode,
        'app_latest_version_name' => trim((string)($settings['app_latest_version_name'] ?? '')),
        'app_update_apk_url' => $updateAvailable ? $apkUrl : '',
        'app_update_sha256' => $sha256,
        'app_update_notes' => trim((string)($settings['app_update_notes'] ?? '')),
        'network_dns_servers' => symex_parse_dns_servers($settings['network_dns_servers'] ?? ''),
        'network_mtu' => $mtu,
        'network_routing_mode' => $routingMode,
    ];
}

function send(string $status, string $message, array $configs = [], array $extra = []) {
    $extra = array_merge(symex_public_client_settings(), $extra);
    $response = [
        'status' => $status,
        'message' => $message,
        'configs' => $configs
    ];
    
    if (!empty($extra)) {
        $response['extra'] = $extra;
    }
    
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}
