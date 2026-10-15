<?php
if (defined('SYMEX_SUBSCRIPTION_CORE_LOADED')) return;
define('SYMEX_SUBSCRIPTION_CORE_LOADED', true);

function symex_sub_supported_schemes(): array {
    return ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'socks', 'socks5', 'wireguard', 'warp', 'anytls', 'snell'];
}

function symex_sub_now(): string {
    return date('Y-m-d H:i:s');
}

function symex_sub_trim_message(string $message, int $limit = 1800): string {
    $message = trim($message);
    if ($message === '') return '';
    return function_exists('mb_substr') ? mb_substr($message, 0, $limit, 'UTF-8') : substr($message, 0, $limit);
}

function symex_sub_decode_http_body_if_needed(string $body): string {
    if ($body !== '' && substr($body, 0, 2) === "\x1f\x8b" && function_exists('gzdecode')) {
        $decoded = @gzdecode($body);
        if (is_string($decoded) && $decoded !== '') return $decoded;
    }
    return $body;
}

function symex_sub_normalize_url(string $url): string {
    $url = html_entity_decode(trim($url), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $url = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $url);
    $url = preg_replace('/\s+/u', '', $url);
    if (strpos($url, '//') === 0) $url = 'https:' . $url;
    return trim($url);
}

function symex_sub_is_public_http_url(string $url): bool {
    $parts = @parse_url($url);
    if (!is_array($parts)) return false;
    $scheme = strtolower((string)($parts['scheme'] ?? ''));
    $host = trim((string)($parts['host'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') return false;

    $hostClean = strtolower(trim($host, '[]'));
    if (in_array($hostClean, ['localhost', 'localhost.localdomain'], true)) return false;
    if (filter_var($hostClean, FILTER_VALIDATE_IP)) {
        $public = filter_var($hostClean, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        return $public !== false;
    }
    return true;
}

function symex_sub_extract_urls(string $text, int $limit = 10): array {
    $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = str_replace('\\/', '/', $text);
    if (!preg_match_all('/https?:\/\/[^\s<>"\'`]+/iu', $text, $matches)) return [];

    $urls = [];
    foreach ($matches[0] as $url) {
        $url = symex_sub_normalize_url(trim($url, " \t\n\r\0\x0B,;)]}"));
        if ($url === '' || !symex_sub_is_public_http_url($url)) continue;
        $urls[$url] = true;
        if (count($urls) >= $limit) break;
    }
    return array_keys($urls);
}

function symex_sub_clean_config(string $candidate): string {
    $candidate = html_entity_decode($candidate, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $candidate = str_replace(["\r\n", "\r"], "\n", $candidate);
    $candidate = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $candidate);
    $candidate = trim($candidate);
    return trim($candidate, " \t\n\r\0\x0B\"'`<>[]{}(),;");
}

function symex_sub_base64_decode_text(string $text) {
    $candidate = preg_replace('/\s+/', '', trim($text));
    if ($candidate === '' || strlen($candidate) < 12) return false;
    if (!preg_match('/^[A-Za-z0-9+\/_-]+={0,3}$/', $candidate)) return false;
    $candidate = strtr($candidate, '-_', '+/');
    $candidate .= str_repeat('=', (4 - strlen($candidate) % 4) % 4);
    $decoded = base64_decode($candidate, true);
    if ($decoded === false || trim($decoded) === '') return false;
    if (preg_match('/[\x00-\x08\x0E-\x1F]/', $decoded)) return false;
    return $decoded;
}

function symex_sub_prepare_text(string $text): string {
    // Reject malformed UTF-8 before applying Unicode regex filters.
    if (preg_match('//u', $text) !== 1) return '';
    $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = str_replace(["\\r\\n", "\\n", "\\r"], "\n", $text);
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $text = str_replace('\\/', '/', $text);
    $text = str_ireplace(
        ['\\u003a', '\\u002f', '\\u003f', '\\u0026', '\\u003d', '\\u0023'],
        [':', '/', '?', '&', '=', '#'],
        $text
    );
    $text = preg_replace('/<br\s*\/?>/iu', "\n", $text);
    $text = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $text);
    return $text;
}

function symex_sub_encoded_scheme_exists(string $text): bool {
    return (bool)preg_match('/(?:vless|vmess|trojan|ssr?|hysteria2?|hy2|tuic|socks5?|wireguard|warp|anytls|snell)%3A%2F%2F/iu', $text);
}

function symex_sub_endpoint_is_valid(string $config): bool {
    if (preg_match('/^[a-z][a-z0-9+.-]*:\/\/(?:[^@\s\/?#]+@)?(\[[^\]]+\]|[^\/\s:?#]+):(\d{1,5})(?:[\/?#]|$)/iu', $config, $m)) {
        $port = (int)$m[2];
        return $port > 0 && $port <= 65535;
    }
    $parts = @parse_url($config);
    if (is_array($parts) && !empty($parts['host']) && !empty($parts['port'])) {
        $port = (int)$parts['port'];
        return $port > 0 && $port <= 65535;
    }
    return false;
}

function symex_sub_is_valid_config_uri(string $config): bool {
    $config = symex_sub_clean_config($config);
    if ($config === '' || preg_match('/[\r\n]/', $config)) return false;
    if (!preg_match('/^([a-z][a-z0-9+.-]*):\/\/(.+)$/iu', $config, $m)) return false;

    $scheme = strtolower($m[1]);
    if (!in_array($scheme, symex_sub_supported_schemes(), true)) return false;

    $body = trim($m[2]);
    if (strlen($body) < 4) return false;

    if ($scheme === 'vmess') {
        $payload = preg_split('/[#?\s]/u', $body)[0] ?? $body;
        $decoded = symex_sub_base64_decode_text($payload);
        if (is_string($decoded)) {
            $json = json_decode($decoded, true);
            if (is_array($json) && (!empty($json['add']) || !empty($json['host'])) && (!empty($json['port']) || !empty($json['ps']))) return true;
        }
        return strlen($body) > 16;
    }

    if (in_array($scheme, ['ss', 'ssr'], true)) {
        return strlen($body) > 8;
    }

    if (in_array($scheme, ['vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'socks', 'socks5', 'wireguard', 'warp', 'anytls', 'snell'], true)) {
        return symex_sub_endpoint_is_valid($config) || !in_array($scheme, ['vless', 'trojan'], true);
    }

    return true;
}

function symex_sub_encode_fragment(string $fragment): string {
    $fragment = trim($fragment);
    if ($fragment === '') return '';
    $decoded = rawurldecode($fragment);
    return rawurlencode($decoded);
}

function symex_sub_strip_uri_tail(string $candidate): string {
    $candidate = preg_split('/[\r\n]+/u', $candidate)[0] ?? $candidate;
    $candidate = preg_split('/<\/?(?:br|pre|div|span|p|body|html|code|textarea)\b[^>]*>/iu', $candidate)[0] ?? $candidate;
    $candidate = symex_sub_clean_config($candidate);

    if (preg_match('/\s/u', $candidate)) {
        if (strpos($candidate, '#') !== false) {
            $parts = explode('#', $candidate, 2);
            $before = $parts[0];
            $fragment = $parts[1] ?? '';
            $fragment = trim($fragment);
            if (preg_match('/\s+(?:https?:\/\/|[A-Za-z][\w.-]*:\/|<\/|<|$)/u', $fragment, $m, PREG_OFFSET_CAPTURE)) {
                $fragment = substr($fragment, 0, $m[0][1]);
            }
            $candidate = $before . '#' . symex_sub_encode_fragment($fragment);
        } else {
            $candidate = preg_split('/\s+/u', $candidate)[0] ?? $candidate;
        }
        $candidate = symex_sub_clean_config($candidate);
    }
    return $candidate;
}

function symex_sub_extract_plain_uris(string $text): array {
    $text = symex_sub_prepare_text($text);
    $schemes = array_map('preg_quote', symex_sub_supported_schemes());
    $pattern = '/(?:' . implode('|', $schemes) . '):\/\//iu';
    if (!preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE)) return [];

    $starts = [];
    foreach ($matches[0] as $hit) $starts[] = $hit[1];
    $starts = array_values(array_unique($starts));
    sort($starts, SORT_NUMERIC);

    $configs = [];
    $length = strlen($text);
    foreach ($starts as $i => $start) {
        $end = $starts[$i + 1] ?? $length;
        if ($end <= $start) continue;
        $candidate = substr($text, $start, $end - $start);
        $candidate = symex_sub_strip_uri_tail($candidate);
        if (symex_sub_is_valid_config_uri($candidate)) {
            $configs[symex_sub_dedupe_key($candidate)] = $candidate;
            continue;
        }

        $tokens = preg_split('/\s+/u', $candidate) ?: [];
        $partial = '';
        foreach ($tokens as $token) {
            $partial .= ($partial === '' ? '' : ' ') . $token;
            $try = symex_sub_strip_uri_tail($partial);
            if (symex_sub_is_valid_config_uri($try)) {
                $configs[symex_sub_dedupe_key($try)] = $try;
                break;
            }
        }
    }

    return array_values($configs);
}

function symex_sub_scalar_to_string($value): string {
    if (is_bool($value)) return $value ? 'true' : 'false';
    if (is_scalar($value)) return trim((string)$value);
    return '';
}

function symex_sub_flatten_array($value, array &$out, string $prefix = '', int $depth = 0): void {
    if ($depth > 8 || !is_array($value)) return;
    foreach ($value as $k => $v) {
        $key = strtolower(str_replace('_', '-', trim((string)$k)));
        if ($key === '') continue;
        $fullKey = $prefix === '' ? $key : $prefix . '.' . $key;
        if (is_array($v)) {
            symex_sub_flatten_array($v, $out, $fullKey, $depth + 1);
            continue;
        }
        $stringValue = symex_sub_scalar_to_string($v);
        if ($stringValue === '') continue;
        $out[$fullKey] = $stringValue;
        if (!isset($out[$key])) $out[$key] = $stringValue;
    }
}

function symex_sub_flat_map(array $proxy): array {
    $out = [];
    symex_sub_flatten_array($proxy, $out);
    return $out;
}

function symex_sub_get(array $map, array $keys, string $default = ''): string {
    foreach ($keys as $key) {
        $key = strtolower(str_replace('_', '-', $key));
        if (isset($map[$key]) && trim((string)$map[$key]) !== '') return trim((string)$map[$key]);
    }
    return $default;
}

function symex_sub_truthy($value): bool {
    if (is_bool($value)) return $value;
    $value = strtolower(trim((string)$value));
    return in_array($value, ['1', 'true', 'yes', 'on', 'enable', 'enabled', 'tls', 'reality'], true);
}

function symex_sub_endpoint_host(string $server): string {
    $server = trim($server);
    if ($server !== '' && $server[0] !== '[' && strpos($server, ':') !== false) return '[' . trim($server, '[]') . ']';
    return $server;
}

function symex_sub_query(array $params): string {
    $clean = [];
    foreach ($params as $key => $value) {
        if ($value === null) continue;
        $value = trim((string)$value);
        if ($value === '') continue;
        $clean[$key] = $value;
    }
    return http_build_query($clean, '', '&', PHP_QUERY_RFC3986);
}

function symex_sub_fragment(string $name): string {
    $name = trim($name);
    return $name === '' ? '' : '#' . rawurlencode(rawurldecode($name));
}

function symex_sub_security(array $map): string {
    $security = strtolower(symex_sub_get($map, ['security', 'security-type', 'tls-type']));
    if ($security === 'reality') return 'reality';
    if ($security === 'tls' || symex_sub_truthy(symex_sub_get($map, ['tls']))) return 'tls';
    return '';
}

function symex_sub_network(array $map): string {
    $network = strtolower(symex_sub_get($map, ['network', 'net', 'transport', 'transport.type']));
    if ($network === 'websocket') return 'ws';
    if ($network === 'h2') return 'http';
    return $network;
}

function symex_sub_proxy_to_uri(array $proxy): string {
    $map = symex_sub_flat_map($proxy);
    $type = strtolower(symex_sub_get($map, ['type', 'protocol']));
    if ($type === 'shadowsocks') $type = 'ss';
    if ($type === 'hysteria2') $type = 'hy2';
    if ($type === 'socks5') $type = 'socks';

    $server = symex_sub_get($map, ['server', 'address', 'add', 'remote-address', 'host']);
    $port = (int)symex_sub_get($map, ['port', 'server-port', 'remote-port']);
    if ($type === '' || $server === '' || $port <= 0 || $port > 65535) return '';

    $endpoint = symex_sub_endpoint_host($server) . ':' . $port;
    $name = symex_sub_get($map, ['name', 'ps', 'remark', 'remarks'], $type . '-' . $server);
    $network = symex_sub_network($map);
    $security = symex_sub_security($map);
    $sni = symex_sub_get($map, ['sni', 'servername', 'server-name', 'tls.servername', 'reality-opts.servername']);
    $path = symex_sub_get($map, ['path', 'ws-path', 'ws-opts.path', 'grpc-opts.grpc-service-name', 'service-name']);
    $hostHeader = symex_sub_get($map, ['ws-host', 'headers.host', 'ws-opts.headers.host', 'plugin-opts.host']);

    if ($type === 'vless') {
        $uuid = symex_sub_get($map, ['uuid', 'id', 'user', 'username']);
        if ($uuid === '') return '';
        $params = [
            'encryption' => symex_sub_get($map, ['encryption'], 'none'),
            'security' => $security === '' ? 'none' : $security,
            'type' => $network,
            'sni' => $sni,
            'host' => $hostHeader,
            'path' => $path,
            'flow' => symex_sub_get($map, ['flow']),
            'fp' => symex_sub_get($map, ['client-fingerprint', 'fingerprint', 'fp']),
            'pbk' => symex_sub_get($map, ['public-key', 'reality-opts.public-key', 'pbk']),
            'sid' => symex_sub_get($map, ['short-id', 'reality-opts.short-id', 'sid']),
            'spx' => symex_sub_get($map, ['spider-x', 'reality-opts.spider-x', 'spx']),
        ];
        return 'vless://' . rawurlencode($uuid) . '@' . $endpoint . '?' . symex_sub_query($params) . symex_sub_fragment($name);
    }

    if ($type === 'vmess') {
        $uuid = symex_sub_get($map, ['uuid', 'id', 'user', 'username']);
        if ($uuid === '') return '';
        $payload = [
            'v' => '2',
            'ps' => $name,
            'add' => $server,
            'port' => (string)$port,
            'id' => $uuid,
            'aid' => symex_sub_get($map, ['alterid', 'alter-id', 'aid'], '0'),
            'scy' => symex_sub_get($map, ['cipher', 'scy'], 'auto'),
            'net' => $network === '' ? 'tcp' : $network,
            'type' => symex_sub_get($map, ['header-type'], 'none'),
            'host' => $hostHeader,
            'path' => $path,
            'tls' => $security === 'tls' ? 'tls' : '',
            'sni' => $sni,
        ];
        return 'vmess://' . base64_encode(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    if ($type === 'trojan') {
        $password = symex_sub_get($map, ['password', 'passwd', 'uuid', 'id']);
        if ($password === '') return '';
        $params = [
            'security' => $security === '' ? 'tls' : $security,
            'type' => $network,
            'sni' => $sni,
            'host' => $hostHeader,
            'path' => $path,
        ];
        return 'trojan://' . rawurlencode($password) . '@' . $endpoint . '?' . symex_sub_query($params) . symex_sub_fragment($name);
    }

    if ($type === 'ss') {
        $method = symex_sub_get($map, ['cipher', 'method']);
        $password = symex_sub_get($map, ['password', 'passwd']);
        if ($method === '' || $password === '') return '';
        $userinfo = rtrim(strtr(base64_encode($method . ':' . $password), '+/', '-_'), '=');
        $plugin = symex_sub_get($map, ['plugin']);
        $pluginParams = [];
        if ($plugin !== '') {
            $pluginValue = $plugin;
            $pluginHost = symex_sub_get($map, ['plugin-opts.host', 'host']);
            $pluginPath = symex_sub_get($map, ['plugin-opts.path', 'path']);
            if ($pluginHost !== '') $pluginValue .= ';host=' . $pluginHost;
            if ($pluginPath !== '') $pluginValue .= ';path=' . $pluginPath;
            if (symex_sub_truthy(symex_sub_get($map, ['plugin-opts.tls', 'tls']))) $pluginValue .= ';tls';
            $pluginParams['plugin'] = $pluginValue;
        }
        $query = symex_sub_query($pluginParams);
        return 'ss://' . $userinfo . '@' . $endpoint . ($query === '' ? '' : '?' . $query) . symex_sub_fragment($name);
    }

    if (in_array($type, ['hy2', 'hysteria'], true)) {
        $password = symex_sub_get($map, ['password', 'auth', 'auth-str', 'auth-strs']);
        if ($password === '') return '';
        $params = [
            'sni' => $sni,
            'insecure' => symex_sub_truthy(symex_sub_get($map, ['skip-cert-verify', 'insecure'])) ? '1' : '',
            'obfs' => symex_sub_get($map, ['obfs', 'obfs-password']),
        ];
        return ($type === 'hy2' ? 'hy2' : 'hysteria') . '://' . rawurlencode($password) . '@' . $endpoint . '?' . symex_sub_query($params) . symex_sub_fragment($name);
    }

    if ($type === 'tuic') {
        $uuid = symex_sub_get($map, ['uuid', 'id']);
        $password = symex_sub_get($map, ['password', 'passwd']);
        if ($uuid === '' || $password === '') return '';
        $params = [
            'sni' => $sni,
            'congestion_control' => symex_sub_get($map, ['congestion-controller', 'congestion-control']),
            'udp_relay_mode' => symex_sub_get($map, ['udp-relay-mode']),
        ];
        return 'tuic://' . rawurlencode($uuid) . ':' . rawurlencode($password) . '@' . $endpoint . '?' . symex_sub_query($params) . symex_sub_fragment($name);
    }

    if ($type === 'socks') {
        $user = symex_sub_get($map, ['username', 'user']);
        $password = symex_sub_get($map, ['password', 'passwd']);
        $auth = $user === '' ? '' : rawurlencode($user) . ($password === '' ? '' : ':' . rawurlencode($password)) . '@';
        return 'socks://' . $auth . $endpoint . symex_sub_fragment($name);
    }

    return '';
}

function symex_sub_yaml_unquote(string $value): string {
    $value = trim($value);
    $value = preg_replace('/\s+#.*$/u', '', $value);
    $value = trim($value, " \t\n\r\0\x0B,");
    if (strlen($value) >= 2) {
        $first = $value[0];
        $last = $value[strlen($value) - 1];
        if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) $value = substr($value, 1, -1);
    }
    return stripcslashes($value);
}

function symex_sub_top_level_colon(string $text) {
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

function symex_sub_split_commas(string $text): array {
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

function symex_sub_parse_inline_map(string $text, array &$out, string $prefix = ''): void {
    $text = trim($text);
    if ($text !== '' && $text[0] === '{' && substr($text, -1) === '}') $text = substr($text, 1, -1);
    foreach (symex_sub_split_commas($text) as $part) {
        $pos = symex_sub_top_level_colon($part);
        if ($pos === false) continue;
        $key = strtolower(str_replace('_', '-', trim(substr($part, 0, $pos), " \t\n\r\0\x0B\"'")));
        $value = trim(substr($part, $pos + 1));
        if ($key === '') continue;
        $fullKey = $prefix === '' ? $key : $prefix . '.' . $key;
        if ($value !== '' && $value[0] === '{' && substr($value, -1) === '}') {
            symex_sub_parse_inline_map($value, $out, $fullKey);
            continue;
        }
        $out[$fullKey] = symex_sub_yaml_unquote($value);
        if (!isset($out[$key])) $out[$key] = $out[$fullKey];
    }
}

function symex_sub_extract_yaml_proxy_arrays(string $text): array {
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $lines = preg_split('/\n/u', $text) ?: [];
    $proxies = [];
    $current = null;
    $section = '';

    foreach ($lines as $line) {
        $line = rtrim($line);
        $trim = trim($line);
        if ($trim === '' || preg_match('/^\s*#/u', $line)) continue;

        if (preg_match('/^\s*-\s*(.+)$/u', $line, $m)) {
            if (is_array($current) && !empty($current)) $proxies[] = $current;
            $current = [];
            $section = '';
            $rest = trim($m[1]);
            if ($rest !== '' && $rest[0] === '{') {
                symex_sub_parse_inline_map($rest, $current);
            } else {
                $pos = symex_sub_top_level_colon($rest);
                if ($pos !== false) {
                    $key = strtolower(str_replace('_', '-', trim(substr($rest, 0, $pos))));
                    $value = symex_sub_yaml_unquote(substr($rest, $pos + 1));
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
            $value = symex_sub_yaml_unquote($value);
            $fullKey = $section === '' ? $key : $section . '.' . $key;
            $current[$fullKey] = $value;
            if (!isset($current[$key])) $current[$key] = $value;
        }
    }

    if (is_array($current) && !empty($current)) $proxies[] = $current;
    return $proxies;
}

function symex_sub_collect_json($value, array &$strings, array &$proxies, int $depth = 0): void {
    if ($depth > 12) return;
    if (is_string($value)) {
        if (trim($value) !== '') $strings[] = $value;
        return;
    }
    if (!is_array($value)) return;

    $map = symex_sub_flat_map($value);
    $type = strtolower(symex_sub_get($map, ['type', 'protocol']));
    $server = symex_sub_get($map, ['server', 'address', 'add', 'remote-address', 'host']);
    $port = (int)symex_sub_get($map, ['port', 'server-port', 'remote-port']);
    if ($type !== '' && $server !== '' && $port > 0) $proxies[] = $value;

    foreach ($value as $k => $v) {
        if (is_string($k) && trim($k) !== '') $strings[] = $k;
        symex_sub_collect_json($v, $strings, $proxies, $depth + 1);
    }
}

function symex_sub_extract_structured_configs(string $text): array {
    $items = [];
    $strings = [];
    $json = json_decode(trim($text), true);
    if (is_array($json)) symex_sub_collect_json($json, $strings, $items);
    foreach (symex_sub_extract_yaml_proxy_arrays($text) as $proxy) $items[] = $proxy;

    $configs = [];
    foreach ($items as $proxy) {
        if (!is_array($proxy)) continue;
        $uri = symex_sub_proxy_to_uri($proxy);
        if ($uri !== '' && symex_sub_is_valid_config_uri($uri)) $configs[symex_sub_dedupe_key($uri)] = $uri;
    }
    return array_values($configs);
}

function symex_sub_dedupe_key(string $config): string {
    $config = symex_sub_clean_config($config);
    if ($config === '') return sha1('');
    if (!preg_match('/^([a-z][a-z0-9+.-]*):\/\/(.+)$/iu', $config, $m)) return sha1($config);

    $scheme = strtolower($m[1]);
    if ($scheme === 'vmess') {
        $payload = preg_split('/[#?\s]/u', $m[2])[0] ?? $m[2];
        $decoded = symex_sub_base64_decode_text($payload);
        if (is_string($decoded)) {
            $json = json_decode($decoded, true);
            if (is_array($json)) {
                ksort($json);
                return 'vmess:' . sha1(json_encode($json, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
        }
        return 'vmess:' . sha1(preg_replace('/\s+/', '', $m[2]));
    }

    if ($scheme === 'ss' || $scheme === 'ssr') return $scheme . ':' . sha1(rawurldecode(preg_replace('/\s+/', '', $m[2])));

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

function symex_sub_extract_configs(string $text): array {
    $queue = [$text];
    $seen = [];
    $configs = [];
    $rounds = 0;

    while (!empty($queue) && $rounds < 140) {
        $rounds++;
        $current = array_shift($queue);
        if (!is_string($current)) continue;
        $current = symex_sub_prepare_text($current);
        if (trim($current) === '') continue;
        $hash = sha1($current);
        if (isset($seen[$hash])) continue;
        $seen[$hash] = true;

        $plain = symex_sub_extract_plain_uris($current);
        foreach ($plain as $config) $configs[symex_sub_dedupe_key($config)] = $config;

        $structured = symex_sub_extract_structured_configs($current);
        foreach ($structured as $config) $configs[symex_sub_dedupe_key($config)] = $config;

        $foundHere = !empty($plain) || !empty($structured);

        $decodedFull = symex_sub_base64_decode_text($current);
        if (is_string($decodedFull) && !isset($seen[sha1($decodedFull)])) $queue[] = $decodedFull;

        $urlDecoded = rawurldecode($current);
        if ($urlDecoded !== $current && (!$foundHere || symex_sub_encoded_scheme_exists($current)) && !isset($seen[sha1($urlDecoded)])) $queue[] = $urlDecoded;

        $json = json_decode(trim($current), true);
        if (is_array($json)) {
            $strings = [];
            $proxyItems = [];
            symex_sub_collect_json($json, $strings, $proxyItems);
            foreach ($strings as $s) {
                if (is_string($s) && trim($s) !== '' && !isset($seen[sha1($s)])) $queue[] = $s;
            }
        }

        $stripped = trim(strip_tags($current));
        if ($stripped !== '' && $stripped !== $current && !isset($seen[sha1($stripped)])) $queue[] = $stripped;

        if (!$foundHere && preg_match_all('/(?<![A-Za-z0-9+\/_-])([A-Za-z0-9+\/_-]{36,}={0,3})(?![A-Za-z0-9+\/_-])/u', $current, $m)) {
            foreach ($m[1] as $blob) {
                $decodedBlob = symex_sub_base64_decode_text($blob);
                if (is_string($decodedBlob) && !isset($seen[sha1($decodedBlob)])) $queue[] = $decodedBlob;
            }
        }
    }

    return array_values($configs);
}

function symex_sub_normalize_config_list(array $items): array {
    $configs = [];
    foreach ($items as $item) {
        if (!is_string($item)) continue;
        $found = symex_sub_extract_configs($item);
        if (empty($found) && symex_sub_is_valid_config_uri($item)) $found = [symex_sub_clean_config($item)];
        foreach ($found as $config) {
            $config = symex_sub_clean_config($config);
            if (!symex_sub_is_valid_config_uri($config)) continue;
            $configs[symex_sub_dedupe_key($config)] = $config;
        }
    }
    return array_values($configs);
}

function symex_sub_fetch_attempt_curl(string $url, array $options): array {
    if (!extension_loaded('curl')) return ['ok' => false, 'body' => false, 'http' => 0, 'error' => 'curl_missing', 'effective' => $url];
    $ch = curl_init();
    if ($ch === false) return ['ok' => false, 'body' => false, 'http' => 0, 'error' => 'curl_init_failed', 'effective' => $url];

    $maxBytes = (int)($options['max_bytes'] ?? 2097152);
    $body = '';
    $tooLarge = false;
    $insecure = !empty($options['allow_insecure_tls']);
    $timeout = (int)($options['timeout'] ?? 18);
    $connectTimeout = (int)($options['connect_timeout'] ?? 8);

    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_HEADER => false,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $connectTimeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 4,
        CURLOPT_SSL_VERIFYPEER => !$insecure,
        CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2,
        CURLOPT_USERAGENT => (string)($options['ua'] ?? 'Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36'),
        CURLOPT_HTTPHEADER => [
            'Accept: text/plain, application/octet-stream, application/json, application/yaml, text/yaml, text/html, */*',
            'Accept-Language: fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cache-Control: no-cache',
            'Pragma: no-cache',
            'Connection: close',
        ],
        CURLOPT_ENCODING => '',
        CURLOPT_FAILONERROR => false,
        CURLOPT_FORBID_REUSE => true,
        CURLOPT_FRESH_CONNECT => true,
        CURLOPT_NOSIGNAL => true,
        CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, &$tooLarge, $maxBytes) {
            $len = strlen($chunk);
            if (strlen($body) + $len > $maxBytes) {
                $tooLarge = true;
                return 0;
            }
            $body .= $chunk;
            return $len;
        },
    ]);
    if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) @curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) @curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    if (defined('CURLOPT_IPRESOLVE') && defined('CURL_IPRESOLVE_V4')) @curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    if (defined('CURLOPT_HTTP_VERSION') && defined('CURL_HTTP_VERSION_1_1')) @curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $effective = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $error = curl_error($ch) ?: ('curl_errno_' . curl_errno($ch));
    curl_close($ch);

    $body = symex_sub_decode_http_body_if_needed($body);
    return [
        'ok' => !$tooLarge && is_string($body) && trim($body) !== '' && ($http === 0 || $http < 500),
        'body' => $body,
        'http' => $http,
        'error' => $tooLarge ? 'response_too_large' : $error,
        'effective' => $effective ?: $url,
    ];
}

function symex_sub_fetch_attempt_stream(string $url, array $options): array {
    $timeout = (int)($options['timeout'] ?? 18);
    $maxBytes = (int)($options['max_bytes'] ?? 2097152);
    $insecure = !empty($options['allow_insecure_tls']);
    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => $timeout,
            'ignore_errors' => true,
            'header' => "User-Agent: " . (string)($options['ua'] ?? 'Mozilla/5.0') . "\r\n" .
                        "Accept: text/plain, application/octet-stream, application/json, application/yaml, text/yaml, text/html, */*\r\n" .
                        "Accept-Language: fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7\r\n" .
                        "Accept-Encoding: gzip, deflate\r\n" .
                        "Cache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\n"
        ],
        'ssl' => [
            'verify_peer' => !$insecure,
            'verify_peer_name' => !$insecure,
            'allow_self_signed' => $insecure,
            'SNI_enabled' => true,
        ],
    ]);
    $fp = @fopen($url, 'rb', false, $ctx);
    if (!$fp) return ['ok' => false, 'body' => false, 'http' => 0, 'error' => 'stream_open_failed', 'effective' => $url];
    $body = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 8192);
        if ($chunk === false) break;
        $body .= $chunk;
        if (strlen($body) > $maxBytes) {
            fclose($fp);
            return ['ok' => false, 'body' => false, 'http' => 0, 'error' => 'response_too_large', 'effective' => $url];
        }
    }
    fclose($fp);
    $body = symex_sub_decode_http_body_if_needed($body);
    return ['ok' => is_string($body) && trim($body) !== '', 'body' => $body, 'http' => 0, 'error' => 'stream_empty_or_failed', 'effective' => $url];
}

function symex_sub_extract_relay_body($body) {
    if (!is_string($body) || trim($body) === '') return false;
    $json = json_decode(trim($body), true);
    if (is_array($json)) {
        foreach (['content', 'body', 'data', 'subscription', 'raw'] as $k) {
            if (isset($json[$k]) && is_string($json[$k]) && trim($json[$k]) !== '') return $json[$k];
        }
        if (isset($json['configs']) && is_array($json['configs'])) {
            $configs = [];
            foreach ($json['configs'] as $config) if (is_string($config) && trim($config) !== '') $configs[] = trim($config);
            if (!empty($configs)) return implode("\n", $configs);
        }
    }
    return $body;
}

function symex_sub_fetch_url(string $url, array $options = []): array {
    $url = symex_sub_normalize_url($url);
    $attempts = [];
    if ($url === '' || !symex_sub_is_public_http_url($url)) {
        return ['ok' => false, 'content' => false, 'error' => 'invalid_or_unsafe_subscription_url', 'attempts' => []];
    }

    @set_time_limit((int)($options['time_limit'] ?? 70));

    $relayUrl = trim((string)($options['relay_url'] ?? ''));
    if (!empty($options['relay_enabled']) && $relayUrl !== '' && symex_sub_is_public_http_url($relayUrl)) {
        $payload = json_encode([
            'url' => $url,
            'secret' => (string)($options['relay_secret'] ?? ''),
            'ua' => 'Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36',
            'timeout' => 18,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($payload !== false) {
            $postOptions = $options;
            $postOptions['ua'] = 'SYMEX-Panel-Relay/2.1';
            if (extension_loaded('curl')) {
                $ch = curl_init($relayUrl);
                if ($ch !== false) {
                    $insecure = !empty($options['allow_insecure_tls']);
                    curl_setopt_array($ch, [
                        CURLOPT_POST => true,
                        CURLOPT_POSTFIELDS => $payload,
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_TIMEOUT => 24,
                        CURLOPT_CONNECTTIMEOUT => 8,
                        CURLOPT_FOLLOWLOCATION => true,
                        CURLOPT_MAXREDIRS => 3,
                        CURLOPT_SSL_VERIFYPEER => !$insecure,
                        CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2,
                        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json, text/plain, */*'],
                        CURLOPT_USERAGENT => 'SYMEX-Panel-Relay/2.1',
                        CURLOPT_ENCODING => '',
                    ]);
                    $body = curl_exec($ch);
                    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    $error = curl_error($ch) ?: ('curl_errno_' . curl_errno($ch));
                    curl_close($ch);
                    $attempts[] = 'relay_post:http' . $http . ':' . (is_string($body) && trim($body) !== '' ? 'body' : $error);
                    $content = symex_sub_extract_relay_body(is_string($body) ? symex_sub_decode_http_body_if_needed($body) : false);
                    if (is_string($content) && trim($content) !== '') return ['ok' => true, 'content' => $content, 'error' => '', 'attempts' => $attempts];
                }
            }
        }
    }

    $candidates = [$url];
    if (!empty($options['allow_insecure_tls']) && stripos($url, 'https://') === 0) $candidates[] = 'http://' . substr($url, 8);
    $candidates = array_values(array_unique($candidates));
    $lastError = 'fetch_failed';

    foreach ($candidates as $candidate) {
        $result = symex_sub_fetch_attempt_curl($candidate, $options);
        $attempts[] = 'curl:http' . (int)($result['http'] ?? 0) . ':' . (($result['ok'] ?? false) ? 'body' : ($result['error'] ?? 'failed'));
        if (!empty($result['ok']) && is_string($result['body']) && trim($result['body']) !== '') {
            return ['ok' => true, 'content' => $result['body'], 'error' => '', 'attempts' => $attempts];
        }
        $lastError = (string)($result['error'] ?? $lastError);

        $stream = symex_sub_fetch_attempt_stream($candidate, $options);
        $attempts[] = 'stream:' . (($stream['ok'] ?? false) ? 'body' : ($stream['error'] ?? 'failed'));
        if (!empty($stream['ok']) && is_string($stream['body']) && trim($stream['body']) !== '') {
            return ['ok' => true, 'content' => $stream['body'], 'error' => '', 'attempts' => $attempts];
        }
        $lastError = (string)($stream['error'] ?? $lastError);
    }

    return ['ok' => false, 'content' => false, 'error' => $lastError, 'attempts' => $attempts];
}

function symex_sub_settings_options(): array {
    $settings = function_exists('load_settings') ? load_settings() : [];
    return [
        'relay_enabled' => !empty($settings['subscription_relay_enabled']),
        'relay_url' => trim((string)($settings['subscription_relay_url'] ?? '')),
        'relay_secret' => (string)($settings['subscription_relay_secret'] ?? ''),
        'allow_insecure_tls' => !empty($settings['allow_insecure_subscription_fetch']),
        'timeout' => 18,
        'connect_timeout' => 8,
        'max_bytes' => 2097152,
    ];
}

function symex_sub_parse_result(string $content): array {
    $configs = symex_sub_normalize_config_list(symex_sub_extract_configs($content));
    return [
        'ok' => !empty($configs),
        'configs' => $configs,
        'count' => count($configs),
        'content_bytes' => strlen($content),
        'message' => !empty($configs) ? 'Subscription parsed successfully.' : 'No supported configs were found in subscription content.',
    ];
}

function symex_sub_fetch_and_parse(string $url, array $options = []): array {
    $fetch = symex_sub_fetch_url($url, $options);
    if (empty($fetch['ok']) || !is_string($fetch['content'])) {
        return [
            'status' => 'fetch_failed',
            'ok' => false,
            'configs' => [],
            'configs_found' => 0,
            'content_bytes' => 0,
            'message' => 'Could not fetch subscription: ' . (string)($fetch['error'] ?? 'unknown_fetch_error'),
            'fetch_error' => (string)($fetch['error'] ?? ''),
            'attempts' => $fetch['attempts'] ?? [],
            'raw_content' => '',
        ];
    }

    $parse = symex_sub_parse_result((string)$fetch['content']);
    if (empty($parse['ok'])) {
        return [
            'status' => 'invalid_content',
            'ok' => false,
            'configs' => [],
            'configs_found' => 0,
            'content_bytes' => strlen((string)$fetch['content']),
            'message' => $parse['message'],
            'fetch_error' => '',
            'attempts' => $fetch['attempts'] ?? [],
            'raw_content' => (string)$fetch['content'],
        ];
    }

    return [
        'status' => 'ok',
        'ok' => true,
        'configs' => $parse['configs'],
        'configs_found' => count($parse['configs']),
        'content_bytes' => strlen((string)$fetch['content']),
        'message' => 'Subscription fetched and parsed successfully.',
        'fetch_error' => '',
        'attempts' => $fetch['attempts'] ?? [],
        'raw_content' => (string)$fetch['content'],
    ];
}
