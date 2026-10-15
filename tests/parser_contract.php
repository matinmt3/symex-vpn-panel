<?php
declare(strict_types=1);
require dirname(__DIR__) . '/symex_subscription_core.php';
$checks = 0;
function check(bool $condition, string $label): void {
    global $checks;
    if (!$condition) throw new RuntimeException($label);
    $checks++;
}
// Synthetic parser fixtures only: example.invalid cannot be an operational endpoint.
$fixture = 'vless://00000000-0000-4000-8000-000000000000@example.invalid:443?encryption=none#fixture';
check(in_array('vless', symex_sub_supported_schemes(), true), 'supported scheme');
check(symex_sub_is_valid_config_uri($fixture), 'synthetic URI is parsed');
check(!symex_sub_is_valid_config_uri('https://example.invalid/not-a-config'), 'HTTP is not a config URI');
check(count(symex_sub_extract_configs($fixture . "\n" . $fixture)) === 1, 'duplicate normalization');
check(count(symex_sub_extract_configs(base64_encode($fixture))) === 1, 'base64 subscription parsing');
check(count(symex_sub_normalize_config_list([$fixture, $fixture, '', 'not-a-config'])) === 1, 'list normalization');
check(!symex_sub_is_public_http_url('http://127.0.0.1/private'), 'loopback subscription URL rejected');
check(!symex_sub_is_public_http_url('file:///private'), 'non-HTTP subscription URL rejected');
check(symex_sub_prepare_text("\xFF\xFE") === '', 'malformed UTF-8 is rejected before Unicode filtering');
echo json_encode(['parser_checks_passed' => $checks], JSON_THROW_ON_ERROR) . PHP_EOL;
