<?php
// Local development only. PHP's built-in server does not read Apache .htaccess.
// Expose application endpoints while keeping runtime data and password files private.
declare(strict_types=1);
$path = rawurldecode((string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH));
if ($path === '/' || $path === '/admin.php') {
    require __DIR__ . '/admin.php';
    return;
}
if ($path === '/license.php') {
    require __DIR__ . '/license.php';
    return;
}
http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');
echo 'Not found';
