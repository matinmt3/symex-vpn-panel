# Local preparation checks

Performed on Windows with the official portable PHP CLI **8.5.11** and Python **3.14**. The PHP ZIP checksum matched the SHA-256 published on php.net before extraction. The runtime was kept in the workspace; no system PHP installation was performed.

- All three original PHP application files passed `php -n -l`; the development router and PHP parser test also passed syntax checks.
- `python -m unittest discover -s tests -v`: **7 tests passed, 0 failures/errors**.
- The parser test contains **9 contracts**: a synthetic reserved-domain URI, scheme validation, duplicate normalization, base64 subscription input, list normalization, loopback/non-HTTP URL rejection and malformed UTF-8 handling.
- Five HTTP checks start actual temporary PHP servers: empty login page, login plus synthetic license creation, missing-CSRF rejection, missing/unknown license input, and direct-file denial by the local router.
- Each HTTP test uses a fresh temporary directory and session store with a random test-only password. Runtime records are removed after the test. No original database or production settings were used.
- Remote URL opening and socket/cURL calls were disabled in test PHP processes. No external subscription, webhook, relay or geolocation service was contacted.
- Original source-file hashes were checked after preparation; the original snapshot was unchanged. The copied shared parser includes the documented malformed-UTF-8 guard.

These checks do not establish Android-device compatibility, real subscription availability, tunnel connectivity/performance, production security or Apache configuration behavior. Browser screenshots and visual/accessibility audits were not performed. The GitHub Actions workflow is prepared but a hosted run is not part of these local results.
