"""Local-only source checks. Runtime records live in disposable temporary copies."""
from pathlib import Path
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PHP = os.environ.get('PHP_BIN') or shutil.which('php')
DISABLED = 'curl_exec,curl_multi_exec,fsockopen,pfsockopen,stream_socket_client,socket_create,socket_connect'


@unittest.skipUnless(PHP, 'PHP CLI must be on PATH or set PHP_BIN')
class PanelSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='symex-panel-test-')
        self.base = Path(self.temp.name)
        for name in ['admin.php', 'license.php', 'symex_subscription_core.php', 'dev-router.php']:
            shutil.copy2(ROOT / name, self.base / name)
        (self.base / 'sessions').mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.origin = f'http://127.0.0.1:{port}'
        self.password = secrets.token_urlsafe(24)
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        self.process = subprocess.Popen(
            [PHP, '-n', '-d', 'allow_url_fopen=0', '-d', f'disable_functions={DISABLED}',
             '-d', f'session.save_path={self.base / "sessions"}', '-S', f'127.0.0.1:{port}', 'dev-router.php'],
            cwd=self.base, env={**os.environ, 'SYMEX_ADMIN_PASSWORD': self.password},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
        )
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        for _ in range(50):
            try:
                self.request('/admin.php')
                break
            except OSError:
                if self.process.poll() is not None:
                    self.fail('Temporary PHP server exited before startup')
                time.sleep(.1)
        else:
            self.fail('Temporary PHP server did not start')

    def tearDown(self):
        if hasattr(self, 'process'):
            self.process.terminate()
            self.process.wait(timeout=10)
        self.temp.cleanup()

    def request(self, path, form=None, json_body=None, client=None):
        headers = {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.origin + path, data=body, headers=headers)
        try:
            with (client or self.client).open(request, timeout=8) as response:
                return response.status, response.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as error:
            try:
                return error.code, error.read().decode('utf-8', errors='replace')
            finally:
                error.close()

    def login(self):
        status, html = self.request('/admin.php', form={'password': self.password})
        self.assertEqual(status, 200)
        self.assertIn('New License', html)
        match = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', html)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_login_page_and_empty_start(self):
        status, html = self.request('/admin.php')
        self.assertEqual(status, 200)
        self.assertIn('Unlock Panel', html)
        self.assertFalse((self.base / '.symex_admin_password_hash').exists())
        self.assertFalse((self.base / '.symex_initial_admin_password').exists())

    def test_admin_login_and_synthetic_license(self):
        token = self.login()
        status, html = self.request('/admin.php', form={
            'csrf_token': token, 'add_license': 'PORTFOLIO-ONLY-TEST',
            'expires_days': '1', 'max_devices': '1', 'bandwidth_limit': '0',
        })
        self.assertEqual(status, 200)
        records = json.loads((self.base / 'licenses.json').read_text(encoding='utf-8'))
        self.assertEqual(list(records), ['PORTFOLIO-ONLY-TEST'])
        self.assertIn('PORTFOLIO-ONLY-TEST', html)

    def test_authenticated_mutation_rejects_missing_csrf(self):
        self.login()
        status, html = self.request('/admin.php', form={'add_license': 'MUST-NOT-EXIST'})
        self.assertEqual(status, 200)
        self.assertIn('Security token mismatch', html)
        records = json.loads((self.base / 'licenses.json').read_text(encoding='utf-8'))
        self.assertNotIn('MUST-NOT-EXIST', records)

    def test_license_api_rejects_missing_and_unknown_inputs(self):
        status, body = self.request('/license.php', json_body={})
        self.assertEqual(status, 200)
        self.assertIn('missing_params', body)
        status, body = self.request('/license.php', json_body={'license': 'NO-SUCH-TEST-LICENSE', 'device_id': 'synthetic-device'})
        self.assertEqual(status, 200)
        self.assertIn('not_found', body)

    def test_development_router_hides_runtime_and_internal_files(self):
        self.login()
        for path in ['/licenses.json', '/logs.json', '/settings.json', '/.symex_admin_password_hash', '/symex_subscription_core.php', '/README.md']:
            with self.subTest(path=path):
                status, _ = self.request(path)
                self.assertEqual(status, 404)


@unittest.skipUnless(PHP, 'PHP CLI must be on PATH or set PHP_BIN')
class ParserAndSyntaxTests(unittest.TestCase):
    def test_application_and_test_php_syntax(self):
        for relative in ['admin.php', 'license.php', 'symex_subscription_core.php', 'dev-router.php', 'tests/parser_contract.php']:
            with self.subTest(file=relative):
                result = subprocess.run([PHP, '-n', '-l', str(ROOT / relative)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, 'PHP syntax check failed')

    def test_shared_subscription_parser_without_network(self):
        result = subprocess.run([PHP, '-n', '-d', 'allow_url_fopen=0', '-d', f'disable_functions={DISABLED}', str(ROOT / 'tests/parser_contract.php')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(json.loads(result.stdout)['parser_checks_passed'], 9)


if __name__ == '__main__':
    unittest.main()
