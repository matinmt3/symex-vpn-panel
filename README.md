# پنل SYMEX VPN | SYMEX VPN Admin Panel

سورس پنل مدیریت و API مجوز همراه پروژهٔ SYMEX VPN، با PHP و ذخیره‌سازی JSON. مدیریت مجوز، محدودیت دستگاه، وضعیت مصرف، فهرست کانفیگ و پردازش محتوای اشتراک در آن پیاده شده است. این مخزن **سرور تونل VPN یا سرویس عمومی فروش نیست**؛ نسخهٔ نمونه‌کارِ سورس ارائه‌شده است.

A PHP administration panel and license API supplied with the SYMEX VPN project. It manages licenses, device limits, usage records, configuration lists and subscription parsing with JSON-file storage. This is application source for portfolio review, not a VPN tunnel server or a hosted subscription service.

## محدودهٔ سورس | Scope

- `admin.php`: English-language admin interface, sessions, license/configuration management and settings.
- `license.php`: companion client license/device API.
- `symex_subscription_core.php`: shared URI, base64, JSON/YAML and subscription parsing/fetch helpers.
- `.htaccess`: Apache access restrictions for generated records and secret files.
- `dev-router.php`: local development route allowlist; it blocks direct requests for runtime files because PHP's development server does not process `.htaccess`.

هیچ مجوز مشتری، شناسهٔ دستگاه واقعی، کانفیگ عملیاتی VPN، پیوند اشتراک خصوصی، تنظیم سرویس، رمز مدیر، پایگاه داده، گزارش دسترسی یا بکاپ هاست در این مخزن قرار ندارد. فایل‌های JSON و اسرار زمان اجرا پس از استفادهٔ محلی ایجاد می‌شوند و در Git نادیده گرفته می‌شوند. دریافت اشتراک، relay و geolocation در بررسی نمونه‌کار اجرا نشده‌اند.

No customer licenses, real device records, operational VPN configurations, private subscription links, service settings, administrator credentials, access logs or hosting backups are included. Runtime files are created locally and ignored by Git. Subscription fetching, relays and geolocation have not been exercised against external services during preparation.

## اجرای محلی در ویندوز | Local Windows run

PHP 8.2+ is the intended runtime; this copy was tested with **PHP CLI 8.5.11**. PHP's built-in server is for local development. Python 3.10+ is used only for the isolated tests. No Composer or Node dependency installation is required.

در PowerShell، رمز آزمایشی خودتان را در حافظهٔ همان ترمینال تنظیم کنید؛ سپس سرور را اجرا کنید:

```powershell
$panelDemoPassword = Read-Host 'Local demo administrator password' -AsSecureString
$env:SYMEX_ADMIN_PASSWORD = [Net.NetworkCredential]::new('', $panelDemoPassword).Password
php -S 127.0.0.1:8090 dev-router.php
```

Open **http://127.0.0.1:8090/admin.php** and use the password you just chose. Stop with `Ctrl+C`; then remove the terminal variable with `Remove-Item Env:\SYMEX_ADMIN_PASSWORD`. The application also supports `SYMEX_ADMIN_PASSWORD_HASH`; no environment file is loaded automatically.

در لینوکس یا macOS می‌توانید متغیر `SYMEX_ADMIN_PASSWORD` را در محیط تنظیم کنید و همان دستور `php -S 127.0.0.1:8090 dev-router.php` را اجرا کنید. استفاده از نشانی loopback و router همراه، بخشی از روش اجرای محلی این نمونه است.

اگر هیچ رمز محیطی یا فایل hash وجود نداشته باشد، رفتار اصلی برنامه در اولین تلاش ورود یک رمز تصادفی و فایل‌های محلی مخفی می‌سازد. این فایل‌ها محرمانه‌اند؛ در سورس عمومی حضور ندارند و router توسعه دسترسی HTTP به آن‌ها را نمی‌دهد.

## آزمون‌ها | Checks

With PHP on `PATH`, run:

```sh
python -m unittest discover -s tests -v
```

اگر PHP روی PATH نیست، متغیر `PHP_BIN` را به مسیر فایل اجرایی PHP تنظیم کنید. آزمون‌ها یک نسخهٔ موقت از سورس می‌سازند، یک PHP server روی loopback و پورت موقت اجرا می‌کنند و سپس همهٔ داده‌ها و پردازش‌های خود را پاک می‌کنند. رمز آزمون تصادفی و کوتاه‌عمر است. شبکهٔ بیرونی در فرایند PHP آزمون غیرفعال است.

The suite covers PHP syntax, nine parser contracts, the login page, local authentication, a synthetic license, CSRF rejection, invalid license API input and private-file denial by the development router. See [VALIDATION.md](VALIDATION.md) for the actual results. The CI workflow repeats local source tests; no hosted CI run or public deployment is claimed.

## منشأ و تغییرات | Provenance and preparation

Prepared from the supplied `symex_panel_v2.9.0_connection_preflight_source` source snapshot. The original files remain untouched. This copy includes the three PHP application files and protective `.htaccess`, plus documentation, a local router, tests and CI. A small guard in the copied subscription parser rejects malformed UTF-8 before Unicode filtering; it prevents a PHP 8.5 deprecation on invalid decoded input and has a regression check.

Runtime JSON, password files and server backups were not copied. No new open-source license for the original application has been selected; see [NOTICE.md](NOTICE.md). The source is not evidence of a verified client commission, public service availability or measured VPN performance.

## Deployment boundary

GitHub Pages cannot execute PHP. An eventual deployment needs a PHP-capable server, private storage/access rules and the corresponding client configuration. Apache `.htaccess` behavior was inspected as source but not tested under Apache; another server needs equivalent restrictions. Optional HTTP subscription operations require suitable PHP extensions and must be reviewed separately. The local router is a development aid, not a production deployment configuration. No Android-device, load, penetration or production-infrastructure audit was performed.
