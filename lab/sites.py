"""The test lab: small websites with known problems planted in them.

`expect` is the right answer for each site, written from what was planted, before the scanner is run.
Each entry is (problem id, severity). A site with expect=[] must get no problems at all."""

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Server": "nginx",
}
GOOD_MAIL = ["v=spf1 include:_spf.google.com -all"]
GOOD_DMARC = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>{head}</head>
<body><h1>{title}</h1><p>Welcome to our company.</p>{body}</body></html>"""


def page(title, head="", body=""):
    return PAGE.format(title=title, head=head, body=body).encode()


def site(slug, about, expect, *, https="good", http="redirect", headers=None, drop=(), cookies=(), html=None,
         files=None, soft404=False, cors=None, spf=None, dmarc=None, txt_error=False, verified=False, wp=None, review=(),
         h2=False):
    h = dict(GOOD)
    h.update(headers or {})
    for d in drop:
        h.pop(d, None)
    return dict(slug=slug, host=f"{slug}.lab.test", about=about, expect=list(expect), https=https, http=http, headers=h,
                cookies=list(cookies), html=html or page(slug.replace("-", " ").title()), files=files or {},
                soft404=soft404, cors=cors, review=sorted(review), h2=h2, spf=GOOD_MAIL if spf is None else spf,
                dmarc=GOOD_DMARC if dmarc is None else dmarc, txt_error=txt_error, verified=verified)


LEAKY_ENV = b"APP_NAME=Shop\nAPP_KEY=base64:Zm9vYmFyYmF6\nDB_HOST=127.0.0.1\nDB_PASSWORD=Summer2024!\n"
WP_CONFIG = b"<?php\ndefine( 'DB_NAME', 'wp' );\ndefine( 'DB_USER', 'wp' );\ndefine( 'DB_PASSWORD', 'hunter2' );\n"
SQL = b"-- MySQL dump 10.13\nCREATE TABLE `customers` (\n  `id` int NOT NULL,\n  `email` varchar(255)\n);\nINSERT INTO `customers` VALUES (1,'anna@example.com');\n"
ZIP = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 40
DS = b"\x00\x00\x00\x01Bud1" + b"\x00" * 60
LISTING = b"<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href='invoice.pdf'>invoice.pdf</a></body></html>"
PHPINFO = b"<!DOCTYPE html><html><head><title>PHP 7.4.3 - phpinfo()</title></head><body><table><tr><td>PHP Version 7.4.3</td></tr></table></body></html>"
STATUS = b"<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for shop</h1></body></html>"
WP_USERS = b'[{"id":1,"name":"admin","slug":"admin"},{"id":2,"name":"Ilze","slug":"ilze"}]'

F = lambda b, ct="text/plain": (200, ct, b)

SITES = [
    # ------------------------------------------------------------- clean
    site("clean-static", "Everything set up well, no cookies, no forms", [], verified=True),
    site("clean-shop", "Well set up shop: safe session cookie, CSRF cookie readable by scripts (as frameworks need), "
                       "current jQuery, HTTPS login form, nonce-based CSP, frame-ancestors instead of X-Frame-Options",
         [], drop=["X-Frame-Options"],
         headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; "
                                             "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"},
         cookies=["shop_session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
                  "csrftoken=xyz; Path=/; Secure; SameSite=Strict"],
         html=page("Shop", '<script src="/static/jquery-3.7.1.min.js"></script>',
                   '<form action="/login" method="post"><input name="u"><input type="password" name="p"></form>'),
         verified=True, review=["login_form"]),
    site("soft-404", "Answers 200 with the home page for every address, including /.env and /.git/HEAD", [],
         soft404=True, verified=True),
    site("blog-sql", "Blog whose missing pages are HTML that talks about SQL and .env files", [],
         soft404=True, verified=True,
         html=page("SQL tips", "", "<pre>CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\nAPP_KEY=x\nDB_HOST=y</pre>")),
    site("clean-wp", "Current WordPress, version not advertised, user list closed", [],
         html=page("Bakery", '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.8.3">'
                             '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'),
         files={"/wp-json/wp/v2/users": (401, "application/json", b'{"code":"rest_forbidden"}')},
         spf=["v=spf1 include:spf.protection.outlook.com ~all"], dmarc=["v=DMARC1; p=quarantine"], verified=True,
         review=["wp_check_plugins", "spf_softfail", "dmarc_partial"]),
    site("borderline", "Nothing wrong, but borderline: HSTS without subdomains, SPF ~all, DMARC at 50%, renewal due in 25 days", [],
         https="renewsoon", headers={"Strict-Transport-Security": "max-age=31536000"},
         spf=["v=spf1 include:_spf.google.com ~all"], dmarc=["v=DMARC1; p=reject; pct=50"],
         review=["hsts_no_subdomains", "spf_softfail", "dmarc_partial", "cert_renew_soon"]),
    site("cors-public", "Public API that allows any site without cookies (Access-Control-Allow-Origin: *)", [], cors="star",
         files={"/go": (302, "redirect", b"http://169.254.169.254/latest/meta-data/")}),
    site("theme-version", "Theme loads its own bootstrap.min.js?ver=1.0.2 (the theme's version, not Bootstrap's)", [],
         html=page("Theme", '<script src="/wp-content/themes/acme/js/bootstrap.min.js?ver=1.0.2"></script>'
                            '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>')),
    site("unverified-leak", "Leaks .env, but the owner has not verified, so it must not be probed", [],
         files={"/.env": F(LEAKY_ENV)}, verified=False),

    # ------------------------------------------------------------- HTTPS
    site("no-https", "Only plain http://, with a login form", [("https_missing", "High"), ("form_http_password", "High")],
         https="none", http="serve",
         html=page("Portal", "", '<form method="post"><input name="u"><input type="password" name="p"></form>')),
    site("expired", "Certificate expired 5 days ago", [("cert_expired", "High")], https="expired"),
    site("wrong-name", "Certificate issued for another company's name", [("cert_name", "High")], https="wrong"),
    site("self-signed", "Self-signed certificate", [("cert_untrusted", "High")], https="self"),
    site("expiring", "Certificate expires in 9 days", [("cert_expiring", "Medium")], https="expiring"),
    site("no-redirect", "http:// shows the site instead of redirecting", [("http_no_redirect", "Medium")], http="serve"),
    site("old-tls", "Accepts TLS 1.0", [("old_tls", "Medium")], https="oldtls"),
    site("old-tls-only", "Speaks only TLS 1.0/1.1, so current browsers can't open it (found on badssl.com in real-world testing)",
         [("old_tls", "High")], https="oldonly"),

    # ----------------------------------------------------------- headers
    site("no-headers", "No security headers, server and PHP versions shown",
         [("hsts_missing", "Medium"), ("csp_missing", "Medium"), ("nosniff_missing", "Low"), ("clickjacking", "Medium"),
          ("referrer_missing", "Low"), ("version_leak", "Low"), ("php2shell", "High"), ("php_eol", "Medium")],
         drop=list(GOOD), headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"}),
    site("php-unpatched", "PHP 8.3.20 shown in X-Powered-By: vulnerable to PHP2Shell",
         [("php2shell", "High"), ("version_leak", "Low")], headers={"X-Powered-By": "PHP/8.3.20"}),
    site("php-patched", "PHP 8.4.28 shown: has the Oct and Nov 2026 fixes, only the version leak is a problem",
         [("version_leak", "Low")], headers={"X-Powered-By": "PHP/8.4.28"}),
    site("php-oct-only", "PHP 8.3.36 shown: has the PHP2Shell fix but not the 19 Nov 2026 release",
         [("php_nov2026", "Medium"), ("version_leak", "Low")], headers={"X-Powered-By": "PHP/8.3.36"}),
    site("php-82-oct", "PHP 8.2.35 shown: missing the Nov release, and 8.2 ends on 31 Dec 2026",
         [("php_nov2026", "Medium"), ("version_leak", "Low")], headers={"X-Powered-By": "PHP/8.2.35"}),
    site("nginx-old-h2", "nginx 1.24.0 shown, HTTP/2 on: open to the Nov 2026 HTTP/2 holes",
         [("nginx2shell", "High"), ("version_leak", "Low")], headers={"Server": "nginx/1.24.0"}, h2=True),
    site("nginx-old-no-h2", "nginx 1.24.0 shown but HTTP/2 off: not affected by these holes, only the version leak",
         [("version_leak", "Low")], headers={"Server": "nginx/1.24.0"}),
    site("nginx-patched-h2", "nginx 1.30.7 (fixed stable) with HTTP/2: only the version leak",
         [("version_leak", "Low")], headers={"Server": "nginx/1.30.7"}, h2=True),
    site("nginx-mainline-old", "nginx 1.31.8 mainline (one before the fix) with HTTP/2",
         [("nginx2shell", "High"), ("version_leak", "Low")], headers={"Server": "nginx/1.31.8"}, h2=True),
    site("nginx-hidden-h2", "nginx with the version hidden and HTTP/2 on: ask to check, don't flag", [], h2=True,
         review=["manual_nginx"]),
    site("php-hidden", "PHP site (session cookie) with the version hidden: must ask to check, not flag",
         [], cookies=["PHPSESSID=x; Secure; HttpOnly; SameSite=Lax"], review=["manual_php"]),
    site("weak-headers", "Headers present but weak: short HSTS, unsafe-inline CSP, ALLOW-FROM, unsafe-url referrer",
         [("hsts_short", "Low"), ("csp_weak", "Low"), ("clickjacking", "Medium"), ("referrer_missing", "Low")],
         headers={"Strict-Transport-Security": "max-age=86400",
                  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
                  "X-Frame-Options": "ALLOW-FROM https://partner.example", "Referrer-Policy": "unsafe-url"}),
    site("report-only", "Only a report-only Content-Security-Policy", [("csp_missing", "Medium")],
         drop=["Content-Security-Policy"],
         headers={"Content-Security-Policy-Report-Only": "default-src 'self'"}),
    site("csp-no-script", "CSP that only controls frames and plugins, not scripts", [("csp_weak", "Low")],
         headers={"Content-Security-Policy": "object-src 'none'; frame-ancestors 'self'"}),
    site("cors-reflect", "Echoes any Origin back and allows cookies", [("cors_reflect", "High")], cors="reflect"),
    site("cors-preflight", "Echoes any Origin back with cookies, but only on preflight (OPTIONS) requests",
         [("cors_reflect", "High")], cors="preflight"),

    # ----------------------------------------------------------- cookies
    site("cookies-bad", "PHP session cookie without Secure / HttpOnly / SameSite; analytics cookie without SameSite",
         [("cookie_secure", "Medium"), ("cookie_httponly", "Medium"), ("cookie_samesite", "Low")],
         cookies=["PHPSESSID=abc123; path=/", "_ga=GA1.1.1; Secure; Max-Age=3600"]),
    site("cookie-tracking", "Only a tracking cookie without Secure (not a login cookie)",
         [("cookie_secure", "Low")], cookies=["_fbp=fb.1.2; Path=/; SameSite=Lax"]),

    # -------------------------------------------------------------- page
    site("mixed", "HTTPS page loads a script and an image over http://",
         [("mixed_active", "Medium"), ("mixed_passive", "Low")],
         html=page("Mixed", '<script src="http://cdn.example.com/widget.js"></script>',
                   '<img src="http://images.example.com/logo.png">')),
    site("form-http", "Login form and newsletter form that send to http://",
         [("form_http_password", "High"), ("form_http", "Medium")],
         html=page("Forms", "", '<form action="http://form-http.lab.test/login" method="post"><input type="password" name="p"></form>'
                                '<form action="http://mail.example.com/subscribe"><input name="email"></form>')),
    site("old-libs", "jQuery 1.12.4 from code.jquery.com and Bootstrap 3.3.7 from a CDN",
         [("old_library", "Medium"), ("old_library", "Medium")],
         html=page("Old", '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>'
                          '<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>')),
    site("angular", "AngularJS 1.8.2 (end of life)", [("old_library", "Medium")],
         html=page("App", '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>')),
    site("wp-insecure", "WordPress 4.9.1 with the version shown; owner verified: user list and wp-config backup exposed",
         [("wp_insecure", "High"), ("wp_version_shown", "Info"), ("wp_users", "Low"), ("config_backup", "High")],
         html=page("Old blog", '<meta name="generator" content="WordPress 4.9.1">'
                               '<link rel="stylesheet" href="/wp-content/themes/twentyseventeen/style.css">'),
         files={"/wp-json/wp/v2/users": F(WP_USERS, "application/json"), "/wp-config.php.bak": F(WP_CONFIG)},
         verified=True),
    site("wp-outdated", "WordPress 6.4.3 found from core file versions (still supported, not latest)",
         [("wp_outdated", "Low")],
         html=page("Clinic", '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.3">')),

    # ----------------------------------------------------- exposed files
    site("git-env", "Owner verified: .git and .env downloadable", [("git_exposed", "High"), ("env_exposed", "High")],
         files={"/.git/HEAD": F(b"ref: refs/heads/main\n"), "/.git/config": F(b"[core]\n\trepositoryformatversion = 0\n"),
                "/.env": F(LEAKY_ENV)}, verified=True),
    site("backups", "Owner verified: database dump, site zip and phpinfo left public",
         [("backup_exposed", "High"), ("phpinfo", "Medium")],
         files={"/backup.sql": F(SQL), "/site.zip": F(ZIP, "application/zip"), "/info.php": F(PHPINFO, "text/html")},
         verified=True),
    site("listing", "Owner verified: open uploads folder, .DS_Store, Apache server-status",
         [("dir_listing", "Medium"), ("ds_store", "Low"), ("server_status", "Medium")],
         files={"/uploads/": F(LISTING, "text/html"), "/.DS_Store": F(DS, "application/octet-stream"),
                "/server-status": F(STATUS, "text/html")}, verified=True),

    # --------------------------------------------- the app's example site
    site("baltic-bakery", "A typical small-company WordPress site: the app's example report",
         [("env_exposed", "High"), ("hsts_missing", "Medium"), ("csp_missing", "Medium"), ("clickjacking", "Medium"),
          ("cookie_httponly", "Medium"), ("cookie_secure", "Medium"), ("old_library", "Medium"), ("dmarc_missing", "Medium"),
          ("cookie_samesite", "Low"), ("referrer_missing", "Low"), ("version_leak", "Low"), ("wp_outdated", "Low")],
         drop=["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"],
         headers={"Server": "Apache/2.4.52 (Ubuntu)"},
         cookies=["PHPSESSID=8f2c1; path=/"],
         html=page("Baltic Bakery", '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.3">'
                                    '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                                    '<script src="https://code.jquery.com/ui/1.12.1/jquery-ui.min.js"></script>',
                   '<form action="/order" method="post"><input name="email"></form>'),
         files={"/.env": F(LEAKY_ENV), "/wp-json/wp/v2/users": (401, "application/json", b'{"code":"rest_forbidden"}'),
                "/.well-known/site-check.txt": F(b"site-check-" + __import__("hashlib").sha256(b"site-check:baltic-bakery.lab.test").hexdigest()[:24].encode())},
         spf=["v=spf1 include:spf.protection.outlook.com -all"], dmarc=[], verified=True),

    # ------------------------------------------------------------- email
    site("email-none", "No SPF and no DMARC", [("spf_missing", "Medium"), ("dmarc_missing", "Medium")], spf=[], dmarc=[]),
    site("email-plusall", "SPF ends in +all, DMARC only monitors", [("spf_weak", "High"), ("dmarc_none", "Low")],
         spf=["v=spf1 +all"], dmarc=["v=DMARC1; p=none; rua=mailto:d@example.com"]),
    site("email-two-spf", "Two SPF records", [("spf_multiple", "Medium")],
         spf=["v=spf1 include:_spf.google.com -all", "v=spf1 include:mailgun.org ~all"]),
    site("email-neutral", "SPF ends in ?all", [("spf_weak", "Low")], spf=["v=spf1 mx ?all"]),
    site("dns-fail", "DNS lookups fail: email checks must say 'could not check', not OK", [], txt_error=True,
         review=["manual_email"]),
]

WP_STATUS = {"4.9.1": "insecure", "6.4.3": "outdated", "6.8.3": "latest"}
