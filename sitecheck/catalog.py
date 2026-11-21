"""Every problem Site Check can report: plain-words reason, fix per host, and how to retest.
{host} and {domain} are filled in for the site being checked."""

AREAS = ["HTTPS", "Headers", "Cookies", "Page", "Email", "Exposed files"]

H = "High"
M = "Medium"
L = "Low"
I = "Info"

_HDR = ("Netlify: add the line under `/*` in a `_headers` file.\n"
        "Cloudflare: Rules → Transform Rules → Modify response header → Set static.\n"
        "Nginx: `add_header {name} \"{value}\" always;` in the server block.\n"
        "Apache: `Header always set {name} \"{value}\"` in the site config or .htaccess.\n"
        "WordPress: set it at your host or CDN, or in .htaccess on Apache hosting.")


def _hdr(name, value):
    return _HDR.format(name=name, value=value)


def _curl(header):
    return f"`curl -sI https://{{host}} | grep -i {header}`"


C = {
    # ------------------------------------------------------------------ HTTPS
    "https_missing": dict(
        area="HTTPS", sev=H, title="The site does not work over HTTPS",
        why="Without HTTPS anyone on the same Wi-Fi or network can read and change what visitors send and see, "
            "including passwords and contact forms. Browsers mark the site 'Not secure'.",
        fix="Turn on a free certificate: Netlify, Cloudflare and most hosts do it with one switch (Let's Encrypt). "
            "On your own server: `certbot --nginx` or `certbot --apache`.",
        retest="Open https://{host} in a browser: it should load with a padlock. Then scan again."),
    "cert_expired": dict(
        area="HTTPS", sev=H, title="The certificate has expired",
        why="Browsers show a full-page security warning, so most visitors leave, and the ones who click through "
            "learn to ignore warnings.",
        fix="Renew it now. With Let's Encrypt, check that automatic renewal runs (`certbot renew --dry-run`).",
        retest="`echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -enddate` "
               "shows a date in the future. Then scan again."),
    "cert_name": dict(
        area="HTTPS", sev=H, title="The certificate is for a different name",
        why="Browsers show a security warning because the certificate does not prove this site is {host}.",
        fix="Issue a certificate that includes {host} (and www. if you use it). On Netlify / Cloudflare add the "
            "name as a domain alias so it is covered.",
        retest="Open https://{host}: no warning. Then scan again."),
    "cert_untrusted": dict(
        area="HTTPS", sev=H, title="The certificate is not trusted (self-signed or incomplete chain)",
        why="Browsers show a security warning. A missing intermediate certificate often works on one computer "
            "and fails on phones.",
        fix="Use a certificate from a public authority (Let's Encrypt is free) and install the full chain "
            "(`fullchain.pem`, not only `cert.pem`).",
        retest="`echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | grep 'Verify return code'` "
               "says `0 (ok)`. Then scan again."),
    "cert_expiring": dict(
        area="HTTPS", sev=M, title="The certificate expires soon",
        why="When it expires, every visitor gets a security warning. This usually means automatic renewal is broken.",
        fix="Renew now and check automatic renewal (`certbot renew --dry-run`, or the host's certificate page).",
        retest="Scan again: the expiry date should be about 60–90 days away."),
    "http_no_redirect": dict(
        area="HTTPS", sev=M, title="The plain http:// address does not send visitors to HTTPS",
        why="People who type the address or follow old links stay on the unprotected version, where traffic can "
            "be read or changed.",
        fix="Netlify: on by default once HTTPS is on (Domain management → HTTPS → Force HTTPS).\n"
            "Cloudflare: SSL/TLS → Edge Certificates → Always Use HTTPS.\n"
            "Nginx: a port-80 server block with `return 301 https://$host$request_uri;`.\n"
            "Apache: `Redirect permanent / https://{host}/` in the port-80 VirtualHost.\n"
            "WordPress: set both addresses in Settings → General to https://, plus the host's redirect.",
        retest="`curl -sI http://{host}` shows `301` (or 308) and `Location: https://{host}/`. Then scan again."),
    "old_tls": dict(
        area="HTTPS", sev=M, title="Old TLS 1.0 / 1.1 is still accepted",
        why="These versions have known weaknesses and were retired in 2021 (RFC 8996). Card payment rules (PCI DSS) "
            "do not allow them.",
        fix="Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS Version 1.2.\n"
            "Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`\nApache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`",
        retest="`openssl s_client -connect {host}:443 -tls1_1` fails to connect. Then scan again."),
    # ---------------------------------------------------------------- headers
    "hsts_missing": dict(
        area="Headers", sev=M, title="HSTS is not set",
        why="Even with a redirect, a visitor's first request goes out unprotected and can be hijacked on public "
            "Wi-Fi. HSTS tells the browser to always use HTTPS for this site.",
        fix=_hdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains") +
            "\nCloudflare also has it under SSL/TLS → Edge Certificates → HSTS.",
        retest=_curl("strict-transport-security") + " shows `max-age=31536000`. Then scan again."),
    "hsts_short": dict(
        area="Headers", sev=L, title="HSTS is set for too short a time",
        why="Browsers forget the rule quickly, so visitors are unprotected again soon. Six months is the usual minimum.",
        fix="Raise it to `max-age=31536000` (one year). " + "Same place you set it now.",
        retest=_curl("strict-transport-security") + " shows a max-age of at least 15552000. Then scan again."),
    "csp_missing": dict(
        area="Headers", sev=M, title="No Content-Security-Policy",
        why="If an attacker manages to inject a script (through a comment, a plugin bug or a hacked ad), nothing "
            "stops the browser from running it. A policy limits where scripts may come from.",
        fix="Start with a report-only policy so nothing breaks, read the reports, then enforce. A safe first step "
            "that blocks plugins and framing: `Content-Security-Policy: object-src 'none'; base-uri 'self'; frame-ancestors 'self'`.\n" +
            _hdr("Content-Security-Policy", "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
        retest=_curl("content-security-policy") + " shows the policy. Then scan again."),
    "csp_weak": dict(
        area="Headers", sev=L, title="The Content-Security-Policy still allows injected scripts",
        why="The policy exists but lets scripts run from anywhere or inline, so it would not stop most injected code.",
        fix="Remove `'unsafe-inline'` / `'unsafe-eval'` / `*` / `http:` / `data:` from script-src; move inline "
            "scripts to files or allow them with a nonce or hash.",
        retest="Scan again: the Content-Security-Policy check should be OK."),
    "nosniff_missing": dict(
        area="Headers", sev=L, title="X-Content-Type-Options is not set",
        why="Without it, a browser may treat an uploaded text or image file as a script.",
        fix=_hdr("X-Content-Type-Options", "nosniff"),
        retest=_curl("x-content-type-options") + " shows `nosniff`. Then scan again."),
    "clickjacking": dict(
        area="Headers", sev=M, title="Other sites can show this site inside a frame (clickjacking)",
        why="An attacker's page can load your site invisibly and trick visitors into clicking buttons on it, "
            "for example 'delete' or 'pay', while they think they are clicking something else.",
        fix=_hdr("X-Frame-Options", "SAMEORIGIN") + "\n(Or `frame-ancestors 'self'` in the Content-Security-Policy.)",
        retest=_curl("x-frame-options") + " shows `SAMEORIGIN` or `DENY`. Then scan again."),
    "referrer_missing": dict(
        area="Headers", sev=L, title="No Referrer-Policy (or a leaky one)",
        why="Full page addresses, which can contain search terms, order numbers or reset codes, are sent to every "
            "other site the visitor goes to from yours.",
        fix=_hdr("Referrer-Policy", "strict-origin-when-cross-origin"),
        retest=_curl("referrer-policy") + " shows the policy. Then scan again."),
    "version_leak": dict(
        area="Headers", sev=L, title="The server tells everyone its software version",
        why="Version numbers let an attacker look up exactly which known holes apply, without any effort.",
        fix="Nginx: `server_tokens off;`\nApache: `ServerTokens Prod` and `ServerSignature Off`\n"
            "PHP: `expose_php = Off` in php.ini (removes X-Powered-By).",
        retest="`curl -sI https://{host} | grep -iE 'server|x-powered-by'` shows no version numbers. Then scan again."),
    "cors_reflect": dict(
        area="Headers", sev=H, title="Any website can read logged-in visitors' data (CORS)",
        why="The site answers 'yes' to requests from any other website and allows cookies with them. A page on "
            "another site can read what a logged-in visitor sees here.",
        fix="Only allow your own domains in Access-Control-Allow-Origin (a fixed list), never echo the request's "
            "Origin back, and don't send Access-Control-Allow-Credentials unless needed.",
        retest="`curl -sI -H 'Origin: https://example.org' https://{host}` does not show "
               "`Access-Control-Allow-Origin: https://example.org` with `Access-Control-Allow-Credentials: true`. Then scan again."),
    # ---------------------------------------------------------------- cookies
    "cookie_secure": dict(
        area="Cookies", sev=M, title="Cookies can be sent without encryption",
        why="A cookie without the Secure flag also travels over plain http://, where it can be read on public Wi-Fi. "
            "For a login cookie that means someone can take over the session.",
        fix="Add `Secure` to the cookie. PHP: `session.cookie_secure = 1`. Most frameworks have a 'secure cookies' setting.",
        retest="`curl -sI https://{host} | grep -i set-cookie` shows `Secure` on every cookie. Then scan again."),
    "cookie_httponly": dict(
        area="Cookies", sev=M, title="The login cookie can be read by scripts",
        why="If any script gets injected into the page, it can steal the login cookie and take over the account.",
        fix="Add `HttpOnly` to session cookies. PHP: `session.cookie_httponly = 1`.",
        retest="`curl -sI https://{host} | grep -i set-cookie` shows `HttpOnly` on the session cookie. Then scan again."),
    "cookie_samesite": dict(
        area="Cookies", sev=L, title="Cookies have no SameSite setting",
        why="SameSite stops other sites from making a logged-in visitor's browser send requests to yours "
            "(cross-site request forgery). Browsers now default to Lax, but older ones don't.",
        fix="Add `SameSite=Lax` (or `Strict`) to cookies. PHP: `session.cookie_samesite = \"Lax\"`.",
        retest="`curl -sI https://{host} | grep -i set-cookie` shows `SameSite=`. Then scan again."),
    # ------------------------------------------------------------------- page
    "mixed_active": dict(
        area="Page", sev=M, title="The HTTPS page loads scripts, styles or frames over plain http://",
        why="Browsers block these, so parts of the page break. Where they load, anyone on the network can replace "
            "them with their own code, which defeats HTTPS.",
        fix="Change these addresses to https:// (or to relative paths). WordPress: update old links in the "
            "database with a search-replace of http://{host} → https://{host}.",
        retest="Open the page with the browser console (F12): no 'Mixed Content' messages. Then scan again."),
    "mixed_passive": dict(
        area="Page", sev=L, title="The HTTPS page loads images or media over plain http://",
        why="The padlock disappears, and the images can be swapped on the network.",
        fix="Change these addresses to https:// or relative paths.",
        retest="Scan again: no insecure images listed."),
    "form_http": dict(
        area="Page", sev=M, title="A form sends what people type over plain http://",
        why="Whatever is typed into it travels unencrypted and can be read on the way.",
        fix="Point the form's action to https:// (or a relative path).",
        retest="Scan again: no insecure forms listed."),
    "form_http_password": dict(
        area="Page", sev=H, title="A password form sends passwords over plain http://",
        why="Passwords travel unencrypted and can be read on any shared network.",
        fix="Point the form's action to https:// (or a relative path), then ask users to change passwords if it "
            "has been like this for long.",
        retest="Scan again: no insecure password forms listed."),
    "old_library": dict(
        area="Page", sev=M, title="An outdated JavaScript library with known security holes",
        why="Known holes in old versions are published with working examples, so they are easy to use against the site.",
        fix="Update the library to a current version (jQuery 3.7+, Bootstrap 5, AngularJS → a supported framework). "
            "WordPress: update the theme and plugins; the old copy usually comes from one of them.",
        retest="View the page source and check the version in the script address. Then scan again."),
    "wp_insecure": dict(
        area="Page", sev=H, title="WordPress is a version with known security holes",
        why="WordPress.org lists this version as insecure: the holes are public and automated attacks look for them.",
        fix="Update WordPress now (Dashboard → Updates), then themes and plugins. Turn on automatic minor updates.",
        retest="Dashboard → Updates says you have the latest version. Then scan again."),
    "wp_outdated": dict(
        area="Page", sev=L, title="WordPress is not the latest version",
        why="It is still getting security fixes, but staying behind makes the next urgent update harder.",
        fix="Update WordPress (Dashboard → Updates), with a backup first.",
        retest="Scan again."),
    "wp_version_shown": dict(
        area="Page", sev=I, title="The page shows its WordPress version",
        why="It tells attackers exactly what to try. Hiding it is not protection by itself; keeping up to date is.",
        fix="Remove the generator tag (many security plugins do this) and keep WordPress updated.",
        retest="View the page source: no `<meta name=\"generator\" content=\"WordPress x.y\">`."),
    # ------------------------------------------------------------------ email
    "spf_missing": dict(
        area="Email", sev=M, title="No SPF record: anyone can send email as @{domain}",
        why="Fake invoices and 'change of bank account' emails in your company's name are the most common "
            "attack on small companies. SPF lists which servers may send mail for your domain.",
        fix="Add a TXT record on {domain}:\nMicrosoft 365: `v=spf1 include:spf.protection.outlook.com -all`\n"
            "Google Workspace: `v=spf1 include:_spf.google.com ~all`\n"
            "If the domain never sends email: `v=spf1 -all`",
        retest="`dig +short TXT {domain}` shows one line starting `v=spf1`. Then scan again."),
    "spf_weak": dict(
        area="Email", sev=M, title="The SPF record does not stop fake senders",
        why="The record exists but ends in a way that lets any server send as your domain.",
        fix="End the record with `-all` (or `~all` while you test) instead of `+all` / `?all`.",
        retest="`dig +short TXT {domain}` shows the record ending in `-all` or `~all`. Then scan again."),
    "spf_multiple": dict(
        area="Email", sev=M, title="Two SPF records: receivers ignore both",
        why="The rules say there must be exactly one; with two, mail servers treat SPF as broken.",
        fix="Merge them into one TXT record, for example `v=spf1 include:a include:b -all`.",
        retest="`dig +short TXT {domain}` shows only one line starting `v=spf1`. Then scan again."),
    "dmarc_missing": dict(
        area="Email", sev=M, title="No DMARC record",
        why="Without DMARC, mail servers don't know what to do with fake mail in your name, and you never hear "
            "about it. It is also required by Google and Yahoo for bulk senders since 2024.",
        fix="Add a TXT record on `_dmarc.{domain}`: `v=DMARC1; p=none; rua=mailto:dmarc@{domain}`. Read the "
            "reports for 2–4 weeks, then change to `p=quarantine`.",
        retest="`dig +short TXT _dmarc.{domain}` shows `v=DMARC1`. Then scan again."),
    "dmarc_none": dict(
        area="Email", sev=L, title="DMARC only watches, it does not stop fake mail",
        why="`p=none` sends you reports but fake mail in your name is still delivered.",
        fix="Once reports show your real mail passes, change to `p=quarantine`, later `p=reject`.",
        retest="`dig +short TXT _dmarc.{domain}` shows `p=quarantine` or `p=reject`. Then scan again."),
    # --------------------------------------------------------- exposed files
    "git_exposed": dict(
        area="Exposed files", sev=H, title="The site's source code history (.git) can be downloaded",
        why="Anyone can rebuild the whole code, often with passwords and keys that were committed at some point.",
        fix="Block it: Nginx `location ~ /\\.git { deny all; }`, Apache `RedirectMatch 404 /\\.git`. Better: deploy "
            "without the .git folder. Then change any password or key that was ever in the code.",
        retest="`curl -s -o /dev/null -w '%{http_code}' https://{host}/.git/HEAD` shows 403 or 404. Then scan again."),
    "env_exposed": dict(
        area="Exposed files", sev=H, title="The .env file with settings and passwords can be downloaded",
        why="It usually holds the database password, API keys and the app's secret key: full access for anyone.",
        fix="Block it right away (Nginx `location ~ /\\.env { deny all; }`, Apache `<Files .env> Require all denied </Files>`), "
            "move it outside the public folder, and **change every password and key in it**.",
        retest="`curl -s -o /dev/null -w '%{http_code}' https://{host}/.env` shows 403 or 404. Then scan again."),
    "backup_exposed": dict(
        area="Exposed files", sev=H, title="A backup of the site or database can be downloaded",
        why="A database dump holds customers' data and password hashes; a site backup holds the code and config. "
            "Leaking customer data is also a GDPR breach you may have to report within 72 hours.",
        fix="Delete the file from the public folder, keep backups outside it, and check the server logs for who "
            "downloaded it.",
        retest="The file's address shows 404. Then scan again."),
    "config_backup": dict(
        area="Exposed files", sev=H, title="A copy of the site's config file (with the database password) can be read",
        why="Editors leave copies like `wp-config.php.bak` that the server shows as plain text, including the "
            "database password.",
        fix="Delete the copy and change the database password and the WordPress keys (salts).",
        retest="The file's address shows 404. Then scan again."),
    "phpinfo": dict(
        area="Exposed files", sev=M, title="A phpinfo page is public",
        why="It lists the server's software, paths and settings, sometimes environment secrets: a map for an attacker.",
        fix="Delete the file.",
        retest="The file's address shows 404. Then scan again."),
    "server_status": dict(
        area="Exposed files", sev=M, title="Apache server-status is public",
        why="It shows every current visitor's address and the pages they are on, including private links.",
        fix="Limit it to the server itself: `<Location /server-status> Require local </Location>`.",
        retest="`curl -s -o /dev/null -w '%{http_code}' https://{host}/server-status` shows 403 or 404. Then scan again."),
    "ds_store": dict(
        area="Exposed files", sev=L, title="A .DS_Store file lists the folder's files",
        why="This Mac file reveals file names in the folder, including ones that are not linked anywhere.",
        fix="Delete .DS_Store files from the server and add them to the deploy ignore list.",
        retest="`curl -s -o /dev/null -w '%{http_code}' https://{host}/.DS_Store` shows 404. Then scan again."),
    "dir_listing": dict(
        area="Exposed files", sev=M, title="A folder lists all its files",
        why="Anyone can browse files that were never meant to be linked, like uploads, exports or old copies.",
        fix="Nginx: `autoindex off;`  Apache: `Options -Indexes`.",
        retest="Open the folder address: it shows 403 or a normal page, not 'Index of'. Then scan again."),
    "wp_users": dict(
        area="Exposed files", sev=L, title="WordPress lists its user names publicly",
        why="Login names are half of what's needed to guess a way in.",
        fix="Limit the REST users endpoint to logged-in users (most security plugins have a switch), and use "
            "two-step login for admins.",
        retest="`https://{host}/wp-json/wp/v2/users` shows an error, not a list. Then scan again."),
}

# ------------------------------------------------- known attacks (2026)
C.update({
    "php2shell": dict(
        area="Page", sev=H, title="PHP version hit by PHP2Shell (being exploited since October 2026)",
        why="PHP2Shell (CVE-2026-109618 / 109619) lets an attacker run their own code on the server without logging in. "
            "It works on ordinary WordPress, Drupal and Joomla sites, CISA lists it as actively exploited, and attacks "
            "started before the fix was out.",
        fix="Ask the host to move the site to PHP 8.3.37, 8.4.28 or 8.5.13 (19 Nov 2026 releases, which also fix the "
            "November holes; 8.2.36 works too but 8.2 ends on 31 Dec 2026). Most hosting panels have a 'PHP version' switch. If the host says their build has the fix backported, ask them to confirm it in writing. "
            "Until then: `session.upload_progress.enabled=0` and `display_errors=Off`.",
        retest="Hosting panel → PHP version shows a fixed release (or the host confirms the backport). Then scan again."),
    "nginx2shell": dict(
        area="Page", sev=H, title="nginx version open to the November 2026 HTTP/2 holes (\"nginx2shell\")",
        why="CVE-2026-123007 and CVE-2026-123633 let an attacker run their own code on the web server over HTTP/2, without "
            "logging in and without any flaw in the website itself. Researchers have shown working attacks.",
        fix="Upgrade nginx to 1.30.7 (stable) or 1.31.9 (mainline) or newer, restart it, and check `nginx -v`. On a hosting "
            "plan, ask the host to confirm the fix (Linux distributions often patch without changing the number). "
            "If you can't upgrade today: `http2 off;` in the server blocks and remove `http2` from `listen`, then reload.",
        retest="`nginx -v` on the server shows 1.30.7+ or 1.31.9+ (or the host confirms the fix). Then scan again."),
    "php_nov2026": dict(
        area="Page", sev=M, title="PHP is missing the November 2026 security release",
        why="On 19 Nov 2026 PHP fixed 18 holes, six of them critical, that can let an attacker run code on the server. "
            "Most need an uncommon setup (FastCGI connection reuse, no production php.ini, shared session stores), and none "
            "is known to be exploited yet, but PHP holes this year were attacked within days.",
        fix="Ask the host to move the site to PHP 8.3.37, 8.4.28 or 8.5.13 (8.2.36 works too, but 8.2 ends on 31 Dec 2026) "
            "and restart PHP-FPM. Until then: keep FastCGI connection reuse off (nginx `fastcgi_keep_conn off`, "
            "Apache `enablereuse=off`) and set `session.upload_progress.enabled=0` in php.ini or the FPM pool.",
        retest="Hosting panel → PHP version shows a 19 Nov 2026 release (or the host confirms the backport). Then scan again."),
    "php_eol": dict(
        area="Page", sev=M, title="PHP version no longer supported",
        why="This PHP branch gets no security fixes any more, so every new hole (like PHP2Shell) stays open.",
        fix="Move to PHP 8.3 or newer with the host (test the site on a copy first; old plugins may need updating).",
        retest="Hosting panel → PHP version shows 8.3 or newer. Then scan again."),
})

# --------------------------------------------------------- worth a closer look
# Not problems: borderline settings, things a passive check can't decide, and checks that could not run.
# Each says what to test by hand.
R = "Review"
C.update({
    "hsts_no_subdomains": dict(
        area="Headers", sev=R, title="HSTS does not cover subdomains",
        why="Fine if no subdomain (shop., mail., portal.) serves anything over plain http. If one does, it is not protected.",
        fix="Once every subdomain works over HTTPS, add `includeSubDomains` to the header.",
        retest="List your subdomains (DNS provider) and open each with https://. If all work, add includeSubDomains and scan again."),
    "spf_softfail": dict(
        area="Email", sev=R, title="SPF ends in ~all (soft fail)",
        why="Common and fine while setting up. Fake mail is marked suspicious rather than refused; DMARC does the enforcing.",
        fix="When you're sure every service that sends as @{domain} is listed (newsletter tool, invoicing, CRM), change ~all to -all.",
        retest="Send a test email from each tool you use and check its headers show `spf=pass`, then switch to -all."),
    "dmarc_partial": dict(
        area="Email", sev=R, title="DMARC is enforcing only partly",
        why="Quarantine (to spam) or a pct below 100 still lets some fake mail through to inboxes.",
        fix="After a few weeks of clean reports, move to `p=reject` with no pct (100%).",
        retest="`dig +short TXT _dmarc.{domain}` shows `p=reject`. Then scan again."),
    "cert_renew_soon": dict(
        area="HTTPS", sev=R, title="Certificate renewal is due",
        why="Automatic renewal usually happens with about 30 days left; this one is close to that point.",
        fix="Nothing yet. If it's still the same certificate in a week, renewal is broken.",
        retest="Scan again in a week: the expiry date should have moved 60–90 days ahead."),
    "no_sri": dict(
        area="Page", sev=R, title="Scripts from other sites load without an integrity check",
        why="If that other site (a CDN, a widget) is hacked, its script runs on your page. An integrity hash makes the "
            "browser refuse a changed file. Not possible for scripts that change often, like analytics.",
        fix="For fixed library files from a CDN, add `integrity=\"sha384-...\" crossorigin=\"anonymous\"` (cdnjs and "
            "jsDelivr show the hash), or host the file yourself.",
        retest="View the page source: fixed CDN scripts have an integrity attribute. Mozilla's 'Subresource integrity' test passes."),
    "login_form": dict(
        area="Page", sev=R, title="There is a login form: test it by hand",
        why="A passive check can't tell whether passwords can be guessed endlessly, whether two-step login exists, or how "
            "password reset works. These are the most common ways in.",
        fix="Turn on two-step login for admins, limit login attempts, and make reset links expire.",
        retest="On a test account: 10 wrong passwords in a row should slow you down or lock briefly; reset links should stop "
               "working after use; admins should be asked for a second step."),
    "wp_check_plugins": dict(
        area="Page", sev=R, title="WordPress: plugins and theme can't be checked from outside",
        why="Most WordPress break-ins come through outdated plugins, which a passive check can't see reliably.",
        fix="Dashboard → Updates: update everything, delete plugins you don't use, turn on automatic plugin updates.",
        retest="Dashboard → Updates shows nothing waiting. Check again monthly."),
    "manual_php": dict(
        area="Page", sev=R, title="Runs on PHP: check it is patched for PHP2Shell",
        why="The site runs on PHP but hides the version, so a scan can't tell whether it has the October 2026 PHP2Shell "
            "fix or the 19 Nov 2026 security release. Hidden is not the same as safe: attacks are automated and don't care.",
        fix="Ask the host (or look in the hosting panel) which PHP version the site runs.",
        retest="It should be 8.3.37, 8.4.28, 8.5.13 or newer (8.2.36 until 31 Dec 2026), or the host confirms the fixes "
               "are backported. Older than 8.3.36, 8.4.27 or 8.5.12 means still open to PHP2Shell."),
    "manual_nginx": dict(
        area="Page", sev=R, title="Runs nginx with HTTP/2: check it has the November 2026 fix",
        why="The server is nginx and speaks HTTP/2, but hides its version, so a scan can't tell whether it has the fix for "
            "the two critical HTTP/2 holes published on 18 November 2026.",
        fix="Ask the host, or run `nginx -v` on the server.",
        retest="It should be 1.30.7 (stable), 1.31.9 (mainline) or newer, or the host confirms the fix is backported."),
    "manual_old_tls": dict(
        area="HTTPS", sev=R, title="Old TLS 1.0 / 1.1: check by hand",
        why="This checker's TLS library could not offer the old versions, so it can't say whether the server accepts them.",
        fix="If they are accepted, set the minimum to TLS 1.2 (see the host's TLS settings).",
        retest="Run the SSL Labs test (ssllabs.com/ssltest) for {host}: 'Protocols' should show TLS 1.0 and 1.1 as No."),
    "manual_email": dict(
        area="Email", sev=R, title="Email records: check by hand",
        why="The DNS lookup failed, so SPF and DMARC were not checked. That is not the same as them being fine.",
        fix="Look up the records yourself.",
        retest="`dig +short TXT {domain}` should show one `v=spf1` line; `dig +short TXT _dmarc.{domain}` a `v=DMARC1` line."),
    "manual_page": dict(
        area="Page", sev=R, title="The home page did not load: headers and page checks were skipped",
        why="Nothing about headers, cookies or scripts can be said without the page.",
        fix="Check the site loads normally, then scan again.",
        retest="Open https://{host} in a browser, then scan again."),
    "redirect_offhost": dict(
        area="HTTPS", sev=R, title="http:// jumps straight to another name",
        why="The first HTTPS stop is on a different name (often www.), so this name never gets its own HSTS rule and its "
            "first visit stays open to hijacking on public Wi-Fi. Mozilla counts this as a failed redirect.",
        fix="Redirect http://{host} to https://{host} first (with HSTS), then to the other name.",
        retest="`curl -sI http://{host}` shows `Location: https://{host}/` (same name). Then scan again."),
    "layers_disagree": dict(
        area="Headers", sev=R, title="The two scanners disagree",
        why="When two independent scanners give different answers, one of them is wrong. A person should look.",
        fix="Read both scanners' evidence for this test.",
        retest="Open Mozilla's full report and compare it with the evidence here."),
})

# Checks that pass are reported too, so a person can see what was looked at.
PASS_TEXT = {
    "https": "HTTPS works with a trusted certificate",
    "redirect": "http:// sends visitors to HTTPS",
    "tls": "Only TLS 1.2 or newer",
    "hsts": "HSTS is set",
    "csp": "Content-Security-Policy is set",
    "nosniff": "X-Content-Type-Options: nosniff",
    "frames": "Protected against clickjacking",
    "referrer": "Referrer-Policy is set",
    "version": "No software versions in headers",
    "cors": "CORS does not trust other sites",
    "cookies": "Cookies are set safely (or there are none)",
    "mixed": "Everything on the page loads over HTTPS",
    "forms": "Forms send over HTTPS (or there are none)",
    "libs": "No outdated libraries found",
    "spf": "SPF record is in place",
    "dmarc": "DMARC is enforcing",
    "files": "No exposed files found",
}
