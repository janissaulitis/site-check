# Site Check — spec

A website security check for small companies, built to be relied on: it says what is wrong, why it matters
in plain words, how to fix it on the common hosts, and exactly how to retest. A second, independent scanner
(Mozilla HTTP Observatory) checks the same site, and any disagreement is shown.

## What it checks

| Area | Checks | Who can run it |
|---|---|---|
| HTTPS | site answers over HTTPS, certificate trusted / not expired / right name, expiry soon, HTTP redirects to HTTPS, old TLS 1.0/1.1 accepted | anyone |
| Headers | HSTS, Content-Security-Policy (missing / weak), X-Content-Type-Options, clickjacking (X-Frame-Options or frame-ancestors), Referrer-Policy, version numbers in Server / X-Powered-By, CORS that trusts any site with logins | anyone |
| Cookies | Secure, HttpOnly on login/session cookies, SameSite | anyone |
| Page | insecure (http://) scripts, styles, frames, images on an HTTPS page; forms that send to http:// (worse with a password field); outdated jQuery / Bootstrap / AngularJS; WordPress version (latest / outdated / insecure, from wordpress.org) | anyone |
| Email | SPF (missing, +all, ?all, two records), DMARC (missing, p=none) on the company domain | anyone |
| Exposed files | `.git`, `.env`, database / site backups, `wp-config` copies, `phpinfo`, Apache `server-status`, `.DS_Store`, open directory listings, WordPress user list | **only a verified owner** |

Everything in the "anyone" rows is what a normal visitor's browser or a normal DNS lookup already sees.
The exposed-files probes ask for specific paths, so they run only after the owner proves control of the site
(a code in `/.well-known/site-check.txt` or a DNS TXT record).

## Rules

- **A finding needs evidence.** Every problem shows the header, line, record or file signature that proves it.
  A file counts as exposed only when its content matches the file type (`ref: refs/` for `.git/HEAD`,
  `KEY=value` lines for `.env`, `PK` for a zip, SQL statements for a dump), never just because the server said 200.
- **Unknown is a result.** If a check cannot run (timeout, blocked, no DNS), it says "could not check", never "OK".
- **Severity is about the business**, written in plain words: High = can be used against you now; Medium = an
  open door that needs another mistake to hurt; Low = hardening; Info = good to know.
- **Every problem has a fix and a retest**: the fix for Netlify / Cloudflare / Nginx / Apache / WordPress where
  it differs, and the exact thing to check after (scan again, or a one-line `curl` / `dig` command).
- **Rescan shows the difference**: fixed / still open / new.
- **No attacks.** No logins, no form submissions, no guessing passwords, no load. Private and internal
  network addresses are refused.
- **Two layers.** Layer 1 is this code. Layer 2 is Mozilla HTTP Observatory, a separate scanner by a different
  team. They are compared test by test where both cover the same thing; disagreements are listed for a person.

## How it is tested

A local test lab of small websites, each with known problems planted (or none). The right answer for each site
is written in `lab/expected.py` **before** the scanner is run against it. The score lists what was caught,
what was missed and every false alarm. Mozilla Observatory is run on the same lab sites for the layer-2
comparison. Real public sites are scanned (passive checks only) in GitHub Actions to compare with Observatory.

## PASS / FAIL

1. PASS if every planted High problem in the lab is found (0 High misses).
2. PASS if ≥ 95% of all planted problems are found, with every miss listed in the app.
3. PASS if the clean lab sites get 0 false alarms at Medium or High.
4. PASS if no exposed-file finding is raised on a site that answers 200 with a normal page for every path (soft 404).
5. PASS if the exposed-files probes never run without verification (tested).
6. PASS if private, loopback and cloud-metadata addresses are refused (tested), including after a redirect.
7. PASS if layer 1 and Mozilla Observatory agree on ≥ 90% of shared tests across the lab, and every disagreement
   is explained.
8. PASS if every problem has evidence, a plain-words reason, a fix and a retest.
9. PASS if the app loads with no errors in light and dark mode, on a phone (390 px) and a desktop, with no
   sideways scrolling, and the answer (what to fix first) is on the first screen.
