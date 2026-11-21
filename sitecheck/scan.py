"""Layer 1: Site Check's own checks. scan() returns every result with its evidence, fix and retest."""
import datetime as dt
import json
import re
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser

from . import catalog as K
from .net import DNSUnknown, Net, Refused, Unreachable

SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3, "Review": 4}
SESSION_RE = re.compile(r"sess|sid$|^sid|auth|token|login|logged|remember|jwt|user|^_?id$|phpsessid|jsessionid|aspnet",
                        re.I)
NOT_SESSION_RE = re.compile(r"csrf|xsrf|^_ga|^_gid|^_gcl|^_fbp|^_hj|consent|cookie_?notice|lang|locale|theme", re.I)
TWO_PART = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "co.jp",
            "com.lv", "org.lv", "id.lv", "net.lv", "edu.lv", "gov.lv", "asn.lv", "conf.lv", "mil.lv",
            "com.ee", "org.ee", "pri.ee", "med.ee", "co.za", "com.tr", "com.pl", "co.in", "com.cn"}


@dataclass
class Target:
    host: str
    https_port: int = 443
    http_port: int = 80
    email_domain: str | None = None  # defaults to the company domain of host

    def url(self, scheme, path="/"):
        port = self.https_port if scheme == "https" else self.http_port
        default = 443 if scheme == "https" else 80
        return f"{scheme}://{self.host}{'' if port == default else f':{port}'}{path}"


def org_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ------------------------------------------------------------------ results
def problem(cid, evidence, sev=None, ctx=None):
    c = K.C[cid]
    fill = lambda s: s.replace("{host}", ctx["host"]).replace("{domain}", ctx["domain"]) if ctx else s
    return dict(id=cid, status="problem", sev=sev or c["sev"], area=c["area"], title=fill(c["title"]),
                evidence=evidence, why=fill(c["why"]), fix=fill(c["fix"]), retest=fill(c["retest"]))


def review(cid, evidence, ctx):
    r = problem(cid, evidence, None, ctx)
    r["status"] = "review"
    return r


def ok(key, area, evidence=""):
    return dict(id=key, status="ok", sev=None, area=area, title=K.PASS_TEXT[key], evidence=evidence)


def unknown(key, area, reason):
    return dict(id=key, status="unknown", sev=None, area=area, title=f"Could not check: {K.PASS_TEXT[key].lower()}",
                evidence=reason)


# ------------------------------------------------------------------ HTML
class Page(HTMLParser):
    ACTIVE = {"script": "src", "iframe": "src", "frame": "src", "object": "data", "embed": "src"}
    PASSIVE = {"img": "src", "audio": "src", "video": "src", "source": "src", "track": "src"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.active, self.passive, self.forms, self.meta = [], [], [], [], {}
        self.no_integrity = []
        self._form = None
        self.title, self._in_title = "", False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
            if "integrity" not in a:
                self.no_integrity.append(a["src"])
        if tag in self.ACTIVE and a.get(self.ACTIVE[tag]):
            self.active.append((tag, a[self.ACTIVE[tag]]))
        if tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.active.append(("stylesheet", a["href"]))
        if tag in self.PASSIVE and a.get(self.PASSIVE[tag]):
            self.passive.append((tag, a[self.PASSIVE[tag]]))
        if tag == "form":
            self._form = dict(action=a.get("action", ""), password=False)
            self.forms.append(self._form)
        if tag == "input" and a.get("type", "").lower() == "password":
            if self._form is not None:
                self._form["password"] = True
            else:
                self.forms.append(dict(action="", password=True))
        if tag == "meta":
            if a.get("name", "").lower() in ("generator", "referrer"):
                self.meta[a["name"].lower()] = a.get("content", "")
            if a.get("http-equiv", "").lower() in ("content-security-policy", "referrer-policy"):
                self.meta[a["http-equiv"].lower()] = a.get("content", "")
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def parse_page(text):
    p = Page()
    try:
        p.feed(text)
    except Exception:
        pass
    return p


# --------------------------------------------------------------- libraries
LIBS = [
    # name, file-name pattern, is the version too old?, why
    ("jQuery", r"^jquery(?:-(\d+\.\d+\.\d+))?(?:\.slim)?(?:\.min)?\.js$", lambda v: v < (3, 5, 0),
     "jQuery before 3.5.0 lets injected HTML run scripts (CVE-2020-11022, CVE-2020-11023)"),
    ("jQuery UI", r"^jquery-ui(?:-(\d+\.\d+\.\d+))?(?:\.custom)?(?:\.min)?\.js$", lambda v: v < (1, 13, 2),
     "jQuery UI before 1.13.2 has cross-site scripting holes (CVE-2021-41182/41183/41184, CVE-2022-31160)"),
    ("Bootstrap", r"^bootstrap(?:-(\d+\.\d+\.\d+))?(?:\.bundle)?(?:\.min)?\.js$",
     lambda v: v < (3, 4, 1) or (v[0] == 4 and v < (4, 3, 1)),
     "Bootstrap before 3.4.1, and 4 before 4.3.1, has a cross-site scripting hole (CVE-2019-8331)"),
    ("AngularJS", r"^angular(?:-(1\.\d+\.\d+))?(?:\.min)?\.js$", lambda v: v[0] == 1,
     "AngularJS (1.x) reached end of life in January 2022 and gets no security fixes"),
]


def _ver(s):
    p = [int(x) for x in s.split(".")[:3]]
    return tuple(p + [0] * (3 - len(p)))


def lib_version(src, file_match):
    """Version from the file name, the folder (/3.4.1/ or @3.4.1), or WordPress core's ?ver= (trusted only there)."""
    low = src.lower()
    path, _, query = low.partition("?")
    if file_match.group(1):
        return file_match.group(1)
    segs = path.split("/")
    for seg in reversed(segs[:-1]):
        m = re.fullmatch(r"v?(\d+\.\d+\.\d+)", seg) or re.search(r"@(\d+\.\d+\.\d+)$", seg)
        if m:
            return m.group(1)
    if "/wp-includes/js/jquery/" in path:
        m = re.search(r"(?:^|&)ver=(\d+\.\d+(?:\.\d+)?)", query)
        if m:
            return m.group(1)
    return None


def find_libraries(scripts):
    found = []
    for src in scripts:
        low = src.lower().split("?")[0]
        file = low.rsplit("/", 1)[-1]
        # WordPress ships jQuery UI as wp-includes/js/jquery/ui/core.min.js
        if "/wp-includes/js/jquery/ui/core" in low:
            file = "jquery-ui.min.js"
        for name, rx, too_old, why in LIBS:
            m = re.match(rx, file)
            if not m:
                continue
            v = lib_version(src, m)
            if v and too_old(_ver(v)):
                found.append((name, v, src, why))
            break
    return found


# ------------------------------------------------------------------ CSP
def parse_csp(value):
    d = {}
    for part in (value or "").split(";"):
        bits = part.strip().split()
        if bits:
            d.setdefault(bits[0].lower(), [b.lower() for b in bits[1:]])
    return d


def csp_weak(csp):
    """Why a policy would not stop injected scripts, or None if it would."""
    src = csp.get("script-src", csp.get("default-src"))
    if src is None:
        return "no script-src or default-src, so scripts may come from anywhere"
    nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in src)
    strict = "'strict-dynamic'" in src
    if "'unsafe-inline'" in src and not (nonce_or_hash or strict):
        return "script-src allows 'unsafe-inline'"
    if "'unsafe-eval'" in src:
        return "script-src allows 'unsafe-eval'"
    broad = [s for s in src if s in ("*", "http:", "https:", "data:", "http://*", "https://*")]
    if broad and not strict:
        return f"script-src allows {' '.join(broad)}"
    return None


# ------------------------------------------------------------- cookies
def parse_cookie(line):
    parts = [p.strip() for p in line.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return dict(name=name, secure="secure" in attrs, httponly="httponly" in attrs,
                samesite=attrs.get("samesite"), session=bool(SESSION_RE.search(name)) and not NOT_SESSION_RE.search(name))


# --------------------------------------------------------- exposed files
def _is_html(b):
    head = b[:600].lower()
    return b"<html" in head or b"<!doctype html" in head or b"<head" in head or b"<body" in head


PROBES = [
    ("/.git/HEAD", "git_exposed", lambda b: re.match(rb"^(ref: refs/|[0-9a-f]{40}\s*$)", b) is not None),
    ("/.git/config", "git_exposed", lambda b: b"[core]" in b[:2000] and not _is_html(b)),
    ("/.env", "env_exposed", lambda b: not _is_html(b) and len(re.findall(rb"(?m)^[A-Z][A-Z0-9_]{2,}=\S*", b[:20000])) >= 2),
    ("/backup.zip", "backup_exposed", lambda b: b[:4] == b"PK\x03\x04"),
    ("/site.zip", "backup_exposed", lambda b: b[:4] == b"PK\x03\x04"),
    ("/www.zip", "backup_exposed", lambda b: b[:4] == b"PK\x03\x04"),
    ("/backup.tar.gz", "backup_exposed", lambda b: b[:2] == b"\x1f\x8b"),
    ("/backup.sql", "backup_exposed", lambda b: _sql(b)),
    ("/dump.sql", "backup_exposed", lambda b: _sql(b)),
    ("/db.sql", "backup_exposed", lambda b: _sql(b)),
    ("/database.sql", "backup_exposed", lambda b: _sql(b)),
    ("/wp-config.php.bak", "config_backup", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.php~", "config_backup", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.php.save", "config_backup", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.bak", "config_backup", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.old", "config_backup", lambda b: b"DB_PASSWORD" in b),
    ("/phpinfo.php", "phpinfo", lambda b: b"phpinfo()" in b and b"PHP Version" in b),
    ("/info.php", "phpinfo", lambda b: b"phpinfo()" in b and b"PHP Version" in b),
    ("/server-status", "server_status", lambda b: b"Apache Server Status" in b),
    ("/.DS_Store", "ds_store", lambda b: b[4:8] == b"Bud1"),
    ("/uploads/", "dir_listing", lambda b: _listing(b)),
    ("/backup/", "dir_listing", lambda b: _listing(b)),
    ("/files/", "dir_listing", lambda b: _listing(b)),
]
WP_PROBES = [
    ("/wp-content/uploads/", "dir_listing", lambda b: _listing(b)),
    ("/wp-json/wp/v2/users", "wp_users", lambda b: _wp_users(b)),
]


def _sql(b):
    return not _is_html(b) and re.search(rb"(?i)\b(CREATE TABLE|INSERT INTO)\b", b[:200000]) is not None


def _listing(b):
    return re.search(rb"(?i)<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /", b[:5000]) is not None


def _wp_users(b):
    try:
        data = json.loads(b)
        return isinstance(data, list) and len(data) > 0 and all("slug" in u for u in data if isinstance(u, dict))
    except Exception:
        return False


# =================================================================== scan
def scan(target, net: Net, verified=False, wp_status=None):
    """Run every check. Returns dict(host, domain, results, facts, errors)."""
    t = target if isinstance(target, Target) else Target(target)
    host, domain = t.host, t.email_domain or org_domain(t.host)
    ctx = dict(host=host, domain=domain)
    R, facts = [], dict(host=host, domain=domain, verified=verified)
    P = lambda cid, ev, sev=None: R.append(problem(cid, ev, sev, ctx))
    Q = lambda cid, ev: R.append(review(cid, ev, ctx))
    facts["Q"] = Q
    facts["P"] = P

    # ------------------------------------------------------------ HTTPS
    tls = None
    try:
        tls = net.tls(host, t.https_port)
    except Refused:
        raise
    except Unreachable as e:
        raise Unreachable(str(e))
    facts["tls"] = tls
    https_ok = tls["ok"]
    https_up = tls["reachable"] and (tls["ok"] or tls["problem"] is not None)
    if not https_up and tls.get("old_only"):
        P("old_tls", f"The server only completes TLS 1.0/1.1 handshakes on port {t.https_port}; current browsers refuse "
                     "these, so the HTTPS site does not open for most visitors", "High")
    elif not https_up:
        P("https_missing", f"No HTTPS answer on port {t.https_port}: {tls['detail'] or 'no connection'}")
    elif tls["problem"] == "expired":
        P("cert_expired", f"Certificate expired on {tls['not_after']}")
    elif tls["problem"] == "name":
        P("cert_name", f"Certificate error: {tls['detail']}")
    elif tls["problem"] == "untrusted":
        P("cert_untrusted", f"Certificate error: {tls['detail']}")
    else:
        R.append(ok("https", "HTTPS", f"{tls['version']}, certificate valid until {tls['not_after']}"))
        if tls["days_left"] is not None and tls["days_left"] < 21:
            P("cert_expiring", f"Certificate expires on {tls['not_after']} ({tls['days_left']} days left). "
                               "Automatic renewal normally renews at 30 days left.")
        elif tls["days_left"] is not None and tls["days_left"] < 30:
            Q("cert_renew_soon", f"Certificate expires on {tls['not_after']} ({tls['days_left']} days left)")
    if https_up:
        if tls["old_tls"] is True:
            P("old_tls", "The server completed a TLS 1.0/1.1 handshake")
        elif tls["old_tls"] is False:
            R.append(ok("tls", "HTTPS", "TLS 1.0 and 1.1 refused"))
        else:
            Q("manual_old_tls", "This checker's TLS library cannot offer TLS 1.0/1.1 to test it")

    # ------------------------------------------------- http -> https
    try:
        hr = net.get(t.url("http"), follow=5, max_bytes=200_000)
        facts["http_chain"] = hr.chain
        final_https = hr.url.startswith("https://")
        first_https = next((u for u, _ in hr.chain if u.startswith("https://")), None)
        if final_https:
            R.append(ok("redirect", "HTTPS", " → ".join(f"{u} ({s})" for u, s in hr.chain)))
            if first_https and first_https.split("/")[2].split(":")[0] != host:
                Q("redirect_offhost", " → ".join(f"{u} ({s})" for u, s in hr.chain))
        elif https_up and preloaded(net, host):
            R.append(ok("redirect", "HTTPS", f"{host} is on the browsers' HSTS preload list, so browsers never use http://"))
        elif https_up:
            P("http_no_redirect", f"{t.url('http')} answered {hr.status} and stayed on http://")
        facts["http_page"] = hr
        facts["http_cookies"] = [c for c in hr.hop_cookies if hr.url.startswith("https://")]
    except (Unreachable, ssl.SSLError):
        facts["http_chain"] = None
        if https_up:
            R.append(ok("redirect", "HTTPS", "Plain http:// is not served at all"))

    # ------------------------------------------------------- main page
    page = None
    scheme = "https" if https_up else "http"
    try:
        page = net.get(t.url(scheme), follow=5, verify=https_ok or scheme == "http")
    except ssl.SSLError:
        page = None
    except Unreachable as e:
        facts["page_error"] = str(e)
    if page is None and scheme == "https" and not https_ok:
        try:
            page = net.get(t.url("https"), follow=5, verify=False)
        except (Unreachable, ssl.SSLError) as e:
            facts["page_error"] = str(e)
    if page is None and https_up is False and facts.get("http_page") is not None:
        page = facts["http_page"]
    facts["page"] = page
    on_https = bool(page and page.url.startswith("https://"))

    if page is None:
        for k, a in [("hsts", "Headers"), ("csp", "Headers"), ("nosniff", "Headers"), ("frames", "Headers"),
                     ("referrer", "Headers"), ("version", "Headers"), ("cors", "Headers"), ("cookies", "Cookies"),
                     ("mixed", "Page"), ("forms", "Page"), ("libs", "Page")]:
            R.append(unknown(k, a, facts.get("page_error", "The page did not load")))
        Q("manual_page", facts.get("page_error", "The page did not load"))
    else:
        doc = parse_page(page.text) if "html" in (page.h("content-type") or "text/html").lower() else parse_page("")
        facts["doc"] = doc
        _headers(page, doc, on_https, R, P, net)
        _cors(net, t, page, R, P, facts)
        _cookies(page, facts, on_https, R, P)
        _content(page, doc, on_https, R, P, wp_status, facts)
        _nginx(page, (tls or {}).get("alpn") == "h2" and on_https, P, Q, facts)

    # ------------------------------------------------------------ email
    _email(net, domain, R, P, facts)
    if any(r["status"] == "unknown" and r["area"] == "Email" for r in R):
        Q("manual_email", f"DNS lookups for {domain} failed")

    # ---------------------------------------------------- exposed files
    if verified and page is not None:
        _probe(net, t, scheme, page, facts, R, P)
    facts["probed"] = bool(verified and page is not None)

    R.sort(key=lambda r: ({"problem": 0, "review": 1, "unknown": 2, "ok": 3}[r["status"]], SEV_ORDER.get(r["sev"], 9),
                          K.AREAS.index(r["area"])))
    facts.pop("Q", None)
    facts.pop("P", None)
    pg = facts.pop("page", None)
    facts.pop("http_page", None)
    facts.pop("doc", None)
    facts["page"] = dict(url=pg.url, status=pg.status, chain=pg.chain,
                         headers={k: v for k, v in pg.headers.items() if k != "set-cookie"}) if pg else None
    facts["libs"] = [list(x) for x in facts.get("libs", [])]
    return dict(host=host, domain=domain, results=R, facts=facts,
                scanned_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


_PRELOAD = {}


def preloaded(net, host):
    """Is the name on Chrome's HSTS preload list (used by all major browsers)? Asked from hstspreload.org; False if unknown."""
    if net is None or net.allow_private:
        return False
    if host not in _PRELOAD:
        try:
            r = net.get(f"https://hstspreload.org/api/v2/status?domain={host}", follow=1, max_bytes=20_000)
            _PRELOAD[host] = json.loads(r.body).get("status") == "preloaded"
        except Exception:
            return False
    return _PRELOAD[host]


def _headers(page, doc, on_https, R, P, net):
    # HSTS
    if on_https:
        hsts = page.h("strict-transport-security")
        if not hsts and preloaded(net, page.url.split("/")[2].split(":")[0]):
            R.append(ok("hsts", "Headers", "On the browsers' HSTS preload list (no header needed for browsers that ship it)"))
        elif not hsts:
            P("hsts_missing", "No Strict-Transport-Security header on the HTTPS page")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                P("hsts_short", f"Strict-Transport-Security: {hsts} (max-age {age} s = {age // 86400} days; "
                                "six months is 15552000)")
            else:
                R.append(ok("hsts", "Headers", f"Strict-Transport-Security: {hsts}"))
                if "includesubdomains" not in hsts.lower():
                    R.append(review("hsts_no_subdomains", f"Strict-Transport-Security: {hsts}", dict(host=page.url.split('/')[2], domain="")))
    # CSP
    csp_v = page.h("content-security-policy") or doc.meta.get("content-security-policy")
    csp = parse_csp(csp_v)
    if not csp_v:
        ro = page.h("content-security-policy-report-only")
        P("csp_missing", "No Content-Security-Policy header" + (" (only a report-only policy, which blocks nothing)" if ro else ""))
    else:
        weak = csp_weak(csp)
        if weak:
            P("csp_weak", f"Content-Security-Policy: {csp_v[:300]} → {weak}")
        else:
            R.append(ok("csp", "Headers", f"Content-Security-Policy: {csp_v[:200]}"))
    # nosniff
    xcto = page.h("x-content-type-options")
    if (xcto or "").strip().lower() == "nosniff":
        R.append(ok("nosniff", "Headers", "X-Content-Type-Options: nosniff"))
    else:
        P("nosniff_missing", f"X-Content-Type-Options: {xcto}" if xcto else "No X-Content-Type-Options header")
    # framing
    xfo = (page.h("x-frame-options") or "").strip().lower()
    fa = csp.get("frame-ancestors")
    if fa is not None and "*" not in fa:
        R.append(ok("frames", "Headers", f"frame-ancestors {' '.join(fa) or '(none)'}"))
    elif xfo in ("deny", "sameorigin"):
        R.append(ok("frames", "Headers", f"X-Frame-Options: {xfo.upper()}"))
    else:
        P("clickjacking", "No X-Frame-Options (DENY / SAMEORIGIN) and no frame-ancestors in a Content-Security-Policy"
          + (f"; X-Frame-Options is '{xfo}', which browsers ignore" if xfo else ""))
    # referrer
    rp = page.h("referrer-policy") or doc.meta.get("referrer-policy") or doc.meta.get("referrer")
    last = (rp or "").split(",")[-1].strip().lower()
    if not rp:
        P("referrer_missing", "No Referrer-Policy header")
    elif last in ("unsafe-url", "no-referrer-when-downgrade"):
        P("referrer_missing", f"Referrer-Policy: {rp} sends full addresses to other sites")
    else:
        R.append(ok("referrer", "Headers", f"Referrer-Policy: {rp}"))
    # version numbers
    leaks = [f"{n}: {v}" for n in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
             for v in page.all(n) if re.search(r"\d+\.\d+", v)]
    if leaks:
        P("version_leak", "; ".join(leaks))
    else:
        R.append(ok("version", "Headers"))


PROBE_ORIGIN = "https://site-check-probe.example"


def _cors(net, t, page, R, P, facts):
    """Ask twice, the way a browser would: a normal request and a preflight (OPTIONS), both from a foreign Origin."""
    seen, answered = [], 0
    for method, extra in (("GET", {}), ("OPTIONS", {"Access-Control-Request-Method": "GET"})):
        try:
            r = net.get(page.url, headers={"Origin": PROBE_ORIGIN, **extra}, follow=0, max_bytes=20_000,
                        verify=page.verified, method=method)
        except (Unreachable, ssl.SSLError, Refused):
            continue
        answered += 1
        acao, acac = r.h("access-control-allow-origin"), (r.h("access-control-allow-credentials") or "").lower()
        if acao and acao.strip() == PROBE_ORIGIN and acac == "true":
            seen.append(f"{method} with Origin: {PROBE_ORIGIN} → Access-Control-Allow-Origin: {acao}, "
                        "Access-Control-Allow-Credentials: true")
        facts.setdefault("cors", {})[method] = dict(acao=acao, acac=acac)
    if seen:
        P("cors_reflect", "; ".join(seen))
    elif answered:
        R.append(ok("cors", "Headers", ""))
    else:
        R.append(unknown("cors", "Headers", "The requests with an Origin header did not answer"))


def _cookies(page, facts, on_https, R, P):
    lines = list(dict.fromkeys(page.hop_cookies + facts.get("http_cookies", []))) or page.all("set-cookie")
    hp = facts.get("http_page")
    cookies = [parse_cookie(c) for c in lines]
    facts["cookies"] = cookies
    if not cookies:
        R.append(ok("cookies", "Cookies", "No cookies set on the home page"))
        return
    bad = False
    if on_https:
        ns = [c for c in cookies if not c["secure"]]
        if ns:
            bad = True
            sev = "Medium" if any(c["session"] for c in ns) else "Low"
            P("cookie_secure", "Without Secure: " + ", ".join(c["name"] for c in ns), sev)
    nh = [c for c in cookies if c["session"] and not c["httponly"]]
    if nh:
        bad = True
        P("cookie_httponly", "Login/session cookies without HttpOnly: " + ", ".join(c["name"] for c in nh))
    nss = [c for c in cookies if not c["samesite"]]
    if nss:
        bad = True
        P("cookie_samesite", "Without SameSite: " + ", ".join(c["name"] for c in nss))
    if not bad:
        R.append(ok("cookies", "Cookies", ", ".join(c["name"] for c in cookies)))


def _content(page, doc, on_https, R, P, wp_status, facts):
    # mixed content
    if on_https:
        act = [f"<{tag}> {u}" for tag, u in doc.active if u.lower().startswith("http://")]
        pas = [f"<{tag}> {u}" for tag, u in doc.passive if u.lower().startswith("http://")]
        if act:
            P("mixed_active", "; ".join(act[:6]) + (f" (+{len(act) - 6} more)" if len(act) > 6 else ""))
        if pas:
            P("mixed_passive", "; ".join(pas[:6]) + (f" (+{len(pas) - 6} more)" if len(pas) > 6 else ""))
        if not act and not pas:
            R.append(ok("mixed", "Page"))
    # forms
    bad_pw = [f for f in doc.forms if f["password"] and (f["action"].lower().startswith("http://") or
                                                         (not on_https and not f["action"].lower().startswith("https://")))]
    bad = [f for f in doc.forms if not f["password"] and f["action"].lower().startswith("http://")]
    if bad_pw:
        P("form_http_password", "Password form sends to " + ", ".join(f["action"] or page.url for f in bad_pw))
    if bad:
        P("form_http", "Form sends to " + ", ".join(f["action"] for f in bad))
    if not bad and not bad_pw:
        R.append(ok("forms", "Page", f"{len(doc.forms)} form(s)" if doc.forms else ""))
    if any(f["password"] for f in doc.forms) and not bad_pw:
        facts["Q"]("login_form", "The home page has a password field")
    own = page.url.split("/")[2].split(":")[0]
    ext = [u for u in doc.no_integrity if u.lower().startswith(("http://", "https://", "//"))
           and u.split("/")[2].split(":")[0].lower() != own]
    if ext:
        facts["Q"]("no_sri", "; ".join(ext[:4]) + (f" (+{len(ext) - 4} more)" if len(ext) > 4 else ""))
    # libraries
    libs = find_libraries(doc.scripts)
    facts["libs"] = libs
    for name, v, src, why in libs:
        sev = "Medium"
        P("old_library", f"{name} {v} ({src}). {why}.", sev)
    if not libs:
        R.append(ok("libs", "Page", f"{len(doc.scripts)} script(s) looked at"))
    # WordPress
    gen = doc.meta.get("generator", "")
    m = re.search(r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", gen)
    body = page.text
    is_wp = bool(m) or "/wp-content/" in body or "/wp-includes/" in body
    ver = m.group(1) if m else None
    if not ver:
        m2 = re.search(r"/wp-includes/(?:css|js)/[^\"'?]+\?ver=(\d+\.\d+(?:\.\d+)?)", body)
        ver = m2.group(1) if m2 and not re.search(r"jquery", m2.group(0)) else None
    _php(page, body, is_wp, facts)
    facts["wordpress"] = dict(is_wp=is_wp, version=ver)
    if is_wp:
        facts["Q"]("wp_check_plugins", f"WordPress {ver or '(version hidden)'} found from the page's files")
    if ver:
        status = None
        if wp_status:
            try:
                status = wp_status(ver)
            except Exception:
                status = None
        facts["wordpress"]["status"] = status
        if status == "insecure":
            P("wp_insecure", f"WordPress {ver}; wordpress.org lists it as insecure")
        elif status == "outdated":
            P("wp_outdated", f"WordPress {ver}; wordpress.org lists it as outdated (still supported)")
        if m:
            P("wp_version_shown", f'<meta name="generator" content="{gen}">')


def _nginx(page, h2, P, Q, facts):
    """nginx2shell (CVE-2026-123007 / 123633): needs HTTP/2. Fixed in 1.30.7 stable and 1.31.9 mainline."""
    srv = " ".join(page.all("server")).lower()
    if "nginx" not in srv:
        return
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", srv)
    if m:
        v = tuple(int(x) for x in m.groups())
        facts["nginx"] = ".".join(map(str, v))
        fixed = v >= (1, 32, 0) or (v[:2] == (1, 31) and v >= (1, 31, 9)) or (v[:2] == (1, 30) and v >= (1, 30, 7))
        if v >= (1, 9, 5) and not fixed and h2:
            P("nginx2shell", f"Server: nginx/{facts['nginx']}, HTTP/2 offered in the HTTPS handshake. Fixed in 1.30.7 / 1.31.9. "
                             "(A Linux distribution may have backported the fix without changing the number: ask the host.)")
    elif h2:
        Q("manual_nginx", "Server: nginx (version hidden), HTTP/2 offered in the HTTPS handshake")


PHP_FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}  # PHP2Shell fixes, 21 Oct 2026
PHP_NOV = {(8, 2): (8, 2, 36), (8, 3): (8, 3, 37), (8, 4): (8, 4, 28), (8, 5): (8, 5, 13)}  # 19 Nov 2026 security releases


def _php(page, body, is_wp, facts):
    """PHP2Shell: flag a visible vulnerable PHP version; if PHP is clearly in use but the version is hidden, ask to check."""
    xpb = " ".join(page.all("x-powered-by"))
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", xpb)
    if m:
        v = tuple(int(x) for x in m.groups())
        fixed = PHP_FIXED.get(v[:2])
        facts["php"] = ".".join(map(str, v))
        if fixed is None and v[:2] > (8, 5):
            return
        if fixed is None:  # 8.1 and older: end of life
            facts["P"]("php2shell", f"X-Powered-By: PHP/{facts['php']}. Branch {v[0]}.{v[1]} is end of life and gets no "
                                    "upstream fix (some Linux distributions backport one: ask the host).")
            facts["P"]("php_eol", f"PHP {facts['php']}")
        elif v < fixed:
            facts["P"]("php2shell", f"X-Powered-By: PHP/{facts['php']}; fixed in {'.'.join(map(str, fixed))}. "
                                    "(A host may have backported the fix without changing the number: ask them.)")
        elif v < PHP_NOV[v[:2]]:
            eol = " Branch 8.2 also reaches end of life on 31 Dec 2026." if v[:2] == (8, 2) else ""
            facts["P"]("php_nov2026", f"X-Powered-By: PHP/{facts['php']}; the 19 Nov 2026 release is "
                                      f"{'.'.join(map(str, PHP_NOV[v[:2]]))}.{eol} (A host may have backported the fixes: ask them.)")
        return
    cookies = " ".join(page.all("set-cookie") + page.hop_cookies)
    php_signs = is_wp or "PHPSESSID" in cookies or re.search(r"\.php[\"'?]", body) or "/wp-content/" in body \
        or "Joomla" in body or "Drupal" in (page.h("x-generator") or "") + body[:5000]
    if php_signs:
        facts["Q"]("manual_php", "PHP in use (" + ("WordPress" if is_wp else "PHP pages or session cookie") + "), version hidden")


def _email(net, domain, R, P, facts):
    try:
        recs = net.txt(domain)
        spf = [r for r in recs if re.match(r"(?i)^v=spf1(\s|$)", r.strip())]
        facts["spf"] = spf
        if not spf:
            P("spf_missing", f"No TXT record starting v=spf1 on {domain}")
        elif len(spf) > 1:
            P("spf_multiple", " | ".join(spf))
        else:
            rec = spf[0]
            m = re.search(r"(?i)(?:^|\s)([+?~-]?)all(?:\s|$)", rec)
            q = m.group(1) if m else None
            if m and q in ("", "+"):
                P("spf_weak", f"{rec} → '{q or '+'}all' lets every server on the internet send as @{domain}", "High")
            elif m and q == "?":
                P("spf_weak", f"{rec} → '?all' makes no decision about other servers", "Low")
            elif not m and "redirect=" not in rec.lower():
                P("spf_weak", f"{rec} → no 'all' at the end, so other servers are not ruled out", "Low")
            else:
                R.append(ok("spf", "Email", rec))
                if m and q == "~":
                    facts["Q"]("spf_softfail", rec)
    except DNSUnknown as e:
        R.append(unknown("spf", "Email", f"DNS lookup for {domain} failed"))
    try:
        recs = net.txt(f"_dmarc.{domain}")
        dm = [r for r in recs if re.match(r"(?i)^v=DMARC1", r.strip())]
        facts["dmarc"] = dm
        if not dm:
            P("dmarc_missing", f"No TXT record starting v=DMARC1 on _dmarc.{domain}")
        else:
            m = re.search(r"(?i)(?:^|;)\s*p\s*=\s*(\w+)", dm[0])
            p = (m.group(1).lower() if m else "none")
            pct = re.search(r"(?i)(?:^|;)\s*pct\s*=\s*(\d+)", dm[0])
            if p == "none":
                P("dmarc_none", dm[0])
            else:
                R.append(ok("dmarc", "Email", dm[0]))
                if p == "quarantine" or (pct and int(pct.group(1)) < 100):
                    facts["Q"]("dmarc_partial", dm[0])
    except DNSUnknown:
        R.append(unknown("dmarc", "Email", f"DNS lookup for _dmarc.{domain} failed"))


def _probe(net, t, scheme, page, facts, R, P):
    base = page.url.split("://", 1)[0] + "://" + page.url.split("://", 1)[1].split("/", 1)[0]
    probes = list(PROBES) + (WP_PROBES if facts.get("wordpress", {}).get("is_wp") else [])
    found, errors = {}, 0

    def one(pr):
        path, cid, sig = pr
        try:
            r = net.get(base + path, follow=0, max_bytes=262_144, verify=page.verified)
        except (Unreachable, ssl.SSLError, Refused):
            return pr, None
        return pr, (r.status == 200 and sig(r.body))

    with ThreadPoolExecutor(6) as ex:
        for (path, cid, _), hit in ex.map(one, probes):
            if hit is None:
                errors += 1
            elif hit:
                found.setdefault(cid, []).append(base + path)
    if _listing(page.body):
        found.setdefault("dir_listing", []).append(page.url)
    facts["probe_hits"] = found
    for cid, urls in found.items():
        P(cid, "Readable at " + ", ".join(urls) + " (content matches the file type)")
    if not found:
        if errors == len(probes):
            R.append(unknown("files", "Exposed files", "None of the file checks got an answer"))
        else:
            R.append(ok("files", "Exposed files", f"{len(probes)} common leak locations checked"))
