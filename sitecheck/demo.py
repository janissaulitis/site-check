"""The client-dashboard demo: twelve weeks of an INVENTED company's monitoring history.

The starting point is a real scan of the lab site baltic-bakery.lab.test (sample_report.json). The story of what got
fixed when is written here by hand and labelled as invented everywhere it is shown."""
import datetime as dt
import json
from pathlib import Path

COMPANY = "Baltic Bakery SIA"
DOMAIN = "balticbakery.lv"
PLAN = "Drošības gads"
TODAY = dt.date(2026, 11, 20)
FIRST = dt.date(2026, 8, 31)  # first weekly check (a Monday)

# problem id -> (date fixed, who fixed it, what they did). Anything not listed is still open.
FIXED = {
    "env_exposed": ("2026-09-02", "Web developer", "Blocked the .env file and changed the database password and keys"),
    "dmarc_missing": ("2026-09-14", "Email admin", "Added a DMARC record, then moved it to quarantine"),
    "cookie_secure": ("2026-09-28", "Web developer", "Session cookie now Secure, HttpOnly and SameSite"),
    "cookie_httponly": ("2026-09-28", "Web developer", "Session cookie now Secure, HttpOnly and SameSite"),
    "cookie_samesite": ("2026-09-28", "Web developer", "Session cookie now Secure, HttpOnly and SameSite"),
    "wp_outdated": ("2026-10-05", "Web developer", "Updated WordPress, themes and plugins"),
    "hsts_missing": ("2026-10-19", "Host", "Turned on HSTS and frame protection in the hosting panel"),
    "clickjacking": ("2026-10-19", "Host", "Turned on HSTS and frame protection in the hosting panel"),
    "old_library": ("2026-11-09", "Web developer", "Replaced jQuery UI 1.12.1 with 1.14"),
}

# early warnings: a new attack in the news, what it meant for this company, and how it ended
WARNINGS = [
    dict(date="2026-10-21", name="PHP2Shell (CVE-2026-109618/109619)", affected="Maybe",
         what="The site runs PHP with the version hidden, so we asked the host to confirm the fix.",
         outcome="Host confirmed PHP 8.3.36 (fixed) on 23 Oct.", closed="2026-10-23"),
    dict(date="2026-11-03", name="WordPress core race condition (CVE-2026-119977)", affected="No",
         what="The site was already on the latest WordPress after the 5 Oct update.", outcome="Nothing to do.",
         closed="2026-11-03"),
    dict(date="2026-11-18", name="nginx HTTP/2 holes, \"nginx2shell\" (CVE-2026-123007/123633)", affected="No",
         what="The site runs on Apache, not nginx.", outcome="Nothing to do.", closed="2026-11-18"),
]

SEV = ("High", "Medium", "Low")


def current_report(sample_path):
    """Today's report: the lab scan with the problems the story says were fixed taken out."""
    d = json.loads(Path(sample_path).read_text())
    rep = d["report"]
    keep = [r for r in rep["results"] if not (r["status"] == "problem" and r["id"] in FIXED)
            and r["id"] not in ("manual_php",)]  # PHP: host confirmed the fix (see WARNINGS)
    for r in keep:
        for k in ("title", "evidence", "fix", "retest", "why"):
            if r.get(k):
                r[k] = r[k].replace("baltic-bakery.lab.test", DOMAIN)
    rep = dict(rep, results=keep, host=DOMAIN, domain=DOMAIN, scanned_at="2026-11-16 06:12 UTC")
    first = dict(d["report"], host=DOMAIN, domain=DOMAIN)
    return first, rep


def history(first_report):
    """One row per weekly check: date and open problems by severity (as of that check)."""
    probs = [r for r in first_report["results"] if r["status"] == "problem" and r["sev"] in SEV]
    rows, d = [], FIRST
    while d <= TODAY:
        open_ = [r for r in probs if r["id"] not in FIXED or dt.date.fromisoformat(FIXED[r["id"]][0]) > d]
        rows.append(dict(date=d, **{s: sum(r["sev"] == s for r in open_) for s in SEV}))
        d += dt.timedelta(days=7)
    return rows


def fixed_log(first_report):
    """What was fixed, newest first, one row per fix (fixes done together are merged)."""
    titles = {r["id"]: r["title"] for r in first_report["results"] if r["status"] == "problem"}
    seen, out = set(), []
    for pid, (date, who, what) in sorted(FIXED.items(), key=lambda kv: kv[1][0], reverse=True):
        key = (date, what)
        if key in seen:
            continue
        seen.add(key)
        same = [titles.get(p, p) for p, v in FIXED.items() if (v[0], v[2]) == key]
        out.append(dict(date=date, who=who, what=what, problems=len(same), example=same[0]))
    return out
