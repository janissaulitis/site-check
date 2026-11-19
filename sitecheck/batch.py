"""Batch mode: passive checks on a list of domains, for market research.

python -m sitecheck.batch domains.csv out_dir
  domains.csv: category,domain   (one per line, # comments allowed)
Writes out_dir/sites.csv (one row per site: PRIVATE, never publish) and out_dir/summary.json (totals only, no names).
Passive only: what a browser and DNS see. No owner-only probes."""
import csv
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from .net import Net, Refused, Unreachable
from .scan import Target, scan

# what the totals report, in plain words: key -> (label, test on the set of problem ids / review ids)
MEASURES = {
    "no_dmarc": ("No DMARC: fake invoices can be sent in their name and nobody is told", lambda p, r: "dmarc_missing" in p),
    "dmarc_not_enforcing": ("DMARC set but not stopping fake mail (p=none)", lambda p, r: "dmarc_none" in p),
    "spoofable": ("Fake email in their name would reach inboxes (no DMARC, or DMARC p=none)",
                  lambda p, r: bool(p & {"dmarc_missing", "dmarc_none"})),
    "no_spf": ("No SPF record", lambda p, r: "spf_missing" in p),
    "spf_broken": ("SPF that doesn't stop fake senders (+all / ?all / two records)", lambda p, r: bool(p & {"spf_weak", "spf_multiple"})),
    "https_problem": ("HTTPS missing or certificate broken", lambda p, r: bool(p & {"https_missing", "cert_expired", "cert_name", "cert_untrusted"})),
    "no_redirect": ("http:// does not send visitors to HTTPS", lambda p, r: "http_no_redirect" in p),
    "old_tls": ("Still accepts old TLS 1.0/1.1", lambda p, r: "old_tls" in p),
    "no_hsts": ("No HSTS", lambda p, r: bool(p & {"hsts_missing", "hsts_short"})),
    "no_csp": ("No Content-Security-Policy", lambda p, r: "csp_missing" in p),
    "clickjacking": ("Can be framed by other sites (clickjacking)", lambda p, r: "clickjacking" in p),
    "version_leak": ("Server shows its software versions", lambda p, r: "version_leak" in p),
    "cookie_issues": ("Login/session cookies set unsafely", lambda p, r: bool(p & {"cookie_secure", "cookie_httponly"})),
    "old_library": ("Outdated JavaScript library with known holes", lambda p, r: "old_library" in p),
    "wordpress": ("Runs WordPress", lambda p, r: "wp_check_plugins" in r),
    "wp_behind": ("WordPress not up to date", lambda p, r: bool(p & {"wp_outdated", "wp_insecure"})),
    "wp_insecure": ("WordPress version with known holes", lambda p, r: "wp_insecure" in p),
    "php2shell": ("PHP version shown is open to PHP2Shell (exploited since Oct 2026)", lambda p, r: "php2shell" in p),
    "php_eol": ("PHP version no longer supported", lambda p, r: "php_eol" in p),
    "php_hidden": ("Runs PHP with the version hidden: PHP2Shell patch status unknown", lambda p, r: "manual_php" in r),
    "mixed": ("HTTPS page loads things over plain http://", lambda p, r: bool(p & {"mixed_active", "mixed_passive"})),
    "any_high": ("At least one serious (High) problem", None),
    "any_medium_plus": ("At least one High or Medium problem", None),
}


def wp_status_fn(net):
    cache = {}

    def f(v):
        if "all" not in cache:
            try:
                cache["all"] = json.loads(net.get("https://api.wordpress.org/core/stable-check/1.0/", max_bytes=200_000).body)
            except Exception:
                cache["all"] = {}
        return cache["all"].get(v)
    return f


def scan_domain(domain, net, wp):
    """Scan the domain; if it has no working HTTPS, try www. (many small sites only have a certificate there)."""
    rep = scan(Target(domain, email_domain=domain), net, verified=False, wp_status=wp)
    ids = {r["id"] for r in rep["results"] if r["status"] == "problem"}
    if ids & {"https_missing", "cert_name"} and not domain.startswith("www."):
        try:
            alt = scan(Target("www." + domain, email_domain=domain), net, verified=False, wp_status=wp)
            if not ({r["id"] for r in alt["results"] if r["status"] == "problem"} & {"https_missing", "cert_name"}):
                return alt
        except (Refused, Unreachable):
            pass
    return rep


def run(domains_file, out_dir, delay=1.0, net=None, wp=None):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for line in Path(domains_file).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "," in line:
            cat, dom = [x.strip() for x in line.split(",", 1)]
            rows.append((cat, dom.lower()))
    net = net or Net(timeout=10)
    wp = wp or wp_status_fn(net)
    sites, errors = [], []
    for i, (cat, dom) in enumerate(rows, 1):
        try:
            rep = scan_domain(dom, net, wp)
        except Exception as e:
            errors.append(dict(category=cat, domain=dom, error=f"{type(e).__name__}: {e}"[:200]))
            print(f"[{i}/{len(rows)}] {dom}: could not check ({type(e).__name__})")
            continue
        probs = {r["id"] for r in rep["results"] if r["status"] == "problem"}
        looks = {r["id"] for r in rep["results"] if r["status"] == "review"}
        sev = Counter(r["sev"] for r in rep["results"] if r["status"] == "problem")
        unknown = {r["id"] for r in rep["results"] if r["status"] == "unknown"}
        row = dict(category=cat, domain=dom, host=rep["host"], high=sev["High"], medium=sev["Medium"], low=sev["Low"],
                   problems=" ".join(sorted(probs)), closer_look=" ".join(sorted(looks)), not_checked=" ".join(sorted(unknown)))
        for k, (_, test) in MEASURES.items():
            if test:
                row[k] = int(test(probs, looks))
        row["any_high"] = int(sev["High"] > 0)
        row["any_medium_plus"] = int(sev["High"] + sev["Medium"] > 0)
        row["email_checked"] = int(not ({"spf", "dmarc"} & unknown))
        sites.append(row)
        print(f"[{i}/{len(rows)}] {dom}: High {sev['High']}, Medium {sev['Medium']}, Low {sev['Low']}")
        time.sleep(delay)

    with open(out / "sites.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sites[0].keys()) if sites else ["domain"])
        w.writeheader()
        w.writerows(sites)
    (out / "errors.json").write_text(json.dumps(errors, indent=1))

    def totals(group):
        n = len(group)
        email_n = sum(r["email_checked"] for r in group)
        t = {}
        for k, (label, _) in MEASURES.items():
            base = [r for r in group if r["email_checked"]] if k in ("no_dmarc", "dmarc_not_enforcing", "spoofable", "no_spf", "spf_broken") else group
            hit = sum(r[k] for r in base)
            t[k] = dict(label=label, count=hit, of=len(base), share=round(hit / len(base), 3) if base else None)
        return dict(sites=n, email_checked=email_n, measures=t)

    by_cat = defaultdict(list)
    for r in sites:
        by_cat[r["category"]].append(r)
    summary = dict(run_at=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), listed=len(rows), checked=len(sites),
                   could_not_check=len(errors), method="Passive checks only (what a browser and DNS see). No names.",
                   all=totals(sites), by_category={c: totals(g) for c, g in sorted(by_cat.items())})
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False))
    a = summary["all"]["measures"]
    print(f"\nChecked {len(sites)} of {len(rows)} sites.")
    for k in ("spoofable", "no_dmarc", "https_problem", "no_hsts", "no_csp", "wp_behind", "old_library", "any_high", "any_medium_plus"):
        m = a[k]
        print(f"  {m['count']:>3} / {m['of']:<3} {m['label']}")
    return summary


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2])
