"""Early warning: which newly exploited holes (CISA KEV) hit technology our watched sites run, and does Site Check
already have a rule for them?

python -m sitecheck.watch sites.csv out_dir [--days 7] [--kev kev.json]
Writes out_dir/alert.md (and alert.json). Exit code 3 when there is something new to act on."""
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# technology key -> what to look for in KEV vendorProject + product (lower case)
TECH = {
    "php": r"\bphp\b(?!.*(group\s?office|mailer))",
    "wordpress": r"wordpress|woocommerce|elementor|wpforms|gravity|kirki|contact form 7|yoast|wp ",
    "apache": r"apache.*http|http server",
    "nginx": r"nginx",
    "litespeed": r"litespeed",
    "iis": r"\biis\b|internet information services",
    "plesk": r"plesk",
    "cpanel": r"cpanel|whm",
    "drupal": r"drupal",
    "joomla": r"joomla",
}
# holes Site Check already detects (CVE -> rule id)
COVERED = {"CVE-2026-109618": "php2shell", "CVE-2026-109619": "php2shell",
           "CVE-2026-123007": "nginx2shell", "CVE-2026-123633": "nginx2shell"}


def load_kev(path=None):
    if path:
        return json.loads(Path(path).read_text())
    import requests
    return requests.get(KEV_URL, timeout=30).json()


def web_entries(kev, since):
    out = []
    for v in kev.get("vulnerabilities", []):
        try:
            added = dt.date.fromisoformat(v["dateAdded"])
        except Exception:
            continue
        if added < since:
            continue
        text = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')}".lower()
        techs = [k for k, rx in TECH.items() if re.search(rx, text)]
        if techs:
            out.append(dict(cve=v["cveID"], added=v["dateAdded"], vendor=v.get("vendorProject"), product=v.get("product"),
                            name=v.get("vulnerabilityName"), action=v.get("requiredAction"), ransomware=v.get("knownRansomwareCampaignUse"),
                            techs=techs, covered=COVERED.get(v["cveID"]) or (
                                "wp_insecure (only where the WordPress version is visible; hidden versions get a closer-look item)"
                                if re.search(r"wordpress\s*core|^wordpress$", f"{v.get('product', '')}".lower()) else None)))
    return out


def run(sites_csv, out_dir, days=7, kev_path=None, today=None):
    today = today or dt.date.today()
    since = today - dt.timedelta(days=days)
    sites = list(csv.DictReader(open(sites_csv)))
    entries = web_entries(load_kev(kev_path), since)
    lines = [f"# Early warning · {today.isoformat()}", "",
             f"Newly exploited holes (CISA KEV, added since {since.isoformat()}) in technology small-business sites run.", ""]
    act = []
    for e in entries:
        hit = [s for s in sites if set((s.get("tech") or "").split()) & set(e["techs"])]
        e["watched_sites_with_tech"] = len(hit)
        e["domains"] = [s["domain"] for s in hit]
        status = f"covered by rule `{e['covered']}`" if e["covered"] else "**NO RULE YET: add a check, test it in the lab, rescan**"
        if not e["covered"] and hit:
            act.append(e)
        lines += [f"## {e['cve']} · {e['vendor']} {e['product']}", "",
                  f"- {e['name']} (added {e['added']}{', used by ransomware' if e['ransomware'] == 'Known' else ''})",
                  f"- Technology: {', '.join(e['techs'])} · watched sites running it: {len(hit)} of {len(sites)}",
                  f"- Site Check: {status}", f"- CISA says: {(e['action'] or '').split('. ')[0].rstrip('.')}.", ""]
    if not entries:
        lines.append("Nothing new this period that matches web technology our sites run.")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "alert.md").write_text("\n".join(lines) + "\n")
    (out / "alert.json").write_text(json.dumps(dict(date=today.isoformat(), entries=entries, act=[e["cve"] for e in act]), indent=1))
    print("\n".join(lines))
    return act


if __name__ == "__main__":
    a = sys.argv[1:]
    days = int(a[a.index("--days") + 1]) if "--days" in a else 7
    kev = a[a.index("--kev") + 1] if "--kev" in a else None
    sys.exit(3 if run(a[0], a[1], days, kev) else 0)
