"""Scores Site Check on the test lab: planted problems caught / missed, false alarms, Mozilla agreement.
Run as root: python -m lab.bench   (writes lab/results.json, used by the app's 'How well it works' tab)"""
import json
import sys
import time
from collections import Counter
from pathlib import Path

from sitecheck import observatory as OBS
from sitecheck.net import Net, Refused
from sitecheck.scan import PROBES, WP_PROBES, Target, scan

from . import certs
from .server import start
from .sites import SITES, WP_STATUS

OUT = Path(__file__).parent / "results.json"
SAMPLE = Path(__file__).parent.parent / "sample_report.json"


def txt_for(site):
    def lookup(name):
        if site["txt_error"]:
            return "error"
        if name == site["host"]:
            return site["spf"] + ["google-site-verification=abc"]
        if name == f"_dmarc.{site['host']}":
            return site["dmarc"]
        return []
    return lookup


def run(with_mozilla=True):
    stop, logs = start()
    time.sleep(0.5)
    ca = certs.ca_file()
    rows, all_obs = [], []
    probe_paths = {p for p, _, _ in PROBES + WP_PROBES}
    try:
        for s in SITES:
            net = Net(ca_file=ca, allow_private=True, timeout=5, txt=txt_for(s))
            logs[s["slug"]].clear()
            rep = scan(Target(s["host"], email_domain=s["host"]), net, verified=s["verified"], wp_status=WP_STATUS.get)
            got = Counter((r["id"], r["sev"]) for r in rep["results"] if r["status"] == "problem")
            exp = Counter(tuple(e) for e in s["expect"])
            caught, missed, extra = exp & got, exp - got, got - exp
            probed = sorted({p for _, p in logs[s["slug"]] if p in probe_paths})
            unknowns = [r["id"] for r in rep["results"] if r["status"] == "unknown"]
            incomplete = [r["id"] for r in rep["results"] if r["status"] == "problem" and not all(r.get(k) for k in ("evidence", "why", "fix", "retest"))]
            reviews = sorted({r["id"] for r in rep["results"] if r["status"] == "review"})
            row = dict(slug=s["slug"], about=s["about"], verified=s["verified"], review=reviews,
                       review_expected=s["review"], review_missed=[x for x in s["review"] if x not in reviews],
                       expected=sorted(exp.elements()), caught=sorted(caught.elements()), missed=sorted(missed.elements()),
                       false_alarms=sorted(extra.elements()), probed_paths=probed, unknown=unknowns, incomplete=incomplete)
            if with_mozilla:
                obs, err = OBS.run_cli(s["host"], ca)
                if obs:
                    cmp = OBS.compare(rep, obs)
                    row["mozilla"] = dict(grade=obs["scan"]["grade"], rows=cmp)
                else:
                    row["mozilla"] = dict(error=err)
            rows.append(row)
            if s["slug"] == "baltic-bakery":
                SAMPLE.write_text(json.dumps(dict(report=rep, mozilla=row.get("mozilla")), indent=1, default=str))
            flag = "OK " if not row["missed"] and not row["false_alarms"] else "!! "
            print(f"{flag}{s['slug']:<16} caught {len(row['caught'])}/{len(row['expected'])}"
                  f"  missed {row['missed'] or '-'}  false {row['false_alarms'] or '-'}"
                  + (f"  probed {probed}" if probed and not s["verified"] else ""))
        ssrf = ssrf_tests(ca)
    finally:
        stop()
    return summarise(rows, ssrf)


def ssrf_tests(ca):
    """The scanner must refuse private addresses, also when a public-looking site redirects to one."""
    out = {}
    net = Net(ca_file=ca, allow_private=False)
    for name, url in [("loopback", "http://127.0.0.1/"), ("private", "http://10.0.0.1/"),
                      ("metadata", "http://169.254.169.254/latest/meta-data/"), ("lab name", "https://clean-static.lab.test/")]:
        try:
            net.get(url, follow=0)
            out[name] = "NOT refused"
        except Refused:
            out[name] = "refused"
        except Exception as e:
            out[name] = f"error: {type(e).__name__}"
    # a site that looks public redirects to the cloud metadata address: the hop must be refused
    try:
        Net(ca_file=ca, trusted_hosts={"cors-public.lab.test"}).get("https://cors-public.lab.test/go", follow=3)
        out["redirect to metadata"] = "NOT refused"
    except Refused:
        out["redirect to metadata"] = "refused"
    except Exception as e:
        out["redirect to metadata"] = f"error: {type(e).__name__}"
    return out


def summarise(rows, ssrf):
    exp = sum(len(r["expected"]) for r in rows)
    caught = sum(len(r["caught"]) for r in rows)
    high_exp = sum(1 for r in rows for e in r["expected"] if e[1] == "High")
    high_missed = [(r["slug"], m) for r in rows for m in r["missed"] if m[1] == "High"]
    clean = [r for r in rows if not r["expected"]]
    fa_med_high = [(r["slug"], f) for r in rows for f in r["false_alarms"] if f[1] in ("High", "Medium")]
    fa_all = [(r["slug"], f) for r in rows for f in r["false_alarms"]]
    cmp_rows = [(r["slug"], c) for r in rows for c in r.get("mozilla", {}).get("rows", []) if c["agree"] is not None]
    agree = sum(1 for _, c in cmp_rows if c["agree"])
    unverified_probed = [r["slug"] for r in rows if not r["verified"] and r["probed_paths"]]
    dns = next(r for r in rows if r["slug"] == "dns-fail")
    checks = {
        "1 no High misses": not high_missed,
        "2 >=95% planted found": exp and caught / exp >= 0.95,
        "3 clean sites: 0 Medium/High false alarms": not [f for f in fa_med_high if f[0] in {c["slug"] for c in clean}],
        "4 soft-404 sites: no exposed-file finding": not any(r["false_alarms"] for r in rows if r["slug"] in ("soft-404", "blog-sql")),
        "5 no probes without verification": not unverified_probed,
        "6 private addresses refused": all(v == "refused" for v in ssrf.values()),
        "7 >=90% agreement with Mozilla": bool(cmp_rows) and agree / len(cmp_rows) >= 0.90,
        "8 every problem has evidence, why, fix, retest": not any(r["incomplete"] for r in rows),
        "unknown is reported, not OK (dns-fail)": set(dns["unknown"]) >= {"spf", "dmarc"},
        "borderline cases flagged for a closer look": not any(r["review_missed"] for r in rows),
    }
    summary = dict(
        sites=len(rows), clean_sites=len(clean), planted=exp, caught=caught, high_planted=high_exp,
        high_missed=high_missed, false_alarms=fa_all, mozilla_compared=len(cmp_rows), mozilla_agree=agree,
        disagreements=[dict(site=s, **c) for s, c in cmp_rows if not c["agree"]], ssrf=ssrf,
        review_expected=sum(len(r["review_expected"]) for r in rows),
        review_found=sum(len(r["review_expected"]) - len(r["review_missed"]) for r in rows),
        review_total=sum(len(r["review"]) for r in rows),
        checks={k: bool(v) for k, v in checks.items()}, rows=rows,
        run_at=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
    OUT.write_text(json.dumps(summary, indent=1))
    print(f"\nPlanted {exp}, caught {caught} ({caught / exp:.0%}); High {high_exp - len(high_missed)}/{high_exp}; "
          f"false alarms {len(fa_all)}; Mozilla agreement {agree}/{len(cmp_rows)}")
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    for d in summary["disagreements"]:
        print(f"  differ: {d['site']:<16} {d['name']:<26} ours={d['ours']} mozilla={d['mozilla']} ({d['mozilla_result']})")
    return summary


if __name__ == "__main__":
    s = run(with_mozilla="--no-mozilla" not in sys.argv)
    sys.exit(0 if all(s["checks"].values()) else 1)
