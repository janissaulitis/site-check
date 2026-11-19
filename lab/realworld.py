"""Real-world validation (runs in GitHub Actions, which has internet access).

1. badssl.com: public test sites with known broken HTTPS, made by others for testing clients.
2. Public websites: layer 1 vs Mozilla's own scanner, test by test. Passive checks only; results are kept as
   totals, no site is named in the app.
Writes lab/realworld.json."""
import json
import sys
import time
from pathlib import Path

from sitecheck import observatory as OBS
from sitecheck.net import Net
from sitecheck.scan import Target, scan

OUT = Path(__file__).parent / "realworld.json"

BADSSL = [  # host, https port, problems that must be found, note
    ("expired.badssl.com", 443, ["cert_expired"], ""),
    ("wrong.host.badssl.com", 443, ["cert_name"], ""),
    ("self-signed.badssl.com", 443, ["cert_untrusted"], ""),
    ("untrusted-root.badssl.com", 443, ["cert_untrusted"], ""),
    ("incomplete-chain.badssl.com", 443, ["cert_untrusted"], "browsers sometimes repair this; servers and phones often don't"),
    ("tls-v1-0.badssl.com", 1010, ["old_tls"], ""),
    ("tls-v1-1.badssl.com", 1011, ["old_tls"], ""),
    ("mixed-script.badssl.com", 443, ["mixed_active"], ""),
    ("hsts.badssl.com", 443, [], "HSTS set: must not be reported missing"),
    ("revoked.badssl.com", 443, [], "revocation is not checked (known limit)"),
]

PUBLIC = ["janis-saulitis-portfolio.netlify.app", "alert-desk.streamlit.app", "github.com", "www.mozilla.org",
          "developer.mozilla.org", "www.wikipedia.org", "www.gov.uk", "www.lsm.lv", "www.latvija.gov.lv", "www.delfi.lv",
          "www.swedbank.lv", "www.airbaltic.com", "bolt.eu", "www.printful.com", "www.tet.lv", "www.lmt.lv", "www.citadele.lv",
          "www.rimi.lv", "220.lv", "www.ss.com", "www.netlify.com", "www.cloudflare.com", "wordpress.org", "www.bbc.co.uk"]


def badssl():
    rows = []
    for host, port, must, note in BADSSL:
        try:
            rep = scan(Target(host, https_port=port, http_port=80), Net(), verified=False)
            got = sorted({r["id"] for r in rep["results"] if r["status"] == "problem"})
            unk = sorted({r["id"] for r in rep["results"] if r["status"] == "unknown"})
            ok = all(m in got for m in must) and not (host.startswith("hsts.") and "hsts_missing" in got)
            rows.append(dict(host=host, must=must, got=got, unknown=unk, ok=ok, note=note))
        except Exception as e:
            rows.append(dict(host=host, must=must, got=[], ok=False, error=f"{type(e).__name__}: {e}", note=note))
        print(("OK  " if rows[-1]["ok"] else "!!  ") + host, rows[-1].get("got"), rows[-1].get("error", ""))
    return rows


def public():
    rows = []
    for host in PUBLIC:
        try:
            rep = scan(Target(host), Net(), verified=False)
        except Exception as e:
            print("!! scan", host, e)
            continue
        obs, err = OBS.run_cli(host)
        if not obs:
            print("!! mozilla", host, err)
            continue
        cmp = OBS.compare(rep, obs)
        both = [c for c in cmp if c["agree"] is not None]
        rows.append(dict(host=host, grade=obs["scan"]["grade"], compared=len(both), agree=sum(c["agree"] for c in both),
                         differ=[dict(test=c["name"], ours=c["ours"], mozilla=c["mozilla"], result=c["mozilla_result"])
                                 for c in both if not c["agree"]],
                         problems=len([r for r in rep["results"] if r["status"] == "problem" and r["sev"] in ("High", "Medium")])))
        print(f"{host:<40} {rows[-1]['agree']}/{rows[-1]['compared']}  {rows[-1]['differ']}")
        time.sleep(1)
    return rows


if __name__ == "__main__":
    b = badssl()
    p = public()
    comp, agr = sum(r["compared"] for r in p), sum(r["agree"] for r in p)
    out = dict(run_at=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), badssl=b, public=p,
               badssl_ok=sum(r["ok"] for r in b), badssl_n=len(b), sites=len(p), compared=comp, agree=agr)
    OUT.write_text(json.dumps(out, indent=1))
    print(f"\nbadssl {out['badssl_ok']}/{out['badssl_n']} · public sites {len(p)} · agreement with Mozilla {agr}/{comp}")
    sys.exit(0)
