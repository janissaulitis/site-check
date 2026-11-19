"""Layer 2: Mozilla HTTP Observatory, a separate scanner by a different team, compared test by test with layer 1."""
import json
import os
import shutil
import subprocess

import requests

API = "https://observatory-api.mdn.mozilla.net/api/v2/analyze?host={host}"
DETAILS = "https://developer.mozilla.org/en-US/observatory/analyze?host={host}"

NAMES = {
    "strict-transport-security": "HSTS",
    "redirection": "Redirect to HTTPS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "Clickjacking protection",
    "referrer-policy": "Referrer-Policy",
    "cookies": "Cookies",
    "cross-origin-resource-sharing": "CORS",
    "subresource-integrity": "Subresource integrity",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}
ONLY_MOZILLA = {"subresource-integrity", "cross-origin-resource-policy"}


def fetch(host, timeout=60):
    """Ask the public Observatory (results are cached by Mozilla for a few minutes). Returns (data, error)."""
    try:
        r = requests.post(API.format(host=host), timeout=timeout,
                          headers={"User-Agent": "SiteCheck/1.0 (+https://janis-saulitis-portfolio.netlify.app)"})
        data = r.json()
    except Exception as e:
        return None, f"Mozilla Observatory did not answer ({type(e).__name__})"
    if r.status_code != 200 or "tests" not in data:
        return None, data.get("message") or data.get("error") or f"Mozilla Observatory answered {r.status_code}"
    return data, None


def run_cli(host, ca_file=None, timeout=90):
    """Run Mozilla's own scanner locally (npm @mdn/mdn-http-observatory). Used by the test lab and CI."""
    exe = os.environ.get("OBSERVATORY_CLI") or shutil.which("mdn-http-observatory-scan")
    if not exe:
        return None, "Observatory CLI not installed"
    env = dict(os.environ)
    if ca_file:
        env["NODE_EXTRA_CA_CERTS"] = ca_file
        for k in ("NO_PROXY", "no_proxy"):  # lab hosts are local: never send them through a proxy
            env[k] = ",".join(x for x in (env.get(k), host) if x)
    try:
        cmd = ["node", exe, host] if exe.endswith(".js") else [exe, host]  # src/scan.js keeps NODE_EXTRA_CA_CERTS
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        data = json.loads(p.stdout[p.stdout.index("{"):])
    except Exception as e:
        return None, f"Observatory CLI failed: {e}"
    if data.get("error"):
        return None, str(data["error"])
    return data, None


def layer1_view(report):
    """What layer 1 found, expressed as pass/fail on each Observatory test both scanners cover."""
    res = report["results"]
    probs = {r["id"] for r in res if r["status"] == "problem"}
    oks = {r["id"] for r in res if r["status"] == "ok"}
    looks = {r["id"] for r in res if r["status"] == "review"}
    cert_bad = bool(probs & {"cert_expired", "cert_name", "cert_untrusted", "https_missing"})
    ref = [r for r in res if r["id"] == "referrer_missing"]
    referrer_set_but_unsafe = bool(ref) and not ref[0]["evidence"].startswith("No Referrer-Policy")
    view = {
        "strict-transport-security": "hsts" in oks and not cert_bad,
        "redirection": not cert_bad and "http_no_redirect" not in probs and "redirect_offhost" not in looks,
        "content-security-policy": "csp" in oks,
        "x-content-type-options": "nosniff" in oks,
        "x-frame-options": "frames" in oks,
        "referrer-policy": not referrer_set_but_unsafe,
        "cookies": not (probs & {"cookie_secure", "cookie_httponly"}),
        "cross-origin-resource-sharing": "cors_reflect" not in probs,
    }
    unknown = {r["id"] for r in res if r["status"] == "unknown"}
    if "cookies" in unknown:
        view.pop("cookies")
    if "cors" in unknown:
        view.pop("cross-origin-resource-sharing")
    return view


def compare(report, obs):
    """Rows: test, name, ours (True/False/None), mozilla (True/False), mozilla_result, agree (None if only Mozilla)."""
    ours = layer1_view(report)
    rows = []
    for test, name in NAMES.items():
        t = (obs.get("tests") or {}).get(test)
        if not t:
            continue
        o = ours.get(test)
        note = None
        if test == "referrer-policy" and any(r["id"] == "referrer_missing" and r["status"] == "problem"
                                             and r["evidence"].startswith("No Referrer-Policy") for r in report["results"]):
            note = "Not set"  # both treat a missing policy as safe enough; Site Check still suggests one (Low)
        # The public API can mark results with no penalty ("not implemented", "no cookies") as not passed; Mozilla's
        # own grade doesn't count them against the site, so neither do we.
        mod = t.get("scoreModifier", t.get("score_modifier"))
        moz_ok = bool(t.get("pass")) or (mod is not None and mod >= 0)
        rows.append(dict(test=test, name=name, ours=o, ours_note=note, mozilla=moz_ok, mozilla_result=t.get("result", ""),
                         agree=None if (test in ONLY_MOZILLA or o is None) else (o == moz_ok)))
    return rows


def grade(obs):
    s = obs.get("scan") or {}
    return s.get("grade"), s.get("score"), s.get("testsFailed", s.get("tests_failed"))
