"""Site Check: a website security check that says what to fix, how, and how to retest. Run: streamlit run app.py"""
import html
import importlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
import streamlit as st

import kit
from sitecheck import catalog as K
from sitecheck import net as N
from sitecheck import observatory as OBS
from sitecheck import report as REP
from sitecheck import scan as S
from sitecheck import verify as V

for _m in (K, N, S, OBS, REP, V, kit):
    importlib.reload(_m)  # Streamlit Cloud keeps old copies of imported files after an update

HERE = Path(__file__).parent
POOL = ThreadPoolExecutor(4)

kit.page("Site Check", "A website security check that says what to fix, how, and how to retest", mark="lock", icon="🔒",
         theme="inspect", badge="Passive checks · free",
         meta="Second opinion from Mozilla HTTP Observatory")

bar = st.container(horizontal=True, key="k_demo")
with bar.popover("How it works"):
    st.markdown(
        "1. **Type a website.** Site Check looks only at what any visitor's browser and a normal DNS lookup can see: "
        "HTTPS, security headers, cookies, the page's scripts and forms, and the email records that stop fake mail in the company's name.\n"
        "2. **Every problem** comes with the evidence, why it matters in plain words, how to fix it on the common hosts, and how to retest.\n"
        "3. **Second opinion:** Mozilla's own scanner checks the same site and the two are compared test by test.\n"
        "4. **Site owners** can prove the site is theirs to also check for leaked files (.env, .git, backups).\n"
        "5. **Scan again** after fixing: it shows what's fixed, what's still open and anything new.")


@st.cache_data(ttl=86400, show_spinner=False)
def wp_versions():
    try:
        return requests.get("https://api.wordpress.org/core/stable-check/1.0/", timeout=8).json()
    except Exception:
        return {}


def wp_status(v):
    return wp_versions().get(v)


LAB = os.environ.get("SITECHECK_LAB")  # local testing against the test lab only; never set on the live app


def make_net():
    if not LAB:
        return N.Net()
    from lab.bench import txt_for
    from lab.certs import ca_file
    from lab.sites import SITES
    by = {x["host"]: x for x in SITES}
    return N.Net(ca_file=ca_file(), allow_private=True,
                 txt=lambda name: next((txt_for(x)(name) for h, x in by.items() if name.endswith(h)), []))


def mozilla(host):
    if LAB:
        from lab.certs import ca_file
        return OBS.run_cli(host, ca_file())
    return OBS.fetch(host)


def run_scan(host, verified):
    if LAB:
        from lab.sites import WP_STATUS
        return S.scan(S.Target(host, email_domain=host), make_net(), verified=verified, wp_status=WP_STATUS.get)
    return S.scan(S.Target(host), make_net(), verified=verified, wp_status=wp_status)


def esc(x):
    return html.escape(str(x))


# ------------------------------------------------------------------ rendering
def areas_row(rep):
    cells = []
    for a in K.AREAS:
        rs = [r for r in rep["results"] if r["area"] == a]
        ps = [r for r in rs if r["status"] == "problem" and r["sev"] != "Info"]
        if a == "Exposed files" and not rep["facts"].get("probed"):
            cells.append(f'<div class="k-area off"><span><i></i>{a}</span><b>owner only</b></div>')
            continue
        if ps:
            worst = min(ps, key=lambda r: S.SEV_ORDER[r["sev"]])["sev"]
            cells.append(f'<div class="k-area {worst}"><span><i></i>{a}</span><b>{len(ps)} to fix</b></div>')
        elif any(r["status"] == "unknown" for r in rs):
            cells.append(f'<div class="k-area unk"><span><i></i>{a}</span><b>not checked</b></div>')
        else:
            cells.append(f'<div class="k-area"><span><i></i>{a}</span><b>fine</b></div>')
    st.markdown('<div class="k-areas">' + "".join(cells) + "</div>", unsafe_allow_html=True)


def finding(r, i, open_=False):
    return (f'<details class="k-f {r["sev"]}"{" open" if open_ else ""}><summary><span class="rail"></span>'
            f'<span class="k-sev {r["sev"]}">{"Look" if r["sev"] == "Review" else r["sev"]}</span><span class="tt">{esc(r["title"])}</span>'
            f'<span class="ar">{esc(r["area"])}</span></summary><div class="bd">'
            f'<div class="ev">{esc(r["evidence"])}</div>'
            f'<h5>Why it matters</h5><div>{esc(r["why"])}</div>'
            f'<h5>How to fix</h5><div>{REP._md(r["fix"])}</div>'
            f'<h5>Retest</h5><div class="rt">{REP._md(r["retest"])}</div></div></details>')


def show_report(rep, sample=False, before=None, mozilla=None):
    v = REP.verdict(rep)
    p = REP.problems(rep)
    oks = [r for r in rep["results"] if r["status"] == "ok"]
    unk = [r for r in rep["results"] if r["status"] == "unknown"]
    first = p[0]["title"].rstrip(".") if p else ""
    body = (f"Most urgent: <b>{esc(first)}</b>. Each problem below has the evidence, the fix and how to retest."
            if v["urgent"] else "Nothing urgent. The improvements below are worth doing when there's time." if p
            else "Every check that could run passed.")
    kick = (f"Example · {rep['host']} · an invented company in the test lab" if sample
            else f"{rep['host']} · checked {rep['scanned_at']}")
    rv = REP.reviews(rep, (mozilla or {}).get("rows"))
    kit.answer(kick, v["head"], body, [("Serious", str(v["n"]["High"])), ("Fix soon", str(v["n"]["Medium"])),
                                       ("Improve", str(v["n"]["Low"])), ("Closer look", str(len(rv))),
                                       ("Passed", str(len(oks)))], tone=v["tone"], raw=False)
    areas_row(rep)

    if before is not None:
        d = REP.diff(before, rep)
        names = lambda xs: ", ".join(esc(x["title"]) for x in xs[:3]) + ("…" if len(xs) > 3 else "")
        st.markdown(
            f'<div class="k-diff"><div class="fx"><b>{len(d["fixed"])}</b>fixed<small>{names(d["fixed"])}</small></div>'
            f'<div><b>{len(d["still"])}</b>still open<small>{names(d["still"])}</small></div>'
            f'<div class="nw"><b>{len(d["new"])}</b>new<small>{names(d["new"])}</small></div></div>', unsafe_allow_html=True)

    if p:
        st.markdown("#### What to fix, most urgent first")
        st.markdown("".join(finding(r, i, open_=(i == 0)) for i, r in enumerate(p)), unsafe_allow_html=True)

    if rv:
        st.markdown("#### Worth a closer look")
        st.caption("Not problems as such: borderline settings, things a passive check can't decide, and places where the two "
                   "scanners disagree. Each says how to test it by hand.")
        st.markdown("".join(finding(r, i) for i, r in enumerate(rv)), unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1], gap="large")
    with c1:
        st.markdown("#### Checked and fine")
        st.markdown('<ul class="k-okl">' + "".join(f"<li>{esc(r['title'])}</li>" for r in oks)
                    + "".join(f'<li class="u">{esc(r["title"])} <small>({esc(r["evidence"])})</small></li>' for r in unk)
                    + "</ul>", unsafe_allow_html=True)
    with c2:
        st.markdown("#### Second opinion · Mozilla")
        if mozilla is not None:
            mozilla_block(rep, mozilla)
        elif not sample:
            mozilla_live(rep)
    return v


def mozilla_block(rep, mz):
    if mz.get("error"):
        st.caption(f"Mozilla's scanner could not check this site: {mz['error']}")
        return
    rows = mz["rows"]
    both = [c for c in rows if c["agree"] is not None]
    agree = sum(c["agree"] for c in both)
    grade = mz.get("grade")
    st.markdown(f"Mozilla HTTP Observatory {'gave grade **' + grade + '**. ' if grade else ''}"
                f"On the **{len(both)} tests both scanners run**, they agree on **{agree}**.")
    kit.table([dict(t=c["name"] + (" ⚠ differs" if c["agree"] is False else ""),
                    us=c.get("ours_note") or ("not checked" if c["ours"] is None else ("OK" if c["ours"] else "Problem")),
                    mz="OK" if c["mozilla"] else "Problem") for c in rows],
              [kit.col("Test", "t", "strong"),
               kit.col("Site Check", "us", "chip", {"OK": "good", "Problem": "bad", "Not set": "warn", "not checked": ""}),
               kit.col("Mozilla", "mz", "chip", {"OK": "good", "Problem": "bad"})])
    if agree < len(both):
        st.caption("Where they differ, look at the evidence above and Mozilla's own report: one of the two is wrong, "
                   "and that is exactly what a second layer is for.")
    if mz.get("url"):
        st.link_button("Open Mozilla's full report", mz["url"])


def mozilla_live(rep):
    fut = st.session_state.get("mz_future")
    if fut is None:
        return

    @st.fragment(run_every=2)
    def _poll():
        f = st.session_state.get("mz_future")
        if f is None or not f.done():
            st.caption("Waiting for Mozilla's scanner (it can take up to a minute)…")
            return
        data, err = f.result()
        if err:
            mz = dict(error=err)
        else:
            g, _, _ = OBS.grade(data)
            mz = dict(grade=g, rows=OBS.compare(rep, data), url=OBS.DETAILS.format(host=rep["host"]))
        st.session_state["mz"] = mz
        st.session_state["mz_future"] = None
        st.rerun()  # whole page, so the downloadable report includes Mozilla's results too
    _poll()


# ------------------------------------------------------------------ tabs
tab_check, tab_proof, tab_what = st.tabs(["Check a site", "How well it works", "What it checks"])

with tab_check:
    bx = st.container(key="k_bar")
    with bx.form("go", border=False, enter_to_submit=True):
        a, b = st.columns([5, 1], vertical_alignment="bottom")
        typed = a.text_input("Website", placeholder="yourcompany.lv", label_visibility="collapsed")
        go = b.form_submit_button("Check", type="primary", use_container_width=True)
    st.caption("Passive checks only: nothing is logged in to, submitted or attacked. Check sites you own or "
               "have permission to check.")

    if go and typed:
        try:
            host = N.clean_host(typed)
        except N.Refused as e:
            st.error(str(e))
            host = None
        last = st.session_state.get("last_run", 0)
        if host and time.time() - last < 8:
            st.warning("One check every few seconds, please.")
            host = None
        if host:
            st.session_state["last_run"] = time.time()
            if st.session_state.get("host") != host:
                st.session_state.pop("verified", None)
            mz_fut = POOL.submit(mozilla, host)
            with st.spinner(f"Checking {host}… usually 5–20 seconds"):
                try:
                    rep = run_scan(host, verified=st.session_state.get("verified") == host)
                    st.session_state.update(host=host, rep=rep, before=None, mz_future=mz_fut, mz_shown=False)
                    st.session_state.pop("mz", None)
                except N.Refused as e:
                    st.error(str(e))
                except N.Unreachable as e:
                    st.error(f"Could not reach {host}: {e}.")
                except Exception as e:
                    st.error(f"The check stopped unexpectedly ({type(e).__name__}). Try again in a minute.")

    rep = st.session_state.get("rep")
    if rep is None:
        smp = json.loads((HERE / "sample_report.json").read_text())
        show_report(smp["report"], sample=True, mozilla=smp.get("mozilla"))
        st.caption("This example comes from the test lab, so it can show every kind of finding, including leaked files. "
                   "Type a real website above to check it.")
    else:
        host = rep["host"]
        acts = st.container(horizontal=True)
        if acts.button("Scan again", key="rescan", help="Run every check again and show what changed"):
            if time.time() - st.session_state.get("last_run", 0) < 8:
                st.warning("One check every few seconds, please.")
            else:
                st.session_state["last_run"] = time.time()
                with st.spinner(f"Checking {host} again…"):
                    try:
                        new = run_scan(host, verified=st.session_state.get("verified") == host)
                        st.session_state.update(before=rep, rep=new, mz_future=POOL.submit(mozilla, host), mz_shown=False)
                        st.session_state.pop("mz", None)
                        rep = new
                    except Exception as e:
                        st.error(f"Could not check again: {e}")
        mz = st.session_state.get("mz")
        acts.download_button("⬇ Report for the site owner (HTML)",
                             REP.build_html(rep, mz.get("rows") if mz else None, mz.get("grade") if mz else None),
                             file_name=f"security-check-{host}.html", mime="text/html")
        show_report(rep, before=st.session_state.get("before"), mozilla=mz)

        st.markdown("#### Leaked files (site owners)")
        if rep["facts"].get("probed"):
            st.success(f"Ownership verified ({st.session_state.get('verified_how', '')}). Common leak locations were "
                       "checked: .git, .env, database and site backups, config copies, phpinfo, server-status, open folders.")
        else:
            tok = V.token(host)
            st.markdown(f"Checking for leaked files means asking for specific addresses, so it only runs for the site's owner. "
                        f"Prove {host} is yours with **one** of these, then press Verify:")
            st.markdown(f"**A file** at `https://{host}{V.PATH}` containing:")
            st.markdown(f'<div class="k-tok">{tok}</div>', unsafe_allow_html=True)
            st.markdown(f"**or a DNS TXT record** on `{host}` (or `_site-check.{host}`) with the value above")
            if st.button("Verify and check for leaked files", key="verify"):
                with st.spinner("Looking for the code…"):
                    ok, how = V.check(host, make_net())
                if not ok:
                    st.error("The code was not found yet. DNS changes can take a few minutes to show up.")
                else:
                    st.session_state.update(verified=host, verified_how=how)
                    with st.spinner("Verified. Checking for leaked files…"):
                        new = run_scan(host, verified=True)
                    st.session_state.update(before=rep, rep=new)
                    st.rerun()

# ------------------------------------------------------------------ proof
with tab_proof:
    res = json.loads((HERE / "lab" / "results.json").read_text())
    st.markdown("Site Check was tested on a **lab of small websites with problems planted on purpose**. The right answer "
                "for each site was written down first; then the scanner, and Mozilla's scanner, were run against them.")
    kit.answer(f"Test lab · {res['sites']} websites · {res['run_at']}",
               f"Found {res['caught']} of {res['planted']} planted problems, with {len(res['false_alarms'])} false alarms",
               f"Every serious problem was found ({res['high_planted'] - len(res['high_missed'])} of {res['high_planted']}). "
               f"The {res['clean_sites']} sites set up correctly, including two that answer every address with a normal page, "
               "got no warnings.",
               [("Problems found", f"{res['caught']} / {res['planted']}"),
                ("Serious ones", f"{res['high_planted'] - len(res['high_missed'])} / {res['high_planted']}"),
                ("False alarms", str(len(res["false_alarms"]))),
                ("Agrees with Mozilla", f"{res['mozilla_agree']} / {res['mozilla_compared']}")])
    if res.get("review_expected"):
        st.markdown(f"**Borderline cases:** {res['review_found']} of {res['review_expected']} planted borderline settings "
                    "(HSTS without subdomains, SPF ~all, DMARC at 50%, renewal due soon, a login form, WordPress plugins, "
                    "failed DNS) were flagged under *Worth a closer look*, not as problems.")
    st.markdown("#### Where the two scanners disagreed")
    WHY = {
        "x-frame-options-allow-from-origin": "Mozilla accepts `X-Frame-Options: ALLOW-FROM`. Current Chrome, Edge, Firefox "
                                             "and Safari ignore that value, so the page can still be framed. Site Check is "
                                             "stricter here on purpose.",
        "cross-origin-resource-sharing-implemented-with-restricted-access":
            "The server copies any website's address back and allows logins with it. Mozilla's scanner (v1.7.2) saw the "
            "header but rated it 'restricted access' and passed it; its check compares against the Origin it sent, which it "
            "does not appear to find. Site Check flags it. This is the case for having two layers.",
    }
    kit.table([dict(site=d["site"], test=d["name"], us="OK" if d["ours"] else "Problem", mz="OK" if d["mozilla"] else "Problem",
                    why=WHY.get(d["mozilla_result"], d["mozilla_result"]).replace("`", "")) for d in res["disagreements"]],
              [kit.col("Lab site", "site", "strong"), kit.col("Test", "test"),
               kit.col("Site Check", "us", "chip", {"OK": "good", "Problem": "bad"}),
               kit.col("Mozilla", "mz", "chip", {"OK": "good", "Problem": "bad"}), kit.col("Which is right, and why", "why", "wrap")])
    st.markdown("#### Every lab site")
    show = lambda xs: ", ".join(f"{a} ({b})" for a, b in xs) if xs else "—"
    kit.table([dict(site=r["slug"], about=r["about"], planted=len(r["expected"]), found=len(r["caught"]),
                    missed=show(r["missed"]), extra=show(r["false_alarms"]),
                    mz=(r.get("mozilla") or {}).get("grade", "—")) for r in res["rows"]],
              [kit.col("Site", "site", "strong"), kit.col("What was planted", "about", "wrap"), kit.col("Planted", "planted", "num"),
               kit.col("Found", "found", "num"), kit.col("Missed", "missed", "wrap"), kit.col("False alarms", "extra", "wrap"),
               kit.col("Mozilla grade", "mz")], max_height=560)
    rw_file = HERE / "lab" / "realworld.json"
    if rw_file.exists():
        rw = json.loads(rw_file.read_text())
        st.markdown("#### Real websites")
        st.markdown(f"**badssl.com** (public test sites with known broken HTTPS, built by others for testing): "
                    f"**{rw['badssl_ok']} of {rw['badssl_n']}** gave the expected result. "
                    f"**{rw['sites']} public websites** were checked by both scanners: they agree on "
                    f"**{rw['agree']} of {rw['compared']}** shared tests. Sites are not named; checked {rw['run_at']}.")
        kit.table([dict(h=r["host"], must=", ".join(r["must"]) or "nothing wrong", got=", ".join(r.get("got", [])) or r.get("error", "—"),
                        ok="PASS" if r["ok"] else "FAIL", note=r.get("note", "")) for r in rw["badssl"]],
                  [kit.col("badssl.com test site", "h", "strong"), kit.col("Must find", "must", "wrap"),
                   kit.col("Site Check found", "got", "wrap"), kit.col("", "ok", "chip", {"PASS": "good", "FAIL": "bad"}),
                   kit.col("Note", "note", "wrap")])
        diffs = {}
        for r in rw["public"]:
            for d in r["differ"]:
                diffs[(d["test"], d["result"])] = diffs.get((d["test"], d["result"]), 0) + 1
        if diffs:
            st.caption("Disagreements on public sites: " + "; ".join(f"{t} ({res}) ×{n}" for (t, res), n in sorted(diffs.items())))
    st.markdown("#### Safety checks")
    kit.table([dict(c=k.split(" ", 1)[1] if k[0].isdigit() else k, r="PASS" if v else "FAIL") for k, v in res["checks"].items()]
              + [dict(c=f"Refuses {k}", r="PASS" if v == "refused" else "FAIL") for k, v in res["ssrf"].items()],
              [kit.col("Check", "c", "wrap"), kit.col("Result", "r", "chip", {"PASS": "good", "FAIL": "bad"})])
    st.caption("Honest limits: the lab was built by the same person as the scanner, so a perfect lab score proves the checks "
               "work as designed, not that they cover everything. That is why every scan also gets Mozilla's independent "
               "second opinion. A passive check finds known kinds of problems; it is not a penetration test.")

# ------------------------------------------------------------------ what
with tab_what:
    st.markdown("Everything in the first five areas is what a normal visitor's browser, or a normal DNS lookup, already sees. "
                "**Exposed files** asks for specific addresses, so it only runs after the owner verifies the site.")
    kit.table([dict(area=c["area"], t=c["title"].replace("{domain}", "your-domain").replace("{host}", "the site"), sev=c["sev"],
                    who="owner only" if c["area"] == "Exposed files" else "anyone")
               for c in sorted(K.C.values(), key=lambda c: (K.AREAS.index(c["area"]), S.SEV_ORDER[c["sev"]]))],
              [kit.col("Area", "area", "strong"), kit.col("Problem it finds", "t", "wrap"),
               kit.col("Severity", "sev", "chip", {"High": "bad", "Medium": "warn", "Low": "info", "Info": ""}),
               kit.col("Who can run it", "who", "muted")])
    st.caption("Severity is about the business: High can be used against you now; Medium is an open door that needs another "
               "mistake to hurt; Low is hardening; Info is good to know.")

kit.footer("scan.py · fixed checks, no AI deciding · second opinion: Mozilla HTTP Observatory")
