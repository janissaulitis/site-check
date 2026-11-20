"""Client dashboard (demo): what a monitored company would see. The company and its history are invented."""
import datetime as dt
import html
import importlib
from pathlib import Path

import streamlit as st

import kit
from sitecheck import demo as DEMO
from sitecheck import report as REP
from sitecheck import ui as UI

for _m in (DEMO, REP, UI):
    importlib.reload(_m)

HERE = Path(__file__).parent
first, rep = DEMO.current_report(HERE / "sample_report.json")
hist = DEMO.history(first)
log = DEMO.fixed_log(first)
v = REP.verdict(rep)
probs = REP.problems(rep)
fixed_n = sum(r["status"] == "problem" for r in first["results"] if r["sev"] in DEMO.SEV) - len(probs)
total0 = hist[0]["High"] + hist[0]["Medium"] + hist[0]["Low"]
days_cert = 79
fmt = lambda d: f"{d.day} {['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.month - 1]}"

st.markdown(
    '<div class="k-tok" style="margin:0 0 14px">Demo: what a client on the monitoring plan sees. Baltic Bakery SIA, its '
    "site and its 12-week history are invented; today's findings come from a real check of a test-lab site.</div>",
    unsafe_allow_html=True)

kit.answer(f"{DEMO.COMPANY} · {DEMO.DOMAIN} · {DEMO.PLAN} · last check Mon 16 Nov, next Mon 23 Nov",
           "Nothing serious open. 1 thing to fix soon",
           f"<b>{fixed_n} of {total0}</b> problems from the first check in August are fixed. The 3 attacks in the news this "
           "autumn did not reach you: we checked each one the day it appeared.",
           [("Open now", str(len(probs))), ("Fixed since Aug", str(fixed_n)),
            ("Certificate", f"{days_cert} days left"), ("Fake email in your name", "Blocked")], tone="warn", raw=True)


def chart(rows, warnings):
    """Stacked bars per weekly check (High / Medium / Low open), early warnings marked on the same time axis."""
    W, H, left, top, bottom = 640, 236, 34, 28, 34
    n = len(rows)
    top_v = max(r["High"] + r["Medium"] + r["Low"] for r in rows) or 1
    step = (W - left - 8) / n
    bw = step * 0.62
    ph = H - top - bottom
    y = lambda v: top + ph - v / top_v * ph
    cols = {"High": "var(--k-bad-ink)", "Medium": "var(--k-warn-ink)", "Low": "var(--k-go)"}
    parts = []
    for t in range(0, top_v + 1, 4):
        parts.append(f'<line x1="{left}" x2="{W - 4}" y1="{y(t):.1f}" y2="{y(t):.1f}" stroke="var(--k-line)"/>'
                     f'<text x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end" font-size="11" fill="var(--k-muted)">{t}</text>')
    for i, r in enumerate(rows):
        x = left + i * step + (step - bw) / 2
        base = 0
        for s in ("High", "Medium", "Low"):
            if r[s]:
                parts.append(f'<rect x="{x:.1f}" y="{y(base + r[s]):.1f}" width="{bw:.1f}" height="{y(base) - y(base + r[s]):.1f}" '
                             f'fill="{cols[s]}" rx="2"><title>{fmt(r["date"])}: {r[s]} {s}</title></rect>')
                base += r[s]
        if i % 2 == 0 or i == n - 1:
            parts.append(f'<text x="{x + bw / 2:.1f}" y="{H - 12}" text-anchor="middle" font-size="11" fill="var(--k-muted)">{fmt(r["date"])}</text>')
    d0 = rows[0]["date"]
    for k, w in enumerate(warnings, 1):
        d = dt.date.fromisoformat(w["date"])
        x = left + (d - d0).days / 7 * step + step / 2
        parts.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top - 6}" y2="{top + ph}" stroke="var(--k-muted)" stroke-dasharray="3 3"/>'
                     f'<circle cx="{x:.1f}" cy="{top - 12}" r="8" fill="var(--k-surface)" stroke="var(--k-muted)"/>'
                     f'<text x="{x:.1f}" y="{top - 8}" text-anchor="middle" font-size="11" font-weight="600" fill="var(--k-ink)">{k}</text>')
    legend = "".join(f'<span><i style="background:{c}"></i>{s}</span>' for s, c in cols.items())
    return (f'<div class="k-hist"><svg viewBox="0 0 {W} {H}" role="img" aria-label="Open problems per weekly check, '
            f'from {total0} in August to {len(probs)} now">{"".join(parts)}</svg>'
            f'<div class="k-legend">{legend}<span><b>1–3</b> early warnings (below)</span></div></div>')


st.markdown("""<style>
.k-hist svg { width: 100%; height: auto; display: block; }
.k-legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; color: var(--k-muted); margin-top: 6px; }
.k-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }
.k-stat { list-style: none; margin: 0; padding: 0; }
.k-stat li { display: grid; grid-template-columns: 22px minmax(0,1fr); gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--k-line); font-size: 14.5px; }
.k-stat li b { display: block; font-weight: 600; }
.k-stat li span { color: var(--k-muted); font-size: 13.5px; }
.k-stat .d { width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; background: var(--k-ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--k-ok) 18%, transparent); }
.k-stat .d.warn { background: var(--k-warn-ink); box-shadow: 0 0 0 3px color-mix(in srgb, var(--k-warn-ink) 20%, transparent); }
.k-lock { border: 1px dashed var(--k-line); border-radius: 12px; padding: 16px 18px; color: var(--k-muted); font-size: 14.5px; }
.k-lock b { color: var(--k-ink); }
</style>""", unsafe_allow_html=True)

c1, c2 = st.columns([1.5, 1], gap="large")
with c1:
    st.markdown("#### Open problems, week by week")
    st.markdown(chart(hist, DEMO.WARNINGS), unsafe_allow_html=True)
with c2:
    st.markdown("#### Your setup today")
    items = [
        ("", "HTTPS", f"Certificate valid until 7 Feb 2027 ({days_cert} days). Renewal is automatic."),
        ("", "Fake email in your name", "Blocked: SPF strict, DMARC set to quarantine since 14 Sep."),
        ("", "WordPress", "Latest version since 5 Oct. Plugins: check monthly in the dashboard of the site."),
        ("", "PHP", "8.3.36, fixed for PHP2Shell (confirmed by your host on 23 Oct)."),
        ("", "Leaked files", "None found (owner-verified check, last run 16 Nov)."),
        ("warn", "Security headers", "1 to add (Content-Security-Policy), 2 small improvements."),
    ]
    st.markdown('<ul class="k-stat">' + "".join(
        f'<li><i class="d {c}"></i><div><b>{html.escape(t)}</b><span>{html.escape(x)}</span></div></li>' for c, t, x in items)
        + "</ul>", unsafe_allow_html=True)

st.markdown("#### To do")
st.caption("Give these to your web developer or host. Each one says how to check it's fixed; our next weekly check confirms it.")
st.markdown("".join(UI.finding(r, i, open_=(i == 0)) for i, r in enumerate(probs)), unsafe_allow_html=True)

st.markdown("#### Early warnings this autumn")
st.caption("When a new attack appears in the news, we check the same day whether it can reach you.")
kit.table([dict(n=str(k), d=fmt(dt.date.fromisoformat(w["date"])), a=w["name"], hit=w["affected"], what=w["what"], out=w["outcome"])
           for k, w in enumerate(DEMO.WARNINGS, 1)],
          [kit.col("#", "n", "muted"), kit.col("Date", "d", "muted"), kit.col("Attack in the news", "a", "strong"),
           kit.col("Affects you?", "hit", "chip", {"No": "good", "Maybe": "warn", "Yes": "bad"}),
           kit.col("What we did", "what", "wrap"), kit.col("Outcome", "out", "wrap")])

st.markdown("#### Fixed so far")
kit.table([dict(d=fmt(dt.date.fromisoformat(x["date"])), w=x["who"], what=x["what"],
                n=f'{x["problems"]} problem{"s" if x["problems"] > 1 else ""}') for x in log],
          [kit.col("Date", "d", "muted"), kit.col("Who", "w"), kit.col("What they did", "what", "wrap"), kit.col("Closed", "n", "muted")])

a, b = st.columns([1, 1], gap="large")
with a:
    st.markdown("#### Reports")
    st.download_button("⬇ This week's report for your IT person (HTML)", REP.build_html(rep),
                       file_name="security-report-balticbakery.html", mime="text/html")
    st.caption("Every weekly check is kept, so you can show your history to a client, an insurer or an auditor.")
with b:
    st.markdown("#### Attacks on your site")
    st.markdown('<div class="k-lock"><b>Pro plan.</b> Connect your hosting logs and this shows who tried to get in each '
                "week (password guessing, scans for leaked files, known attacks) and alerts you only when an attempt "
                "matches a weak spot you actually have.</div>", unsafe_allow_html=True)

kit.footer("Demo dashboard · invented company · findings from a real check of a test-lab site")
