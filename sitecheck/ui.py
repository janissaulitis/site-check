"""Rendering pieces shared by the check page and the client dashboard."""
import html

import streamlit as st

from . import catalog as K
from . import report as REP
from . import scan as S


def esc(x):
    return html.escape(str(x))


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


