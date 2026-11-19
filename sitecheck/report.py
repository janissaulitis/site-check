"""Comparing two scans, and the downloadable report for the site owner."""
import html
import re

SEV = ["High", "Medium", "Low", "Info"]


def problems(rep):
    return [r for r in rep["results"] if r["status"] == "problem"]


def reviews(rep, obs_rows=None):
    """Borderline results, checks to do by hand, and tests where the two scanners disagree."""
    out = [r for r in rep["results"] if r["status"] == "review"]
    for c in obs_rows or []:
        if c.get("agree") is False:
            out.append(dict(id="layers_disagree", status="review", sev="Review", area="Headers",
                            title=f"The two scanners disagree: {c['name']}",
                            evidence=f"Site Check: {'OK' if c['ours'] else 'problem'} · Mozilla: {'OK' if c['mozilla'] else 'problem'} ({c['mozilla_result']})",
                            why="When two independent scanners give different answers, one of them is wrong. A person should look.",
                            fix="Compare the evidence in the problem list above with Mozilla's full report for this test.",
                            retest="Fix whichever is right, then scan again: both scanners should agree."))
    return out


def key(r):
    return (r["id"], r["evidence"].split(":")[0] if r["id"] == "old_library" else "")


def diff(before, after):
    """fixed / still open / new, matched by problem type."""
    b = {key(r): r for r in problems(before)}
    a = {key(r): r for r in problems(after)}
    return dict(fixed=[b[k] for k in b if k not in a], still=[a[k] for k in a if k in b], new=[a[k] for k in a if k not in b])


def verdict(rep):
    p = problems(rep)
    n = {s: sum(r["sev"] == s for r in p) for s in SEV}
    urgent = n["High"] + n["Medium"]
    if n["High"]:
        head, tone = f"Fix {n['High']} serious problem{'s' if n['High'] > 1 else ''} now", "bad"
    elif n["Medium"]:
        head, tone = f"{n['Medium']} thing{'s' if n['Medium'] > 1 else ''} to fix soon", "warn"
    elif n["Low"]:
        head, tone = "In good shape, with a few improvements", "good"
    else:
        head, tone = "No problems found", "good"
    return dict(head=head, tone=tone, n=n, urgent=urgent)


def _md(text):
    """Very small Markdown subset used in the catalogue: `code`, **bold**, new lines."""
    out = html.escape(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", out)
    return out.replace("\n", "<br>")


def build_html(rep, obs_rows=None, obs_grade=None):
    v = verdict(rep)
    p = problems(rep)
    rv = reviews(rep, obs_rows)
    oks = [r for r in rep["results"] if r["status"] == "ok"]
    unk = [r for r in rep["results"] if r["status"] == "unknown"]
    e = html.escape
    items = "".join(
        f'<div class="f {r["sev"]}"><div class="top"><span class="sev">{r["sev"]}</span><span class="area">{e(r["area"])}</span></div>'
        f'<h3>{i}. {e(r["title"])}</h3><p class="ev"><b>Found:</b> {e(r["evidence"])}</p>'
        f'<p><b>Why it matters:</b> {e(r["why"])}</p><p><b>How to fix:</b><br>{_md(r["fix"])}</p>'
        f'<p class="rt"><b>☐ Retest:</b> {_md(r["retest"])}</p></div>' for i, r in enumerate(p, 1))
    look = "".join(
        f'<div class="f Review"><h3>{e(r["title"])}</h3><p class="ev"><b>Found:</b> {e(r["evidence"])}</p>'
        f'<p>{e(r["why"])}</p><p><b>What to do:</b> {_md(r["fix"])}</p><p class="rt"><b>☐ Test it:</b> {_md(r["retest"])}</p></div>'
        for r in rv)
    ok_list = "".join(f"<li>{e(r['title'])}</li>" for r in oks)
    unk_list = "".join(f"<li>{e(r['title'])}: {e(r['evidence'])}</li>" for r in unk)
    second = ""
    if obs_rows:
        rows = "".join(f"<tr><td>{e(c['name'])}</td><td>{'—' if c['ours'] is None else ('OK' if c['ours'] else 'Problem')}</td>"
                       f"<td>{'OK' if c['mozilla'] else 'Problem'}</td><td>{'' if c['agree'] is None else ('agree' if c['agree'] else 'DIFFERENT')}</td></tr>"
                       for c in obs_rows)
        second = (f"<h2>Second opinion: Mozilla HTTP Observatory{' (grade ' + e(obs_grade) + ')' if obs_grade else ''}</h2>"
                  f"<table><tr><th>Test</th><th>Site Check</th><th>Mozilla</th><th></th></tr>{rows}</table>")
    probed = "Exposed-file checks were run (owner verified)." if rep["facts"].get("probed") else \
        "Exposed-file checks were not run: they need the site owner to verify first."
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Security check – {e(rep['host'])}</title>
<style>html{{background:#fff}}body{{font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#151a1f;background:#fff;max-width:860px;margin:0 auto;padding:28px 20px}}
h1{{font-size:24px;margin:0}}h2{{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #dde2e6;padding-bottom:6px}}h3{{font-size:15.5px;margin:6px 0}}
.sub{{color:#5b6570}}.k{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}.k div{{border:1px solid #dde2e6;border-radius:8px;padding:10px 12px}}.k b{{display:block;font-size:24px}}
.f{{border:1px solid #dde2e6;border-left:5px solid #9aa4ae;border-radius:8px;padding:12px 16px;margin:12px 0;page-break-inside:avoid}}.f.High{{border-left-color:#c62828}}.f.Medium{{border-left-color:#b26a00}}.f.Low{{border-left-color:#3f6ad8}}.f.Review{{border-left-style:dashed;border-left-color:#7a8691}}
.top{{display:flex;gap:10px;font-size:12px;color:#5b6570}}.sev{{font-weight:700}}.f p{{margin:6px 0}}.ev{{font-family:ui-monospace,monospace;font-size:12.5px;background:#f4f6f8;padding:6px 8px;border-radius:6px;word-break:break-all}}
code{{font-family:ui-monospace,monospace;font-size:12.5px;background:#f1f3f5;padding:1px 4px;border-radius:4px;word-break:break-all}}.rt{{background:#f6f8fb;padding:6px 8px;border-radius:6px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #e6e9ee;padding:6px 8px;text-align:left}}th{{color:#5b6570}}
.note{{color:#5b6570;font-size:12px;margin-top:24px}}</style></head><body>
<h1>Website security check</h1><div class="sub">{e(rep['host'])} · email domain {e(rep['domain'])} · {e(rep['scanned_at'])}</div>
<div class="k"><div><b>{v['n']['High']}</b>serious</div><div><b>{v['n']['Medium']}</b>to fix soon</div><div><b>{v['n']['Low']}</b>improvements</div><div><b>{len(oks)}</b>checks passed</div></div>
<p><b>{e(v['head'])}.</b> {e(probed)}</p>
<h2>What to fix, most urgent first</h2>{items or '<p>Nothing to fix.</p>'}
{('<h2>Worth a closer look (borderline, or test by hand)</h2>' + look) if rv else ''}
{second}
<h2>Checked and fine</h2><ul>{ok_list}</ul>
{('<h2>Could not check</h2><ul>' + unk_list + '</ul>') if unk else ''}
<p class="note">Made with Site Check (passive checks: only what a normal visitor's browser and DNS can see{', plus owner-verified file checks' if rep['facts'].get('probed') else ''}). A check finds known kinds of problems; it is not a full penetration test.</p></body></html>"""
