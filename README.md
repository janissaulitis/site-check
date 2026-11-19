# Site Check

A website security check for small companies that says **what to fix, how, and how to retest**.
Live: https://site-check.streamlit.app/

- **Layer 1 (this code):** HTTPS and certificate, security headers, cookies, insecure content and forms, outdated
  JavaScript libraries and WordPress, SPF/DMARC email protection, and (only for a verified owner) leaked files such as
  `.git`, `.env` and backups. Fixed rules, no AI deciding.
- **Layer 2:** Mozilla HTTP Observatory, a separate scanner, compared test by test. Disagreements are shown.
- **Worth a closer look:** borderline settings, checks a passive scan can't decide, and disagreements, each with how to
  test it by hand.
- **Scan again** shows fixed / still open / new. The report downloads as HTML for the site owner.

Passive only: no logins, no form submissions, no attacks. Private and internal addresses are refused.

## How it is tested

- `python -m lab.bench` (as root): a lab of small websites with problems planted on purpose, right answers written
  first in `lab/sites.py`; Mozilla's scanner runs on the same sites. Results: `lab/results.json`.
- `python -m lab.realworld`: badssl.com test sites and public websites vs Mozilla (GitHub Actions, weekly).
- `pytest tests`: units, including private-address refusal.

See `SPEC.md` for the rules and PASS/FAIL checks.
