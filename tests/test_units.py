"""Unit tests that need no network. The lab benchmark (python -m lab.bench) tests whole scans."""
import pytest

from sitecheck import verify
from sitecheck.net import Net, Refused, clean_host
from sitecheck.report import diff
from sitecheck.scan import csp_weak, find_libraries, org_domain, parse_cookie, parse_csp


@pytest.mark.parametrize("text,host", [("https://Example.com/path?q=1", "example.com"), ("www.shop.lv:443", "www.shop.lv"),
                                       (" example.com. ", "example.com")])
def test_clean_host(text, host):
    assert clean_host(text) == host


def test_idn():
    assert clean_host("http://bērnudārzs.lv").startswith("xn--") and clean_host("bērnudārzs.lv").endswith(".lv")


@pytest.mark.parametrize("text", ["localhost", "127.0.0.1", "http://10.0.0.1/", "user@example.com", "", "exa mple.com"])
def test_clean_host_refuses(text):
    with pytest.raises(Refused):
        clean_host(text)


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://10.1.2.3/", "http://192.168.1.1/", "http://169.254.169.254/",
                                 "http://[::1]/", "http://0.0.0.0/", "http://100.64.0.1/"])
def test_private_refused(url):
    with pytest.raises(Refused):
        Net().get(url, follow=0)


def test_org_domain():
    assert org_domain("www.shop.co.uk") == "shop.co.uk"
    assert org_domain("veikals.com.lv") == "veikals.com.lv"
    assert org_domain("a.b.example.lv") == "example.lv"


def test_csp():
    assert csp_weak(parse_csp("default-src 'self'")) is None
    assert csp_weak(parse_csp("script-src 'self' 'nonce-abc' 'unsafe-inline'")) is None
    assert "unsafe-inline" in csp_weak(parse_csp("script-src 'self' 'unsafe-inline'"))
    assert "unsafe-eval" in csp_weak(parse_csp("default-src 'self' 'unsafe-eval'"))
    assert csp_weak(parse_csp("frame-ancestors 'none'"))
    assert "https:" in csp_weak(parse_csp("script-src https:"))


def test_cookies():
    c = parse_cookie("PHPSESSID=1; path=/")
    assert c["session"] and not c["secure"] and not c["httponly"] and c["samesite"] is None
    assert not parse_cookie("csrftoken=1; Secure")["session"]
    assert not parse_cookie("_ga=1")["session"]
    assert parse_cookie("wordpress_logged_in_abc=1; Secure; HttpOnly; SameSite=Lax")["samesite"] == "Lax"


def test_libraries():
    hit = lambda src: [f[:2] for f in find_libraries([src])]
    assert hit("https://code.jquery.com/jquery-1.12.4.min.js") == [("jQuery", "1.12.4")]
    assert hit("/wp-includes/js/jquery/jquery.min.js?ver=3.7.1") == []
    assert hit("/theme/js/bootstrap.min.js?ver=1.0.2") == []  # a theme's version, not Bootstrap's
    assert hit("https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js") == []
    assert hit("https://cdn.jsdelivr.net/npm/bootstrap@4.1.0/dist/js/bootstrap.bundle.min.js") == [("Bootstrap", "4.1.0")]
    assert hit("/js/jquery-migrate-1.4.1.min.js") == []
    assert hit("https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js") == [("jQuery UI", "1.12.1")]


def test_token_is_per_host():
    assert verify.token("a.lv") != verify.token("b.lv") and verify.token("A.lv") == verify.token("a.lv")


def test_diff():
    r = lambda *ids: dict(results=[dict(id=i, status="problem", sev="Low", evidence="x") for i in ids])
    d = diff(r("a", "b"), r("b", "c"))
    assert [x["id"] for x in d["fixed"]] == ["a"] and [x["id"] for x in d["still"]] == ["b"] and [x["id"] for x in d["new"]] == ["c"]


def test_watch_matches_web_tech(tmp_path):
    import json
    import datetime as dt
    from sitecheck import watch
    kev = {"vulnerabilities": [
        {"cveID": "CVE-2026-109618", "vendorProject": "PHP Group", "product": "PHP", "vulnerabilityName": "x", "dateAdded": "2026-11-15"},
        {"cveID": "CVE-1", "vendorProject": "WordPress", "product": "Kirki plugin", "vulnerabilityName": "x", "dateAdded": "2026-11-18"},
        {"cveID": "CVE-2", "vendorProject": "Cisco", "product": "IOS XE", "vulnerabilityName": "x", "dateAdded": "2026-11-18"},
        {"cveID": "CVE-3", "vendorProject": "Drupal", "product": "core", "vulnerabilityName": "x", "dateAdded": "2026-01-01"}]}
    (tmp_path / "kev.json").write_text(json.dumps(kev))
    (tmp_path / "sites.csv").write_text("category,domain,tech\nvet,a.lv,php wordpress\nlaw,b.lv,nginx\n")
    act = watch.run(tmp_path / "sites.csv", tmp_path / "out", 7, tmp_path / "kev.json", today=dt.date(2026, 11, 20))
    assert [e["cve"] for e in act] == ["CVE-1"]  # PHP2Shell is covered; Cisco is not web tech; Drupal is too old
