"""Proof that the person running the scan controls the site, before the exposed-files probes run."""
import hashlib
import ssl

from .net import DNSUnknown, Refused, Unreachable

PATH = "/.well-known/site-check.txt"


def token(host):
    return "site-check-" + hashlib.sha256(f"site-check:{host.lower()}".encode()).hexdigest()[:24]


def check(host, net, base_url=None):
    """Returns (verified, how). Looks for the token in /.well-known/site-check.txt or a DNS TXT record."""
    tok = token(host)
    url = (base_url or f"https://{host}") + PATH
    try:
        r = net.get(url, follow=2, max_bytes=4096)
        if r.status == 200 and tok in r.text:
            return True, f"file {PATH}"
    except (Unreachable, ssl.SSLError, Refused):
        pass
    for name in (host, f"_site-check.{host}"):
        try:
            if any(tok in t for t in net.txt(name)):
                return True, f"DNS TXT record on {name}"
        except DNSUnknown:
            pass
    return False, None
