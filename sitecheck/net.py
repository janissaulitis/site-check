"""Network access for Site Check: HTTP with a size cap and manual redirects, TLS details, DNS.
Every connection is checked against private / internal addresses first (unless lab mode allows them)."""
import datetime as dt
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "SiteCheck/1.0 (+https://janis-saulitis-portfolio.netlify.app; passive security check)"
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


class Refused(Exception):
    """The address is not allowed (private network, bad name)."""


class Unreachable(Exception):
    pass


class DNSUnknown(Exception):
    """The lookup failed for a reason other than 'no such record'."""


@dataclass
class Resp:
    url: str
    status: int
    headers: dict  # lower-case name -> list of values
    body: bytes
    chain: list = field(default_factory=list)  # [(url, status)] for every hop, final included
    verified: bool = True
    hop_cookies: list = field(default_factory=list)  # Set-Cookie lines from every hop, redirects included

    def h(self, name, default=None):
        v = self.headers.get(name.lower())
        return ", ".join(v) if v else default

    def all(self, name):
        return self.headers.get(name.lower(), [])

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


def clean_host(text):
    """'https://Example.com:443/path' -> 'example.com'. Raises Refused for anything that is not a host name."""
    t = (text or "").strip().lower()
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t)
    t = t.split("/")[0].split("?")[0].split("#")[0]
    if "@" in t:
        raise Refused("Addresses with a user name are not checked.")
    t = t.rsplit(":", 1)[0] if re.search(r":\d+$", t) else t
    t = t.rstrip(".")
    try:
        t = t.encode("idna").decode("ascii")
    except UnicodeError:
        raise Refused("That is not a valid web address.")
    if not HOST_RE.match(t) or "." not in t:
        raise Refused("Type a web address like example.com.")
    try:
        ipaddress.ip_address(t)
        raise Refused("Type the site's name, not an IP address.")
    except ValueError:
        pass
    return t


def _bad_ip(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
            or a.is_unspecified or not a.is_global)


class Net:
    def __init__(self, ca_file=None, allow_private=False, timeout=8.0, txt=None, trusted_hosts=()):
        self.ca = ca_file or True
        self.allow_private = allow_private
        self.trusted = set(trusted_hosts)  # tests only: names treated as public
        self.timeout = timeout
        self._txt = txt  # optional replacement for DNS TXT lookups: name -> list[str] | None
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.s.trust_env = False

    # ------------------------------------------------------------ safety
    def guard(self, host):
        if self.allow_private or host in self.trusted:
            return
        host = host.strip("[]")
        try:
            if _bad_ip(host):
                raise Refused(f"{host} is a private or internal address; only public sites are checked.")
            return
        except ValueError:
            pass  # a name, not an IP address
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise Unreachable(f"{host} does not exist (no DNS record)")
        ips = {i[4][0] for i in infos}
        if any(_bad_ip(ip) for ip in ips):
            raise Refused(f"{host} points to a private or internal address; only public sites are checked.")

    # -------------------------------------------------------------- HTTP
    def get(self, url, headers=None, follow=5, max_bytes=2_000_000, verify=True, method="GET"):
        chain, cookies = [], []
        for _ in range(follow + 1):
            u = urllib3.util.parse_url(url)
            if u.scheme not in ("http", "https") or not u.host:
                raise Refused(f"Not a web address: {url}")
            self.guard(u.host)
            try:
                r = self.s.request(method, url, headers=headers or {}, allow_redirects=False, stream=True,
                               timeout=self.timeout, verify=(self.ca if verify else False))
            except requests.exceptions.SSLError as e:
                raise ssl.SSLError(str(e))
            except requests.exceptions.RequestException as e:
                raise Unreachable(_short(e))
            body = b""
            try:
                for chunk in r.iter_content(16384):
                    body += chunk
                    if len(body) >= max_bytes:
                        break
            except requests.exceptions.RequestException:
                pass
            finally:
                r.close()
            hdrs = {}
            for k, v in r.raw.headers.items():
                hdrs.setdefault(k.lower(), []).append(v)
            chain.append((url, r.status_code))
            cookies += hdrs.get("set-cookie", [])
            loc = r.headers.get("location")
            if r.status_code in (301, 302, 303, 307, 308) and loc and len(chain) <= follow:
                url = requests.compat.urljoin(url, loc)
                continue
            return Resp(url, r.status_code, hdrs, body[:max_bytes], chain, verify, cookies)
        return Resp(url, r.status_code, hdrs, body[:max_bytes], chain, verify, cookies)

    # --------------------------------------------------------------- TLS
    def tls(self, host, port=443):
        """{'ok', 'problem' (None|expired|name|untrusted), 'detail', 'days_left', 'not_after', 'version', 'old_tls'}"""
        self.guard(host)
        out = dict(ok=False, problem=None, detail="", days_left=None, not_after=None, version=None, old_tls=None,
                   reachable=False)
        ctx = ssl.create_default_context(cafile=self.ca if isinstance(self.ca, str) else None)
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                out["reachable"] = True
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    out.update(ok=True, version=s.version())
                    der = s.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError as e:
            code = getattr(e, "verify_code", None)
            out["problem"] = {10: "expired", 62: "name"}.get(code, "untrusted")
            out["detail"] = getattr(e, "verify_message", "") or str(e)
            der = self._peek_cert(host, port)
        except (ssl.SSLError, ConnectionResetError) as e:
            out["detail"] = f"TLS handshake failed: {_short(e)}"
            out["old_tls"] = self._old_tls(host, port)  # a server that only speaks TLS 1.0/1.1 fails here
            out["old_only"] = out["old_tls"] is True
            return out
        except OSError as e:
            out["detail"] = _short(e)
            return out
        if der:
            na = _not_after(der)
            if na:
                out["not_after"] = na.date().isoformat()
                out["days_left"] = (na - dt.datetime.now(dt.timezone.utc)).days
            if out["problem"] is None and out["days_left"] is not None and out["days_left"] < 0:
                out["problem"] = "expired"
        out["old_tls"] = self._old_tls(host, port)
        return out

    def _peek_cert(self, host, port):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    return s.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None

    def _old_tls(self, host, port):
        """True if the server completes a TLS 1.0/1.1 handshake, False if it refuses, None if we can't tell."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return None
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    return s.version() in ("TLSv1", "TLSv1.1")
        except ssl.SSLError as e:
            msg = str(e).lower()
            if "no protocols available" in msg or "no ciphers available" in msg:
                return None  # this computer's TLS library can't even try
            return False
        except (ConnectionResetError, BrokenPipeError):
            return False  # servers often just hang up on old versions
        except OSError:
            return None

    # --------------------------------------------------------------- DNS
    def txt(self, name):
        """TXT strings for a name; [] when there are none; raises DNSUnknown when the lookup itself fails."""
        if self._txt is not None:
            v = self._txt(name)
            if v == "error":
                raise DNSUnknown(name)
            return v or []
        import dns.exception
        import dns.resolver
        r = dns.resolver.Resolver()
        r.lifetime = 6
        try:
            ans = r.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise DNSUnknown(str(e))
        return [b"".join(x.strings).decode("utf-8", "replace") for x in ans]


def _not_after(der):
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        return c.not_valid_after_utc
    except Exception:
        return None


def _short(e):
    s = str(e)
    for pat, txt in [("Name or service not known", "the name does not exist"), ("timed out", "timed out"),
                     ("Connection refused", "connection refused"), ("Max retries", "could not connect")]:
        if pat.lower() in s.lower():
            return txt
    return s.splitlines()[0][:160]
