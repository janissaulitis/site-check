"""Runs every lab site on its own loopback address (127.0.1.N), ports 80 and 443, named <slug>.lab.test.
Needs root (low ports, /etc/hosts). Run directly to keep the lab up: python -m lab.server"""
import http.server
import ssl
import threading
import warnings
from pathlib import Path

from . import certs
from .sites import SITES

HOSTS = Path("/etc/hosts")
MARK = "# site-check lab"


def ip(i):
    return f"127.0.1.{i + 1}"


def write_hosts(sites=SITES):
    lines = [l for l in HOSTS.read_text().splitlines() if MARK not in l]
    lines += [f"{ip(i)} {s['host']} www.{s['host']} {MARK}" for i, s in enumerate(sites)]
    HOSTS.write_text("\n".join(lines) + "\n")


def make_handler(site, is_https, log):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "lab"
        sys_version = ""

        def log_message(self, *a):
            pass

        def version_string(self):
            return site["headers"].get("Server", "")

        def _send(self, status, ctype, body, extra=None):
            self.send_response_only(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in site["headers"].items():
                if k != "Server":
                    self.send_header(k, v)
            if site["headers"].get("Server"):
                self.send_header("Server", site["headers"]["Server"])
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            log.append(("https" if is_https else "http", path))
            if not is_https and site["http"] == "redirect":
                self.send_response_only(301)
                self.send_header("Location", f"https://{site['host']}{self.path}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            extra = {}
            origin = self.headers.get("Origin")
            if site["cors"] == "reflect" and origin:
                extra = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
                         "Vary": "Origin"}
            elif site["cors"] == "star":
                extra = {"Access-Control-Allow-Origin": "*"}
            if path in site["files"]:
                st, ct, body = site["files"][path]
                if ct == "redirect":
                    return self._send(st, "text/html", b"", {"Location": body.decode()})
                return self._send(st, ct, body, extra)
            if path == "/" or site["soft404"]:
                cookies = site["cookies"] if path == "/" else []
                self.send_response_only(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(site["html"])))
                for k, v in list(site["headers"].items()) + list(extra.items()):
                    self.send_header(k, v)
                for c in cookies:
                    self.send_header("Set-Cookie", c)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(site["html"])
                return
            return self._send(404, "text/html", b"<!doctype html><html><head><title>Not found</title></head>"
                                                b"<body><h1>Page not found</h1></body></html>", extra)

        do_HEAD = do_GET

        def do_OPTIONS(self):
            log.append(("https" if is_https else "http", "OPTIONS " + self.path))
            self.send_response_only(204)
            origin = self.headers.get("Origin")
            if site["cors"] in ("reflect", "preflight") and origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Access-Control-Allow-Methods", "GET, POST")
            elif site["cors"] == "star":
                self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, ctx=None):
        super().__init__(addr, handler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = super().get_request()
        if self.ctx:
            sock = self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        pass  # failed handshakes are expected (expired, old TLS tests)


def tls_ctx(site):
    kind = site["https"]
    certfile, keyfile = certs.site_cert(site["slug"], site["host"], "good" if kind in ("oldtls", "oldonly") else kind)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    if kind in ("oldtls", "oldonly"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            if kind == "oldonly":
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if site.get("h2"):
        ctx.set_alpn_protocols(["h2", "http/1.1"])  # announces HTTP/2 (the lab still answers in HTTP/1.1)
    return ctx


def start(sites=SITES):
    write_hosts(sites)
    servers, logs = [], {}
    for i, s in enumerate(sites):
        log = logs.setdefault(s["slug"], [])
        if s["https"] != "none":
            servers.append(Server((ip(i), 443), make_handler(s, True, log), tls_ctx(s)))
        if s["http"] != "none":
            servers.append(Server((ip(i), 80), make_handler(s, False, log)))
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop():
        for srv in servers:
            srv.shutdown()
            srv.server_close()
    return stop, logs


if __name__ == "__main__":
    import time
    stop, _ = start()
    print(f"{len(SITES)} lab sites up. CA: {certs.ca_file()}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop()
