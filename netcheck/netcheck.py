#!/usr/bin/env python3
"""netcheck - confirmation-only checker for hosts you own or are authorized to test.
Standard library only. Starts a browser UI bound to 127.0.0.1.

What it does : open TCP ports, banners, HTTP security headers/cookies, TLS certificate,
               whether admin-like URLs respond (status code only, no login attempts).
What it never does: exploit, brute-force, log in, or judge SQL injection.
Safety       : private ranges + loopback only by default; whole run refused if any target
               is out of range; consent required; per-start token; max targets; log file.
"""
import concurrent.futures as cf, datetime, html, http.client, ipaddress, json, os, secrets
import socket, ssl, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ALLOWED = [ipaddress.ip_network(n) for n in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
STD_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
             2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
EXT_PORTS = STD_PORTS + [81, 389, 636, 873, 1521, 2375, 5000, 5601, 8081, 8888, 9000, 11211, 5984, 9090, 15672]
RISKY = {21: "FTP (plaintext)", 23: "Telnet (plaintext)", 111: "rpcbind", 135: "MS RPC", 139: "NetBIOS",
         445: "SMB", 1433: "MSSQL exposed", 2049: "NFS", 2375: "Docker API (unauth)", 3306: "MySQL exposed",
         3389: "RDP", 5432: "PostgreSQL exposed", 5900: "VNC", 6379: "Redis exposed", 9200: "Elasticsearch",
         11211: "Memcached", 27017: "MongoDB exposed", 873: "rsync", 5984: "CouchDB"}
ADMIN_PATHS = ["/admin", "/administrator", "/login", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
               "/manager/html", "/console", "/server-status", "/.git/HEAD", "/.env"]
SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
               "X-Frame-Options", "Referrer-Policy"]
LOG = os.path.join(HERE, "netcheck.log")
TOKEN = secrets.token_urlsafe(16)
LOCK = threading.Lock()

class TooMany(Exception): pass

def load_config():
    cfg = {"allowed_ranges": [], "max_targets": 256, "port_timeout": 1.0, "delay": 0.02}
    try:
        cfg.update(json.load(open(os.path.join(HERE, "config.json"))))
    except Exception:
        pass
    return cfg

def allowed_nets(cfg):
    extra = [ipaddress.ip_network(n, strict=False) for n in cfg.get("allowed_ranges", [])]
    return DEFAULT_ALLOWED + extra

def log(msg):
    with LOCK, open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}\n")

def expand(text, cfg):
    """Return list of IPs from lines of IP / CIDR / hostname. Raises TooMany / ValueError."""
    maxn = int(cfg["max_targets"])
    ips = []
    for raw in text.replace(",", "\n").splitlines():
        t = raw.strip()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > maxn * 4:
                raise TooMany(t)
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            ips += [str(h) for h in hosts]
        except TooMany:
            raise
        except ValueError:
            try:
                ips.append(socket.gethostbyname(t))
            except OSError:
                raise ValueError(f"cannot resolve: {t}")
        if len(ips) > maxn:
            raise TooMany(t)
    ips = list(dict.fromkeys(ips))
    if len(ips) > maxn:
        raise TooMany("total")
    return ips

def check_allowed(ips, cfg):
    nets = allowed_nets(cfg)
    bad = [ip for ip in ips if not any(ipaddress.ip_address(ip) in n for n in nets)]
    return bad

def probe_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = ""
            try:
                if port in (80, 8000, 8080, 8081, 3000, 5000, 8888, 9000):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(200).decode("latin-1", "replace").strip().splitlines()[0][:120] if True else ""
            except Exception:
                pass
            return {"port": port, "banner": banner}
    except Exception:
        return None

def http_get(ip, port, path, tls, timeout):
    cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    kw = {"context": ssl._create_unverified_context()} if tls else {}
    c = cls(ip, port, timeout=timeout, **kw)
    try:
        c.request("GET", path, headers={"User-Agent": "netcheck/1.0 (confirmation only)"})
        r = c.getresponse()
        r.read(1)
        return r.status, r.getheaders()
    finally:
        c.close()

def tls_info(ip, port, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as s, ctx.wrap_socket(s) as t:
            der = t.getpeercert(binary_form=True)
            ver = t.version()
        info = {"tls_version": ver}
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            import tempfile
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(pem); fn = f.name
            d = ssl._ssl._test_decode_cert(fn); os.unlink(fn)
            exp = datetime.datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z")
            info["expires"] = exp.date().isoformat()
            info["days_left"] = (exp - datetime.datetime.utcnow()).days
        except Exception:
            pass
        if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
            info["warn"] = f"old protocol {ver}"
        return info
    except Exception:
        return None

def check_host(ip, ports, cfg):
    to = float(cfg["port_timeout"])
    res = {"ip": ip, "open": [], "findings": [], "http": []}
    for p in ports:
        r = probe_port(ip, p, to)
        time.sleep(float(cfg["delay"]))
        if r:
            res["open"].append(r)
            if p in RISKY:
                res["findings"].append(f"port {p} open: {RISKY[p]} - confirm it must be reachable")
    for r in res["open"]:
        p = r["port"]
        tls = p in (443, 8443)
        if p in (80, 443, 8000, 8080, 8081, 8443, 3000, 5000, 8888, 9000):
            h = {"port": p, "tls": tls, "missing_headers": [], "cookies": [], "admin_urls": []}
            try:
                st, hdrs = http_get(ip, p, "/", tls, to)
                h["status"] = st
                names = {k.lower(): v for k, v in hdrs}
                h["missing_headers"] = [x for x in SEC_HEADERS if x.lower() not in names]
                if "server" in names or "x-powered-by" in names:
                    h["disclosure"] = {k: names[k] for k in ("server", "x-powered-by") if k in names}
                for k, v in hdrs:
                    if k.lower() == "set-cookie":
                        flags = [f for f in ("secure", "httponly", "samesite") if f not in v.lower()]
                        if flags:
                            h["cookies"].append(f'{v.split("=")[0]} missing: {", ".join(flags)}')
                for path in ADMIN_PATHS:
                    try:
                        s2, _ = http_get(ip, p, path, tls, to)
                        time.sleep(float(cfg["delay"]))
                        if s2 in (200, 401, 403):
                            h["admin_urls"].append(f"{path} -> {s2}")
                    except Exception:
                        pass
                res["http"].append(h)
                if h["admin_urls"]:
                    res["findings"].append(f"port {p}: admin-like URLs respond ({len(h['admin_urls'])}) - restrict by IP/VPN")
            except Exception as e:
                h["error"] = str(e)[:80]
                res["http"].append(h)
            if tls:
                ti = tls_info(ip, p, to)
                if ti:
                    h["tls"] = ti
                    if ti.get("days_left") is not None and ti["days_left"] < 30:
                        res["findings"].append(f"port {p}: certificate expires in {ti['days_left']} days")
                    if ti.get("warn"):
                        res["findings"].append(f"port {p}: {ti['warn']}")
    return res

def run(text, ext, cfg):
    ips = expand(text, cfg)
    bad = check_allowed(ips, cfg)
    if bad:
        log(f"REFUSED out-of-range: {bad[:5]}")
        return {"error": "Refused: targets outside allowed ranges: " + ", ".join(bad[:5]) +
                " . Add your own range to config.json allowed_ranges only if you are authorized."}
    ports = EXT_PORTS if ext else STD_PORTS
    log(f"RUN targets={len(ips)} ports={len(ports)}")
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda ip: check_host(ip, ports, cfg), ips))
    return {"results": results, "note": "SQL injection cannot be determined by this tool. Use code scanning (Semgrep) or an authorized staging test."}

PAGE = """<!doctype html><meta charset=utf-8><title>netcheck</title>
<style>body{font:14px system-ui;max-width:900px;margin:20px auto;padding:0 12px}textarea{width:100%;height:90px}
pre{background:#f4f4f4;padding:8px;overflow:auto}.w{background:#fff4d6;padding:8px;border-radius:6px}.f{color:#b00}</style>
<h2>netcheck <small>(confirmation only)</small></h2>
<p class=w>Only scan systems you own or are authorized to test. Defaults to private ranges only.
SQL injection cannot be determined here.</p>
<textarea id=t placeholder="192.168.0.10&#10;192.168.0.0/28"></textarea><br>
<label><input type=checkbox id=e> extended ports</label>
<label><input type=checkbox id=c> I am authorized to check these targets</label>
<button onclick=go()>Run</button><div id=o></div>
<script>
const T=new URLSearchParams(location.search).get('t')||'';
async function go(){const o=document.getElementById('o');o.textContent='running...';
const r=await fetch('/run?t='+encodeURIComponent(T),{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({targets:t.value,extended:e.checked,consent:c.checked})});const j=await r.json();
if(j.error){o.innerHTML='<p class=f>'+esc(j.error)+'</p>';return}
o.innerHTML='<p>'+esc(j.note)+'</p>'+j.results.map(x=>'<h3>'+esc(x.ip)+'</h3>'+
(x.findings.length?'<ul class=f>'+x.findings.map(f=>'<li>'+esc(f)+'</li>').join('')+'</ul>':'<p>no flagged items</p>')+
'<pre>'+esc(JSON.stringify({open:x.open,http:x.http},null,1))+'</pre>').join('')}
function esc(s){return String(s).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]))}
</script>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _tok(self):
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("t", [""])[0] == TOKEN
    def do_GET(self):
        if not self._tok():
            return self._send(403, "forbidden", "text/plain")
        self._send(200, PAGE, "text/html")
    def do_POST(self):
        if not self._tok() or urllib.parse.urlparse(self.path).path != "/run":
            return self._send(403, json.dumps({"error": "forbidden"}))
        try:
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except Exception:
            return self._send(400, json.dumps({"error": "bad request"}))
        if d.get("consent") is not True:
            return self._send(200, json.dumps({"error": "Consent checkbox is required."}))
        cfg = load_config()
        try:
            out = run(d.get("targets", ""), bool(d.get("extended")), cfg)
        except TooMany:
            out = {"error": f"Too many targets (max {cfg['max_targets']}). Use a smaller range."}
        except ValueError as e:
            out = {"error": str(e)}
        self._send(200, json.dumps(out))

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    srv = HTTPServer(("127.0.0.1", port), H)
    print(f"Open: http://127.0.0.1:{port}/?t={TOKEN}\nCtrl+C to stop. Log: {LOG}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
