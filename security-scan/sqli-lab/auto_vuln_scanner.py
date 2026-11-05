"""
Minimal, rule-based vulnerability auto-scanner. LLM-free by default.

Strix (AI-agent pentesting) uses an LLM to decide what to try next, and
can look for many vulnerability classes (SQLi, XSS, SSRF, auth bugs, ...).
This script replaces that decision-making with a fixed payload list PER
vulnerability class, and deterministic response checks -- no LLM, no
agent loop, no Docker, unless you opt into one of the two LLM-assisted
modes below. Adding a new class means adding a new entry to VULN_CLASSES
below: a payload list + a detect() function.

Optional (off unless passed): --llm-payloads asks an LLM for EXTRA payload
strings for an existing class (judgment stays with that class's own
reviewed detect() -- see 2026-11-06 README note). --llm-class lets the LLM
define a brand-new class by name, but only by filling in one of a small,
fixed set of safe detection *types* -- never code that gets executed. Both
are UNREVIEWED relative to the 11 built-in classes; see
"補足: これは『Strixの簡易版』ではない" in README.ja.md and
../ai-sast-trial-notes.md for why an LLM's own verdict is not trusted here.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlparse

import requests

# PHP2Shell (CVE-2026-109618, CVE-2026-109619; CVSS 9.2): critical
# memory-safety vulnerabilities in the PHP runtime itself, not an
# application-level bug -- affects any app running on a vulnerable PHP
# version. Disclosed 2026-10 (Wiz Research / OpenAI Codex Security / Calif).
# This is a version-range check only (no exploit code): first-fixed release
# per branch, as published at https://www.php2shell.com/ on 2026-10-21.
PHP2SHELL_FIRST_FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
PHP2SHELL_REFERENCE = (
    "PHP2Shell (CVE-2026-109618/109619, CVSS 9.2): a PHP *runtime* bug, "
    "not an application bug -- affects any app on a vulnerable PHP version. "
    "https://www.php2shell.com/"
)


def check_php2shell(powered_by: str) -> str | None:
    """Compare an 'X-Powered-By: PHP/x.y.z' header against PHP2Shell's
    first-fixed version per branch. Returns a warning string if the version
    looks vulnerable, else None. This is a version-range comparison, not an
    exploit attempt -- it never sends a PHP2Shell payload."""
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", powered_by or "")
    if not m:
        return None
    major, minor, patch = (int(x) for x in m.groups())
    branch = (major, minor)
    version_str = f"{major}.{minor}.{patch}"

    if branch in PHP2SHELL_FIRST_FIXED:
        fixed = PHP2SHELL_FIRST_FIXED[branch]
        if (major, minor, patch) < fixed:
            fixed_str = ".".join(str(x) for x in fixed)
            return (
                f"PHP {version_str} is below the first fixed release {fixed_str} "
                f"for this branch -- vulnerable to {PHP2SHELL_REFERENCE}"
            )
        return None

    if branch < (8, 2):
        return (
            f"PHP {version_str} is on a branch (< 8.2) this repo has no confirmed "
            f"fixed version for -- treat as vulnerable until checked against "
            f"php.net's own advisory. {PHP2SHELL_REFERENCE}"
        )

    return None  # branch newer than what this repo has data for (e.g. 8.6+)


# CVE-2026-23918: double-free in Apache httpd's mod_http2 stream-cleanup code
# (CVSS 8.8), fixed in httpd 2.4.67 (released 2026-05-04). Version-range
# check only -- this never sends the HTTP/2 HEADERS+RST_STREAM trigger.
APACHE_HTTP2_FIRST_FIXED = (2, 4, 67)
APACHE_HTTP2_REFERENCE = (
    "CVE-2026-23918 (Apache httpd mod_http2 double-free, CVSS 8.8): "
    "https://thehackernews.com/2026/05/critical-apache-http2-flaw-cve-2026.html"
)


def check_apache_http2(server_header: str) -> str | None:
    """Compare a 'Server: Apache/x.y.z' header against CVE-2026-23918's
    first-fixed version. Returns a warning string if the version looks
    vulnerable, else None. Only the 2.4.x branch is in scope: mod_http2
    (where the bug lives) didn't exist before Apache httpd 2.4.17, so an
    old 2.2.x/2.0.x server is a different problem, not this CVE."""
    m = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", server_header or "")
    if not m:
        return None
    version = tuple(int(x) for x in m.groups())
    if version[:2] != APACHE_HTTP2_FIRST_FIXED[:2]:
        return None  # not the 2.4.x branch this CVE applies to
    if version < APACHE_HTTP2_FIRST_FIXED:
        version_str = ".".join(str(x) for x in version)
        fixed_str = ".".join(str(x) for x in APACHE_HTTP2_FIRST_FIXED)
        return (
            f"Apache {version_str} is below the first fixed release {fixed_str} "
            f"-- vulnerable to {APACHE_HTTP2_REFERENCE}"
        )
    return None


# CVE-2026-42945 ("NGINX Rift"): heap-based buffer overflow in
# ngx_http_rewrite_module (CVSS 9.2), affecting NGINX Open Source 0.6.27
# through 1.30.0, fixed in 1.30.1 (backport) / 1.31.0 (mainline) --
# equivalently: fixed if version >= 1.30.1. Version-range check only --
# this never sends the crafted rewrite-triggering request.
NGINX_REWRITE_FIRST_FIXED = (1, 30, 1)
NGINX_REWRITE_REFERENCE = (
    "CVE-2026-42945 (Nginx ngx_http_rewrite_module overflow, 'NGINX Rift', CVSS 9.2): "
    "https://qualysec.com/cybersecurity-news/nginx-cve-2026-42945-exploited-in-wild/"
)


def check_nginx_rewrite(server_header: str) -> str | None:
    """Compare a 'Server: nginx/x.y.z' header against CVE-2026-42945's
    first-fixed version. Returns a warning string if the version looks
    vulnerable, else None. Note: exploitability also requires a specific
    rewrite-directive pattern in nginx.conf this check cannot see -- an
    old version alone doesn't prove the host is actually exploitable."""
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", server_header or "")
    if not m:
        return None
    version = tuple(int(x) for x in m.groups())
    if version < NGINX_REWRITE_FIRST_FIXED:
        version_str = ".".join(str(x) for x in version)
        fixed_str = ".".join(str(x) for x in NGINX_REWRITE_FIRST_FIXED)
        return (
            f"nginx {version_str} is below the first fixed release {fixed_str} "
            f"-- vulnerable to {NGINX_REWRITE_REFERENCE} (if nginx.conf uses the "
            f"specific vulnerable rewrite-directive pattern; version alone isn't proof)"
        )
    return None


# Same allow-list as netcheck/netcheck.py: loopback + RFC1918 private ranges.
# This scanner actually fires live attack payloads, so by default it refuses
# to touch anything that isn't a target you plausibly run yourself.
ALLOWED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128")
]


def _is_allowed_target(url: str) -> tuple[bool, str]:
    host = urlparse(url).hostname
    if not host:
        return False, f"could not parse a hostname out of {url!r}"

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return False, f"could not resolve host {host!r}: {exc}"

    addrs = {info[4][0] for info in infos}
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if not any(ip in net for net in ALLOWED_NETWORKS):
            return False, (
                f"{host!r} resolves to {addr}, which is outside localhost/RFC1918 "
                f"private ranges. This scanner only fires live attack payloads at "
                f"targets you own; pass --i-own-this-target to override."
            )
    return True, ""

# --------------------------------------------------------------------------
# SQLi
# --------------------------------------------------------------------------

SQL_ERROR_MARKERS = (
    "sql error",
    "sqlite3.operationalerror",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "odbc sql server driver",
)

SQLI_PAYLOADS = [
    "' --",
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' OR 1=1 --",
    "') OR ('1'='1' --",
    "' UNION SELECT NULL,NULL,NULL --",
    "'",
    '"',
]


def detect_sqli(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    text = resp.text.lower()
    if any(marker in text for marker in SQL_ERROR_MARKERS):
        return "error-based: SQL error leaked in response"

    baseline_looked_like_success = "login ok" in baseline.text.lower()
    if not baseline_looked_like_success and "login ok" in text:
        return "boolean/auth-bypass: baseline failed, payload succeeded"

    if resp.status_code != baseline.status_code:
        return f"status code changed ({baseline.status_code} -> {resp.status_code})"

    return None


# --------------------------------------------------------------------------
# Reflected XSS: payload reflected verbatim (unescaped) in the HTML body
# --------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]


def detect_xss(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    # If the exact payload (with its angle brackets/quotes intact) shows up
    # verbatim in the body, the app reflected it without HTML-escaping.
    if payload in resp.text:
        return "reflected: payload echoed back unescaped in HTML body"
    return None


# --------------------------------------------------------------------------
# OS command injection: a marker command's distinctive output leaks into
# the response when shell metacharacters are not neutralized.
# --------------------------------------------------------------------------

CMDI_PAYLOADS = [
    "x; id",
    "x && id",
    "x | id",
    "x `id`",
    "x $(id)",
]


def detect_cmdi(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if "uid=" in resp.text and "uid=" not in baseline.text:
        return "command injection: 'id' output leaked into response"
    return None


# --------------------------------------------------------------------------
# Path traversal: ../ sequences escape the intended directory and reach
# an unrelated file (/etc/passwd here, as a readable marker file).
# --------------------------------------------------------------------------

TRAVERSAL_PAYLOADS = [
    "../" * 10 + "etc/passwd",
    "..%2f" * 10 + "etc/passwd",
    "....//" * 10 + "etc/passwd",
]


def detect_traversal(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if "root:x:0:0" in resp.text:
        return "path traversal: read /etc/passwd outside the intended directory"
    return None


# --------------------------------------------------------------------------
# Mass assignment: inject a field (is_admin) the caller should never be
# able to set, and see if it gets bound onto the created object anyway.
# --------------------------------------------------------------------------

MASS_ASSIGNMENT_PAYLOADS = [
    "true",
    "1",
    "True",
]


def detect_mass_assignment(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    marker = f"'is_admin': '{payload}'"
    if marker in resp.text and marker not in baseline.text:
        return "mass assignment: is_admin accepted from request params and bound onto the new account"
    return None


# --------------------------------------------------------------------------
# SSRF: ask the server to fetch a URL pointing at an internal-only service
# and look for that service's own secret coming back in the response.
# --------------------------------------------------------------------------

SSRF_SECRET_MARKER = "INTERNAL-SECRET-KEY-DO-NOT-EXPOSE"

# Must match vulnerable_app.py's VULN_INTERNAL_PORT (default 5001).
_INTERNAL_PORT = os.environ.get("VULN_INTERNAL_PORT", "5001")
SSRF_PAYLOADS = [
    "http://127.0.0.1:%s/latest/meta-data/secret-key" % _INTERNAL_PORT,
    "http://localhost:%s/latest/meta-data/secret-key" % _INTERNAL_PORT,
]


def detect_ssrf(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if SSRF_SECRET_MARKER in resp.text:
        return "SSRF confirmed: an internal-only service's secret was fetched via the server"
    return None


# --------------------------------------------------------------------------
# Account enumeration: a known-already-registered value should look no
# different from an unregistered one, if the endpoint is fixed.
# --------------------------------------------------------------------------

ACCOUNT_ENUM_PAYLOADS = [
    "alice@example.com",
]


def detect_account_enum(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if resp.status_code != baseline.status_code or "already registered" in resp.text.lower():
        return f"account enumeration: distinct response reveals {payload!r} is already registered"
    return None


# --------------------------------------------------------------------------
# Registry: add a new vulnerability class here
# --------------------------------------------------------------------------


@dataclass
class VulnClass:
    payloads: list[str]
    detect: Callable[[requests.Response, requests.Response, str], str | None]
    # Only set when this repo has already verified a real-world incident in
    # the same vulnerability class against a primary source (see
    # ../lineage.md). Left unset rather than guessed -- not every class here
    # has one.
    reference: str | None = None
    # Below: used only by the structured per-finding report (--report-dir).
    # Generic, class-level text -- not specific to any one finding's payload.
    title: str = ""
    impact: str = "この脆弱性クラスにより、攻撃者が意図しない形でアプリの挙動を変えられる可能性がある。"
    fix: str = "入力を信頼せず、用途に合った対策(パラメータ化・エスケープ・許可リスト等)を行う。"


VULN_CLASSES: dict[str, VulnClass] = {
    "sqli": VulnClass(
        SQLI_PAYLOADS,
        detect_sqli,
        reference=(
            "wp2shell: WordPress REST API batch-endpoint route confusion "
            "(CVE-2026-63030) exposing an unauthenticated SQLi (CVE-2026-60137), "
            "used in the wild to place a webshell (Wiz, 2026-10). This repo's R13: "
            "../detections/sigma/r13_wp2shell_wordpress_batch_exploitation.yml"
        ),
        title="SQL インジェクション",
        impact="攻撃者が、DB に送る SQL 文の構造そのものを書き換えられる。認証の回避、他人のデータの"
        "閲覧・窃取、データの改ざんにつながりうる。",
        fix="SQL をパラメータ化クエリ(プレースホルダ)で組み立てる。文字列結合で値を埋め込まない。",
    ),
    "xss": VulnClass(
        XSS_PAYLOADS,
        detect_xss,
        title="反射型クロスサイトスクリプティング(XSS)",
        impact="入力した値が、エスケープされずにそのまま応答の HTML に出る。閲覧者のブラウザで任意の"
        "スクリプトが実行され、セッションの窃取などにつながりうる。",
        fix="出力時に、文脈に合った方法でエスケープする(HTML エスケープ等)。テンプレートエンジンの"
        "自動エスケープを無効化しない。",
    ),
    "cmdi": VulnClass(
        CMDI_PAYLOADS,
        detect_cmdi,
        title="OS コマンドインジェクション",
        impact="入力値が、シェルに渡すコマンドの一部として解釈される。サーバー上で任意のコマンドを"
        "実行されうる(最も深刻な部類)。",
        fix="シェルを経由せず、引数を配列で渡す API を使う。どうしてもシェル経由が必要なら、入力を"
        "許可リストで厳しく制限する。",
    ),
    "traversal": VulnClass(
        TRAVERSAL_PAYLOADS,
        detect_traversal,
        title="パストラバーサル",
        impact="入力したファイル名が、`../` 等でディレクトリをまたぎ、意図しない場所のファイルを"
        "読まれうる(設定ファイル・秘密情報など)。",
        fix="ファイル名を正規化してから、許可したディレクトリの配下に収まっているか確認する"
        "(`realpath` 等での比較)。",
    ),
    "mass_assignment": VulnClass(
        MASS_ASSIGNMENT_PAYLOADS,
        detect_mass_assignment,
        title="マスアサインメント",
        impact="利用者が送った余分なフィールド(`is_admin` 等)が、そのままモデルやレコードに"
        "反映される。権限の昇格につながりうる。",
        fix="受け取るフィールドを許可リストで明示する(全フィールドをそのまま代入しない)。",
    ),
    "ssrf": VulnClass(
        SSRF_PAYLOADS,
        detect_ssrf,
        reference=(
            "Double Agents: GCP Vertex AI's overly broad default service-account "
            "permissions, reachable via SSRF to the cloud metadata service, abused "
            "for LLMjacking (Unit 42). This repo's R10: "
            "../detections/sigma/r10_metadata_service_credential_access.yml"
        ),
        title="SSRF(サーバーサイドリクエストフォージェリ)",
        impact="サーバー自身に、攻撃者が指定した URL への通信をさせられる。内部ネットワークや"
        "クラウドのメタデータサービスへの到達につながりうる。",
        fix="取得先の URL を許可リストで制限する。内部アドレス・メタデータサービスの"
        "アドレスを明示的に拒否する。",
    ),
    "account_enum": VulnClass(
        ACCOUNT_ENUM_PAYLOADS,
        detect_account_enum,
        title="アカウント列挙",
        impact="登録済みかどうかで応答が変わり、既存のメールアドレス・ユーザー名を外部から"
        "特定されうる(標的型攻撃の下準備になる)。",
        fix="登録済み・未登録にかかわらず、同じ応答(文言・応答時間)を返す。",
    ),
}


# --------------------------------------------------------------------------
# Discovery (static only): read a Flask app's source and list its routes and
# the GET params they read, instead of a human typing --url/--fuzz by hand.
# This is the one part of "target auto-discovery" (see README.ja.md's "this
# is not a lightweight Strix") that is reachable without firing any
# payload: it just reads Python source with ast, it does not import or run
# the app, and it sends no HTTP requests. It still cannot find params a
# route reads by means this doesn't recognize (e.g. request.json, a helper
# function), or routes defined dynamically (add_url_rule in a loop) --
# those still need a human to add --fuzz by hand, same as before.
# --------------------------------------------------------------------------


@dataclass
class DiscoveredRoute:
    path: str
    methods: list[str]
    func_name: str
    params: list[str]


def _route_decorator_info(dec: ast.AST) -> tuple[str, list[str]] | None:
    """Pull (path, methods) out of an @app.route("/x", methods=[...]) call.
    Returns None for anything that isn't shaped like that (e.g. @app.get)."""
    if not isinstance(dec, ast.Call):
        return None
    func = dec.func
    if not (isinstance(func, ast.Attribute) and func.attr == "route"):
        return None
    if not dec.args or not isinstance(dec.args[0], ast.Constant) or not isinstance(dec.args[0].value, str):
        return None
    path = dec.args[0].value
    methods = ["GET"]
    for kw in dec.keywords:
        if kw.arg == "methods" and isinstance(kw.value, ast.List):
            vals = [e.value for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if vals:
                methods = vals
    return path, methods


def _params_read_in(node: ast.AST) -> list[str]:
    """Find request.args.get("x") / request.args["x"] / request.form.get("x")
    style reads inside a route function body. Static text matching only --
    a param read through a helper function, or built from a variable instead
    of a string literal, will not show up here."""
    names: list[str] = []
    for sub in ast.walk(node):
        src = None
        key_node = None
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "get":
            inner = sub.func.value
            if isinstance(inner, ast.Attribute) and inner.attr in ("args", "form", "values"):
                src = inner.attr
                if sub.args:
                    key_node = sub.args[0]
        elif isinstance(sub, ast.Subscript):
            inner = sub.value
            if isinstance(inner, ast.Attribute) and inner.attr in ("args", "form", "values"):
                src = inner.attr
                key_node = sub.slice
        if src is not None and isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            if key_node.value not in names:
                names.append(key_node.value)
    return names


def discover_routes(py_file: str) -> list[DiscoveredRoute]:
    with open(py_file, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=py_file)

    routes: list[DiscoveredRoute] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            info = _route_decorator_info(dec)
            if info is None:
                continue
            path, methods = info
            routes.append(DiscoveredRoute(path, methods, node.name, _params_read_in(node)))
    return routes


def print_discovered_routes(routes: list[DiscoveredRoute], base_url: str) -> None:
    print(f"Discovered {len(routes)} route(s) (static read of the source; nothing was run or requested):\n")
    for r in routes:
        params = ", ".join(r.params) if r.params else "(none found statically)"
        print(f"  {'/'.join(r.methods):10} {r.path}  (def {r.func_name})")
        print(f"    params: {params}")
        if "GET" in r.methods and r.params:
            fuzz = " ".join(f"--fuzz {p}" for p in r.params)
            baseline = " ".join(f"--baseline {p}=zzz" for p in r.params)
            print(
                f"    next step (human decides --class; this prints the command, it does not run it):\n"
                f"      python3 auto_vuln_scanner.py --url {base_url}{r.path} --class <sqli|xss|...> "
                f"{baseline} {fuzz}"
            )
        print()


# --------------------------------------------------------------------------
# Discovery (dynamic): actually browse the running app -- plain GET requests
# only, following <a href> links and reading (never submitting) <form>
# elements -- to find pages and GET params without reading the source. This
# is the "crawling/browsing" half of Strix's auto-discovery that --discover
# (static, source-only) cannot do: it only sees what a route handler
# generates and links to at runtime, which can differ from what's in the
# source (e.g. conditionally-rendered links). It still sends no attack
# payload and submits no form, so it is not itself a vulnerability scan --
# only an automated version of a human clicking around.
# --------------------------------------------------------------------------


class _LinkFormParser(HTMLParser):
    """Pulls <a href=...> targets and <form> actions/methods/input-names out
    of one page of HTML. Deliberately simple (stdlib only, no bs4): good
    enough for this lab's plain HTML, not a full browser-grade parser."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = a.get("name")
            if name:
                self._current_form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


@dataclass
class CrawledPage:
    url: str
    status: int
    params: list[str]  # from this page's own URL query string, if any
    forms: list[dict]


def crawl(base_url: str, max_pages: int = 25) -> list[CrawledPage]:
    """Breadth-first, same-host crawl starting at base_url. GET requests
    only -- no form is ever submitted, no attack payload is ever sent.
    Stays in scope (checked once up front by the caller via
    _is_allowed_target, same guard as the payload-firing scan)."""
    seen: set[str] = set()
    queue: list[str] = [base_url]
    host = urlparse(base_url).netloc
    pages: list[CrawledPage] = []

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = requests.get(url, timeout=5)
        except requests.RequestException:
            continue
        parsed = urlparse(url)
        own_params = sorted(set(p.split("=", 1)[0] for p in parsed.query.split("&") if p))
        parser = _LinkFormParser()
        if "html" in resp.headers.get("Content-Type", ""):
            parser.feed(resp.text)
        pages.append(CrawledPage(url, resp.status_code, own_params, parser.forms))
        for href in parser.links:
            next_url = urljoin(url, href)
            if urlparse(next_url).netloc == host and next_url not in seen:
                queue.append(next_url)

    return pages


def print_crawled_pages(pages: list[CrawledPage]) -> None:
    print(
        f"Crawled {len(pages)} page(s) (GET requests only, no form was submitted, "
        "no attack payload was sent):\n"
    )
    for p in pages:
        print(f"  {p.status} {p.url}")
        if p.params:
            print(f"    query params seen in this URL: {', '.join(p.params)}")
        for f in p.forms:
            inputs = ", ".join(f["inputs"]) if f["inputs"] else "(none found)"
            print(f"    form: method={f['method']} action={f['action'] or '(same page)'} inputs: {inputs}")
        print()
    if len(pages) <= 1:
        print(
            "Note: this found nothing beyond the seed URL. A target with no navigable "
            "<a href> links or <form> elements from its seed page (e.g. a flat set of "
            "independent API-style endpoints, as in this lab's vulnerable_app.py) cannot "
            "be discovered by browsing -- use --discover (reads the source) instead.\n"
        )


@dataclass
class Finding:
    param: str
    payload: str
    reason: str
    response_snippet: str = field(repr=False)
    status_code: int = 0
    baseline_status_code: int = 0


@dataclass
class TargetAssessment:
    status_code: int
    elapsed_ms: float
    content_length: int
    server: str
    powered_by: str
    content_type: str


def assess_target(url: str, base_params: dict[str, str]) -> TargetAssessment:
    """Baseline probe before firing any attack payload. Separates "target is
    down/misconfigured" (this raises) from "scanned fine, found nothing"
    (the actual scan below), and surfaces enough about the target (status,
    size, Server/X-Powered-By) to sanity-check --baseline/--url before
    trusting a "no indicators found" result."""
    resp = requests.get(url, params=base_params, timeout=10)
    return TargetAssessment(
        status_code=resp.status_code,
        elapsed_ms=resp.elapsed.total_seconds() * 1000,
        content_length=len(resp.content),
        server=resp.headers.get("Server", "(none)"),
        powered_by=resp.headers.get("X-Powered-By", "(none)"),
        content_type=resp.headers.get("Content-Type", "(none)"),
    )


def print_target_assessment(a: TargetAssessment) -> None:
    print("Target assessment:")
    print(f"  status={a.status_code} size={a.content_length}B time={a.elapsed_ms:.0f}ms content-type={a.content_type!r}")
    print(f"  Server={a.server!r} X-Powered-By={a.powered_by!r}")
    if a.status_code >= 400:
        print(
            f"  warning: baseline request returned {a.status_code} -- findings below may be "
            "unreliable (check --baseline params and --url path)"
        )
    for warning in (
        check_php2shell(a.powered_by),
        check_apache_http2(a.server),
        check_nginx_rewrite(a.server),
    ):
        if warning:
            print(f"  warning: {warning}")


def probe(
    url: str, base_params: dict[str, str], param: str, payload: str
) -> requests.Response:
    params = dict(base_params)
    params[param] = payload
    return requests.get(url, params=params, timeout=10)


def scan(
    url: str,
    base_params: dict[str, str],
    fuzz_params: list[str],
    vuln_class: VulnClass,
    on_finding: Callable[[Finding], None] | None = None,
) -> list[Finding]:
    """on_finding, if given, is called the moment each finding is confirmed --
    i.e. during the scan, not after it finishes (see --stream/--report-dir).
    This is still only a local callback (print / write a file): no network
    call to any third-party notification service is made here."""
    baseline = requests.get(url, params=base_params, timeout=10)

    findings: list[Finding] = []
    for param in fuzz_params:
        for payload in vuln_class.payloads:
            resp = probe(url, base_params, param, payload)
            reason = vuln_class.detect(resp, baseline, payload)
            if reason:
                f = Finding(param, payload, reason, resp.text, resp.status_code, baseline.status_code)
                findings.append(f)
                if on_finding:
                    on_finding(f)

    return findings


# --------------------------------------------------------------------------
# Streaming + structured report ("即時報告" / "構造化レポート"). Local only:
# an event is a JSON Lines line (stdout, and/or a file under --report-dir);
# forwarding it to Slack/a ticket system is left to whoever reads that line
# or file -- this script does not call any such service itself.
# --------------------------------------------------------------------------


def make_finding_event(class_name: str, vuln_class: VulnClass, url: str, idx: int, f: Finding) -> dict:
    return {
        "id": f"F-{idx:02d}",
        "type": "finding",
        "class": class_name,
        "title": vuln_class.title or class_name,
        "url": url,
        "param": f.param,
        "payload": f.payload,
        "reason": f.reason,
        "status_code": f.status_code,
        "baseline_status_code": f.baseline_status_code,
    }


def print_finding_event_line(event: dict) -> None:
    """One compact JSON object per line (JSON Lines), printed the moment a
    finding is confirmed -- not buffered until the scan ends. Pipe this to
    whatever you want notified; this script itself sends it nowhere."""
    print(json.dumps(event, ensure_ascii=False), flush=True)


def render_finding_report_md(class_name: str, vuln_class: VulnClass, url: str, idx: int, f: Finding) -> str:
    """A single finding as a structured Markdown report: ID, 内容, 種類,
    重大度, 影響, 再現手順, 修正方針. 重大度 is not computed here (this tool
    doesn't rank classes against each other) -- left as a field to fill in
    by hand, same as this repo's other reports (SARIF/vuln_triage.html)."""
    report_id = f"F-{idx:02d}"
    title = vuln_class.title or class_name
    payload_text = f.payload.replace("\n", "\\n")
    repro = (
        f"1. `{url}` に、`{f.param}={payload_text}` を含めて GET リクエストを送る\n"
        f"2. 応答を確認する: ベースライン(通常の入力)は status={f.baseline_status_code}、"
        f"この入力では status={f.status_code}\n"
        f"3. 検出の根拠: {f.reason}"
    )
    lines = [
        f"# {report_id}: {title}",
        "",
        f"- **対象 URL**: `{url}`",
        f"- **パラメータ**: `{f.param}`",
        f"- **種類**: {class_name}",
        f"- **重大度**: (手動で記入。この道具は、クラス間の優劣をつけない)",
        "",
        "## 影響",
        "",
        vuln_class.impact,
        "",
        "## 再現手順",
        "",
        repro,
        "",
        "## 応答の抜粋(検出の根拠になった部分を含む可能性。中身は機微情報を含みうるので、"
        "公開前に確認すること)",
        "",
        "```",
        f.response_snippet[:800],
        "```",
        "",
        "## 修正方針",
        "",
        vuln_class.fix,
    ]
    if vuln_class.reference:
        lines += ["", "## 参考(実際の事例)", "", vuln_class.reference]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Optional LLM use ("未知のパターンへの適応" / "汎用性" in README.ja.md's
# "this is not a lightweight Strix" section). Off by default -- nothing
# above this point needs an LLM, and plain `--url/--class/--fuzz` behaves
# exactly as before. This section is additive: it either (a) asks an LLM
# for MORE payload strings for an EXISTING, already-reviewed class (the
# verdict is still the existing deterministic detect_*() function -- see
# ../ai-sast-trial-notes.md for why letting an LLM judge its own findings
# is unreliable: it has dismissed real vulnerabilities as false positives
# in repeated runs here), or (b) lets the LLM define a brand-new class by
# name, but only by filling in a small, fixed set of safe, parametrized
# detection *types* below -- it never supplies code that gets executed.
# Treat any --llm-class result with the same caution as an AI-SAST verdict:
# it is unreviewed and has not been checked against a known-vulnerable
# target the way the 11 built-in classes have (see "実証した攻撃" above).
# --------------------------------------------------------------------------

LLM_CAUTION_NOTE = (
    "caution: this class/these payloads came from an LLM and are UNREVIEWED -- "
    "unlike the 11 built-in classes, nobody has confirmed them against a known-"
    "vulnerable target. See ../ai-sast-trial-notes.md: this project's own trials "
    "found LLM judgment unreliable (false positives, and real vulnerabilities "
    "dismissed) across repeated runs of the same model."
)


def ask_llm(base_url: str, model: str, api_key: str, system: str, user: str, timeout: float = 120.0) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    if not url.lower().startswith(("http://", "https://")):  # file:// など、http 以外は拒否する
        raise ValueError("--llm-url は http:// か https:// で始めてください: %s" % base_url)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    body = {
        "model": model,
        "stream": False,
        "temperature": 0.2,
        "max_tokens": 700,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    resp = requests.post(url, json=body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    choices = resp.json().get("choices") or []
    if not choices:
        return ""
    return (choices[0].get("message") or {}).get("content") or ""


_JSON_FENCE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.S)
_MAX_LLM_PAYLOADS = 10
_MAX_PAYLOAD_LEN = 300
_MAX_MARKER_LEN = 200


def _extract_json(text: str) -> dict | None:
    m = _JSON_FENCE.search(text or "")
    candidate = m.group(1) if m else text
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return None


def llm_suggest_payloads(
    base_url: str, model: str, api_key: str, class_name: str, existing_payloads: list[str], count: int = 5
) -> list[str]:
    """Ask the LLM for extra payload strings for an EXISTING class, to try
    alongside (not instead of) the fixed list. Judgment still uses that
    class's own deterministic detect_*() -- the LLM only supplies strings."""
    system = (
        "You suggest short HTTP query-parameter attack payload strings for an "
        "authorized security test of a system the tester owns. Reply with ONLY "
        "the payload strings, one per line, no numbering, no explanation, no code fences."
    )
    user = (
        f"Vulnerability class: {class_name}\n"
        f"Existing payloads already tested (do not repeat these): {existing_payloads}\n"
        f"Give {count} different, short payload strings to additionally try for this class."
    )
    text = ask_llm(base_url, model, api_key, system, user)
    out: list[str] = []
    for line in text.splitlines():
        p = line.strip().strip("`").lstrip("-*0123456789. ").strip()
        if p and len(p) <= _MAX_PAYLOAD_LEN and p not in existing_payloads and p not in out:
            out.append(p)
        if len(out) >= count:
            break
    return out


# Fixed, safe detection types an LLM-defined class can pick from. Each is
# real, reviewed Python -- the LLM only supplies the small set of string/
# number parameters named in SAFE_DETECT_TYPES below, never code.
SAFE_DETECT_TYPES = {
    "reflected_marker": "marker (str) appears verbatim in the response body but not the baseline",
    "error_marker": "marker (str) appears in the response body but not the baseline (error/leak text)",
    "status_flip": "response status code differs from the baseline's status code",
    "length_diff": "response body length differs from the baseline's by more than ratio (float, default 0.5)",
}


def _make_llm_detect(cfg: dict) -> Callable[[requests.Response, requests.Response, str], str | None]:
    dtype = cfg.get("type")
    marker = cfg.get("marker")
    if isinstance(marker, str):
        marker = marker[:_MAX_MARKER_LEN]
    try:
        ratio = float(cfg.get("ratio", 0.5))
    except (TypeError, ValueError):
        ratio = 0.5

    def detect(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
        if dtype in ("reflected_marker", "error_marker") and isinstance(marker, str) and marker:
            if marker in resp.text and marker not in baseline.text:
                kind = "reflected" if dtype == "reflected_marker" else "error/leak text"
                return f"llm-defined ({kind}): {marker!r} seen in response, not in baseline"
            return None
        if dtype == "status_flip":
            if resp.status_code != baseline.status_code:
                return f"llm-defined (status flip): baseline={baseline.status_code} payload={resp.status_code}"
            return None
        if dtype == "length_diff":
            base_len = max(len(baseline.content), 1)
            if abs(len(resp.content) - base_len) / base_len > ratio:
                return f"llm-defined (length diff): baseline={base_len}B payload={len(resp.content)}B"
            return None
        return None  # unknown/malformed type: never matches, rather than guessing

    return detect


def llm_propose_class(base_url: str, model: str, api_key: str, class_name: str) -> VulnClass | None:
    """Ask the LLM to define a brand-new class: payload strings + ONE of the
    SAFE_DETECT_TYPES above, as data. We never eval/exec anything the LLM
    returns -- only the fixed, reviewed functions in _make_llm_detect()
    actually run, parametrized by the (size-capped) strings the LLM gives."""
    system = (
        "You help define an authorized security test for a system the tester owns. "
        "Reply with ONLY a single JSON object (no prose, no code fences), shaped exactly as:\n"
        '{"payloads": ["...", "..."], "detect": {"type": "<one of: '
        + ", ".join(SAFE_DETECT_TYPES) + '>", "marker": "...", "ratio": 0.5}}\n'
        "\"marker\" is only used by reflected_marker/error_marker (a short string to look for "
        "in the response, such as a canary value your payloads embed, or an error-message "
        "fragment). \"ratio\" is only used by length_diff. Omit fields a type does not use."
    )
    user = f"Vulnerability class to test for: {class_name}\nGive up to {_MAX_LLM_PAYLOADS} payload strings."
    text = ask_llm(base_url, model, api_key, system, user)
    data = _extract_json(text)
    if not isinstance(data, dict):
        print(f"llm-class: model did not return parseable JSON, refusing to guess:\n{text[:500]}", file=sys.stderr)
        return None
    payloads = [p for p in data.get("payloads", []) if isinstance(p, str) and p][:_MAX_LLM_PAYLOADS]
    payloads = [p[:_MAX_PAYLOAD_LEN] for p in payloads]
    detect_cfg = data.get("detect")
    if not payloads or not isinstance(detect_cfg, dict) or detect_cfg.get("type") not in SAFE_DETECT_TYPES:
        print(
            "llm-class: response missing payloads or a recognized detect.type "
            f"(got: {detect_cfg!r}), refusing to guess.",
            file=sys.stderr,
        )
        return None
    return VulnClass(
        payloads,
        _make_llm_detect(detect_cfg),
        title=class_name,
        impact="LLM が提案した、未レビューのクラス。実際の影響は、指摘ごとに人が確認すること。",
        fix="指摘ごとに、該当コードを読んで判断する(固定の対策は無い)。",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--discover",
        metavar="APP.PY",
        help="static-only: read this Flask app's source and list its routes/params "
        "(ast parse, no import, no HTTP request, no payload sent) instead of scanning. "
        "All other flags except --base-url are ignored in this mode.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5000",
        help="with --discover, the base URL to print in the suggested next-step command "
        "(default: http://127.0.0.1:5000)",
    )
    parser.add_argument(
        "--crawl",
        metavar="SEED_URL",
        help="dynamic: browse the running app from this URL (GET requests only, no form "
        "is submitted, no attack payload is sent) and list the pages/forms/params found. "
        "Scope-checked the same way as a scan, unless --i-own-this-target is passed.",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=25,
        help="with --crawl, stop after visiting this many pages (default 25)",
    )
    parser.add_argument("--url", help="e.g. http://127.0.0.1:5000/search")
    parser.add_argument(
        "--class",
        dest="vuln_class_name",
        choices=sorted(VULN_CLASSES),
        help="vulnerability class to test for",
    )
    parser.add_argument(
        "--baseline",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="known-benign baseline param, repeatable, e.g. --baseline q=zzz",
    )
    parser.add_argument(
        "--fuzz",
        action="append",
        help="param name to fuzz, repeatable, e.g. --fuzz q",
    )
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="override the localhost/RFC1918-only scope check; only use this "
        "against a target you actually own or are explicitly authorized to test",
    )
    parser.add_argument(
        "--llm-payloads",
        action="store_true",
        help="with --class, also ask the LLM for extra payload strings to try alongside the "
        "fixed list. Judgment still uses that class's existing, reviewed detect_*() -- the "
        "LLM only supplies strings, never a verdict. Requires --llm-url/--llm-model.",
    )
    parser.add_argument(
        "--llm-class",
        metavar="NAME",
        help="instead of --class, give the LLM a free-text vulnerability class name/description "
        "and let it define payloads + ONE of a fixed set of safe detection types (see "
        f"SAFE_DETECT_TYPES: {', '.join(SAFE_DETECT_TYPES)}). UNREVIEWED -- see the caution "
        "note this prints before any finding. Requires --llm-url/--llm-model.",
    )
    parser.add_argument(
        "--llm-url",
        default="http://127.0.0.1:11434/v1",
        help="OpenAI-compatible chat/completions base URL for --llm-payloads/--llm-class "
        "(default: a local Ollama server, http://127.0.0.1:11434/v1)",
    )
    parser.add_argument("--llm-model", default="qwen2.5-coder:3b", help="model name for the LLM endpoint")
    parser.add_argument("--llm-api-key", default=os.environ.get("LLM_API_KEY", ""), help="optional bearer token")
    parser.add_argument(
        "--llm-count", type=int, default=5, help="with --llm-payloads, how many extra payloads to request"
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="print each finding as a JSON Lines event the moment it is confirmed, during the "
        "scan -- not only in the summary printed after it finishes. This script sends the line "
        "nowhere itself; pipe it to whatever you want notified.",
    )
    parser.add_argument(
        "--report-dir",
        metavar="DIR",
        help="also write one structured Markdown report per finding into this directory "
        "(F-01.md, F-02.md, ...: 内容/種類/影響/再現手順/修正方針), written as each finding is "
        "confirmed, not only at the end. Directory is created if missing.",
    )
    args = parser.parse_args()

    if args.discover:
        routes = discover_routes(args.discover)
        print_discovered_routes(routes, args.base_url.rstrip("/"))
        return 0

    if args.crawl:
        if not args.i_own_this_target:
            allowed, reason = _is_allowed_target(args.crawl)
            if not allowed:
                print(f"Refusing to crawl: {reason}", file=sys.stderr)
                return 2
        pages = crawl(args.crawl, max_pages=args.max_pages)
        print_crawled_pages(pages)
        return 0

    if not args.url or not (args.vuln_class_name or args.llm_class) or not args.fuzz:
        parser.error(
            "--url, (--class or --llm-class) and --fuzz are required unless --discover/--crawl is used"
        )
    if args.vuln_class_name and args.llm_class:
        parser.error("--class and --llm-class are mutually exclusive")

    if not args.i_own_this_target:
        allowed, reason = _is_allowed_target(args.url)
        if not allowed:
            print(f"Refusing to scan: {reason}", file=sys.stderr)
            return 2

    base_params = dict(kv.split("=", 1) for kv in args.baseline)

    if args.llm_class:
        vuln_class = llm_propose_class(args.llm_url, args.llm_model, args.llm_api_key, args.llm_class)
        if vuln_class is None:
            return 2
        class_label = f"{args.llm_class} (llm-defined)"
        print(f"*** {LLM_CAUTION_NOTE} ***")
    else:
        vuln_class = VULN_CLASSES[args.vuln_class_name]
        class_label = args.vuln_class_name
        if args.llm_payloads:
            extra = llm_suggest_payloads(
                args.llm_url, args.llm_model, args.llm_api_key, args.vuln_class_name,
                vuln_class.payloads, args.llm_count,
            )
            if extra:
                print(f"LLM suggested {len(extra)} extra payload(s) for {args.vuln_class_name}: {extra}")
                print(f"*** {LLM_CAUTION_NOTE} (payloads only -- judgment is still {args.vuln_class_name}'s own rule) ***")
                vuln_class = VulnClass(
                    vuln_class.payloads + extra, vuln_class.detect, vuln_class.reference,
                    vuln_class.title, vuln_class.impact, vuln_class.fix,
                )
            else:
                print("LLM suggested no usable extra payloads (empty/unparseable reply); using the fixed list only.")

    print(f"Target: {args.url}")
    print(f"Vulnerability class: {class_label}")
    print(f"Baseline params: {base_params}")
    print(f"Fuzzing params: {args.fuzz}")
    print(f"Payload count: {len(vuln_class.payloads)}")
    print("-" * 60)

    try:
        assessment = assess_target(args.url, base_params)
    except requests.RequestException as exc:
        print(f"Target assessment failed -- aborting before firing any payload: {exc}", file=sys.stderr)
        return 2
    print_target_assessment(assessment)
    print("-" * 60)

    class_key = args.llm_class if args.llm_class else args.vuln_class_name
    report_count = [0]  # mutable counter for closure; report IDs run 1.. across this scan

    if args.report_dir:
        os.makedirs(args.report_dir, exist_ok=True)

    def on_finding(f: Finding) -> None:
        report_count[0] += 1
        idx = report_count[0]
        if args.stream:
            print_finding_event_line(make_finding_event(class_key, vuln_class, args.url, idx, f))
        if args.report_dir:
            path = os.path.join(args.report_dir, f"F-{idx:02d}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render_finding_report_md(class_key, vuln_class, args.url, idx, f))

    findings = scan(
        args.url, base_params, args.fuzz, vuln_class,
        on_finding=on_finding if (args.stream or args.report_dir) else None,
    )

    if not findings:
        print("No indicators found with this payload set.")
        return 0

    print(f"{len(findings)} finding(s):\n")
    for f in findings:
        print(f"  param={f.param!r} payload={f.payload!r}")
        print(f"    reason: {f.reason}")
        print()

    if vuln_class.reference:
        print(f"Related real-world incident: {vuln_class.reference}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
