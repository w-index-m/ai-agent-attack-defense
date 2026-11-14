#!/usr/bin/env python3
"""cloud_audit_check: クラウド・CIの監査ログ(JSON)を読み、乗っ取り・痕跡消しの兆候を探す(確認専用、読み取りのみ)。

**【下書き・未検証】** イベント名とフィールド名は、AWS CloudTrail・Google Cloud の監査ログ・GitHub の監査ログの
公開されている形式についての知識に基づいて書いたもので、**本物のログでは確かめていない**(このセッションには、
実際のログが無い)。合成ログでの確認だけで、「本物のログで動く」ことの証拠ではない。お使いの環境のログで、
(1) 対象のイベントが期待どおりの名前・形で出るか、(2) 普段の操作でどれだけ出る(誤検知)か、を確かめてから使う。
昇格の条件は security-scan/cloud-audit-check-notes.md。

背景(どの観測に基づくか):
  - GTIG の2026年9月のレポート(利用者が貼り付けた本文に基づく)の、Mandiant のインシデント対応の事例:
    露出した GitHub の PAT からクラウドに侵入し、全員公開(allUsers)の Cloud Run に AI 基盤を展開、
    Editor 権限の不正なサービスアカウントを作ってキーを書き出し、GPU の割り当て引き上げを要求、
    AI 系 API を有効化。別のマルウェアは、GitHub Actions の実行ログを API で削除。
  - GTIG の「ARTEX and Friends」(2026-10-30)の記事: 新しい SSH キーペア・Elastic IP・ロールつきの踏み台
    インスタンス、アカウントの作成、ドライラン(権限の探り)の連発、**ID単位の数秒〜数十秒の大量操作**。

対応するログ(形式は自動判別。JSON配列・JSON Lines・CloudTrailの {"Records": [...]} のどれでも):
  AWS CloudTrail / Google Cloud 監査ログ(Cloud Logging のエントリ) / GitHub の監査ログ(エクスポートした JSON)

探すもの(ID は画面の表示用で、detections/ の R番号とは別。下書きなので、R番号は付けていない):
  CLOUD-AWS-1  新しいアクセス手段の作成(キーペア・アクセスキー・ログインプロファイル・ユーザー・Elastic IP)
  CLOUD-AWS-2  IAMロール(インスタンスプロファイル)つきのインスタンス起動
  CLOUD-GCP-1  サービスアカウントの作成・キーの書き出し
  CLOUD-GCP-2  リソースの全員公開(allUsers / allAuthenticatedUsers への付与)
  CLOUD-GCP-3  高権限ロール(owner / editor)の付与
  CLOUD-GCP-4  AI 系 API(generativelanguage / aiplatform)の有効化
  CLOUD-GCP-5  割り当て(クオータ)の引き上げ要求
  CLOUD-GH-1   ワークフロー実行の削除(痕跡消しの可能性)
  CLOUD-BURST  同じ ID の短時間の大量操作(既定: 30秒以内に25件以上)
  CLOUD-DRYRUN 同じ ID のドライラン失敗(Client.DryRunOperation)の連発(既定: 30秒以内に5件以上)

正直な限界:
  - 上のとおり、実ログで未確認。ID単位のバーストは、ベースライン(普段の量)が無いと、自動化(CI・IaC)と区別できない。
    --allow-principal で、既知の自動化のIDを外す。
  - GCP の SetIamPolicy は、記録の形がサービスごとに違い得る。bindingDeltas(追加された分)が無い形では、
    owner/editor の付与は判定できない(allUsers は、ポリシー全体に含まれるかで、弱く判定する)。
  - 画像のような、ログに出ない操作は見えない。

使用例:
  python3 scripts/cloud_audit_check.py --log-path cloudtrail.json
  python3 scripts/cloud_audit_check.py --log-path audit.jsonl --allow-principal terraform --burst-events 40
終了コード: 0(見つからなかった) / 1(見つかった) / 2(読み取りエラー)
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

AWS_NEW_ACCESS = {"CreateKeyPair", "ImportKeyPair", "AllocateAddress", "CreateAccessKey", "CreateLoginProfile",
                  "UpdateLoginProfile", "CreateUser"}
GCP_AI_APIS = ("generativelanguage.googleapis.com", "aiplatform.googleapis.com")
GH_RUN_DELETE = {"workflows.delete_workflow_run", "workflows.delete_workflow_run_logs"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
HIGH_ROLES = {"roles/owner", "roles/editor"}
LABELS = {
    "CLOUD-AWS-1": ("medium", "新しいアクセス手段の作成(キーペア・アクセスキー・ログインプロファイル・ユーザー・Elastic IP)"),
    "CLOUD-AWS-2": ("low", "IAMロール(インスタンスプロファイル)つきのインスタンス起動"),
    "CLOUD-GCP-1": ("medium", "サービスアカウントの作成・キーの書き出し"),
    "CLOUD-GCP-2": ("high", "リソースの全員公開(allUsers / allAuthenticatedUsers)"),
    "CLOUD-GCP-3": ("high", "高権限ロール(owner / editor)の付与"),
    "CLOUD-GCP-4": ("medium", "AI 系 API の有効化"),
    "CLOUD-GCP-5": ("medium", "割り当て(クオータ)の引き上げ要求"),
    "CLOUD-GH-1": ("medium", "ワークフロー実行の削除(痕跡消しの可能性)"),
    "CLOUD-BURST": ("medium", "同じ ID の短時間の大量操作"),
    "CLOUD-DRYRUN": ("medium", "同じ ID のドライラン失敗の連発(権限の探りの可能性)"),
}


def parse_ts(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return v / 1000.0 if v > 1e11 else float(v)
    m = re.match(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)?$", str(v).strip())
    if not m:
        return None
    digits = ((m.group(3) or "")[1:] + "000000")[:6] if m.group(3) else ""
    tz = m.group(4) or "Z"
    tz = "+00:00" if tz == "Z" else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
    try:
        return datetime.fromisoformat("%sT%s%s%s" % (m.group(1), m.group(2), ("." + digits) if digits else "", tz)).timestamp()
    except ValueError:
        return None


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


def get(d, *keys):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def normalize(e):
    """生のイベント(辞書)を共通の形にする。判別できなければ None。"""
    if not isinstance(e, dict):
        return None
    if "eventName" in e and "eventSource" in e:
        ui = e.get("userIdentity") or {}
        return {"provider": "aws", "name": str(e["eventName"]), "ts": parse_ts(e.get("eventTime")),
                "principal": ui.get("arn") or ui.get("principalId") or ui.get("userName") or "(不明)",
                "error": e.get("errorCode"), "raw": e}
    if isinstance(e.get("protoPayload"), dict):
        pp = e["protoPayload"]
        return {"provider": "gcp", "name": str(pp.get("methodName", "")), "ts": parse_ts(e.get("timestamp")),
                "principal": get(pp, "authenticationInfo", "principalEmail") or "(不明)", "error": None, "raw": e}
    if "action" in e and ("actor" in e or "@timestamp" in e or "created_at" in e):
        return {"provider": "github", "name": str(e["action"]), "ts": parse_ts(e.get("@timestamp") or e.get("created_at")),
                "principal": str(e.get("actor") or e.get("actor_login") or "(不明)"), "error": None, "raw": e}
    return None


def load_events(path):
    """(正規化したイベントのリスト, 読めなかった行数)"""
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    raws, bad = [], 0
    try:
        data = json.loads(text)
        raws = data["Records"] if isinstance(data, dict) and isinstance(data.get("Records"), list) else (
            data if isinstance(data, list) else [data])
    except ValueError:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                raws.append(json.loads(line))
            except ValueError:
                bad += 1
    events = []
    for i, r in enumerate(raws, 1):
        ev = normalize(r)
        if ev:
            ev["line"] = i
            events.append(ev)
    return events, bad


def rule_hits(ev):
    """1イベントが当たる規則のIDのリスト。"""
    hits, name, raw = [], ev["name"], ev["raw"]
    if ev["provider"] == "aws":
        if name in AWS_NEW_ACCESS:
            hits.append("CLOUD-AWS-1")
        if name == "RunInstances" and get(raw, "requestParameters", "iamInstanceProfile"):
            hits.append("CLOUD-AWS-2")
    elif ev["provider"] == "gcp":
        pp = raw["protoPayload"]
        if name.endswith(".CreateServiceAccountKey") or name.endswith(".CreateServiceAccount"):
            hits.append("CLOUD-GCP-1")
        if name.endswith("SetIamPolicy"):
            deltas = get(pp, "serviceData", "policyDelta", "bindingDeltas")
            if isinstance(deltas, list):
                added = [d for d in deltas if isinstance(d, dict) and d.get("action") == "ADD"]
                if any(d.get("member") in PUBLIC_MEMBERS for d in added):
                    hits.append("CLOUD-GCP-2")
                if any(d.get("role") in HIGH_ROLES for d in added):
                    hits.append("CLOUD-GCP-3")
            elif any(s in PUBLIC_MEMBERS for s in strings(pp.get("request"))):
                hits.append("CLOUD-GCP-2")  # 追加か既存かは判別できない(ポリシー全体に含まれる)
        if name.endswith(".EnableService") or name.endswith(".BatchEnableServices"):
            if any(api in s for s in strings(pp.get("request")) for api in GCP_AI_APIS):
                hits.append("CLOUD-GCP-4")
        if name.endswith(".CreateQuotaPreference") or name.endswith(".UpdateQuotaPreference"):
            hits.append("CLOUD-GCP-5")
    elif ev["provider"] == "github" and name in GH_RUN_DELETE:
        hits.append("CLOUD-GH-1")
    return hits


def window_hits(times, window, need):
    """ソート済みの時刻のうち、window 秒以内に need 件以上が入る最初の時刻(無ければ None)。"""
    j = 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        if i - j + 1 >= need:
            return t
    return None


def scan(events, allow=(), burst_events=25, burst_seconds=30, dryrun_events=5):
    hits = []
    kept = [e for e in events if not any(a in e["principal"] for a in allow)]
    for ev in kept:
        for rid in rule_hits(ev):
            hits.append({"rule": rid, "principal": ev["principal"], "name": ev["name"], "line": ev["line"], "ts": ev["ts"]})
    by_pr, by_pr_dry = defaultdict(list), defaultdict(list)
    for ev in kept:
        if ev["ts"] is None:
            continue
        by_pr[(ev["provider"], ev["principal"])].append(ev["ts"])
        if ev["error"] == "Client.DryRunOperation":
            by_pr_dry[(ev["provider"], ev["principal"])].append(ev["ts"])
    for rid, table, need in (("CLOUD-BURST", by_pr, burst_events), ("CLOUD-DRYRUN", by_pr_dry, dryrun_events)):
        for (prov, pr), times in table.items():
            t = window_hits(sorted(times), burst_seconds, need)
            if t is not None:
                hits.append({"rule": rid, "principal": pr, "name": "(%d件以上 / %d秒)" % (need, burst_seconds), "line": 0, "ts": t})
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log-path", required=True, help="監査ログ(JSON配列・JSON Lines・CloudTrailのRecords形式)")
    ap.add_argument("--allow-principal", action="append", default=[], help="除外するIDに含まれる文字列(例: terraform)。繰り返し指定可")
    ap.add_argument("--burst-events", type=int, default=25)
    ap.add_argument("--burst-seconds", type=float, default=30)
    ap.add_argument("--dryrun-events", type=int, default=5)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        events, bad = load_events(a.log_path)
    except OSError as e:
        print("%s の読み取りに失敗しました: %s" % (a.log_path, e), file=sys.stderr)
        return 2
    print("対象ログ: %s (%d イベント。読めなかった行: %d)" % (a.log_path, len(events), bad))
    print("【下書き・未検証】実際のログでの確認が必要です(--help)。")
    print("-" * 60)
    hits = scan(events, a.allow_principal, a.burst_events, a.burst_seconds, a.dryrun_events)
    if not hits:
        print("対象の兆候は見つかりませんでした。")
        return 0
    order = {"high": 0, "medium": 1, "low": 2}
    for h in sorted(hits, key=lambda h: (order[LABELS[h["rule"]][0]], h["rule"], h["line"])):
        sev, label = LABELS[h["rule"]]
        print("  [%s] (%s) %s -> %s %s%s" % (h["rule"], sev, label, h["principal"], h["name"],
                                          (" (行/件 %d)" % h["line"]) if h["line"] else ""))
    print("\n計 %d 件。見つかったものは「調べる手がかり」で、悪意の証明ではありません。" % len(hits))
    return 1


if __name__ == "__main__":
    sys.exit(main())
