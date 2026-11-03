#!/usr/bin/env python3
"""audit_log: 改ざんを検知できる、追記専用の監査ログ(ハッシュ連鎖のJSON Lines)。

各行(1件の記録)は、1つ前の行のハッシュ(prev)を含んだ内容から計算したハッシュ(hash)を持つ。
途中の行を書き換えたり、削除・挿入したりすると、その行以降の連鎖が合わなくなり、verify で検知できる。

正直な限界:
  - 「改ざんできない」ではなく「改ざんを検知できる」。ファイルに書き込める者は、連鎖全体を
    最初から計算し直せば、つじつまの合うログを作れてしまう。
  - 末尾の数行をまとめて削除する(切り詰める)と、残った部分の連鎖は正しいままなので検知できない。
  - これらへの対策が「外部アンカー」: `head` で表示される番号とハッシュを、ログとは別の場所
    (チケット、メール、紙など)に控えておき、後で `verify --expect-seq N --expect-hash H` で
    その時点までのログが変わっていないことを確かめる。
  - プロセス内では排他しているが、複数のプロセスが同じファイルに同時に書くことは想定していない
    (部品ごとに別のファイルを使う)。

使い方:
    python scripts/audit_log.py verify results/local-scan/audit.jsonl
    python scripts/audit_log.py head   results/local-scan/audit.jsonl
    python scripts/audit_log.py verify results/local-scan/audit.jsonl --expect-seq 12 --expect-hash <hash>
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import hashlib
import json
import os
import sys
import threading
import time

GENESIS = "0" * 64
_LOCK = threading.Lock()


def _canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _compute_hash(entry):
    """hash 以外の全フィールド(prev を含む)から計算する。"""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _last_state(path):
    seq, last_hash = 0, GENESIS
    if not os.path.exists(path):
        return seq, last_hash
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entry = json.loads(line)
                seq, last_hash = entry["seq"], entry["hash"]
    return seq, last_hash


def append(path, event):
    """event(辞書)に seq・ts・prev・hash を付けて1行追記し、書いた内容を返す。"""
    with _LOCK:
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        seq, prev = _last_state(path)
        entry = dict(event)
        entry["seq"] = seq + 1
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry["prev"] = prev
        entry["hash"] = _compute_hash(entry)
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(_canonical(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry


def verify(path, expect_seq=None, expect_hash=None):
    """ログ全体を検証する。戻り値: (ok, 件数, 問題点のリスト, 最後のハッシュ)。"""
    problems = []
    prev, expected_seq, count = GENESIS, 1, 0
    anchor_seen = expect_seq is None
    if not os.path.exists(path):
        return False, 0, ["ファイルがありません: %s" % path], GENESIS
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                problems.append("%d行目: JSONとして読めません" % lineno)
                break
            count += 1
            if entry.get("seq") != expected_seq:
                problems.append("%d行目: 番号が連続していません(期待 %d、実際 %s)" % (lineno, expected_seq, entry.get("seq")))
            if entry.get("prev") != prev:
                problems.append("%d行目: 前の行とのつながり(prev)が合いません(削除・挿入・並べ替えの可能性)" % lineno)
            if entry.get("hash") != _compute_hash(entry):
                problems.append("%d行目: 内容とハッシュが合いません(書き換えの可能性)" % lineno)
            if expect_seq is not None and entry.get("seq") == expect_seq:
                anchor_seen = True
                if entry.get("hash") != expect_hash:
                    problems.append("%d行目: 控えておいた番号%dのハッシュと一致しません" % (lineno, expect_seq))
            prev = entry.get("hash")
            # 1か所の削除で以降の全行が「番号ずれ」と報告されないよう、実際の番号に合わせ直す
            expected_seq = (entry["seq"] if isinstance(entry.get("seq"), int) else expected_seq) + 1
            if len(problems) >= 20:
                problems.append("(問題が多いため、以降の検査を打ち切りました)")
                break
    if not anchor_seen:
        problems.append("控えておいた番号%dの行がありません(末尾の切り詰めの可能性)" % expect_seq)
    return not problems, count, problems, prev


def main():
    ap = argparse.ArgumentParser(description="ハッシュ連鎖の監査ログを検証・表示する")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="ログ全体の連鎖を検証する")
    v.add_argument("path")
    v.add_argument("--expect-seq", type=int, help="外部に控えておいた番号")
    v.add_argument("--expect-hash", help="外部に控えておいたハッシュ")
    h = sub.add_parser("head", help="最新の番号とハッシュを表示する(外部に控える用)")
    h.add_argument("path")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if a.cmd == "head":
        seq, last = _last_state(a.path)
        print("番号: %d" % seq)
        print("ハッシュ: %s" % last)
        print("この2つをログとは別の場所に控えておくと、後で verify --expect-seq/--expect-hash で照合できます。")
        return 0
    if (a.expect_seq is None) != (a.expect_hash is None):
        print("--expect-seq と --expect-hash は一緒に指定してください。", file=sys.stderr)
        return 2
    ok, count, problems, last = verify(a.path, a.expect_seq, a.expect_hash)
    if ok:
        print("OK: %d件、連鎖は正しくつながっています(最新ハッシュ %s)" % (count, last))
        return 0
    print("NG: %d件を検査し、問題が見つかりました。" % count)
    for p in problems:
        print("  - " + p)
    return 1


if __name__ == "__main__":
    sys.exit(main())
