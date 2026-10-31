#!/usr/bin/env python3
"""同じ条件で、複数回実行した SAST(AI あり)の結果を、まとめて、ばらつきを見る。

LLM の出力は、実行のたびに変わる。1回の結果で、AI あり・なしの優劣は決められないので、複数回の
レポート(local-ai-sast の JSON)を、compare_sast_ground_truth.py の数え方で評価して、
- 種類ごとに、「脆弱版を、何回検出したか」「修正版を、何回誤検知したか」
- 「AI が、脆弱版の指摘を、打ち消した回数」(= 本物の脆弱性を、AI が捨てた回数)
- 全体の検出数・誤検知数の、最小〜最大
を出す。読み取り専用で、ネットワークには出ない。

使い方:
    python3 aggregate_sast_runs.py vulnerable_app.py report1.json report2.json ...
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_sast_ground_truth as cmp  # noqa: E402


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    target, reports = argv[1], argv[2:]
    results = [cmp.evaluate(r, target) for r in reports]
    n = len(results)

    print("## %d 回の実行の分布\n" % n)
    print("| 脆弱性の種類 | 脆弱版を検出 | (うち要確認のみ) | 修正版を誤検知 | AI が本物を打ち消した |")
    print("|---|---|---|---|---|")
    for i, (kind, *_rest) in enumerate(results[0]["per_class"]):
        det = sum(r["per_class"][i][1] is not None for r in results)
        weak = sum(r["per_class"][i][1] == "weak" for r in results)
        fp = sum(r["per_class"][i][2] for r in results)
        lost = sum(r["per_class"][i][3] for r in results)
        print("| %s | %d/%d | %d | %d/%d | %d |" % (kind, det, n, weak, fp, n, lost))

    det_each = [sum(c[1] is not None for c in r["per_class"]) for r in results]
    fp_each = [sum(c[2] for c in r["per_class"]) for r in results]
    print("\n各回の検出数(11 種類中): %s(最小 %d、最大 %d)" % (", ".join(map(str, det_each)), min(det_each), max(det_each)))
    print("各回の修正版の誤検知数: %s(最小 %d、最大 %d)" % (", ".join(map(str, fp_each)), min(fp_each), max(fp_each)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
