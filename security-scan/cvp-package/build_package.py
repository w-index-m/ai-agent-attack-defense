#!/usr/bin/env python3
"""CVP 申請パッケージ(HTML / PDF)を、元の Markdown から作り直す。

    python3 security-scan/cvp-package/build_package.py

必要なもの: pandoc と Chromium(Playwright 同梱のものでよい)、日本語フォント(IPAGothic など)。
  - Chromium の場所は --chromium、環境変数 CHROMIUM、または /opt/pw-browsers/*/chrome-linux/chrome から探す。
  - 出力: cvp-application-package.html / cvp-application-package.pdf(この README と同じディレクトリ)

組み立て: 表紙(00-cover.md) → 適用メモ → 防御・検知ノート → Cairn ランブック → Strix ノート。

作り方の注意点(過去の不具合から):
  - GFM で読み、**タイトルブロックを出さない**(pandoc の --metadata title だと日本語が文字化けした)。
    HTML の <title> だけ ASCII の pagetitle で指定する。
  - 全角のかっこや句読点の直後で閉じる `**…**` は、GFM では太字にならずアスタリスクが残る。
    そこでビルド時だけ `**…**` を <strong> に置き換える(元の Markdown は変えない。コード部分は触らない)。
  - 用紙は A4。Chromium の CLI は用紙を指定できないので、CSS の @page で指定する。
  - 文書の区切りは <hr> ではなく、「直前で改ページ」するだけの要素にする。<hr> に「直後に改ページ」を付けると、
    表紙がちょうど 1 ページを埋めたときに <hr> が次ページの先頭に落ちて白紙ページになり、本文中の `---` ごとに
    ほぼ空のページも増える(そのため style.css の hr には改ページを付けない)。
標準ライブラリだけで動く(外部コマンドは pandoc と Chromium)。ネットワークには接続しない。
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.dirname(HERE)  # security-scan/

SOURCES = [
    os.path.join(HERE, "00-cover.md"),
    os.path.join(SCAN, "cvp-readiness.md"),
    os.path.join(SCAN, "defense-detection-notes.md"),
    os.path.join(SCAN, "cairn-lab", "cairn-authorized-lab-runbook.md"),
    os.path.join(SCAN, "strix-local-backend-notes.md"),
]
PAGE_CSS = ("@page { size: A4; margin: 14mm 13mm; }\n"
            ".docbreak { break-before: page; page-break-before: always; height: 0; margin: 0; }\n")


FENCE = re.compile(r"(^```.*?^```[^\n]*$)", re.S | re.M)
BOLD = re.compile(r"\*\*((?:(?!\n[ \t]*\n)[^*])+?)\*\*")  # 段落をまたがない。行をまたぐ太字も拾う


def fix_cjk_bold(md):
    """`**…**` を <strong> に置き換える。コードブロックとインラインコードの中は触らない。"""
    chunks = FENCE.split(md)  # 偶数番目がコードブロック以外、奇数番目がコードブロック
    for i in range(0, len(chunks), 2):
        parts = re.split(r"(`[^`\n]*`)", chunks[i])
        for j in range(0, len(parts), 2):  # 偶数番目がインラインコード以外
            parts[j] = BOLD.sub(r"<strong>\1</strong>", parts[j])
        chunks[i] = "".join(parts)
    return "".join(chunks)


def strip_trailing_rule(text):
    """各文書の末尾の区切り線(---)を外す。結合時に自分で 1 本だけ入れるため。"""
    lines = text.rstrip().split("\n")
    if lines and re.fullmatch(r"-{3,}\s*", lines[-1]):
        lines.pop()
    return "\n".join(lines).rstrip() + "\n"


def find_chromium(arg):
    cands = [arg, os.environ.get("CHROMIUM")]
    cands += sorted(glob.glob("/opt/pw-browsers/*/chrome-linux/chrome"), reverse=True)
    cands += [shutil.which(n) for n in ("chromium", "chromium-browser", "google-chrome")]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def main():
    ap = argparse.ArgumentParser(description="CVP 申請パッケージ(HTML/PDF)を作り直す")
    ap.add_argument("--chromium", help="Chromium の実行ファイル")
    ap.add_argument("--no-pdf", action="store_true", help="HTML だけ作る")
    a = ap.parse_args()

    if not shutil.which("pandoc"):
        print("pandoc が見つかりません。", file=sys.stderr)
        return 2
    for s in SOURCES:
        if not os.path.exists(s):
            print("元の文書が見つかりません: %s" % s, file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory() as tmp:
        md = ("\n<div class=\"docbreak\"></div>\n\n").join(
            strip_trailing_rule(open(s, encoding="utf-8").read()) for s in SOURCES)
        md_path = os.path.join(tmp, "combined.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(fix_cjk_bold(md))

        css_path = os.path.join(tmp, "style.css")
        with open(css_path, "w", encoding="utf-8") as f:
            f.write(open(os.path.join(HERE, "style.css"), encoding="utf-8").read() + "\n" + PAGE_CSS)

        html_out = os.path.join(HERE, "cvp-application-package.html")
        subprocess.run(["pandoc", "-f", "gfm", "-t", "html5", "-s", "--embed-resources", "--css", css_path,
                        "--metadata", "pagetitle=CVP application package", "-o", html_out, md_path], check=True)
        print("書き出しました: " + html_out)

        if a.no_pdf:
            return 0
        chrome = find_chromium(a.chromium)
        if not chrome:
            print("Chromium が見つかりません(--chromium で指定)。HTML だけ作りました。", file=sys.stderr)
            return 1
        pdf_out = os.path.join(HERE, "cvp-application-package.pdf")
        subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
                        "--print-to-pdf=" + pdf_out, "file://" + html_out],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("書き出しました: " + pdf_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
