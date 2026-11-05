# 残タスク一覧

2026-11-06 時点(2026-10-31 版からの更新)。今日までの作業(`dep_cve_check.py` / `ghsa_lookup.py` の実通信の検証、
NuGet・poetry・uv・Go への対応、CI への組み込み、AI-SAST の試験(3B・7B)、Dockerfile の非 root 化、
Trivy/gitleaks/Semgrep の CI 警告、`netcheck`・`sqli-lab` の実機検証、`sqli-lab` への `--discover`/`--crawl`/
`--llm-payloads`/`--llm-class` の追加)から、**残っていること**を、1か所に集めたもの。
各項目に、「何が分かっていて、何が分かっていないか」を書く。完了したら、消すか、「完了」に移す。

> 更新のしかた: 作業を終えたら、この表を直して、PR に含める。長い説明は、各ノート(`security-scan/*-notes.md`)に書く。

## 1. 調査が必要(原因が分かっていない、または一部しか分かっていない)

| 項目 | 分かっていること | 分かっていないこと |
|---|---|---|
| **突き合わせ不可の 2 件**(`golang.org/x/text` の `CVE-2026-56851`、`CVE-2026-56852`) | **原因を切り分けた**(診断の出力)。GHSA には、この 2 件の記載はあるが、**影響を受けるパッケージの項目が空**(「GHSA 側の記載: パッケージの記載なし」)。名前やエコシステムの違いではない。ツールは、想定どおり「突き合わせ不可」と報告している(一致と偽らない)。16 件中 14 件が一致 | GHSA の記載にパッケージが無い理由(審査前の記載などが考えられるが、未確認)。サンドボックスからは GHSA・OSV に届かず(プロキシで拒否)、これ以上の調査には PC か Actions が必要 |
| **AI-SAST の精度**(3B・7B とも完了) | 3B(独立 5 回): 検出 3〜6/11(平均 5.0)、誤検知 1〜2、本物を打ち消した回が 2 種類で 2/5。7B(独立 5 回): 検出 5/11・誤検知 1(SSRF のみ)が毎回同じで安定、本物を打ち消した回は無し。ただし見逃し 6 種類はルールだけと同じ | より大きなモデル、または別アプリで、見逃しの幅が広がるかは未確認 |

## 2. PC なしで、できること(自動で進められる)

| 項目 | 内容 | 優先度 |
|---|---|---|
| **GitHub Actions の更新** | `actions/checkout@v4` などが Node.js 20 を使っており、廃止予定の警告が出ている | 低 |
| **`crosscheck` の CI への組み込み** | 今は手動の試験用ワークフローだけ。`dep_cve_check` の後に、自動で突き合わせるか | 低(要検討) |
| **`go.mod` への対応** | `go.sum` は、使われない古い版も含むため、誤検知が出る。`go.mod` のほうが、実際の版に近い | 低(要検討) |
| **`php2shell` の件** | PHP 8.1 以前の「公式の修正版なし」の記載を、php.net のアドバイザリで裏取りしていない(`sqli-lab/README.ja.md` 126 行目) | 低 |
| **`security-summary.ja.md` の「次にやること」の同期** | この文書と、内容が重なる。どちらを正とするか決める | 低 |
| **`--llm-payloads`/`--llm-class` の実物の Ollama での確認** | このセッションのサンドボックスでは `registry.ollama.ai`/`ollama.com` に届かず(403)、モックでの配線確認のみ。PC か Actions(`ai-sast-trial.yml` と同じ Docker 経由)なら実物のモデルで試せる | 中 |

## 3. あなたの PC が必要

| 項目 | 内容 |
|---|---|
| **ポートを変えたラボの起動** | `VULN_APP_PORT=15000 VULN_INTERNAL_PORT=15001 python3 vulnerable_app.py` が、ミラーモードの WSL で起動するか。Windows 側の 5000/5001 は、Datadog Agent と見られるプロセスが使っている(プロセス名 `agent` で、実行ファイルの場所は、権限の問題で未確認) |
| **PentestGPT(従来型)の実行** | WSL から Ollama には届いた(`Sessions initialized.` まで確認)。的(`127.0.0.1` のラボ)を渡して、実際にタスクを受けて、提案を返すところは、未確認 |
| **Strix の再実行(モック LLM)** | Windows + Docker Desktop + モックの応答サーバーへの接続を、非 root 化後に再確認する(途中で停止中) |
| **自分のプロジェクトへの適用** | `pip freeze > requirements.txt` などで、実際の依存関係を書き出し、`dep_cve_check.py` にかける |
| **PC の `main` を最新にする** | `git checkout main` と `git pull`(PC の `main` は、古いまま) |
| **一時ファイルの削除** | `req_test.txt`、`*.sarif`、`g*.md`、`packages.lock.json` など(リポジトリには入れていない) |
| **`netcheck`・各スクリプトの Windows ネイティブでの動作確認** | `dep_cve_check.py`/`ghsa_lookup.py` は Windows で実通信まで確認済みだが、`netcheck.py` や `sqli-lab` のスクリプトは、Windows ネイティブでは未確認(サンドボックスの Linux でのみ確認) |

## 4. 判断が必要(あなたの決定待ち)

- `local-ai-sast` には `LICENSE` が無い。**今後も試験に使うか**(取り込みや再配布はしない方針)。

## 5. 検証の状態(まだ「未確認」のもの)

| 項目 | 未確認の内容 |
|---|---|
| 返った CVE の中身 | 14 件は、GHSA と修正版が一致(実データ)。それ以外の項目(説明文、影響範囲)の、個別の突き合わせは未実施 |
| Cisco ASA/FTD の SSL VPN ポータル検知(`netcheck`) | 一般に知られているパス・応答の特徴から判定しているが、本物の Cisco 機器では未検証 |
| Cisco IOS/IOS XE の SSH の CVE | Web 検索で再調査(二次情報のみ)。Cisco 公式アドバイザリでの裏取りは未実施 |
| `cairn dispatch` を通した全体の経路 | 非 root 化(2026-11-04)の後は未確認。`cairn` 本体を、この環境で動かしていない |

## 完了したこと(参考)

- `dep_cve_check.py` / `ghsa_lookup.py` の実通信の検証、終了コード 2、CVE 単位のまとめ、コミットハッシュの短縮
- NuGet(`.csproj`、`packages.lock.json`)、`poetry.lock`、`uv.lock`、`go.sum` への対応(`uv`・`poetry`・`go`・`dotnet` が
  生成した実物の 4 形式を、PC で OSV にかけて確認済み)
- CI への組み込み(依存関係の照合、CVE の詳細、`summarize.py` の要約)
- `crosscheck_osv_ghsa.py`(OSV の修正版を GHSA と突き合わせる)と、実データでの確認(16 件中 14 件が一致)
- `sqli-lab` のポートを、環境変数で変えられるようにした
- AI-SAST の試験用ワークフロー、比較スクリプト、集計スクリプト(3B・7B とも独立 5 回、完了)
- PentestGPT を、実機の WSL2 + Ollama で起動する記録
- 作り方のまとめ(`docs/how-we-built-this.ja.md`)、残タスク一覧(この文書)、スライド(`docs/ai-built-tools-process.pptx`、
  12 枚以上)
- Semgrep の CI 修正(`--config p/default` を明示)と、**残り 13〜15 件の指摘の確認**(緊急・高は無し。TLS 検証なし・
  `pickle` 使用は、診断ツール自身の意図どおりの挙動と確認。`dynamic-urllib-use-detected` は、固定 URL は問題なし、
  利用者が渡す URL は `http`/`https` 以外を拒否する検査を追加して対応)
- Dockerfile・`worker-mock.Dockerfile` の非 root 化(`scanner`、`node`)。ビルドと動作を実際に確認
- Trivy・gitleaks の CI ステップに、結果ファイルが無いときの警告を追加(`|| true` で隠れる失敗への対策)
- Semgrep の指摘の一覧(重大度・ルール ID・場所)を CI のログに出すステップを追加
- `netcheck` の実機検証: 本物の Apache 2.4.58(`SENSITIVE_FILES` 15/15)・nginx 1.24.0(14/15、残り 1 件は Apache 専用
  機能で想定どおり)、ブラウザ(Chromium、PC 幅・スマホ幅)、本物の `sshd`(OpenSSH 9.6 は判定されないことを確認)
- `sqli-lab` の SQL インジェクションを、自分のラボ(`vulnerable_app.py`)で実際に動作確認(脆弱版で 5 件検出、
  修正版で誤検知 0)
- `auto_vuln_scanner.py` に、Strix が持つ「自動発見」「未知のパターンへの適応」「汎用性」を、脆弱性を突かずに/
  判定を安全側に保ったまま追加: `--discover`(ソースの静的読み取り)、`--crawl`(GET のみの動的な閲覧)、
  `--llm-payloads`(判定は既存ルールのまま、LLM は追加ペイロードのみ)、`--llm-class`(LLM は安全な判定タイプの
  パラメータのみ。コードの `eval`/`exec` はしない)
- 検知タグ(R1–R17)が、`defense-detection-notes.md`(説明文)・`shared/taxonomy.json`(唯一の定義)・
  `detections/`(実ルール)という、同じ定義の 3 つの形態であることを明記
