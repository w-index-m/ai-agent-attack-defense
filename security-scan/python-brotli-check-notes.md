# Python brotli/brotlicffi バージョン確認（確認専用）

`scripts/python_brotli_check.py`: Pythonの`brotli`/`brotlicffi`パッケージが、
CVE-2026-111497(通称「Node2Shell」、PyPI側への波及は2026-10-22公開のGitHub公式
Security Advisory GHSA-9v8h-qqgm-4m35で確認。[`detections/`](detections/) の R24 参照)の
対象になりうるかを確認する。

> ⚠️ 方針：**確認だけ**。パッケージの更新、コードの実行、ネットワークへの送信は一切しない。

## 背景: CVE-2026-111497とR24の関係

根本原因はBrotliデコーダの境界外書き込み(out-of-bounds write)。攻撃者が細工したBrotliデータを
展開させることで、メモリリークまたは任意コード実行に繋がりうる。元々はNode.js本体の脆弱性として
公開され("Node2Shell")、2026-10-21にNode.js公式が22.23.4/24.22.1/26.12.1で修正(同時にリリース
された他9件のCVEのうち4件がhigh評価)。

2026-10-22、GitHub公式Security Advisory(GHSA-9v8h-qqgm-4m35、Critical評価)で、PyPIの
`brotli`(1.0.3〜1.2.0が脆弱、1.2.1で修正)と`brotlicffi`(1.0.3〜1.2.0.xが脆弱、1.2.1.0で修正)
への波及が確認された。`requests`・`httpx`・`aiohttp`等の主要HTTPクライアントライブラリが、
これらのパッケージが入っていれば自動的に読み込むため、直接`import brotli`していないアプリも
間接的に影響を受けうる。

2026-10-23時点で、Aikido Securityの指摘では、脆弱性DB側(pip-audit/Dependabot/Safety)が
このCVEをPyPIパッケージに正しくマッピングできておらず、既存の自動スキャンでは検出されない
可能性がある。本ツールは、このギャップを埋める目的で作成した。

R24(`detections/sigma/r24_brotli_node2shell_crash.yml`等)は、**R13(wp2shell)やR15
(PHP2Shell)と違い、ベンダー/研究者が公開したリクエスト単位・ログ単位のIOCが無い**ため、
本リポジトリ独自に構成した未確証の探索的ヒューリスティック(gunicorn/uwsgi等のworkerクラッシュ
パターンを、brotli文脈の近くで探すだけ)である。本スクリプトはそれを補完する、ホスト側の
**パッケージバージョン確認**ツール。

## できること

- **既定**: このインタプリタ自身の`brotli`/`brotlicffi`のバージョンを、`importlib.metadata`で
  読み取り(ネットワークアクセスなし)、GHSA-9v8h-qqgm-4m35の修正版と照合する。
- **`--python <path>`**: 別のPython実行ファイル(venv内等)のパッケージを、サブプロセス経由で
  同様に確認する。
- **ログ確認(任意、`--log-path` または `--journalctl-unit`)**: アプリケーションログから、
  R24のSigmaルールと同じパターン(gunicorn/uwsgi等のworkerクラッシュ行がbrotli文脈の近くに
  あるか)を確認する。R24自体が未確証のヒューリスティックであるため、この確認結果も同様に
  「調査すべき手がかり」止まりである点に注意。
- SARIF 2.1.0 での出力にも対応(`--out`)。`vuln_triage.html` に読み込める。

## できないこと・正直な限界

- `brotli`/`brotlicffi`以外の経路でBrotli展開を行っているケース(他言語のバインディング、
  システムの共有ライブラリを直接使うコード等)は対象外。
- ログ確認は、R24自体がベンダー未公開のヒューリスティックであるため、ヒットしても
  CVE-2026-111497固有の確証にはならない(他の原因のworkerクラッシュでも同じ形になりうる)。
- パッケージ自体のバグを検査するわけではない(動的なエクスプロイト再現は行わない)。

## 使い方

```bash
python3 scripts/python_brotli_check.py
python3 scripts/python_brotli_check.py --out brotli_check.sarif
python3 scripts/python_brotli_check.py --python /path/to/venv/bin/python3
python3 scripts/python_brotli_check.py --log-path /var/log/myapp/gunicorn.log
```

## 検証

- このサンドボックスの既定Python環境には`brotli`/`brotlicffi`はインストールされておらず、
  その場合に正しく`info`レベルで報告することを確認した。
- **実際に脆弱なバージョンでの検証**: `/tmp`に専用のvenvを作り、`pip install Brotli==1.2.0`
  (脆弱版)をインストールした上で`--python`経由で確認したところ、正しく`high`判定
  (`1.2.0 は修正版(1.2.1)未満です`)になることを確認した。続けて`Brotli==1.2.1`(修正版)に
  アップグレードして再実行し、正しく`info`判定(修正版以降)に変わることも確認した。
- `parse_version()`は、`1.2.0`・`1.2.1`・`1.0.3`・`1.2.0.5`・`1.2.1.0`等の表記を直接
  ユニットテストし、意図したタプルに解釈されることを確認した。
- ログ確認は、合成したgunicornログ(`WORKER TIMEOUT`の近くに`brotli/decompress.py`への
  言及があるトレースバック)でユニットテストし、正しく検知することを確認した。brotli文脈を
  伴わない無関係なクラッシュ行(合成データ)では検知しないことも確認した。

> 確認・検知の設計に限定。攻撃の実行手順やエクスプロイトコードは含めない。
