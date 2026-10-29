# Node2Shell Radar の使い方（第三者ツール・利用ノート）

[`Secragon/node2shell-radar`](https://github.com/Secragon/node2shell-radar) は、Node2Shell /
HTTP2Shell(CVE-2026-111497、Brotliデコーダの境界外書き込み。本リポジトリの
[`detections/`](detections/) の R24・R25 参照)に対する**サーバー側の露出**を、ドメイン/URL
を指定して確認する第三者ツールです。本リポジトリの
[`scripts/python_brotli_check.py`](python-brotli-check-notes.md)は「このホストに入っている
`brotli`/`brotlicffi`パッケージのバージョン」しか確認できず、**外部から見た本番サーバーの
露出確認**はできません。Node2Shell Radarはそのギャップを埋める、対象ドメイン/URLに対する
確認専用(パッシブ中心)ツールです。本リポジトリでは実装せず(既に公開・保守されている
第三者ツールのため)、R24・R25の検知ルールと[`tools-dashboard.html`](tools-dashboard.html)
から参照しています。

> ⚠️ 方針：**第三者ツール**。「ディスカバリ」は公開情報源(サブドメイン列挙・DNS・TLS証明書名)
> に接触し、任意の「アクティブチェック」は対象サイトへ実際に追加のHTTPリクエストを送ります。
> **自分が所有している、または書面で許可を得た対象にだけ使うこと**(netcheck/zgrab2_guardと
> 同じ方針)。ツール自身のREADMEも「Scan only sites you own or are authorized to assess」と
> 明記している。本リポジトリでの検証は、下記のとおり**自分で立てた使い捨てのローカルNode.js
> サーバー(127.0.0.1)だけ**を対象に行った。

## 【重要】READMEとソースの食い違い: 実は本物のCLIが存在する

ツール自身のREADMEは「デスクトップGUIのみ、CLIやフラグはドキュメント化されていない」という
書き方だが、ソース(`pyproject.toml`の`[project.scripts]`、`radar/cli.py`、`radar/__main__.py`)
を実際に読むと、**`PySide6`(GUI)に一切依存しない、完全headlessなCLIモードが存在する**:

```bash
python -m radar --cli <targets...> [options]
# または、pip配布のエントリポイント名で:
node2shell-radar-cli <targets...> [options]
```

`radar/__main__.py`は`sys.argv`に`--cli`があれば`radar.cli:main`を、無ければ
`radar.gui:main`(GUI)を呼ぶだけの薄いディスパッチャ。`radar/cli.py`が実際に import するのは
`radar.engine`・`radar.models`・`radar.storage`のみで、`radar.gui`や`PySide6`には一切触れない
(`grep`で確認済み)。つまり**GUIセッションが無いこのサンドボックスでも、素のPythonだけで
実機検証できる**——これは当初の下調べ(README読解のみ)の時点では分からなかった、重要な訂正。

## このツールが確認すること

- ドメインまたはURLを指定してスキャンを実行する。ドメイン指定時は通常のWebポートを、
  URL指定時はそのアドレスを確認する。
- **ディスカバリ**: 公開のサブドメイン情報源・一般的なDNS名・TLS証明書名を使って対象を
  見つけ、公開HTTPレスポンスヘッダ・Cookie・ページ内容からNode.jsやNext.js/Nuxt等の
  フレームワークを判定する(パッシブ)。`--no-passive-dns`・`--no-active-dns`・
  `--no-tls-names`でそれぞれ無効化できる(単一URLだけを確認したい場合は全て無効化推奨)。
- **アクティブチェック**(`--active-check`、既定オフ): 候補サイトへ、ごく少数の追加
  リクエストを送り、「Brotliのリクエスト解析が、確認したパス上で到達可能に見えるか」を
  報告する。
- 結果は`verdict`フィールドで「Fixed version」「At risk(古いNode.jsバージョンが報告された)」
  「Unconfirmed」の3区分。ツール自身が`decoder_patch_status: "Unverified remotely"`を
  常に添えており、**判定は確定的な証拠ではない**ことを明記している。
- 結果はローカル保存のみ。CLIは標準出力にJSONを吐くか、`--output`でJSON/CSVへ書き出す。

## インストール(ソースから、GUI依存を除外)

CLIにはPySide6(GUI)が不要なため、公式リリースのバイナリをダウンロードしなくても、
軽量に検証できる。

```bash
git clone https://github.com/Secragon/node2shell-radar
cd node2shell-radar
python3 -m venv .venv
# PySide6(GUI)を除外し、CLIの実行に必要な分だけ入れる
.venv/bin/pip install --no-deps -e .
.venv/bin/pip install "httpx>=0.28,<1" "dnspython>=2.7,<3" "cryptography>=43,<52"
```

デスクトップGUIとして使いたい場合は、公式リリース(`Node2Shell-Radar-linux-x86_64.tar.gz`
等、`SHA256SUMS`同梱)をダウンロードするか、上記venvに`PySide6>=6.8,<7`も追加して
`.venv/bin/python -m radar`(`--cli`無し)で起動する。

## 使い方

```bash
# 単一URLだけを確認(ディスカバリを全部オフに)
python -m radar --cli https://your-site.example/ \
  --no-passive-dns --no-active-dns --no-tls-names

# アクティブチェックも含め、結果をJSONファイルへ
python -m radar --cli https://your-site.example/ \
  --no-passive-dns --no-active-dns --no-tls-names \
  --active-check --output result.json
```

| フラグ | 意味 |
|---|---|
| `--no-passive-dns` | 公開のサブドメイン情報源への接触をスキップ |
| `--no-active-dns` | 一般的なDNS名の試行をスキップ |
| `--no-tls-names` | TLS証明書名からの対象発見をスキップ |
| `--extra-ports` | 一般的な非標準Webポートも確認 |
| `--crawl` | 同一オリジン内のリンクを範囲限定で辿る |
| `--all-addresses` | 解決した全アドレスを確認 |
| `--active-check` | 安全なBrotliリクエスト解析チェック(Strapiのペアログインテスト含む)を実行 |
| `--output <file>` | JSON/CSVへエクスポート(拡張子で判定) |

## 実機検証(本リポジトリで実際に実行・確認)

GUIではなく上記のCLIモードを、**自分で立てたローカルの使い捨てNode.jsサーバー
(127.0.0.1:5055、`sqli-lab`とは別プロセス)**を対象に、実際に3パターン実行して確認した。

1. **バージョンヘッダ無し**(`X-Powered-By: Express`のみ) →
   `verdict: "Unconfirmed"`、`verdict_reason: "The running Node.js version is unknown."`
2. **脆弱バージョンを報告**(`X-Node-Version: 22.22.0`、修正版`22.23.4`未満) →
   `verdict: "At risk"`、理由は「HTTPレスポンスが修正前のNode.jsバージョンを報告している。
   ベンダーのバックポートや別のデコーダ選択により実際のパッチ状態は変わりうる」の旨
3. **修正済みバージョンを報告**(`X-Node-Version: 22.23.4`) →
   `verdict: "Fixed version"`(理由は「実行プロセスと選択されたBrotliデコーダ自体は
   検証していない」の旨)

いずれも`decoder_patch_status`は常に`"Unverified remotely"`で、ツール自身が主張する
「リモートからの確定的な証拠ではない」という限界と一致する挙動だった。修正版バージョン表
(`FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}`、`radar/models.py`)は、
`python_brotli_check.py`の検証ノートに記載したNode.js公式の修正版と一致することも確認した。

## 本リポジトリとの関係

- R24(`detections/sigma/r24_brotli_node2shell_crash.yml`等、PyPI `brotli`/`brotlicffi`側)・
  R25(同CVEのNode.js本体向け)は、workerクラッシュパターンとバージョンバナーという、
  ログ/ネットワーク観測に基づく探索的ヒューリスティック(未確証)。Node2Shell Radarは
  それより直接的な、**対象ドメイン/URL単位の露出確認**を担う。
- 本リポジトリの`scripts/python_brotli_check.py`は、このホストに入っている
  `brotli`/`brotlicffi`パッケージのバージョンを確認するだけで、外部から見た
  サーバーの露出までは確認できない。「社外に公開しているサーバーが実際にどう見えるか」を
  確認したい場合にNode2Shell Radarを使う、という役割分担。

## 限界(ツール自身の記載どおり)

- 「Fixed version」の判定もリモートからデコーダの実ビルドを検証したものではない。
- サイトが報告するバージョンがパッチ状態を正確に反映しない場合、「At risk」でも実際には
  ベンダー修正が当たっている可能性がある。
- アクティブチェックは「脆弱性・パッチ状態・悪用可能性の証明にはならない」。
- リバースプロキシ等でパッシブなシグナルが隠蔽・変更される場合がある。
- フレームワークの検出だけでは「対象が実際にNode.jsで動いている」ことの証明にはならない。
- 完全な資産棚卸しでもない。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
