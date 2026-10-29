# Node2Shell Radar の使い方（第三者ツール・利用ノート）

[`Secragon/node2shell-radar`](https://github.com/Secragon/node2shell-radar) は、Node2Shell /
HTTP2Shell(CVE-2026-111497、Brotliデコーダの境界外書き込み。本リポジトリの
[`detections/`](detections/) の R24・R25 参照)に対する**サーバー側の露出**を、ドメイン/URL
を指定して確認するデスクトップGUI製の第三者ツールです。本リポジトリの
[`scripts/python_brotli_check.py`](python-brotli-check-notes.md)は「このホストに入っている
`brotli`/`brotlicffi`パッケージのバージョン」しか確認できず、**外部から見た本番サーバーの
露出確認**はできません。Node2Shell Radarはそのギャップを埋める、対象ドメイン/URLに対する
確認専用(パッシブ中心)ツールです。本リポジトリでは実装せず(既に公開・保守されている
第三者ツールのため)、R24・R25の検知ルールと[`tools-dashboard.html`](tools-dashboard.html)
から参照しています。

> ⚠️ 方針：**第三者ツール**。本リポジトリ側ではビルド・実行・検証をしていません(未実行・
> 未検証)。「ディスカバリ」は公開情報源(サブドメイン列挙・DNS・TLS証明書名)に接触し、
> 任意の「アクティブチェック」は対象サイトへ実際に追加のHTTPリクエストを送ります。
> **自分が所有している、または書面で許可を得た対象にだけ使うこと**(netcheck/zgrab2_guardと
> 同じ方針)。ツール自身のREADMEも「Scan only sites you own or are authorized to assess」と
> 明記している。

## このツールが確認すること

- ドメインまたはURLを入力してスキャンを実行するデスクトップGUIアプリ(CLIフラグは
  ドキュメント化されていない)。ドメイン指定時は通常のWebポートを、URL指定時はその
  アドレスを確認する。
- **ディスカバリ**: 公開のサブドメイン情報源・一般的なDNS名・TLS証明書名を使って対象を
  見つけ、公開HTTPレスポンスヘッダ・Cookie・ページ内容からNode.jsやNext.js/Nuxt等の
  フレームワークを判定する(パッシブ)。
- **アクティブチェック(既定オフ)**: 候補サイトへ、ごく少数の追加リクエストを送り、
  「Brotliのリクエスト解析が、確認したパス上で到達可能に見えるか」を報告する。
- 結果は「Fixed version」「At risk(古いNode.jsバージョンが報告された)」
  「Unconfirmed」の3区分。ツール自身が「Fixed versionの結果でも、デコーダのビルドを
  リモートで検証したわけではない」と明記しており、**判定は確定的な証拠ではない**。
- 結果はローカル保存のみ(Secragonへはアップロードされない)。JSON/CSVでエクスポート可能。

## インストール(公式リリース、SHA256SUMSつき)

CLIではなくデスクトップアプリなので、ビルド済みバイナリをダウンロードして実行する。

```bash
# https://github.com/Secragon/node2shell-radar/releases/latest から取得
# Linux x64:
curl -fsSLO https://github.com/Secragon/node2shell-radar/releases/latest/download/Node2Shell-Radar-linux-x86_64.tar.gz
curl -fsSLO https://github.com/Secragon/node2shell-radar/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS

tar -xzf Node2Shell-Radar-linux-x86_64.tar.gz
./Node2Shell-Radar   # デスクトップ(GUI)セッションが必要
```

Windows 10/11 x64向けは `Node2Shell-Radar-windows-x64.exe`(単体EXE、ダブルクリックで起動)。
SHA256SUMSの検証コマンド自体はツールのREADMEに明記されていないため、上記は一般的な
`sha256sum --check`の手順。ソースからのビルド(Python 3.11+)も可能:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[build]'
.venv/bin/python -m radar
```

## 使い方(自分が管理する対象にだけ)

1. アプリを起動し、確認したい**ドメイン**(例: `your-site.example`)または**URL**
   (例: `https://your-site.example/api`)を入力してスキャンを実行する。
2. 既定ではパッシブなディスカバリ(公開情報源・レスポンスヘッダ)のみ。対象サイトへ
   追加リクエストを送る「アクティブチェック」は明示的にオンにした場合のみ実行される。
3. 結果の一覧で「Fixed version」「At risk」「Unconfirmed」を確認し、
   「Export results」でJSON/CSVに書き出せる(表示中の行のみ)。

## 本リポジトリとの関係

- R24(`detections/sigma/r24_brotli_node2shell_crash.yml`等、PyPI `brotli`/`brotlicffi`側)・
  R25(同CVEのNode.js本体向け)は、workerクラッシュパターンとバージョンバナーという、
  ログ/ネットワーク観測に基づく探索的ヒューリスティック(未確証)。Node2Shell Radarは
  それより直接的な、**対象ドメイン/URL単位の露出確認**を担う。
- 本リポジトリの`scripts/python_brotli_check.py`は、このホストに入っている
  `brotli`/`brotlicffi`パッケージのバージョンを確認するだけで、外部から見た
  サーバーの露出までは確認できない。「社外に公開しているサーバーが実際にどう見えるか」を
  確認したい場合にNode2Shell Radarを使う、という役割分担。

## 検証状況・限界(正直に)

- このセッションでは、node2shell-radarのREADME(2026-10-28時点の内容)を取得して読んだのみで、
  **ビルド・起動・実機での動作確認はしていない**(デスクトップGUIアプリのため、かつ
  このサンドボックスにGUIセッションが無いため)。
- ツール自身がREADMEで明記している限界: 「Fixed version」の判定もリモートからデコーダの
  実ビルドを検証したものではない。サイトが報告するバージョンがパッチ状態を正確に反映しない
  場合、「At risk」でも実際にはベンダー修正が当たっている可能性がある。アクティブチェックは
  「脆弱性・パッチ状態・悪用可能性の証明にはならない」。リバースプロキシ等でパッシブな
  シグナルが隠蔽・変更される場合がある。フレームワークの検出だけでは「対象が実際にNode.jsで
  動いている」ことの証明にはならない。完全な資産棚卸しでもない。
- 上記の使い方・判定区分・限界の記述は、ツール自身のREADME(2026-10-28時点)から転記した
  もの。ツールが更新された場合、内容が古くなる可能性がある。利用前に
  `github.com/Secragon/node2shell-radar`の最新READMEを確認すること。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
