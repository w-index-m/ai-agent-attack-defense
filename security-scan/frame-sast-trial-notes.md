# frame(lambdasec/frame)の試験: SMTソルバーベースSASTを、正解つきの的で確認

他人のSASTツール [lambdasec/frame](https://github.com/lambdasec/frame)(PyPI: `frame-security`)を、
このリポジトリの「正解つきの的」(`security-scan/sqli-lab/vulnerable_app.py`、15クラスの脆弱性と
修正版)にかけて、`ai-sast-trial-notes.md`(local-ai-sastの試験)と同じやり方で精度を確認した。

## frameとは

Z3(SMTソルバー)ベースのseparation logic証明エンジンを使う、**決定的なSAST**。
「パターンマッチではなく解を証明する」と謳っており、LLMはオプション(`--ai`/`--hunt-authz`)。
今回は**LLMを使わない既定モード**(`frame scan`、ネットワーク通信なし)だけを試した。

## 環境・実行

```bash
pip install "frame-security[scan]"   # 1.1.3、依存はz3-solverのみ
frame scan security-scan/sqli-lab/vulnerable_app.py -f json -o frame_scan.json
```

- 実行時間: 約0.15〜0.6秒(2回実行して比較)。
- **決定的**: 同じ入力で2回実行し、`scan_time_ms`以外のJSONが完全一致することを確認
  (local-ai-sastでは同じモデル・同じコードで判定が変わることがあった。この点はfameの
  「ソルバーで証明する」という設計が効いている)。
- ネットワーク通信なし(`frame-security[scan]`はpip installのみで、scan自体はオフライン完結)。

## 結果(11件の指摘)

| 行 | 関数 | 種類 | evidence |
|---|---|---|---|
| 118 | `user_exists` | sql_injection | solver-verified |
| 234 | `diag` | command_injection | solver-verified |
| 257 | `file_view` | path_traversal | solver-verified |
| 273 | `file_view_safe` | path_traversal | solver-verified |
| 403 | `deserialize` | deserialization | solver-verified |
| 527 | `fetch_url` | ssrf | solver-verified |
| 544 | `fetch_url_safe` | ssrf | solver-verified |
| 592 | `<module>`(`app.run`) | secret_exposure | solver-verified |
| 37 | `<module>`(`app.secret_key`) | hardcoded_secret | matched |
| 66 | `login`(SQLi本体の行) | hardcoded_secret | matched |
| 366 | `<module>`(`ADMIN_SECRET_NOTE`) | hardcoded_secret | matched |

## 正解との突き合わせ(15クラス)

| クラス | 結果 |
|---|---|
| sqli(`/login`) | **見逃し**。SQLi本体の行(66行目)を検出したが、`sql_injection`ではなく`hardcoded_secret`(「接続文字列にハードコードされた認証情報」)として誤分類。本リポジトリの脆弱性実証で最も中心的な脆弱性が、正しい種類で拾えなかった |
| sqli_blind_boolean(`/user_exists`) | **検出**(脆弱版のみ、修正版`/user_exists_safe`は誤検知0件) |
| sqli_blind_time・second_order_sqli | 見逃し(`/login`の時間ベース変種、`/second_order_signup`→`/second_order_audit`間のクロスリクエスト・テイント追跡は対象外) |
| xss(`/search`) | 見逃し(反射型XSSの指摘は1件も無し) |
| cmdi(`/diag`) | **検出**(脆弱版のみ、修正版で誤検知0件) |
| traversal(`/file`) | **検出**(脆弱版)。ただし**修正版(`/file_safe`)でも誤検知** — `os.path.realpath`での正規化チェックをサニタイザとして認識していない |
| mass_assignment(`/signup`) | 見逃し |
| ssrf(`/fetch_url`) | **検出**(脆弱版)。ただし**修正版(`/fetch_url_safe`)でも誤検知** — プライベート/ループバックIPの拒否チェックをサニタイザとして認識していない |
| account_enum(`/register`) | 見逃し |
| csrf | 見逃し |
| idor(`/idor_account`) | 見逃し |
| deserialize(`/deserialize`) | **検出**(脆弱版のみ、修正版で誤検知0件) |
| stored_xss(`/review`→`/reviews`) | 見逃し |
| bfla(`/admin_secrets`) | 見逃し |

**検出: 5/15**(sqli_blind_boolean・cmdi・traversal・ssrf・deserialize)。
**見逃し: 10/15**。**修正版での誤検知: 2件**(traversal・ssrf)。

## 所感

- **taint解析(source→sink)で素直に追える種類は強い**: cmdi・deserialize・ssrfの脆弱版は、
  修正版で誤検知せず正確に検出した(2クラスを除く)。実行のたびに判定が変わるAI-SASTとは違い、
  **同じ入力なら毎回同じ結果**という決定性は、local-ai-sastに対する明確な優位点。
- **「安全化の手段」を認識できないと誤検知する**: `realpath`での正規化、プライベートIPの拒否、
  という**コードパターンとしては単純だが意味を理解する必要がある**サニタイザを認識できず、
  修正版を脆弱と誤判定した。これは`compare_sast_ground_truth.py`的な「種類が合っているか」の
  チェックだけでなく、「脆弱版/修正版のペアで必ず両方試す」という本リポジトリの一貫した検証
  方針がそのまま効いた例(修正版だけ見ていたら誤検知に気づけなかった)。
- **最も重要な脆弱性(`/login`のSQLi)を見逃した**のは意外な結果だった。別の、より単純な
  SQLi(`/user_exists`)は正しく検出できているので、「SQLiという種類を原理的に検出できない」
  わけではなく、`/login`特有のコード構造(複数行にまたがるf-string、`try/except`での
  エラーハンドリング)が、このバージョンのtaint解析を迂回させた可能性がある。根本原因は
  未調査。
- **業務ロジック系(CSRF・IDOR・BFLA・マスアサインメント・アカウント列挙・セカンドオーダー)は
  全滅**。これらは単純な「汚染データがシンクに届く」という形のtaint解析では原理的に拾いにくい
  種類で、AI-SASTの試験(`ai-sast-trial-notes.md`)でも同様にIDOR以外は全滅していた
  (IDORだけはAIが`needs_review`で拾えた回があった)。
- **反射型/格納型XSSも0件**: taint解析の対象シンクに、HTMLレンダリング(Flaskの文字列直接返却)
  が含まれていない可能性がある。

## AI-SASTとの比較(同じ的、同じ15クラス基準)

| | ルールだけ(本リポジトリの`sqli-lab`) | AI-SAST(local-ai-sast、3B) | frame(ソルバー、LLM無し) |
|---|---|---|---|
| 検出 | 15/15(当然。正解そのものを検証するスキャナーのため) | 5〜6/11(旧15クラス拡張前の基準) | 5/15 |
| 修正版の誤検知 | 0 | 1〜2 | 2 |
| 判定のばらつき | 無し(決定的) | **あり**(同じモデル・同じコードで結果が変わる) | **無し**(決定的、2回実行で確認) |
| 実行時間 | 数秒(HTTPリクエストベース) | 約4〜12分(モデルサイズ依存) | 0.15〜0.6秒 |

frameは、AI-SASTで問題になっていた「判定のばらつき」「本物の脆弱性を誤検知として打ち消す」
という問題は構造的に起きない(ソルバーの証明は決定的)。一方で、**taint解析が原理的に拾えない
種類(業務ロジック系)はAI-SASTと同じく全滅**であり、「LLMを使わないから優れている」という
単純な話ではなく、**得意不得意の形が違う**、という結論になる。

## 追記(2026-11-07): SCA・Git履歴のシークレット検出を試験

### `frame deps`(SCA、ロックファイルの読み取り)

`--vulns`(実際の脆弱性照合)は`huggingface.co`(アドバイザリDB`lambdasec/frame-advisories`の配布元)
への通信が必要で、このサンドボックスではブロックされていた(`frame kb pull --advisories`が
`Tunnel connection failed: 403 Forbidden`で失敗)。そのため、**ロックファイルの読み取り部分のみ**
確認した。

```bash
# requirements.txt: jinja2==2.10 / requests==2.19.0
# (dep-cve-check-notes.mdの実通信検証と同じパッケージ・版)
frame deps -f json
```

- 2パッケージとも正しく`name`/`version`/`ecosystem: PyPI`/`direct: true`で抽出。
- `dep_cve_check.py`の実通信検証(`dep-cve-check-notes.md`、同じ2パッケージでOSVから22件取得→
  11件にまとめ済み)と**同じ入力を正しく解釈できている**ことを確認。ただし脆弱性照合自体
  (CVE番号・修正版)は本サンドボックスでは比較できていない。

### `frame history`(Git履歴のシークレット検出)

ネットワーク不要なため、完全に試験できた。合成のgitリポジトリ(scratchpad)に以下を仕込んで確認:

| ケース | 内容 | 結果 |
|---|---|---|
| AWSキー(ドキュメント用の例示値`AKIAIOSFODNN7EXAMPLE`) | 1コミット目で追加、そのまま残存 | **検知せず**(既知のプレースホルダーとして除外していると推定。良い設計) |
| AWSキー(実在しそうな値)・GitHubトークン(`ghp_...`) | 追加後、現在も残存 | **検知**。provider("AWS"/"GitHub")・format・コミットハッシュ・ファイル・行番号を正しく報告、`in_head: true` |
| Stripeのライブキー(`sk_live_...`) | 追加後、**別コミットでファイルごと削除** | **検知**。`in_head: false`で「現在は無い」ことまで正しく判定、コミットハッシュも正確 |
| 無関係なファイル(`print('hello')`) | - | 誤検知0件 |

**値は出力されない**(`redacted: "AKIA... (20 characters)"`のように、形式と長さだけ表示)設計も確認した。
この機能は、**ネットワークに依存せず、本サンドボックスで完全に動作・高精度**という結果になった
(3/3検出、誤検知0、現在の有無の判定も正確)。SASTのtaint解析(5/15)より、こちらの方が
明確に実用的な結果だった。

## 未確認

- `--ai`・`--hunt-authz`(LLMを使うモード)は、外部のLLMエンドポイント設定が必要なため未試験
  (このサンドボックスでLLM APIに届かない制約は、本リポジトリの他の試験と同じ)。
- `/login`のSQLi見逃しの根本原因(taint解析のどの段階で追跡が切れたか)は未調査。
- `--sca`の脆弱性照合本体(`--vulns`)・`--iac`・`--verify-secrets`は、アドバイザリDB配布元
  (`huggingface.co`)または各プロバイダAPIへの通信が必要なため未試験。
- 1つのアプリ(約600行)、1バージョン(1.1.3)の結果で、一般化はできない。
