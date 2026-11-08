# sqli-lab 対応状況(2026-11-08時点)

`security-scan/sqli-lab/`(`vulnerable_app.py` + `auto_vuln_scanner.py` + `session_vuln_check.py`)が、
脆弱版/修正版エンドポイントのペアとして実機検証済みの脆弱性クラス一覧。全クラス、
`run_regression.py`で「脆弱版は必ずVULNERABLE・修正版は必ずsafe」とアサートするCI回帰テストの対象。

```
python3 run_regression.py
→ OK: all 19 classes classified correctly (38 endpoint checks).
```

## 19クラスの一覧

### `auto_vuln_scanner.py`(GETパラメータにペイロードを注入してレスポンスを比較する型、12クラス)

| クラス | 脆弱エンドポイント | 修正版エンドポイント | 検知の根拠 |
|---|---|---|---|
| `sqli` | `/login` | `/login_safe` | SQLエラー文字列の漏洩・認証バイパス・ステータス変化 |
| `sqli_blind_time` | `/login` | `/login_safe` | 応答時間の差のみ(SQLiteに`sleep()`が無いため再帰CTEで代替、約1秒遅延) |
| `sqli_blind_boolean` | `/user_exists` | `/user_exists_safe` | 「Match./No match.」の2値のみからの真偽判定 |
| `xss` | `/search` | `/search_safe` | ペイロードがエスケープされずHTMLに反射 |
| `cmdi` | `/diag` | `/diag_safe` | `id`コマンドの出力漏洩 |
| `traversal` | `/file` | `/file_safe` | `/etc/passwd`の内容読み出し |
| `mass_assignment` | `/signup` | `/signup_safe` | `is_admin`等、許可していないフィールドの反映 |
| `ssrf` | `/fetch_url` | `/fetch_url_safe` | 内部限定サービスの秘密情報の漏洩 |
| `account_enum` | `/register` | `/register_safe` | 登録済みメールアドレスで応答が変わる |
| `header_injection` | `/header_inject` | `/header_inject_safe` | CR/LF混入によるレスポンス分割(余分なSet-Cookieヘッダ注入) |
| `mail_header_injection` | `/contact` | `/contact_safe` | CR/LF混入によるBccヘッダ注入 |
| `clickjacking` | `/dashboard` | `/dashboard_safe` | `X-Frame-Options`/CSP `frame-ancestors`の欠落 |

### `session_vuln_check.py`(セッション状態を跨いだ判定・多段リクエストが必要な型、7クラス)

| クラス | 脆弱エンドポイント | 修正版エンドポイント | 検知の根拠 |
|---|---|---|---|
| `csrf` | `/csrf_transfer` | `/csrf_transfer_safe` | トークン無しの偽装リクエストが通る |
| `idor` | `/idor_account` | `/idor_account_safe` | 他人のオブジェクトIDを指定して閲覧できる |
| `deserialize` | `/deserialize` | `/deserialize_safe` | pickle逆シリアライズによるRCE(コマンド実行結果の漏洩) |
| `stored_xss` | `/reviews`(`/review`へ投稿) | `/reviews_safe` | 別リクエストで未エスケープのまま反射 |
| `second_order_sqli` | `/second_order_audit`(`/second_order_signup`で注入) | `/second_order_audit_safe` | signupで保存した値が、別の後続リクエストで初めてSQLに使われる |
| `bfla` | `/admin_secrets` | `/admin_secrets_safe` | 非admin権限のセッションでadmin専用機能を呼べる |
| `session_fixation` | `/fixation_login`(+`/fixation_whoami`) | `/fixation_login_safe`(+`/fixation_whoami_safe`) | ログイン前に提示したセッションIDを、サーバーがログイン後も使い続ける |

## IPA「安全なウェブサイトの作り方」(1.1–1.11)との対応

2026-11-08、IPAの目次(1.1〜1.11)と本リポジトリの対応状況を照合した結果。

| IPAの項目 | 対応クラス | 状態 |
|---|---|---|
| 1.1 SQLインジェクション | `sqli`・`sqli_blind_time`・`sqli_blind_boolean`・`second_order_sqli` | ✅ 対応 |
| 1.2 OSコマンド・インジェクション | `cmdi` | ✅ 対応 |
| 1.3 パス名パラメータ未チェック/ディレクトリ・トラバーサル | `traversal` | ✅ 対応 |
| 1.4 セッション管理の不備 | `session_fixation` | ✅ 対応(2026-11-08追加) |
| 1.5 クロスサイト・スクリプティング | `xss`・`stored_xss` | ✅ 対応 |
| 1.6 CSRF | `csrf` | ✅ 対応 |
| 1.7 HTTPヘッダ・インジェクション | `header_injection` | ✅ 対応(2026-11-08追加) |
| 1.8 メールヘッダ・インジェクション | `mail_header_injection` | ✅ 対応(2026-11-08追加) |
| 1.9 クリックジャッキング | `clickjacking` | ✅ 対応(2026-11-08追加) |
| 1.10 バッファオーバーフロー | — | ❌ 対象外(下記参照) |
| 1.11 アクセス制御や認可制御の欠落 | `idor`・`bfla` | ✅ 対応 |

**1.10バッファオーバーフローが対象外な理由**: Pythonはメモリ安全な言語であり、アプリケーション
コード自体にはバッファオーバーフローが原理的に発生しない。IPAが指すこの種の脆弱性は、C/C++等の
ネイティブコードの話であり、sqli-labの「脆弱版/修正版HTTPエンドポイントのペア」という型には
乗らない。本リポジトリでは、この種のメモリ安全性バグは別パターン(各ソフトウェアのバージョンを
照合するスクリプト)で扱っており、R16(Apache HTTP/2ダブルフリー、CVE-2026-23918)・
R24/R25(Node.js/PyPI Brotliデコーダ境界外書き込み、CVE-2026-111497)・R26(Linuxカーネル
UAF、CVE-2026-98432)が該当する(いずれもGate 3まで一次情報源で裏取り済み。
`verification-gates.md`参照)。

sqli-labの19クラスのうち、`mass_assignment`・`ssrf`・`account_enum`・`deserialize`は、
IPAの目次には明示的な項目が無いが、本リポジトリが独自に対応している脆弱性クラス。

## 2026-11-08の変更点(新規4クラス)

「gate 2も不確定なもので実現が難しい場合どうするのか」という議論の後、IPAの目次との照合で
見つかった未対応5項目のうち4項目を実装した:

- **`session_fixation`**: ログイン前に自分で選んだセッションIDを提示し、ログイン後もサーバーが
  同じIDを使い続けるか、かつそのIDがログインを一度も見ていない別クライアントからも使えるかを確認。
- **`header_injection`**: Flask/Werkzeug自身がヘッダ値へのCR/LF混入を`ValueError`で拒否するため、
  通常のFlask Response APIでは再現できないことを実機で確認。生のWSGIディスパッチへバイパスする
  脆弱版エンドポイントを別途実装して、実際にレスポンス分割(余分なSet-Cookieヘッダの注入)が
  起きることを確認した。
- **`mail_header_injection`**: 実メール送信はせず、構築した生ヘッダ文字列への注入を検知。
- **`clickjacking`**: `X-Frame-Options`/CSP `frame-ancestors`の有無を確認。

副産物として、`probe()`/baselineがデフォルトでリダイレクトを追跡してしまい、
`header_injection`の検知対象であるリダイレクト応答自体を素通りして別ページの404を見てしまう
バグを発見・修正した(`allow_redirects=False`)。既存15クラスの回帰には影響なし。

詳細は[`sqli-lab/README.ja.md`](sqli-lab/README.ja.md)を参照。
