# 自分のPCで脆弱性チェックを試す一式(ローカル試験の入口)

このリポジトリの中で「自分のPC上で、自分が所有・管理する対象だけに対して脆弱性チェックを
試す」ための一連の作業をまとめたもの。各ステップの詳細ノートへのリンク集。

> ⚠️ 対象は必ず自分が所有する、または許可を得た環境に限定すること。他人の資産には使わない。

## 全体の流れ

```
①棚卸し(netcheck)  →  ②練習対象を立てる(DVWA/Juice Shop)  →  ③自動診断(Strix+ローカルLLM)
   開いているポート/        自分のPC内のDockerで、            AIエージェントに自律的に
   管理画面/設定漏れを        意図的に脆弱なWebアプリを          脆弱性を探させる(課金なし)
   確認するだけ(無害)         動かす                           ※Docker必須、精度は小型モデル次第
```

## ① netcheck ― 自分の機器・自作ソフトの露出を確認する

[`netcheck/`](../netcheck/) 配下の `netcheck.py` をローカルで起動し、ブラウザ画面から
IP/ホスト名を入力して確認する。やっているのは「ポートが開いているか」「管理画面やバックアップ
ファイルが取得できる状態か」の**読み取りだけ**で、脆弱性を突く動作(SQLi試行など)は行わない。

```bash
cd netcheck
python netcheck.py
```

自作ソフトの静的解析(Bandit等)も合わせて行うと、コードレベルの問題(ハードコードされた
認証情報、危険な関数呼び出し等)もカバーできる。

```bash
pip install bandit
bandit -r <自作ソフトのディレクトリ>
```

netcheckは**SQLiなどのコード固有の脆弱性は検知しない**設計(`netcheck.py` の `SQLI_NOTE`
参照)。そこから先は②③に進む。

## ② 練習対象を自分のPC内に立てる(DVWA / OWASP Juice Shop)

SQLi等を実際に手で確認・体験したい場合、意図的に脆弱性を仕込んだ練習用Webアプリを
Dockerで起動する。外部には公開されない、自分のPC内だけの環境。

```bash
# DVWA(PHP/MySQL、古典的なSQLi)
docker run -d -p 8080:80 vulnerables/web-dvwa

# OWASP Juice Shop(モダンなSPA、チュートリアル付き)
docker run -d -p 3000:3000 bkimminich/juice-shop
```

DVWAは初回アクセス時にDBセットアップ(「Create / Reset Database」ボタン)、ログイン後
「DVWA Security」を Low に設定してからSQLiページを試す。

## ③ Strix ― AIエージェントによる自動診断(ローカルLLM・課金なし)

Windows 11 + WSL2 + Docker Desktop + ローカルOllama の組み合わせで、クラウドLLM課金なしに
Strix(自律型ペネトレーションテストAIエージェント)を動かす、実機検証済みの手順:

**[`strix-local-poc/windows-wsl-ollama-setup.md`](strix-local-poc/windows-wsl-ollama-setup.md)**

要点だけ書くと:

1. Windows側でOllamaを `OLLAMA_HOST=0.0.0.0:11434` で起動(WSLから到達可能にする)
2. WSL側で `ip route` から得たWindowsホストIPへの疎通を確認
3. WSL側でStrix CLIを導入(`curl -sSL https://strix.ai/install | bash`)
4. Docker DesktopのWSL Integrationを有効化、`docker`グループにユーザーを追加
5. `docker pull ghcr.io/usestrix/strix-sandbox:1.3.0`
6. 環境変数を設定して実行

```bash
export STRIX_LLM="ollama/qwen2.5:1.5b"
export OLLAMA_API_BASE="http://<WindowsホストIP>:11434"
export LLM_API_KEY="dummy"
strix -n -t http://localhost:8080 --scan-mode quick --max-budget 10
```

1.5Bのような小型モデルでも実際にLLM応答が返ってくることを実機で確認済み(CPU推論、GPUなし)。
スキャンが最後まで完走するか・検出精度がどの程度かは、モデルサイズに依存する未検証の部分。

結果は `strix_runs/<run-name>/penetration_test_report.md` 等に出力される。

## 補足: もっと軽くSQLiだけ確認したい場合

Strixは「AIエージェントの自律的な振る舞い」を見る/試す目的でなければ、やや重い(Docker・
LLM必須)。単にSQLiの有無だけを素早く確認したいなら、`sqlmap`(SQLi専用の自動診断ツール)や
`OWASP ZAP`(GUIでクロール→自動スキャン)の方が手早い。

## 関連ドキュメント

- [`netcheck/`](../netcheck/) ― 露出確認ツール本体
- [`strix-local-backend-notes.md`](strix-local-backend-notes.md) ― Strixの実行フロー解析、
  Docker不要のローカルバックエンド設計(より発展的な内容)
- [`strix-local-poc/windows-wsl-ollama-setup.md`](strix-local-poc/windows-wsl-ollama-setup.md)
  ― 本ノートの③の詳細・実機でのつまずきポイント集
