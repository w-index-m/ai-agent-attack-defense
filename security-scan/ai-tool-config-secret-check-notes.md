# ai_tool_config_secret_check: AI開発ツールの設定ファイルの平文の秘密情報の点検

`scripts/ai_tool_config_secret_check.py`(2026-11-14追加)。**自分のマシン**で、ファイルを読むだけで、何も書き換えない。
標準ライブラリだけで動く。

## 背景

GTIGの2026年9月のレポート(利用者が貼り付けた本文に基づく)は、情報窃取マルウェア(ACRSTEALER)の制御者が、AIコーディング支援の
設定ファイル(Clineの`secrets.json`、Continueの`config.yaml`)を狙うファイル収集ルールを配信したと報告している。これらは、
平文のAPIキーやモデルの接続先を保存し得て、盗まれると、被害者の有料のモデルの割り当てと基盤が使われる(LLMJacking)。
リポジトリの秘密情報は、gitleaks・Trivyが見るが、**利用者のホームの設定ファイルは、対象外**だった。

## 何をするか

- 既知の設定ファイルの場所(下の表)と、`--path`で指定した場所を読み、**APIキー・トークン・秘密鍵の形の文字列**と、「キー」「トークン」
  「パスワード」などの名前の項目の**平文の値**を探す。
- **見つけた値は、画面にもSARIFにも、一文字も出さない**。出すのは、場所・行・種類・長さ・ファイルの権限だけ(テストで、キーの全体・
  先頭10文字・末尾10文字が、出力に含まれないことを確認している)。
- 環境変数の参照(`${ANTHROPIC_API_KEY}`・`$OPENAI_API_KEY`など)と、ひな形の値(`YOUR_API_KEY`・`xxxx`など)は、指摘しない。
  環境変数の参照を使っている項目の数は、「推奨の形」として表示する。
- POSIXでは、他のユーザーが読める権限(group/otherに読み取り権限)を警告する。**WindowsのACLは見ない**。
- **「どの場所を確認して、何が存在したか」を必ず表示する**(場所の一覧が、お使いの版と合っているかを、確かめられるように)。

## 確認する場所(私の知識に基づく。版やOSで違い得る)

| 場所(ホームからの相対) | ツール | 自信 |
|---|---|---|
| `.continue/config.yaml`・`config.json` | Continue | 中〜高 |
| `.claude.json`・`.claude/settings.json`・`settings.local.json` | Claude Code(MCPの設定の環境変数など) | 高 |
| `.cursor/mcp.json` | Cursor(MCPの設定) | 高 |
| `.codex/config.toml`・`auth.json` | Codex CLI | 中 |
| `.aider.conf.yml` | Aider | 中〜高 |
| `.config/github-copilot/hosts.json`・`apps.json` | GitHub Copilot | 中 |
| VS Code系の`globalStorage`(`.config/Code/User/…`、`Library/Application Support/Code/User/…`、`%APPDATA%\Code\User\…`、Cursorも同様)のうち、フォルダ名に`claude-dev`・`cline`・`continue`・`roo`を含むもの | Cline・Continue・Roo等の拡張機能 | **低〜中**(Clineの保存先の正確なパスは、確実には知らない。名前で探す形にした) |

見つからなければ、`--path`で、お使いの保存先を指定する。

## 使い方

```bash
python3 scripts/ai_tool_config_secret_check.py
python3 scripts/ai_tool_config_secret_check.py --path ./myproject/.cursor --out ai_tool_secrets.sarif
```
```powershell
python scripts\ai_tool_config_secret_check.py
```
終了コード: 0(見つからなかった) / 1(見つかった) / 2(指定した場所が無いなどのエラー)。

見つかったら: キーを、環境変数(設定ファイルでは`${変数名}`の参照)やOSのキーストアに移し、設定ファイルからは消す。すでに他人に見られた、
またはマルウェアに感染した可能性があれば、そのキーを失効して、発行し直す。権限が広いファイルは、`chmod 600 <ファイル>`。

## 確認したこと(2026-11-14、このサンドボックス)

- **合成ファイル**(キーは、実行時に組み立てた。ソースには書いていない): Anthropic・OpenAI・Google・GitHub・AWS・Slack・Hugging Face・Groq形式のキー、
  秘密鍵、「キー・トークン・パスワード」の名前の項目を、既知の場所と`globalStorage`の中で検知。環境変数の参照・ひな形・短い値・パスや
  `max_tokens`のような名前・単純すぎる値は、指摘しない。同じ位置を、二重に指摘しない。権限の警告、`--path`・`--no-default-locations`・
  サイズの上限・シンボリックリンクを辿らないこと、終了コード。
- **実際のClaude Codeの設定**: このサンドボックスのホームで実行した。18か所のうち、`~/.claude.json`の1か所が存在し、指摘は0件(値は表示されない)。
- **回帰テスト**(`tools/test_ai_guards.py`の`TestAiToolConfigSecretCheck`、9件): 種類・二重カウント・環境変数の参照・ひな形・エントロピー・
  名前の末尾の判定・権限の警告・サイズ・シンボリックリンク・既定の場所・秘密鍵・`globalStorage`の探索・値が出力に出ないことを、1つずつ壊して、
  失敗することを確認した。最初に、二重カウントを、テストが見逃したので、テストを直した。名前の除外語は、末尾の判定と重複していたので、削除した。

## 限界

- **お使いのPCの実際の設定では、確認していない**。既知の場所の一覧は、私の知識に基づくので、「確認した場所」の表示で、存在するかを確かめる。
- 独自の形式のトークン、暗号化・難読化されたもの、OSのキーストアの中身は、見えない。
- WindowsのACL(ファイルの権限)は見ない。
- 値が「環境変数の参照」でも、その環境変数がどこに保存されているか(シェルの設定ファイルなど)は、対象外。
