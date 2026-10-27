# CAI (Cybersecurity AI framework) をモックLLMで動かす設計メモ

対象: [aliasrobotics/cai](https://github.com/aliasrobotics/cai)(`cai-framework` v1.1.5)。
README曰く「アーカイブ済み(2026-10時点)」で、後継は非公開の Cybersecurity Superintelligence (CSI)。
最終版のソースツリーがそのまま公開されているため、実機検証には支障なかった。

> ⚠️ CAIは認可されたペネトレーションテスト用ツール。対象は自分が所有・許可を得たものだけに限定すること。

## 背景

Strix・Cairnに続き、「モックLLM(無料・機械的)で、実際のツール実行だけは本物にする」という
同じ手法が他のAIセキュリティツールにも通用するかを検証した。CAIを選んだ理由は、
`18論文・30+CVE・CTF世界1位`等を謳う実績のある、独立した別系統のフレームワークだったため。

## 1. アーキテクチャ調査(コードを読んだ事実、推測ではない)

```
src/cai/cli.py                 エントリ (argparse → headless REPL)
  └─ src/cai/cli_headless.py    run_cai_cli() : 対話ループ / 単発実行
       └─ src/cai/agents/*.py   Agent定義 (one_tool_agent 等)
            └─ cai.sdk.agents   独自ベンダリングされたエージェントSDK
                 (OpenAIChatCompletionsModel 等。Strixが使う openai-agents と同系統)
```

- `src/cai/agents/one_tool.py`:
  ```python
  from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
  from openai import AsyncOpenAI
  ...
  one_tool_agent = Agent(
      name="CTF agent",
      tools=[generic_linux_command],
      model=OpenAIChatCompletionsModel(
          model=model_name,
          openai_client=AsyncOpenAI(api_key=api_key),
      ),
  )
  ```
  `cai.sdk.agents`が、Strixで検証済みの`openai-agents`系SDKの独自フォークであることをソースから確認。
  ツールは`generic_linux_command`の1つだけで、Strixの48個より大幅に単純。

- `src/cai/util/llm_api_base.py`の`resolve_llm_openai_compatible_base()`:
  非aliasモデル(モデルIDが`cai`/`alias`/`csi`で始まらない)の場合、
  `OPENAI_API_BASE`環境変数をそのままAPIベースURLとして使う設計であることをソースから確認。
  alias系モデルだと`CSI_CUSTOM_ENDPOINT`/`ALIAS_API_URL`が優先され、`ALIAS_API_KEY`が必須になる。

## 2. 実機でハマった点と対処(起きた順)

### 2.1 既定モデルがプロプライエタリゲートウェイ必須

既定の`CAI_MODEL`は`"alias1"`(`src/cai/config.py`)で、このモデルIDは`_ALIAS_API_URL_MODEL_PREFIXES`
(`cai`/`alias`/`csi`)に該当するため、`ALIAS_API_KEY`が無いと起動直後に
`Authentication Error: ALIAS_API_KEY is invalid or not set`で停止する。

→ `CAI_MODEL="openai/mock-model"`のように、aliasプレフィックスに当たらないモデルIDを明示的に指定して回避。

### 2.2 起動時ライセンスチェック(モデルとは別の、無条件のゲート)

`CAI_MODEL`を変えても、`src/cai/cli.py`の`main()`内で`_chk()`(`src/cai/util_ext.py`)という
**プロプライエタリ版のライセンスAPIキー確認**が無条件に走り、同じ`ALIAS_API_KEY is invalid`
エラーで止まる。これはLLM接続とは別物(OSSアーカイブに残っている、元は商用版向けのゲート)。

→ `CAI_LICENSE_OFF=1`で、`_license_off()`がTrueになりこのチェック自体をスキップできる
(ソースのdocstringに明記: 「OSSビルド向けにライセンスチェックを完全にバイパスする」)。

### 2.3 単発実行(非対話)の仕組み

`--prompt "..."`だけでは、初回プロンプトを実行した後も対話REPLに入ってしまう(headlessだが
終了しない)。`src/cai/cli_headless.py`に`CAI_SINGLE_SHOT_CLI`環境変数による専用の単発実行モードが
実装されていることをソースから発見(`_single_shot_cli_active()`)。

→ `CAI_SINGLE_SHOT_CLI=1`を指定すると、1ターン実行後に`return`で素直に終了する
(Strixの`-n`相当)。

### 2.4 エージェント名の誤り

`CAI_AGENT_TYPE=one_tool`を指定すると
`ValueError: Invalid agent type: one_tool. Available agents: ... one_tool_agent ...`
で失敗。利用可能なエージェント名一覧がエラーメッセージに出るため、正しい名前
(`one_tool_agent`)に修正して解決。

### 2.5 モックLLMプロトコル: Strixと違い非ストリーミング

Strix用の`mock_llm_server.py`をそのまま流用したところ、CAIからのリクエストで
`stream`キーが存在しない(非ストリーミング)ことが、受信リクエストの生ログ
(`requests.jsonl`)から判明。Strixは`stream: true`のSSEだったため、「非ストリーミングなら常に
`content: "OK"`を返す」という以前のロジックのままだと、ツール定義(`tools`)付きのリクエストでも
`OK`としか返さず、ツール呼び出しが一切発生しなかった。

→ 非ストリーミング分岐でも`tools`の有無とそれまでのやり取り回数を見て、
`{"role": "assistant", "content": null, "tool_calls": [...]}`形式のツール呼び出しレスポンスを
返すように修正(ストリーミングのSSE形式は不要、プレーンJSONの`chat.completion`で十分)。

### 2.6 `--yolo`はセーフティ上の理由で使わなかった

CAIは、コマンドが「機密パターン」(`sudo`・破壊的操作・リバースシェル・`curl | sh`・環境変数の
持ち出し等、`src/cai/util/user_prompts.py`の`_SENSITIVE_PATTERNS`)に一致した場合のみ、
実行前に確認を求める設計(ソースから確認。全コマンドを毎回確認するわけではない)。
`--yolo`/`CAI_YOLO=1`はこの確認を一律無効化するフラグで、本セッションの自動分類器に
「安全性バイパス」として実行を拒否された。

今回使った`curl -s 'http://127.0.0.1:5000/login?...'`は上記の機密パターン(`sudo`・`rm -rf`・
`curl | sh`・環境変数の持ち出し等)のいずれにも一致しないため、`--yolo`なしでも確認なしで
実行されることをソースの正規表現から確認済み。→ `--yolo`は使わず、確認が不要なコマンドだけを
台本に使うことで対処(安全側の回避)。

### 2.7 原因特定に時間を要した「ハング」は、CAI自体の問題ではなかった

上記をすべて解決した後、1回目のツール呼び出し(`generic_linux_command`)までは成功するのに、
その後数分間応答が返らない現象が発生。`py-spy dump`でPythonレベルのスタックトレースを取得し、
メインスレッドが`asyncio`の`select()`で待機したまま(`_run_non_streamed`内)であることを確認。
モックサーバーへの生curlで検証したところ`Connection refused`——**このサンドボックス環境で、
バックグラウンド起動していたモックLLMサーバープロセス自体が、デバッグ試行錯誤の途中でいつの間にか
落ちていた**ことが原因だった(本セッションで繰り返し発生している、バックグラウンドプロセスの
時間制限/誤killの問題。Strix・Cairn検証時にも同種の問題が起きている)。

→ モックサーバーを再起動し、`ss -ltnp`で`LISTEN`状態を確認してから再実行したところ、
即座に完走した。**教訓: ハングに見えたら、まずモックサーバーが本当に生きているか
(`ss -ltnp`やサーバー自身への生curl)を確認する。**

## 3. 完走結果

```bash
CAI_LICENSE_OFF=1 \
CAI_MODEL="openai/mock-model" \
CAI_AGENT_TYPE="one_tool_agent" \
CAI_SINGLE_SHOT_CLI=1 \
OPENAI_API_BASE="http://127.0.0.1:8899/v1" \
OPENAI_API_KEY="dummy-mock-key" \
uv run cai --prompt "Check the /login endpoint on 127.0.0.1:5000 for SQL injection and report findings"
```

- モックが`generic_linux_command(command="curl -s '.../login?username=admin%27%20--&password=x'")`
  を指示 → CAIが**実際にホスト上でcurlを実行**し、`security-scan/sqli-lab`の実サーバーから
  本物のレスポンス(`Login OK ... Rows: [(3, 'admin', 1)]`)を取得。
- `~/.cai/logs/<session>.jsonl`のセッションログに、`{"role": "tool", "tool_call_id": "...",
  "content": "Login OK. Query was: ..."}`として、実行結果がそのまま記録されていることを確認
  (捏造ではなく、本当にホストプロセスとして実行された証拠)。
- モックが台本どおりの最終報告メッセージを返し、1ターンで正常終了。
  `Total CAI Session Cost: $0.000000`。

→ **StrixやCairnと同じ「台本LLM・本物のツール実行」パターンが、全く別系統のフレームワークである
CAIでも成立することを確認した。** 鍵となった条件は、CAIが`OPENAI_API_BASE`での接続先差し替えに
対応していたこと(`src/cai/util/llm_api_base.py`で明示的にサポートされている設計)。

## 検証2: プロンプトインジェクションガードレールの実機検証(2026-10-27)

モックLLMは台本どおりに固定の行動を返すだけなので、「悪意ある文字列に騙されるか」という
**LLM自身の判断力**は検証できない。その代わり、CAIが**フレームワーク側に自動的な防御機構
(guardrails)を持っているか**をソースから調査し、実機で検証した。

`src/cai/agents/guardrails.py`に、`prompt_injection_guardrail`という正規表現ベースの
検知機構(`INJECTION_PATTERNS`、Unicode同形異字の正規化、base64デコードしての危険コマンド検出
等、かなり作り込まれている)が実装されていることを発見。これは`@input_guardrail`として
CAIのAgent定義に組み込まれている。

実機で2点を確認:

```python
import os
print(os.getenv('CAI_GUARDRAILS', 'false').lower() == 'false')  # -> True(未設定時)
```

1. **既定で無効**: `prompt_injection_guardrail`は冒頭で
   `if os.getenv("CAI_GUARDRAILS", "false").lower() == "false": return allowed`
   と早期リターンしており、環境変数`CAI_GUARDRAILS=true`を明示的に設定しない限り、
   パターンマッチは一切実行されない。

2. **ツール出力由来に見える文字列は検知対象外**: `detect_injection_patterns()`自身の
   冒頭に `if "'role': 'tool'" in text: return False, []` という早期リターンがある。
   同一の悪意ある文字列(`IGNORE ALL PREVIOUS INSTRUCTIONS...`等)を、素のユーザー入力として
   渡すと5個のパターンにヒットして検知されるが、`{'role': 'tool', 'content': '...'}`という
   ツール出力の形で渡すと**0個のパターンで検知されない**ことを、`detect_injection_patterns()`を
   直接呼び出して確認した:

   ```
   as tool-output-shaped string -> flagged: False patterns: 0
   as plain user input          -> flagged: True patterns: 5
   ```

   さらに、`@input_guardrail`はSDKの設計上、**セッション開始時のユーザー入力1回だけ**に
   適用される仕組みであり、会話途中で`exec_command`等のツール出力として流れ込んでくる
   悪意あるコンテンツ(間接プロンプトインジェクション、OWASP LLM01の典型例)は、
   そもそもこのガードレールの評価対象にすら入らない。

→ **この実装は「素の自己申告的な指示上書き」を素のユーザー入力として受け取った場合には
機能するが、エージェント型ツールにとって最も現実的な脅威である「ツール出力経由の間接的な
プロンプトインジェクション」には、既定設定でも、明示的に有効化した設定でも、届いていない**
ことが、ソースコードの直接実行による検証で判明した。これはCAI固有の実装詳細の指摘であり、
一般的なLLMの脆弱性ではない。

## 検証3: マルチエージェント・ハンドオフの実機検証(2026-10-27)

検証1は`one_tool_agent`という単一エージェント・単一ツール構成だった。CAIの既定エージェントは
`selection_agent`で、タスクに応じて専門エージェント(`red_team_agent`・`blue_team_agent`等、
計19個)に**SDKのhandoff機構で制御を引き渡す**設計(`src/cai/agents/operational_handoffs.py`の
`build_operational_handoffs()`)。これが台本からも実際に機能するか検証した。

まずログ専用のモック(`probe_mock_server.py`、常に`OK`を返しつつリクエストのtools一覧を
出力するだけ)で、`selection_agent`が実際に`transfer_to_red_team_agent`等19個のhandoffツールを
モデルに渡していることを確認(`check_available_agents`等3個の通常ツール+19個のhandoff)。

その上で、台本を「1手目: `transfer_to_red_team_agent`を呼ぶ→2手目以降: ハンドオフ先の
`generic_linux_command`で実際にcurlを実行→終了」という流れに変更して実行したところ:

- 画面表示が`● CTF agent`から**`● Red Team Agent`に切り替わった**(実際にアクティブ
  エージェントが変化したことを示す)。
- ハンドオフ後に呼んだ`generic_linux_command`の結果が、CAIのセッションログに
  本物のHTTPレスポンス(`HTTP/1.1 401 UNAUTHORIZED\r\nServer: Werkzeug/3.1.9 ...`)として
  記録されていることを確認。

→ **ハンドオフは見た目だけのギミックではなく、実際にアクティブエージェントが切り替わり、
切り替わった先のエージェントが持つ別のツールセットで本物の実行が行われる**ことを実証した。

## 未検証(本PoCのスコープ外)

- 実LLMキーでの、本物の知能によるエンドツーエンドの脆弱性発見(今回はStrix/Cairn同様、
  既知の脆弱性を台本で再確認しただけ)。
- Docker/SSH/CTFコンテナバックエンド(`active_container`/`ssh_user`経由)での動作
  (今回はローカルホスト実行のみ検証)。
- `CAI_GUARDRAILS=true`を有効化した状態での、素のユーザー入力への実際のブロック動作
  (ソースの早期リターンロジックから「無効時は確実に素通りする」ことは確認したが、
  有効化後の実ブロック挙動そのものは未検証)。
