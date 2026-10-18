# Windows 11 + WSL2 + Ollama で Strix をローカルLLMだけで動かす手順(実機メモ)

対象: 自分が所有する Windows 11 機で、クラウドLLM課金なしに Strix (v1.7.0) を試す場合の
実機セットアップ手順。`strix-local-backend-notes.md` の「ローカルLLM」部分の、実際に踏んだ手順の記録。

> ⚠️ 対象は自分が所有・管理するローカル環境(自作ソフト、または DVWA/Juice Shop のような
> 自分で立てた練習用環境)に限定すること。Strix はペネトレーションテスト用ツールであり、
> 許可のない対象への実行は行わないこと。

## 前提

- Windows 11、WSL2 (Ubuntu)
- Docker Desktop(WSL2 バックエンド)
- Ollama for Windows(GUI 版)に、ツール呼び出し対応の小型モデル(例: `qwen2.5:1.5b`)を導入済み

## 1. OllamaをWSL側から到達可能にする

既定では Ollama は `127.0.0.1` のみで待ち受けるため、WSL2(別ネットワーク名前空間)から到達できない。

Windows 側(PowerShell、新規ウィンドウ)で環境変数を設定:

```powershell
setx OLLAMA_HOST "0.0.0.0:11434"
```

`setx` は新規プロセスにしか反映されないため、**Ollamaアプリを完全終了してから**、新しい
PowerShellで起動し直す:

```powershell
echo $env:OLLAMA_HOST   # 0.0.0.0:11434 になっているか確認
ollama serve
```

ログに `Listening on [::]:11434` が出れば待ち受け成功。このウィンドウは閉じずに開いたままにする。

## 2. WSL側からWindowsホストへの到達性を確認する

WSL2 の `localhost` 自動転送は環境によって効かないことがある。効かない場合は、WSLから見た
Windowsホストの実IPを使う。

```bash
# まず localhost を試す
curl http://localhost:11434/api/tags

# ダメなら、WindowsホストのIPを調べる(ip route の方が確実)
ip route show | grep default
# 例: default via 172.25.208.1 dev eth0 proto kernel

curl http://172.25.208.1:11434/api/tags   # 上で出たIPに置き換える
```

`{"models":[...]}` が返れば疎通OK。`capabilities` に `"tools"` が含まれるモデルを使うこと
(Strix はツール呼び出し=function callingを多用するため)。

それでも繋がらない場合は Windows Defender ファイアウォールの受信ブロックが疑われる。
PowerShell(管理者権限)で許可ルールを追加する:

```powershell
New-NetFirewallRule -DisplayName "Ollama 11434" -Direction Inbound -LocalPort 11434 -Protocol TCP -Action Allow
```

## 3. Strix CLI の導入(WSL側)

Strixのインストーラは bash スクリプトなので、PowerShellではなく **WSL側** で実行する。

```bash
curl -sSL https://strix.ai/install | bash
```

インストール直後は `.bashrc` に PATH 追記のみで、**今開いているシェルには反映されない**。

```bash
source ~/.bashrc
strix --version   # strix 1.7.0 のように出ればOK
```

> 補足: 導入時に一度だけ `curl: (60) SSL: certificate subject name 'NA' does not match target
> hostname` という証明書検証エラーが出ることがあった。再実行で解消した。再発する場合は、
> 社内プロキシやセキュリティソフトのHTTPS検査機能がTLSを中継していないか確認すること。

## 4. Docker Desktop の WSL 統合を確認する

`docker info` が PowerShell 側で通っても、**WSL側のそのディストロに対して WSL Integration が
有効になっていないと** Strix(WSL側プロセス)から Docker デーモンに到達できず、
`DOCKER NOT AVAILABLE` エラーになる。

Docker Desktop → **Settings → Resources → WSL Integration** で、使っているディストロ
(例: Ubuntu)のトグルを ON にし、Apply & Restart する。

WSL側で確認:

```bash
docker info
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0
```

## 5. 環境変数を設定してスキャン実行(WSL側)

```bash
export STRIX_LLM="ollama/qwen2.5:1.5b"
export OLLAMA_API_BASE="http://172.25.208.1:11434"   # 手順2で確認したIPに置き換える
export LLM_API_KEY="dummy"                            # ローカルOllamaは認証不要だが値は必須

# 自分で立てたDVWA(docker run --rm -p 8080:80 vulnerables/web-dvwa)を対象に、
# 軽量モードで実行
strix -n -t http://localhost:8080 --scan-mode quick --max-budget 10
```

結果は `strix_runs/<run-name>/` 以下に `penetration_test_report.md` /
`vulnerabilities.json` / `findings.sarif` として出力される(`AGENTS.md` 記載の仕様)。

## 既知の留意点

- `qwen2.5:1.5b` のような小型モデルは、Strixが要求する複雑なツール呼び出し
  (正確なJSON形式での関数呼び出し、長い推論チェーン)に対して力不足な可能性が高い。
  エージェントループ途中でツール呼び出しの形式を誤って停止することが起こり得る。
  その場合は `ollama pull qwen2.5:7b` 等、もう一段大きいモデルへの切り替えを検討する。
- `STRIX_LLM` は LiteLLM のモデルID形式。`config/settings.py` のエイリアス定義で
  `OLLAMA_API_BASE` が公式にサポートされていることをソースコードで確認済み
  (推測ではない)。
- Docker版バックエンド(既定)を使う場合、ネットワーク系ツール(nmap等)はコンテナ内に
  同梱されているため追加導入は不要。Docker不要の `local` バックエンドを使う場合は
  `strix-local-backend-notes.md` を参照(caido/nmap等は別途ホストへの導入が必要)。

## 実機での動作確認(手順通りに実施した記録)

上記手順を、実際に Windows 11 + WSL2(Ubuntu) + Docker Desktop + Ollama(`qwen2.5:1.5b`) の
組み合わせで最後まで実施し、以下を確認した。

- `OLLAMA_HOST=0.0.0.0:11434` 設定 → Ollama 再起動 → `Listening on [::]:11434` を確認。
- WSL から `localhost` では届かず、`ip route show | grep default` で得た Windows ホストの
  実IP(例: `172.25.208.1`)で `curl http://<IP>:11434/api/tags` が通ることを確認。
  （ファイアウォール設定は今回は不要だった。環境により `New-NetFirewallRule` が要る場合がある)
- `curl -sSL https://strix.ai/install | bash` のインストール直後は、同じシェルでは
  `strix` コマンドが見つからない(PATH が `.bashrc` に追記されるだけで、今のシェルには
  未反映)。`source ~/.bashrc` で解決。
- Docker Desktop の **WSL Integration** が対象ディストロで無効だと、`docker` コマンド自体が
  WSL側に存在しない(`docker info` 以前の問題)。Settings → Resources → WSL Integration で
  有効化してから `Apply & Restart` が必要。
- WSL Integration 有効化後も `docker ps` が
  `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock`
  で失敗するケースがあった。原因はユーザーが `docker` グループ未所属。
  `sudo usermod -aG docker $USER` 後、**ターミナルを再起動しないと反映されない**
  (`groups` で `docker` が出るか確認)。
- `docker pull ghcr.io/usestrix/strix-sandbox:1.3.0` は 700MB超あり、回線状況によっては
  `short read: unexpected EOF` で失敗することがあった。同じコマンドを再実行すれば、
  `Pull complete` 済みの層はキャッシュされ、失敗した層だけ再取得される。
- `export` した環境変数(`STRIX_LLM` 等)は、**ターミナルを閉じて開き直すと消える**
  (`.bashrc` に書いていない限り)。都度 `echo $STRIX_LLM` で確認するのが安全。
- 上記全てをクリアした状態で `strix -n -t http://localhost:8080 --scan-mode quick
  --max-budget 10` を実行し、**`ollama/qwen2.5:1.5b` から実際にレスポンスが返ってくる
  ことを確認した**(Input ~2.0K tokens / Output 269 tokens / Cost $0.0000)。
  → 「ローカルOllamaでの接続は未検証」としていた前段の記述を、ここで実証済みに更新する。
  GPU なし(CPU 推論、AMD iGPU 未対応環境)でも、最初の応答に数分程度かかる以外は動作した。

## `-n`(headless)は常に付けなくてよい

`AGENTS.md`(Strix公式のエージェント向けガイド)には「ヘッドレス実行には常に`-n`を使う」と
あるが、これはCI/自動化向けの指示。**手元で対話的に様子を見ながら試す用途では`-n`を外した
方がよい**。`-n`ありだと要約パネルしか出ず、別ターミナルで`strix view <run-name>`を開いて
ブラウザで見る、という2系統の操作が必要になる。`-n`を外すと、同じターミナル内の対話型TUI
(ライブビュー)でエージェントの動き・コマンド・結果が見られ、ブラウザを別途開く必要がない。

```bash
# 観察しながら試す場合(1ウィンドウで完結)
strix -t http://localhost:8080 --scan-mode quick --max-budget 10 --max-turns 30 \
  --instruction "..."

# 自動化/CI向け(-n、要約のみ。strix viewと組み合わせる)
strix -n -t http://localhost:8080 --scan-mode quick --max-budget 10 --max-turns 30 \
  --instruction "..."
```

## モデルサイズ別の実機比較(`qwen2.5:1.5b` vs `qwen2.5:7b`)

ハードウェア: AMD Ryzen 7 7735HS(内蔵GPU、ただしドライバ未更新のためCPU推論)、実装RAM 32GB
(30.8GB使用可能)。`ollama serve`起動時のログで、CPU推論時の実効メモリは約10GB(他コンテナ
稼働中の残り)と表示された。27Bクラス(Q4量子化で16〜18GB程度)は、この空きメモリでは厳しく、
現実的な選択肢は7B前後と判断した。

対象: 自分のPC内の DVWA(`docker run -d -p 8080:80 vulnerables/web-dvwa`)、
`strix -n -t http://localhost:8080 --scan-mode quick --max-budget 10`。

### `qwen2.5:1.5b`(986MB、Q4_K_M) ― 実用不可と判断

`strix view <run-name>` でライブビューを開いて確認した結果、以下が起きていた。

- **対象と無関係な内容を捏造した**。実際にはDVWA(`localhost:8080`)を調べていないのに、
  「Acme Customer Portal」という架空のサービス名で、存在しないSSRF・テナント分離不備の
  Executive Summaryを最初から書き始めた。
- **ツール呼び出しのJSON形式を継続的に誤り続けた**。`wait_for_agents` / `finish_scan` を、
  存在しないパラメータ名(`max_retries`, `sleep_seconds`, `timeout` 等をランダムに変えながら)
  で呼び続け、有効な呼び出しに一度も収束しなかった。
- Strix側のハーネスが「有効なツール呼び出しが来ない」状態を検知し、
  `"This is recovery attempt 24/500."` のような強制的な軌道修正メッセージを送り続けていた
  (500回まで許容する設計)。ローカルLLMのため課金は発生しないが、空回りしたまま終わる。
- 一部、`nc -e /bin/sh 127.0.0.1 4444`(リバースシェル)や、`apply_patch` での
  `/etc/passwd` ・ `/etc/hosts` 書き換えのような、文脈と無関係な破壊的コマンドの生成も
  見られた。Dockerサンドボックスコンテナの中に閉じているため、ホスト(Windows/WSL)への
  実害はないが、モデルが状況を全く理解できていないことを示す強いシグナル。

→ **結論: 1.5Bはツール呼び出しの精度が足りず、実用的なスキャンができない**。

### `qwen2.5:7b`(4.7GB、Q4_K_M) ― まともな挙動を確認

同じ対象・同じ`--scan-mode quick`で切り替えて実行したところ、ライブビューの最初の一手が

```
curl http://host.docker.internal:8080
```

だった。これは**文脈に即した正しい判断**。Strixのエージェントはサンドボックスコンテナの中で
動くため、ホスト側(WSL)で動いているDVWAに到達するには、Dockerが提供するゲートウェイ名
`host.docker.internal`を使う必要があり、そこを正しく選べていた。1.5Bで見られたような
捏造や無関係なコマンドは、ここまでの観測では出ていない。

→ 7Bは、少なくとも「対象に実際にアクセスしようとする」という最初のステップを正しく踏める。
  スキャンが最後まで完走するか、実際にDVWAの既知の脆弱性(SQLi等)を検出できるかは、
  このメモの時点では未確認(続報があれば追記する)。

### 運用上の補足(つまずいた点)

- **PC再起動後は、WSLから見たWindowsホストIP(`ip route show | grep default`)が変わって
  いないか再確認すること**(今回は変わらなかったが、環境によっては変わり得る)。
- **PC再起動・Docker Desktop再起動のたびに、`docker run -d`で起動していたDVWAコンテナは
  停止している**(`docker ps -a` で `Exited` になる)。`docker start <container-id>` で
  再開するか、`docker run -d -p 8080:80 vulnerables/web-dvwa` で新しく起動し直す。
- **WSLターミナルを閉じて開き直すたびに、`export`した環境変数は消える**
  (`.bashrc`に書いていない場合)。`STRIX_LLM` だけ打ち直して `OLLAMA_API_BASE` を
  忘れると、`litellm.APIConnectionError: Cannot connect to host localhost:11434`
  のように既定値(`localhost`)にフォールバックしたまま失敗する。3つとも毎回
  `echo` で確認するのが安全。
- **進捗をリアルタイムで見るには `strix view <run-name>` が便利**。別のWSLターミナルで
  実行すると、ブラウザで開けるローカルURL(トークン付き)が表示され、エージェントの
  思考・個々のツール呼び出し・検知した脆弱性(Issues)をライブで確認できる。スキャン本体は
  止めずに並行して見られる。WSLは `gio: ... Operation not supported` という警告付きで
  ブラウザを自動起動できないので、表示されたURLを手動でコピーしてWindows側のブラウザに
  貼る。

## 自動化スクリプト(Windows側から一括起動)

ここまでの手順(Docker起動確認・Ollama起動確認・DVWAコンテナ起動確認・WSL側での環境変数
設定とstrix実行)を、PowerShellスクリプトとして自動化したものが
[`start-strix-test.ps1`](start-strix-test.ps1)。

Windows側から直接 `wsl.exe` を呼ぶ構成(Python経由ではない)。Windows側のプロセス
(Docker Desktop・Ollama)はPowerShellから、実行自体はWSL側のStrixに委譲するのが素直なため。

```powershell
# 既定値(DVWA、qwen2.5:7b、対話TUI)で実行
.\security-scan\strix-local-poc\start-strix-test.ps1

# 指示付き・モデル指定
.\security-scan\strix-local-poc\start-strix-test.ps1 `
  -Model "qwen2.5-coder:7b" `
  -Instruction "This is DVWA. Log in with admin:password, set DVWA Security to Low, then test the SQL Injection page only."
```

未検証の部分(初回実行時に確認すること):
- `$DockerDesktopPath` の既定値(`C:\Program Files\Docker\Docker\Docker Desktop.exe`)が
  実際のインストール先と一致しているか。
- 既にOllamaアプリ(GUI版)が `OLLAMA_HOST` 未設定のまま起動している場合、スクリプトは
  `http://localhost:11434/api/tags` への疎通だけ見て「起動済み」と判断する。WSL側から
  到達できない構成(0.0.0.0で待ち受けていない)のまま進んでしまう可能性があるため、
  その場合は一度Ollamaアプリを終了してからスクリプトを再実行すること。

## 追加検証: `hermes3:8b`、および`STRIX_FORCE_REQUIRED_TOOL_CHOICE`

7Bでのループ問題への対策として、以下を試した。

- **モデル変更(`hermes3:8b`、Q4_0、ツール呼び出し特化を謳うモデル)** ―
  1手目から`exec_command: invalid arguments — Invalid JSON: trailing characters`で
  litellmのパースが失敗(`litellm.APIConnectionError: Extra data`)。
- **`qwen2.5:7b` + `STRIX_FORCE_REQUIRED_TOOL_CHOICE=true`**(LLMに対してツール呼び出し
  形式での応答を強制する設定、`strix/config/settings.py`の`force_required_tool_choice`)―
  同じく1手目から`Invalid JSON: trailing characters`で失敗。

いずれも、`exec_command`に渡す`curl`コマンドの引数(Cookie jarのパス等を含む、やや長い
文字列)を含むツール呼び出しで発生した。モデル固有の問題ではなく、**Ollama経由のツール
呼び出しで、引数が長くなると量子化された小型モデルがJSONを正しく閉じられない**という、
構造的な限界である可能性が高い。`STRIX_FORCE_REQUIRED_TOOL_CHOICE`は「ツール呼び出し
形式で返すこと」は強制できても、「その中身が正しいJSONであること」までは保証しない。

対話TUI(`-n`なし)でこのエラーが出た場合、ヘッドレスのような自動リトライ/軌道修正が
働かず、`Send a message`の入力待ちのまま停止することも確認した。

## 追加検証: クラウドLLM(Groq)との比較

ローカル小型モデルの不安定さが「モデルの弱さ」なのか「Strix側の一般的な癖」なのかを
切り分けるため、クラウドLLM(Groq、無料枠あり・高速推論)に切り替えて同条件で試した。

```bash
export GROQ_API_KEY="<Groqのキー>"
export STRIX_LLM="groq/openai/gpt-oss-120b"
```

結果、**ローカルモデルとは全く別種の失敗**が、しかも1手目から発生した。

```
litellm.BadRequestError: GroqException – {"error":{"message":
"invalid JSON schema for tool list_mcps, tools[33].function.parameters:
'required' present but 'properties' is missing", ...}}
```

Strixが内部で定義しているMCP関連ツール`list_mcps`(`strix/tools/mcp/agent_tools.py`、
引数なしの関数)のJSONスキーマ自動生成に不備があり、`required`だけ出力されて
`properties`が欠落している。Ollama(スキーマ検証がゆるい)では表面化しなかったが、
OpenAI互換で厳密な検証をするGroqに変えたことで、**Strix自身(または依存する
`openai-agents` SDK)のバグ**が顕在化した。公式には、MCPツール群だけを無効化する
フラグは見当たらなかった(`strix --help`に該当オプションなし)。

この時点で、`gpt-oss-120b`というモデル自体の良し悪しを評価する前に、Strix本体側の
問題でリクエストが一つも通らない状態になった。モデル側(`qwen/qwen3.8-27b`等、Groq上の
他の候補)への切り替えでは回避できない、**Strixのバージョン(v1.7.0)とGroq(厳密スキーマ
検証プロバイダ)の組み合わせ自体の非互換性**と判断し、ここで検証を打ち切った。

## Groqのエラーに対するパッチ(未実機検証)

`list_mcps`のJSONスキーマ不備の原因を追ったところ、`strix/agents/factory.py`の
`_with_strictness()`に行き着いた。Strixが依存する`openai-agents` SDKの
`FunctionTool.__post_init__`は、`strict_json_schema=True`のときに必ず
`ensure_strict_json_schema()`を呼び、パラメータなしのツールのスキーマを
`{"properties": {}, "required": [], "additionalProperties": false, ...}`という、
SDK自身が定義する「空スキーマの正規形」(`agents.strict_schema._EMPTY_SCHEMA`)に
正規化する。これ自体は仕様上正しい形のはずだが、Groq(または litellm→Groq間の
どこか)がこの正規形を「`required`はあるのに`properties`が無い」と誤認識して拒否する。

対策として、パラメータなしのツールだけ`strict_json_schema`を`False`に落とし、SDKの
自動正規化(`ensure_strict_json_schema`)自体を素通りさせることで、`required`も
`additionalProperties`も付与されない最小スキーマ(`{"type": "object", "properties": {}}`)
のまま送信されるようにした。パラメータを持つツール(`call_mcp`等)には影響しない。

パッチ: [`groq-empty-schema.patch`](groq-empty-schema.patch)(`strix/agents/factory.py`の
`_with_strictness`関数に対する差分)。このセッション内でのスキーマ生成の単体検証
(`_with_strictness`の戻り値を直接確認)は通ったが、**実際にWindows機でGroqに対して
スキャンが完走するかは未検証**。

適用手順(WSL側):

```bash
# 1. インストール済みStrixのfactory.pyの場所を探す
find / -path "*/strix/agents/factory.py" 2>/dev/null

# 2. 見つかったパスに対して適用(リポジトリをWSL側にも置いている場合)
patch <見つかったfactory.pyのパス> < groq-empty-schema.patch

# 3. 適用後、再度Groqでの実行を試す
export STRIX_LLM="groq/openai/gpt-oss-120b"
strix -t http://localhost:8080 --scan-mode quick --max-budget 10 --max-turns 50 \
  --instruction "..."
```

`patch`コマンドが無ければ、`groq-empty-schema.patch`の内容を見ながら該当関数を
手動で書き換えてもよい。

Strix本家へのフィードバックとしても価値がある内容(GitHub Issueの材料)と考えられる。

## 結論(2026-10-18 時点)

| 試行 | 症状 |
|---|---|
| `qwen2.5:1.5b`(ローカル) | 対象と無関係な内容を捏造。ツール呼び出し形式が終始崩壊(`wait_for_agents`等を存在しないパラメータで呼び続ける)。文脈と無関係な破壊的コマンド(`nc`でのリバースシェル試行、`/etc/passwd`書き換え試行)も出現(サンドボックス内で完結、実害なし)。 |
| `qwen2.5:7b`(ローカル・通常) | 最初の数手は対象に即した正しい判断(`curl http://host.docker.internal:8080`等)。ターンが進むと`ls`/`pwd`等の無意味な繰り返しループに陥る。指示(`--instruction`)で的を絞っても、SQLiページへの実際のリクエスト(`id=1'`)までは到達したが、その後また無関係な探索に戻った。 |
| `hermes3:8b`(ローカル) | 1手目のツール呼び出しからJSONが壊れてパース失敗。 |
| `qwen2.5:7b` + `STRIX_FORCE_REQUIRED_TOOL_CHOICE=true`(ローカル) | 同上、1手目からJSONが壊れてパース失敗。 |
| `groq/openai/gpt-oss-120b`(クラウド) | モデルの応答以前に、Strix内部の`list_mcps`ツールのJSONスキーマ不備でリクエスト自体がGroqに拒否される。 |

**このマシン・このモデルサイズ帯(ローカル、CPU推論、1.5B〜8B)では、Strixが要求する
「長い引数を含む正確なJSON形式のツール呼び出し」を安定して生成できない。クラウド側
(Groq、厳密なOpenAI互換スキーマ検証)に切り替えても、今度はモデルの出来とは無関係に
Strix自身(`list_mcps`ツール)のスキーマ不備でブロックされる**、というのが今回の一連の
実験で得られた結論。Strix自体の技術検証(Docker不要バックエンド、WSL2環境でのOllama
接続、Groq接続)は一通り成立することを確認できたが、**実用的な自動診断としての完走・
検出精度は、ローカル・クラウドのどちらの構成でも確認できなかった**。

次に試す価値がありそうな方向性(いずれも未検証):
- Strixの新しいバージョンがリリースされ、`list_mcps`のスキーマ不備が修正されるのを待つ
  (Groq等の厳密なプロバイダを使う上での前提条件)。
- `list_mcps`周りのスキーマ生成コードに自前でパッチを当てて、Groqでの続きを試す
  (`strix/tools/mcp/agent_tools.py`、`function_tool`デコレータの自動生成ロジック)。
- AMD内蔵GPUのドライバ更新 + `OLLAMA_IGPU_ENABLE=1`での高速化(ローカルモデルの精度
  自体は変わらないが、試行回数を増やしやすくなる)。
- OpenRouter等、別のOpenAI互換プロバイダでも同じスキーマ検証エラーが出るか確認。

## 未検証(このメモの範囲外)

- `qwen2.5:7b` でのスキャン完走、および実際の脆弱性検出精度(DVWAの既知のSQLi等を
  見つけられるか)。
- `qwen2.5:7b` より大きいモデル(14B等)での動作。27Bクラスは、このマシンの空きメモリ
  事情では現実的ではないと判断し、今回は試していない。
- `llama3.1:8b`など、他のツール呼び出し特化モデルでの動作。
