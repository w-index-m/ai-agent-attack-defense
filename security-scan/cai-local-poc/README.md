# CAI (Cybersecurity AI framework) モックLLM PoC

[aliasrobotics/cai](https://github.com/aliasrobotics/cai)(`cai-framework`、v1.1.5。2026-10時点で**アーカイブ済み**、
後継は非公開のCybersecurity Superintelligence)を、実LLM APIキー不要のモックLLMサーバーで
エンドツーエンドに動かした PoC。設計の背景は
[`strix-local-poc/`](../strix-local-poc/)・[`cairn-lab/`](../cairn-lab/)と同じ発想(「頭脳は台本どおりの
偽物だが、手足(実際のツール実行)は本物」)で、Strix・Cairnに続く3つ目の事例。

> ⚠️ CAIは認可されたペネトレーションテスト用ツール。対象は自分が所有・許可を得たものだけに限定すること。

## 要点

- CAIの`cai.sdk.agents`は、Strixが使う`openai-agents` SDKと同系統の**独自フォーク**。
  LLM接続は`OPENAI_API_BASE`/`OPENAI_API_KEY`で差し替え可能(`src/cai/util/llm_api_base.py`)。
- ただしStrixと異なり、**非ストリーミング**のプレーンJSON `chat.completions`リクエストを送る
  (`"stream"`キー自体が存在しない)。SSE/chunked対応は不要。
- 既定モデル(`alias1`)はAlias Robotics独自ゲートウェイ向けで`ALIAS_API_KEY`が必須。
  `CAI_MODEL`を`openai/`プレフィックスの非aliasモデル名に変えることで回避できる。
- 起動時に無条件のライセンスチェックがあり、`CAI_LICENSE_OFF=1`で回避する(OSS利用モード)。
- デフォルトのエージェント(`selection_agent`)は複雑なため、ツールを1つ(`generic_linux_command`)
  しか持たない`one_tool_agent`(`CAI_AGENT_TYPE=one_tool_agent`。注意: `one_tool`ではなく
  `one_tool_agent`が正式名)を使うと最小構成で検証できる。
- `CAI_SINGLE_SHOT_CLI=1` + `--prompt "..."`で、対話REPLに入らず1ターンだけ実行して終了する。

## ファイル

| ファイル | 内容 |
|---|---|
| `mock_llm_server.py` | OpenAI互換(非ストリーミング)モックLLMサーバー。1回目のツール呼び出しで`generic_linux_command`を使い、`security-scan/sqli-lab`の`/login`SQLi認証バイパスを実際にcurlで再現させ、2回目以降は台本どおりの最終報告メッセージを返して1ターンを終了させる。 |

詳細な調査記録・ハマった点は[`../cai-local-backend-notes.md`](../cai-local-backend-notes.md)参照。

## 再現手順

```bash
# 1) CAI を取得して依存を入れる
git clone https://github.com/aliasrobotics/cai ~/cai
cd ~/cai
uv sync

# 2) 対象(sqli-lab)を起動
cd /path/to/ai-agent-attack-defense/security-scan/sqli-lab
VULN_APP_HOST=127.0.0.1 python3 vulnerable_app.py &

# 3) モックLLMサーバーを起動
mkdir -p /tmp/cai_mock
python3 /path/to/ai-agent-attack-defense/security-scan/cai-local-poc/mock_llm_server.py 8899 &

# 4) CAI を実LLMキー不要・単発実行で動かす
cd ~/cai
CAI_LICENSE_OFF=1 \
CAI_MODEL="openai/mock-model" \
CAI_AGENT_TYPE="one_tool_agent" \
CAI_SINGLE_SHOT_CLI=1 \
OPENAI_API_BASE="http://127.0.0.1:8899/v1" \
OPENAI_API_KEY="dummy-mock-key" \
uv run cai --prompt "Check the /login endpoint on 127.0.0.1:5000 for SQL injection and report findings"
```

成功すると、最終メッセージとして台本の報告文が表示され、`Total CAI Session Cost: $0.000000`で終わる。
`~/.cai/logs/*.jsonl`のセッションログに、実際に実行された`curl`の本物のレスポンス
(`Login OK ... Rows: [(3, 'admin', 1)]`)が`role: tool`のメッセージとして記録される。
