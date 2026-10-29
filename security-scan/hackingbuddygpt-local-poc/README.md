# hackingBuddyGPT モックLLM PoC

[ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT)を、実LLM APIキー不要の
モックLLMサーバーでエンドツーエンドに動かしたPoC。Strix・Cairn・CAI・PentestGPTに続く
5つ目の事例。litellmを単一のLLMアップストリームとして使う設計で、OpenAI互換の
関数呼び出し(tool_calls)でCapability(コマンド実行等)を駆動する点はStrix/CAIに近い。

> ⚠️ hackingBuddyGPTは認可されたペネトレーションテスト用ツール。対象は自分が所有・許可を得たものだけに限定すること。

**先に読むべき重要な発見**: hackingBuddyGPT自身の`api_base`設定項目は**死んでいる
(デッドコード)**。詳細・再現方法は[`../hackingbuddygpt-local-backend-notes.md`](../hackingbuddygpt-local-backend-notes.md)参照。

## ファイル

| ファイル | 内容 |
|---|---|
| `mock_llm_server.py` | OpenAI互換(非ストリーミング)モックLLMサーバー。リクエストに`tools`が含まれていれば`record_note`等の1件目のツール名に対する台本どおりの`tool_calls`を返し、無ければプレーンテキストを返す。 |
| `drive_tools_smoke_test.py` | `hackingBuddyGPT.utils.llm.LiteLLM`を直接呼び出し、(1)プレーンテキスト応答、(2)`RecordNote`というCapabilityを関数呼び出しスキーマに変換して渡し、モックが返した`tool_calls`が正しくパースされること、の両方を検証するスクリプト。 |
| `api_base_bug_repro.py` | `api_base`デッドコードバグの再現スクリプト。「`api_base`だけ設定(失敗)」「`api_base`+`OPENAI_API_BASE`両方設定(成功)」をそれぞれ2回ずつ、さらに「`api_base`は正しいが`OPENAI_API_BASE`は到達不能(失敗)」という陰性対照を1回実行し、到達先を実際に決めているのが`OPENAI_API_BASE`環境変数だけであることを切り分ける。 |

## 再現手順

```bash
# 1) hackingBuddyGPTを取得
git clone https://github.com/ipa-lab/hackingBuddyGPT ~/hackingbuddygpt

# 2) 依存関係を入れる(venv。リポジトリ自身のビルドは実行しない — PyPI配布分だけ個別インストール)
python3 -m venv ~/hbgpt-venv
~/hbgpt-venv/bin/pip install litellm httpx pydantic PyYAML python-dotenv rich tenacity \
  fabric asyncssh Mako requests pypsexec beautifulsoup4 faker mcp

# 3) モックLLMサーバーを起動
python3 /path/to/ai-agent-attack-defense/security-scan/hackingbuddygpt-local-poc/mock_llm_server.py 8900 &

# 4) 直接LLM層を駆動(重要: api_base引数ではなくOPENAI_API_BASE環境変数を使うこと)
OPENAI_API_BASE="http://127.0.0.1:8900/v1" \
~/hbgpt-venv/bin/python /path/to/ai-agent-attack-defense/security-scan/hackingbuddygpt-local-poc/drive_tools_smoke_test.py ~/hackingbuddygpt/src
```

成功すると、プレーンテキスト応答とtool_calls応答の両方が、モックサーバーが実際に受け取った
リクエスト(`model`・`messages`・`tools`の有無)とともにログに記録される。
