# hackingBuddyGPT のモックLLM検証メモ

[ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT)を、Strix・Cairn・CAI・
PentestGPTに続く5つ目の事例として検証した記録。PoCの成果物は
[`hackingbuddygpt-local-poc/`](hackingbuddygpt-local-poc/)参照。

> ⚠️ hackingBuddyGPTは認可されたペネトレーションテスト用ツール。対象は自分が所有・許可を得たものだけに限定すること。

## アーキテクチャの確認

- 全てのLLM呼び出しは`src/hackingBuddyGPT/utils/llm.py`の`LiteLLM`クラス1つを経由する
  (`litellm`ライブラリの薄いラッパー)。Strix/CAIと同じく、
  Capability(コマンド実行等)をOpenAI形式の`tools`に変換して渡し、モデルが返す
  `tool_calls`をフレームワーク側が実行する設計。
- `litellm.completion(model=..., tools=..., ...)`を直接呼ぶ単一の`raw_completion()`が
  全プロバイダ共通の経路(OpenAI・OpenRouter・Anthropic等はすべてlitellmのmodel文字列
  プレフィックスで切り替え)。

## 検証1: `api_base`設定項目がデッドコードであることを発見・確認(2026-10-29)

[`mock-llm-framework-bug-hunting.md`](mock-llm-framework-bug-hunting.md)の手法のうち
「ソースを直接読む」を実践したところ、**深く調べるまでもなく**コード中に明示的な
TODOコメント付きの不備を発見した:

```python
# src/hackingBuddyGPT/utils/llm.py, raw_completion()
return litellm.completion(
    model=self.model,
    messages=messages,
    tools=tools,
    tool_choice=tool_choice,
    # api_base=self.api_base, TODO: why is this not working anymore
    api_key=self.api_key,
    ...
)
```

`api_base`は`LiteLLM`の設定フィールド(CLI/設定ファイルから渡せる、既定値
`https://openrouter.ai/api`)として定義されているが、全コードベースを検索しても
**この1箇所のコメントアウトされた行以外、一切使われていない**。つまりユーザーが
`api_base`を設定しても、**完全に無視される**(エラーも出ない)。開発者自身が
TODOコメントで「なぜ動かなくなったのか分からない」と認めている既知の不具合。

### 実機で再現・確認(2回再現+陰性対照で原因を切り分け)

「台本を書く前にソースを読んだだけで見つけた」発見だったため、本当にそのとおりか
([`mock-llm-framework-bug-hunting.md`](mock-llm-framework-bug-hunting.md)の
「クリーンな状態から2回以上再現する」に沿って)サンドボックスで4パターン・計5回、
改めて検証した(モックサーバーを再起動したクリーンな状態から実施)。

| 実行 | `api_base`引数 | `OPENAI_API_BASE`環境変数 | 結果 |
|---|---|---|---|
| B-run1 | モックのURL | (未設定) | **失敗**(モックに届かず、`ConnectionError`) |
| B-run2 | モックのURL | (未設定) | **失敗**(同上、再現) |
| C-run1 | モックのURL | モックのURL | **成功**(モックが応答) |
| C-run2 | モックのURL | モックのURL | **成功**(同上、再現) |
| D(陰性対照) | モックのURL | **到達不能なURL**(`http://127.0.0.1:1/v1`) | **失敗** |

B(2回とも)は、`api_base`引数にモックを正しく指定していても毎回失敗し、モック側の
ログにはリクエストが一切記録されない(=litellmの既定である実際のOpenAI APIへ
接続しようとして失敗している)ことを確認した。C(2回とも)は、同じ`api_base`引数に
加えて`OPENAI_API_BASE`環境変数も設定すると毎回成功し、モック側のログに
実際に2件のリクエストが記録されていることをサーバー側ログでも照合した。

D(陰性対照)が重要: `api_base`引数は**正しくモックのURLを指している**ままで、
`OPENAI_API_BASE`だけを到達不能なアドレスに変えると、**やはり失敗する**。これは
「`api_base`引数が多少なりとも効いている可能性」を完全に排除し、**到達先を
決めているのは`OPENAI_API_BASE`環境変数だけであり、`api_base`引数は本当に
何の影響も持たない**ことを示す。

```bash
# C run (再現コマンド)
OPENAI_API_BASE="http://127.0.0.1:8900/v1" python3 -c "
from hackingBuddyGPT.utils.llm import LiteLLM
llm = LiteLLM(api_key='dummy-mock-key', model='openai/mock-model', context_size=8000,
              api_base='http://127.0.0.1:8900/v1')  # この引数自体は本当に無視される(D run で確認)
llm.init()
print(llm.get_response('ping').answer)
"
# -> モックサーバーが実際にリクエストを受信し、台本どおりの応答が返る
```

→ **本リポジトリで今後hackingBuddyGPTをモックLLMで動かす場合は、`api_base`引数では
なく`OPENAI_API_BASE`環境変数を使うこと**(モデル名を`openai/`プレフィックス付きに
する必要あり。`openrouter/`等、litellmが別の環境変数を参照するプレフィックスでは
この回避策は効かない可能性がある、未検証)。

上記5回分の再現手順は[`hackingbuddygpt-local-poc/api_base_bug_repro.py`](hackingbuddygpt-local-poc/api_base_bug_repro.py)として収録済み。

## 検証2: 関数呼び出し(tool_calls)の配線確認

`RecordNote`という外部依存の無いシンプルなCapabilityを使い、
`capability.capabilities_to_tools()`でOpenAI形式の`tools`スキーマに変換→
`LiteLLM.get_response(messages, capabilities={...})`経由でモックへ送信→モックが
台本どおりの`tool_calls`(`record_note`関数呼び出し)を返す、という一連の流れを
実機で確認した。`result.result`(チャット形式呼び出し時は生の`Message`オブジェクト)の
`.tool_calls`に、モックが返した関数名・引数が正しくパースされて入っていることを確認した
(StrixやCAIで確認した`tool_calls`パースと同じパターンが、litellm経由でも成立する)。

## 未検証(本PoCのスコープ外)

- 実際にCapability(`local_exec`等)を呼び出し、本物のコマンドが実行されるところまでの
  確認。`local_exec`はtmuxセッションへの接続が前提([`LocalShellConnection`](https://github.com/ipa-lab/hackingBuddyGPT/blob/main/src/hackingBuddyGPT/utils/connectors/local_shell.py))のため、
  今回はセットアップの手間を避けて見送った。`capabilities_to_tools`→`tool_calls`の
  配線自体は検証2で確認済みなので、実行させること自体の追加検証価値は限定的と判断。
- `openrouter/`プレフィックスや他プロバイダでの、同じ`api_base`デッドコード問題の
  影響範囲(litellmの環境変数名がプロバイダごとに異なるため、ワークアラウンドの
  可否も変わりうる)。
- [`mock-llm-framework-bug-hunting.md`](mock-llm-framework-bug-hunting.md)の
  4ステップのうち「境界ケース(攻撃チェーン・マルチエージェント等)」は未実施。
  今回は「ソースを直接読む」ステップだけで実質的なバグが見つかったため、そこで
  区切った。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
