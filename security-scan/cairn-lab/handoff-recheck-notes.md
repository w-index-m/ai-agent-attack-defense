# Cairn: ワーカー間ハンドオフの再検証(2026-10-30、クリーンな陰性結果)

[`mock-llm-framework-bug-hunting.md`](../mock-llm-framework-bug-hunting.md)の
「横展開できそうな対象」で候補に挙げていた、Cairnのマルチエージェント構成(ワーカーA→
ワーカーBの受け渡し)に、Strixで見つかった「前の手の結果が欠落する」問題と同クラスの
バグが無いかを再検証した記録。結論: **バグは見つからなかった(クリーンな陰性結果)**。

> 確認・検知の設計に限定。実標的への攻撃は一切行っていない(`cairn serve`をこの
> sandbox内でローカルに起動し、ワーカーコンテナ・Docker・実/モックLLMは一切使わず、
> `CairnClient`とプロンプト構築コードを直接呼び出しただけ)。

## 1. アーキテクチャの確認

Cairnの「記憶」はStrix(単一エージェントの会話ターン履歴、インメモリ)と違い、
**サーバー側(`cairn serve`)のSQLite上のFact-Intentグラフ**そのものである。

- `cairn/src/cairn/dispatcher/scheduler/loop.py`: ディスパッチャは各tickで新しいIntentを
  ワーカーに割り当てる直前に、必ず`self.client.export_project(summary.id)`で**その場で
  最新のグラフYAMLを取得**している(`_dispatch_reason`/`_dispatch_explore`の直前、
  L291/296/317)。キャッシュして再利用している箇所は無い。
- `cairn/src/cairn/dispatcher/tasks/explore.py`の`run_explore_task()`は、その
  `export_yaml`を`write_graph_snapshot_reference()`で毎回新規UUIDのファイルに書き出し、
  `explore.md`プロンプトの`{graph_yaml}`に差し込む。プロンプトには**グラフ全体**
  (全Fact・全Intent)が含まれ、個別のFactだけを選んで渡す設計ではない。
- サーバー側(`cairn/src/cairn/server/`): 1リクエスト1 SQLite接続、`WAL`モードで
  即`commit()`してから`close()`(`server/db.py`)。`/export`(`routers/export.py`)は
  `facts`テーブルを無条件に全件`SELECT`するため、Factの選択的な欠落は起きない。

これらを読む限り、Strix型の「スナップショットが古い/一部しか含まない」バグが起きる
余地は構造的に小さい。実機で確認した。

## 2. 実機確認: `cairn serve`を起動し、`CairnClient`を直接呼ぶ

Docker・`codex`/`claudecode`ワーカー・LLM(モックも含む)は一切使わず、
[`mock-llm-framework-bug-hunting.md`](../mock-llm-framework-bug-hunting.md)の
手法ステップ3(「フレームワークの内部関数を、エージェントループを経由せず直接呼ぶ」)
をそのまま適用した:

1. `cairn serve`を起動(ディスポーザブルなSQLite db)。
2. プロジェクト作成(`origin`/`goal`のみ、bootstrap無効)。
3. **ワーカーA役**として`CairnClient.create_intent()`→`heartbeat()`→`conclude()`を
   直接呼び、一意マーカー文字列(`MARKER-A-xxxx`)を含むFactを生成。
4. ワーカーAのconclude**直後**に`export_project()`を呼び、マーカーが含まれているかを
   確認(スケジューラが次tickで行うのと同じ呼び出し)。
5. **ワーカーB役**として、FactAを`from`に指定した新しいIntentを作成し、
   `cairn.dispatcher.tasks.explore.run_explore_task()`と全く同じ呼び方
   (`load_prompt("default", "explore.md")` + `render_prompt(...)`)で、
   ワーカーBが実際に受け取るプロンプト文字列を再現。
6. そのプロンプト文字列に、ワーカーAのマーカーが含まれているかを確認。
7. ワーカーBをconclude、最終exportに両マーカーが残っていること、Intent Bの
   `from`に正しくFact AのIDが記録されていることまで確認。

再現スクリプト: [`handoff_recheck_test.py`](handoff_recheck_test.py)。

### 結果(クリーンな状態から2回独立に再現)

サーバーを完全に再起動・DBファイルを削除した、独立した2回の実行で、いずれも:

- ワーカーAのconclude直後のexportにマーカーA含有 ✅
- ワーカーBの実際のプロンプト文字列にマーカーA含有(ハンドオフ成立) ✅
- 最終exportに両マーカー含有、Intent Bの`from`がFact Aを正しく指す ✅
- (サニティチェック)一度も書いていないマーカーはどこにも現れない ✅

2回とも同じ結果(バグなし)。

## 3. 陰性対照: このテストは本当にバグを検出できるのか

「常に通ってしまうだけのテストではないか」を排除するため、**わざと古い
(ワーカーAのconclude**前**に取得した)スナップショットをワーカーBに渡す**という
仮想的なバグケースを別途実行した([`handoff_negative_control.py`](handoff_negative_control.py))。

結果: この場合は期待どおり、ワーカーBのプロンプトにマーカーAが**含まれない**ことを
確認した。つまり`handoff_recheck_test.py`の`assert marker_a in prompt_b`は、実際に
ステイル(古い)ハンドオフが起きた場合に確実に失敗する、意味のある検査である。

## 4. 結論と限界

- 今回検証した範囲(Factグラフの受け渡し、プロンプトへの反映)では、Strix型の
  「前の手の結果が欠落する」バグはCairnには見つからなかった。サーバー側で全状態を
  同期的にSQLiteへコミットし、ワーカー起動の直前に毎回フルエクスポートし直す設計が、
  この種のバグを構造的に防いでいると考えられる。
- 本検証は**HTTP API層とプロンプト構築層**の直接呼び出しに限定しており、実際の
  Dockerワーカーコンテナ・`codex`/`claudecode` CLI経由のエンドツーエンド実行(
  [`cairn-authorized-lab-runbook.md`](cairn-authorized-lab-runbook.md)§6で別途検証済み)
  は組み合わせていない。コンテナ内でのファイル書き込み(`write_graph_snapshot_reference`)
  やワーカーCLI自体がグラフファイルを正しく読むかどうかは、本検証のスコープ外。
- 並行実行(`max_project_workers > 1`)時に、複数ワーカーが同時に別Intentをexploreしている
  間の競合(片方がconcludeした直後、もう片方が古いスナップショットのまま実行中、等)は
  未検証。これは「バグ」というよりアーキテクチャ上の既知のタイミング特性であり、
  致命的なデータ欠落には繋がりにくいと考えられるが、厳密な検証はしていない。
