# Strix をローカル実行する設計メモ（Docker 不要の `local` バックエンド）

対象: [usestrix/strix](https://github.com/usestrix/strix) v1.7.0 を、Docker デーモンを使わずに
ホスト（例: Claude Code の cloud sandbox）上で直接動かす方法の調査メモ。

> ⚠️ Strix は認可されたペネトレーションテスト用ツールです。対象は必ず自分が所有・許可を得たものに限定すること。

## 背景

Strix は「LLM API キーを入れれば動く」のではなく、**スキャン対象を隔離した Docker コンテナを起動し、
その中でエージェント（LLM ↔ ツール）を動かす**設計。したがって本来の必須要件は 2 つ:

- LLM API キー（`STRIX_LLM` / `LLM_API_KEY`、LiteLLM の model id）
- **稼働中の Docker デーモン**

cloud sandbox は Docker-in-Docker を通常持たないため（`docker info` が到達不可）、
公式のローカル CLI モードはそのままでは動かない。マネージド版（app.strix.ai）は
ネットワークポリシーで `app.strix.ai` への到達が拒否される場合がある。

## 実行フロー（コード地図）

```
strix/interface/main.py            エントリ (project.scripts: strix=...main:main)
  └─ interface/cli.py  run_cli()    引数 → scan_config
       └─ core/runner.py  run_strix_scan()
            ├─ runtime/session_manager.create_or_reuse()   ← サンドボックス起動
            │     └─ runtime/backends.get_backend(name)    ← STRIX_RUNTIME_BACKEND で分岐
            └─ エージェントループ（LLM ↔ tools/*）
```

- `runtime/backends.py`: `STRIX_RUNTIME_BACKEND`（既定 `docker`）でバックエンドを選ぶ**レジストリ**。
  `register_backend(name, fn, supports_bind_mounts=...)` で独自バックエンドを追加できる。
- `runtime/docker_client.py`: openai-agents SDK の `DockerSandboxClient` を継承し、コンテナに
  NET_ADMIN/NET_RAW（`nmap -sS` 等の raw socket 用）、`host.docker.internal` ゲートウェイを付与。
- `tools/shell` の `exec_command` は **SDK 提供**（`agents.sandbox.capabilities.tools.shell_tool.ShellTool`）。
  エージェントの全コマンド実行はサンドボックスセッション経由 → 「セッション = 実行環境」。

## 結論: ゼロから書く必要はない

openai-agents SDK に **`UnixLocalSandboxClient`（ローカル Unix サンドボックス）が同梱**されている。

```
.venv/.../agents/sandbox/sandboxes/unix_local.py
  class UnixLocalSandboxClient     # create() で session を返す
  class UnixLocalSandboxSession    # ホスト上で直接コマンド実行、workspace = manifest.root（ホスト FS）
```

Docker 版 `_docker_backend` の実体は「SDK の Client を作って session を返す」だけなので、
これを Unix 版へ差し替えるだけで成立する。

## 実装案（新バックエンド ~15 行）

`strix/runtime/backends.py` に追加:

```python
async def _unix_local_backend(
    *, image, manifest, exposed_ports, bind_mounts=None,
):
    # image と bind_mounts は使わない（ホスト FS がそのまま workspace）
    from agents.sandbox.sandboxes.unix_local import (
        UnixLocalSandboxClient, UnixLocalSandboxClientOptions,
    )
    client = UnixLocalSandboxClient()
    options = UnixLocalSandboxClientOptions(exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session

# bind mount 非対応（= manifest entries 経由でソースを materialize）
register_backend("local", _unix_local_backend, supports_bind_mounts=False)
```

起動:

```bash
export STRIX_RUNTIME_BACKEND=local
export STRIX_LLM="anthropic/claude-sonnet-5-5"   # LiteLLM の model id
export LLM_API_KEY=...
uv run strix -n -t ./ --scan-mode quick --max-budget 10
```

`get_backend()` が `STRIX_RUNTIME_BACKEND` で分岐するため、既存の Docker 経路には触れない。

## 注意点（ここが実質的な作業）

| # | 論点 | 内容 |
|---|---|---|
| ① | ツールの非同梱 | nmap / ffuf / caido(プロキシ) / playwright 等は Docker イメージ側に同梱。ローカルには無い → 使うツールだけホストに `apt`/`pip` で導入が必要。 |
| ② | manifest の users/groups 不可 | `UnixLocalSandboxSession` は manifest の user/group 指定を**非サポート**（コードに明示）。`session_manager._host_identity_env` が uid/gid を積むため、local 経路では渡さない調整が要る。 |
| ③ | caido 前提の除外 | Docker 版は起動時に `bootstrap_caido()` で in-container プロキシ(48080)へ接続。ローカルには無い → caido をホスト起動するか、`proxy` ツール依存フローを無効化。 |
| ④ | 分離性の喪失（最重要） | Docker 隔離をやめてホストで直接ツール実行 = 攻撃実行環境がホストになる。対象は自分が権限を持つものに限定。`nmap -sS` 等は root/cap が必要。 |
| ⑤ | bind mount vs materialize | `supports_bind_mounts=False` なら `session_manager.build_manifest_entries()` が `LocalDir` でソースを workspace に展開。`-t ./` のローカルコード解析はこれで動く。 |

## 推奨スコープ（最小 PoC）

`-t ./`（ローカルコードの静的解析 = code_review 相当）に限定すれば、ネットワーク系ツール
（nmap/caido）が不要になり、①③④をほぼ回避できる。まずこの構成で PoC するのが現実的。
実スキャンには LLM API キーが必要。

## 確認済みの事実（この環境での動作確認）

- `uv sync` で依存導入、`uv run strix --help` 正常（v1.7.0）。
- `docker info` 到達不可（ローカル CLI の実スキャンは不可）。
- `strix cloud login` はネットワークポリシーにより `app.strix.ai` へ 403（プロキシ CONNECT 拒否）。
- SDK に `unix_local.py` が存在することを確認。

## PoC 結果（実装して検証した）

設計案どおり 2 ファイルにパッチを当て、PoC を実行して成立を確認した。
パッチ: [`strix-local-poc/strix-local-backend.patch`](strix-local-poc/strix-local-backend.patch)
検証スクリプト: [`strix-local-poc/poc_local_backend.py`](strix-local-poc/poc_local_backend.py)

### 当てたパッチ（3 ファイル）

1. `strix/runtime/backends.py`: `_unix_local_backend` を追加し `_BACKENDS["local"]` に登録。
   さらに **caido 対応をバックエンド単位で持つレジストリ** `_CAIDO_BACKENDS`（既定 `{"docker"}`）と
   `backend_supports_caido()` を追加。`register_backend` に `supports_caido` 引数を追加。
2. `strix/interface/main.py`: Docker 事前チェック（`check_docker_installed` / `pull_docker_image`）を
   `settings.runtime.backend == "docker"` のときだけ実行するようゲート。
3. `strix/runtime/session_manager.py`: `create_or_reuse` の **caido 結合をバックエンド単位でゲート**。
   caido 非対応バックエンド（`local`）では (a) caido プロキシ env（`http_proxy`/`https_proxy`/`ALL_PROXY`）を
   注入しない、(b) `exposed_ports=()`、(c) `resolve_exposed_port` と `bootstrap_caido` をスキップ、
   (d) `caido_client=None`。proxy ツールは既存の graceful-degradation（`_ctx_client` が None →「利用不可」）に乗る。

### 検証 1: バックエンドを直接叩く（LLM 非依存）

`poc_local_backend.py` を `uv run python` で実行した結果:

- `supported_backends()` → `['docker', 'local']`、`get_backend('local')` 解決 OK。
- `DOCKER_HOST=unix:///nonexistent-docker.sock` にしても **セッション起動成功**
  （`UnixLocalSandboxSession`）。Docker デーモンに一切触れない。
- `session.exec(...)` が**ホスト上で**実行される（`uname -a` が実ホスト、`whoami=root`、
  `python3 --version=3.13.16`）。
- `LocalDir` で対象ソースが workspace に materialize され、`ls repo` に
  `netcheck / scripts / security-scan / …` が出現。
- 対象リポジトリ自身のツール `scripts/summarize.py` をセッション内で実行し完走（exit 0）。

### 検証 2: 実 CLI 配線（`strix -n -t ./ --scan-mode quick`）

`STRIX_RUNTIME_BACKEND=local` で CLI を起動:

- パッチ前: 起動時の Docker 事前チェックで `DOCKER NOT AVAILABLE` により即停止。
- パッチ後: Docker ゲートを通過し、環境検証 → **LLM プリフライト接続**まで到達。
  ダミーキーのため `invalid x-api-key` で停止（`api.anthropic.com` への到達自体は成功）。
  → **残る唯一の前提は有効な LLM API キーのみ**。実キーがあれば検証 1 で実証済みの
  ローカルセッション起動を経てエージェントループに進む。

### 検証 3: caido 非依存（`create_or_reuse` を `local` で直接呼ぶ）

`poc_caido_free.py` を実行した結果:

- `backend_supports_caido('local')=False` / `('docker')=True`。
- `create_or_reuse(backend=local)` が **caido bootstrap を呼ばずに**セッションを返す。
- `bundle["caido_client"] is None`（proxy ツールは「利用不可」に degrade。クラッシュしない）。
- セッション内に caido プロキシ env が**注入されていない**（`echo $http_proxy $ALL_PROXY` が空）。
- 対象ソースの materialize と `session.exec` は正常。

→ これで `local` バックエンドは **caido サイドカー無しで完結**する。コード解析系スキャン
（`proxy` ツールを使わないフロー）なら、追加の外部依存なしに動かせる。

### PoC で判明した追加の実挙動（設計メモの補足）

- **base_dir = `Path.cwd()` 制約**: SDK の `LocalDir` 展開は、ソースが CWD 配下でないと
  `LocalDirReadError (outside_base_dir)` で拒否する（source grant 未指定時）。
  Strix の正規の使い方 `-t ./`（対象＝カレント）では常に満たされるため実害なし。
  CWD 外を対象にする場合は source grant の付与か、対象を CWD 配下に置く必要がある。
- **Docker 事前チェックの無条件実行**: `main.py` の `check_docker_installed` /
  `pull_docker_image` はバックデンド設定を見ずに走るため、`local` でも上記ゲートが必須。
- シンボリックリンクは `LocalDir` 展開で非サポート（`symlink_not_supported`）。
  `.git` などリンクを含むツリーは除外して渡すのが無難。

### 未検証（本 PoC のスコープ外）

- 実 LLM キーでのエンドツーエンドのスキャン完走。
- 動的スキャン（live_test）で `proxy` ツールを使うフロー。`local` では caido が無いため
  トラフィック捕捉系は使えない（コード解析系に限定すれば問題なし）。
- nmap など外部ツールを要する動的スキャン（ホストに未導入）。
