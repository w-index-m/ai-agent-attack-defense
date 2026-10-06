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
