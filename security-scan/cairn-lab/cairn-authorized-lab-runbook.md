# Cairn 動作確認ランブック（自分の隔離ラボ・認可済み前提）

[oritera/Cairn](https://github.com/oritera/Cairn)（AGPL-3.0, v0.2.1）を、**自分が所有・認可した、ネットワーク隔離された“やられ環境”**に対して実際に動かすための設計書。

> ⚠️ Cairn は能動的に脆弱性を突いてシェル/権限を奪う実行役。**対象を所有しているか、書面で認可を得ている場合のみ**実行すること。本ランブックは authorized pentest / 自前ラボ / CTF を想定し、第三者・本番・未認可の対象には一切向けない。
>
> ℹ️ この Claude セッションの sandbox では実行しない（Docker デーモン無し・LLM キー無し・外部通信制限）。実行はあなたの隔離ラボ側で行う。

---

## 0. 実行前チェックリスト（すべて YES でなければ実行しない）

- [ ] 対象は**自分が所有**、または**書面の認可**がある（範囲・期間・対象 IP が明記）。
- [ ] 対象と Cairn ワーカーは**独立したネットワークセグメント**に隔離（下記「ネットワーク隔離」）。
- [ ] 対象・ワーカーとも**使い捨て or スナップショット**済みで、終了後に復元できる。
- [ ] 外部通信は **LLM API エンドポイント（と初回のイメージ取得）だけ**に限定。対象以外の内部ホスト・インターネットへ到達しない。
- [ ] 予算・ステップ上限（タスク timeout / worker 数）を**保守的**に設定。
- [ ] 実行中は**監視下**に置き、いつでも停止できる（`completed_action: stop` で事後調査可）。

---

## 1. 構成要素

| 要素 | 役割 | 実行場所 |
|---|---|---|
| **Cairn Server** (`cairn serve`) | 黒板（fact-intent グラフ）を持つ FastAPI。SQLite に状態保存。`POST /projects` で origin/goal を登録 | ラボ内のどこでも可（UI/ API は 8000） |
| **Dispatcher + Workers** (`cairn dispatch`) | スケジューラ＋OODA ワーカー。**container モード**（`ghcr.io/oritera/cairn-worker-container:latest` を 1 プロジェクト 1 コンテナで exec、Docker 必要）か **local モード**（ホストプロセス、claude/codex/pi CLI を再利用） | **隔離ネットワーク上** |
| **LLM プロバイダ** | ワーカーの推論。worker env で `ANTHROPIC_MODEL`/`BASE_URL`/`AUTH_TOKEN`（claudecode 型）等 | 外部 API or ローカルモデル |
| **やられ対象** | origin に記載。例: `http://10.77.0.10` / goal: `get a shell` / `capture the flag` | 隔離ネットワーク上 |

> ワーカーは `nmap -sS` など raw socket を使う場合 `cap_add: [NET_RAW, NET_ADMIN]` が要る。付けるのは必要時のみ。

---

## 2. ネットワーク隔離の設計（最重要）

`dispatch.example.yaml` は `network_mode: "host"` を例示しているが、**隔離目的には不可**（ホストのネット全体に素通し）。代わりに：

```
┌─────────────────── isolated lab net (例: 10.77.0.0/24, internet 到達なし) ──────────────────┐
│                                                                                              │
│   [cairn worker container(s)]  ──攻撃トラフィック──▶  [vulnerable target 10.77.0.10]          │
│            │                                                                                 │
│            └── LLM API のみ egress 許可（allowlist proxy 経由 or ローカルモデルで egress ゼロ）  │
│                                                                                              │
│   [cairn server 8000] ◀── fact/intent/hint ── workers                                        │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

- 専用の **internal な Docker ネットワーク**（または隔離 VLAN）を作り、対象とワーカーをそこへ。
- **egress は LLM エンドポイントだけ**を許可（ファイアウォール allowlist）。可能なら**ローカルモデル**にして egress を無くすのが最も安全。
- 対象以外の内部ホスト、インターネット、会社ネットへ**ルートが無い**ことを実行前に確認（`ip route` / 対象外 IP への ping が全て失敗すること）。

---

## 3. 手順

### 3.1 ラボ準備
1. 隔離ネットワークを作成（internet 到達なし）。
2. やられ対象を立てる（自作の脆弱アプリ、または自分が用意した CTF 的ターゲット）。スナップショット取得。
3. Cairn を動かすホスト（ワーカー）もスナップショット可能にする。

### 3.2 インストール
```bash
git clone https://github.com/oritera/Cairn && cd Cairn
uv sync --project cairn
# container モードなら worker イメージを取得（この時だけ egress 必要）
docker pull ghcr.io/oritera/cairn-worker-container:latest
```

### 3.3 設定（`dispatch.yaml`）
`dispatch.example.yaml` をコピーして編集。最低限：
- `server:` をラボ内のサーバ URL に。
- `workers[].env` に**自分の LLM 資格情報**（例 `ANTHROPIC_MODEL` / `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN`）。
- `container.network_mode` は host をやめ、**作成した隔離ネットワーク名**を指定。`cap_add` は必要時のみ。
- `runtime.max_workers` / `tasks.*.timeout` を保守的に（まず小さく）。

> 秘密情報は `dispatch.yaml` にベタ書きせず環境変数や secret 管理から注入する。`dispatch.yaml` はリポジトリにコミットしない。

### 3.4 まず安全スモーク（mock・攻撃なし）
実標的に向ける前に、エンジンが回ることをモックで確認（§4 参照）。

### 3.5 本番実行
```bash
# 1) サーバ
uv run --project cairn cairn serve --host 0.0.0.0 --port 8000

# 2) プロジェクト作成（origin=ラボ対象, goal=目標）: POST /projects
curl -s -X POST http://<server>:8000/projects \
  -H 'Content-Type: application/json' \
  -d '{"origin":"target http://10.77.0.10","goal":"get a shell","bootstrap_enabled":true}'

# 3) ディスパッチャ起動（ワーカーが OODA ループを回し始める）
uv run --project cairn cairn dispatch --config dispatch.yaml
```

### 3.6 観測・記録
- `GET /projects/{id}` で fact-intent グラフの成長を確認（server の static UI でも可）。
- `export.py` ルータ（`/export`）で結果を取得し、ラボ記録として保存。
- `completed_action: stop` なのでワーカーコンテナを事後調査できる。

### 3.7 片付け
- ディスパッチャ/サーバ停止 → ワーカーコンテナ削除 → 対象とワーカーホストをスナップショットへ復元。
- egress allowlist を元に戻す。

---

## 4. 安全スモーク（mock）: 攻撃せずにエンジンだけ回す

`type: mock` ワーカーは LLM も実コマンドも使わず、確率的にダミーの Fact/Intent を出すだけ。`execution: local` にすればコンテナも不要（ホストの `python3` サブプロセスで動く）。実標的に向ける前の配線確認に最適。

- `dispatch_mock.yaml` をベースに `runtime.execution: local` を足した設定で `cairn serve` + `cairn dispatch` を起動。
- `POST /projects` で**到達先の無いダミー origin**（例: `origin: "mock target"`）を登録。
- fact-intent グラフが OODA で成長していくのを UI/API で観察。**どこへもパケットは飛ばない**。

> この mock スモークは本 Claude セッションの sandbox でも技術的には実行可能（Docker/LLM 不要）。本番の exploitation はラボ側のみ。

---

## 5. やってはいけないこと

- 未認可・第三者・本番環境を origin にする。
- `network_mode: host` のまま、隔離せずに実行する。
- egress を絞らず、対象以外へ到達できる状態で走らせる。
- 秘密情報を `dispatch.yaml` に残してコミットする。

---

## 参考（リポジトリ内）
- `dispatch.example.yaml` — container モードの完全な設定例
- `dispatch.local.example.yaml` — local モード（ホスト実行、CLI 再利用）
- `dispatch_mock.yaml` — mock ワーカー（攻撃なし）
- `docs/specs/server-protocol.md` — 黒板プロトコル / `POST /projects`（origin・goal）
- `docs/specs/dispatcher-design.md` — ディスパッチャ設計
