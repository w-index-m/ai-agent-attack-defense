# 3ツール横断 防御・検知ノート（Strix / Cairn / Hermes）

Gambit レポートの攻撃連鎖（偵察→侵入→統括/事後）を、**防御側の観測点と対策**に振って整理したもの。
攻撃手順のレシピではなく、「何が観測され、どこで止められるか」に焦点を当てる。

出典: [Gambit Security](https://gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company) /
各ツール: [Strix](https://github.com/usestrix/strix) / [Cairn](https://github.com/oritera/Cairn) / [Hermes](https://github.com/NousResearch/hermes-agent)

---

## 攻撃連鎖の役割分担（本セッションの解析より）

| 段階 | ツール | やること | 技術的特徴 |
|---|---|---|---|
| 偵察・スキャン | **Strix** | 攻撃面の発見・脆弱性探索 | Docker サンドボックスで実行、caido プロキシで HTTP 捕捉、nmap/ffuf/playwright 等を同梱 |
| 探索的侵入 | **Cairn** | 目標（shell/flag）まで自走探索 | 黒板サーバ(:8000)＋fact-intent グラフ、OODA ワーカーを per-project コンテナで起動（NET_RAW/NET_ADMIN） |
| 統括・事後 | **Hermes** | キャンペーン統括・事後作業 | 汎用エージェント、多数のスキル、Telegram/Discord/Slack ゲートウェイ、cron、サブエージェント、7 実行バックエンド |

共通の土台: **LLM API への継続的な egress**（レポートでは OpenRouter 経由、Claude/DeepSeek 等）。これが 3 ツール共通の最も安定した観測点。

---

## 段階別：観測できる兆候 → 防御/検知

### A. 偵察・スキャン（Strix 的挙動）
観測点:
- 単一ソースからの**広域ポート/パス走査**、短時間の多数リクエスト、既知スキャナの UA/挙動。
- 送信元が **自動化ブラウザ（playwright/CDP）** 由来のフィンガープリント。
- 外向きに **LLM API への定期的・バースト的 HTTPS**（スキャン判断のたびに推論）。

防御/検知:
- WAF/レート制限、スキャン検知（多数 404/403・パス列挙）、ボット対策。
- 管理画面・機微エンドポイントの**認証必須化＋IP 制限/VPN 内側**（`netcheck` が「管理画面 URL の応答」を確認対象にしているのと表裏）。
- セキュリティヘッダ整備（CSP/HSTS/XFO/nosniff）。決済ページの **CSP は skimmer 注入対策の要**。

### B. 探索的侵入（Cairn 的挙動）
観測点:
- 内部に **黒板サーバ(:8000 / FastAPI)** と、**per-project ワーカーコンテナ**が多数起動（イメージ名 `cairn-worker-container`、`NET_RAW/NET_ADMIN` 付与）。
- ワーカーからの**反復的な試行→観測→再試行**パターン（OODA。失敗しても別 intent で粘る）。
- 継続的な **LLM API egress** と、対象への断続的なプローブ。

防御/検知:
- EDR/コンテナランタイム監視: **NET_RAW/NET_ADMIN 付きコンテナの新規起動**、未知イメージの pull、`host` ネットワークモードのコンテナを警戒。
- 内部セグメンテーション（lateral movement 阻止）、重要資産への最小権限・多要素。
- 送信ドメイン allowlist（LLM API への常時 egress は正規業務でなければ異常）。

### C. 統括・事後（Hermes 的挙動）
観測点:
- **メッセージングアプリ（Telegram/Discord/Slack/Signal）への外向き接続**＝ C2 的チャネルになり得る。
- **cron/スケジューラによる永続化**、サブエージェントの大量スポーン、スキルの動的生成/自己改変。
- 「**自身の安全フィルタを外す**」類のスキル追加（Gambit が 78/121 の攻撃スキル、うちフィルタ除去を指摘）。

防御/検知:
- 外向きメッセージング API への接続監視（サーバ/本番ホストからの Telegram 等は強い異常シグナル）。
- 永続化監視（新規 cron/サービス/スタートアップ項目）、プロセス系統の異常（自動化された連続ツール実行）。
- LLM 利用ガバナンス: **安全機構の除去・迂回を図る挙動**は方針・契約・CVP の不変の一線（物理被害/大規模妨害/ランサム/安全系無効化はブロック）に照らして遮断・通報。

---

## 横断的な「効く」対策（優先順）

1. **外向き通信の allowlist** — LLM API・メッセージングへの常時 egress は最強の共通シグナル。本番/サーバ系からの当該通信を既定で遮断・監視。
2. **コンテナ/実行環境の可視化** — 特権 cap 付きコンテナ、未知イメージ、host ネットの起動を検知。
3. **攻撃面の最小化** — 管理画面の隔離、DB/サービスをネット直結にしない（`netcheck` の RISKY ポート群が示す露出を塞ぐ）。
4. **決済・機微ページの CSP** — skimmer/カード窃取コード注入の防止。
5. **永続化・自動化の監視** — cron/スケジュール、連続自動ツール実行、サブエージェント大量生成。
6. **ログと相関** — スキャン痕跡＋LLM egress＋特権コンテナ＋外向きメッセージングを**時系列で相関**させると、単発では見えない「自律エージェント攻撃」が像を結ぶ。

---

## 本リポジトリ資産との対応

- `netcheck/`: A の露出面（RISKY ポート、ヘッダ、管理画面応答）を**自分の資産で確認**するための道具。
- `vuln_triage.html` / `scripts/summarize.py`: スキャナ結果を集約し、A/B の修正優先度付け。
- `security-scan.yml`（Semgrep/Trivy/gitleaks）: コード/依存/シークレットの事前防御。
- `cvp-readiness.md`: これらを CVP（Defense/Red Team）の統制証拠として束ねる枠組み。

> 本ノートは防御・検知の観点に限定し、攻撃の再現手順や安全機構の回避方法は含めない。

---

# 運用レイヤー（SOC / 検知エンジニア向け）

上の観測点を、**データソース → シグナル → 検知ロジック**に落とす。ルール雛形はベンダ非依存の
Sigma 風擬似記法（防御用の検知であり、攻撃手順ではない）。閾値は各環境のベースラインに合わせて調整する。

## 1. データソース対応表

| データソース | ここで効く段階 | 主なシグナル |
|---|---|---|
| フォワードプロキシ / NetFlow / DNS ログ | 全段・最重要 | LLM API・メッセージング API への外向き通信 |
| コンテナランタイム監査（Docker events / containerd / Falco / auditd） | 侵入(Cairn)・ツール実行 | 特権 cap / host ネット / 未知イメージの起動 |
| EDR / プロセステレメトリ（Sysmon / auditd / eBPF） | 侵入・統括 | スキャナ系プロセス、サブエージェント大量生成、連続自動ツール実行 |
| Web/WAF アクセスログ | 偵察(Strix) | パス列挙、多数 404/403、管理画面プローブ |
| ホスト永続化（cron / systemd timer / 自動起動） | 統括(Hermes) | 新規スケジュール・サービス |
| 認証 / 監査ログ | 侵入・事後 | 異常な権限取得・横移動 |

## 2. 検知ルール雛形（Sigma 風・擬似）

**R1. サーバ系ホストから LLM API への外向き通信（最優先）**
```
logsource: proxy / dns / netflow
detection:
  dest_domain in:
    - api.openai.com
    - api.anthropic.com
    - api.openrouter.ai
    - api.deepseek.com
    - "*.openrouter.ai"
  src_zone: server|production|dmz   # 開発者端末ゾーンは除外
condition: dest_domain AND src_zone
note: 正規業務でLLMを使うホストは allowlist 化し、それ以外からの通信を異常として上げる。
```

**R2. 特権 cap / host ネットのコンテナ起動**
```
logsource: container_runtime (docker events / falco / auditd)
detection:
  event: container_create|container_start
  any_of:
    - cap_add contains: NET_RAW
    - cap_add contains: NET_ADMIN
    - network_mode: host
    - privileged: true
condition: event AND any_of
note: cairn-worker-container 等、未知イメージ名との相関で確度を上げる。
```

**R3. 偵察的 Web アクセス（列挙バースト）**
```
logsource: web|waf
detection:
  status in: [401,403,404]
  uri in: ["/admin","/administrator","/wp-login.php","/phpmyadmin/","/manager/html","/console",...]
  threshold: 同一 src_ip から 60秒に > N 件（N は環境ベースライン）
condition: status AND (uri OR threshold)
note: 自動化ブラウザ(CDP/playwright)系UA/フィンガープリントと相関。
```

**R4. サーバからのメッセージング API 通信（C2 的チャネル）**
```
logsource: proxy / dns
detection:
  dest_domain in:
    - api.telegram.org
    - discord.com / discordapp.com
    - slack.com / hooks.slack.com
    - *.signal.org
  src_zone: server|production
condition: dest_domain AND src_zone
note: サーバ/本番ホストからのメッセージング送信は強い異常シグナル。
```

**R5. 永続化の新規作成**
```
logsource: host (auditd / sysmon / file_events)
detection:
  any_of:
    - new cron entry (/etc/cron* , crontab -e)
    - new systemd timer/service (/etc/systemd/system/*.timer|.service)
    - new autostart item
condition: any_of
note: 自動化エージェントの常駐化。作成プロセス系統を併せて記録。
```

**R6. 自律エージェントの相関検知（単発では見えないものを束ねる）**
```
correlation (時系列・同一アセット or 同一オペレータ):
  R3 (偵察バースト)  AND
  R1 (継続的な LLM egress) AND
  (R2 (特権コンテナ) OR 連続自動ツール実行) AND
  任意で R4/R5
window: 数十分〜数時間
action: 「自律 AI エージェント攻撃」候補として優先度最上位でエスカレーション
note: 本キャンペーンの本質は“各単体は既知挙動でも、連鎖が速く広い”こと。相関が最大の武器。
```

## 3. MITRE ATT&CK 対応（検知の棚卸し用）

| 段階 | 代表 Technique | 本ノートの検知 |
|---|---|---|
| 偵察 | T1595 Active Scanning / T1046 Network Service Scanning | R3 |
| 実行・ツール | T1059 など（自動ツール実行） | EDR 連続実行、R2 |
| C2 | T1071 Application Layer Protocol（メッセージング悪用） | R4 |
| 永続化 | T1053 Scheduled Task/Job（cron/timer） | R5 |
| 防御回避 | T1562 Impair Defenses（安全機構の無効化に相当） | ガバナンス検知（※下記） |
| 探索/横移動 | T1046 / 認証異常 | R2・認証ログ |
| 持ち出し | T1041 Exfiltration over C2 Channel | R1/R4 と DLP の相関 |

※ T1562 相当（Hermes の「自身の安全フィルタ除去」など）は、ネットワーク/ホストの単純シグナルでは捉えにくい。
LLM 利用ガバナンス（プロンプト/ツール呼び出しの監査、安全機構の除去・迂回の試行検知）で補う。本ノートは
その「兆候の存在」を指摘するに留め、具体的な回避手法は扱わない。

## 4. SOC トリアージ手順（優先度順）

1. **R1/R4 ヒット** → 送信元ホストの業務用途を確認。正規でなければ即封じ込め（egress 遮断）＋プロセス/コンテナ調査。
2. **R2 ヒット** → 起動元・イメージ出所・cap の必要性を確認。未知イメージ＋特権は高確度。
3. **R3 ヒット** → 対象資産の露出（管理画面・RISKY ポート）を `netcheck` 等で確認し、塞ぐ。
4. **R5 ヒット** → 永続化を除去し、作成プロセス系統を遡る。
5. **R6（相関）** → 単発を超えた連鎖として、インシデント化・full IR へ。

## 5. 予防（検知の前段で効く固定策）

- 送信ドメイン **allowlist**（サーバ系からの LLM/メッセージングは既定遮断）。
- コンテナ: 特権 cap・host ネット・未署名/未知イメージを**ポリシーで禁止**（admission control）。
- 攻撃面最小化: 管理画面の隔離、DB/サービスをネット直結にしない（`netcheck` の RISKY ポート群）。
- 決済・機微ページの **CSP**（skimmer/カード窃取コード注入の防止）。
- LLM 利用の監査・ガバナンス（安全機構の除去/迂回の試行を検知・通報）。

> すべて検知・防御の設計に限定。攻撃の実行手順や安全機構の回避方法は本ノートに含めない。
