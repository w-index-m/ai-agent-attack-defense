# 系統図 — URL からの派生（ツール要素 → 検知 → 防御）

起点は共有された **Strix の URL**。そこから 3 ツール（Strix/Cairn/Hermes）を読み込み、各ツールの
**要素/挙動**を**検知ルール R1–R7**と**防御コントロール**に結びつけた。本書はその派生をたどる系統図。
検知・防御の設計に限定。

起点: https://github.com/usestrix/strix
関連: [Cairn](https://github.com/oritera/Cairn) / [Hermes](https://github.com/NousResearch/hermes-agent)

## フロー図（ツール要素 → 検知 → 防御）

```mermaid
flowchart LR
  URL["起点URL<br/>usestrix/strix"]:::origin

  subgraph TOOLS["① 3ツール（Gambit 分業チェーン）"]
    direction TB
    S["Strix<br/>偵察・脆弱性"]:::tool
    C["Cairn<br/>自律侵入"]:::tool
    H["Hermes<br/>統括・事後"]:::tool
  end
  URL --> S --> C --> H

  subgraph TRAITS["② 要素 / 挙動"]
    direction TB
    t_scan["スキャナ/ブラウザ自動化<br/>nmap・ffuf・playwright"]:::trait
    t_llm["LLM API への継続 egress"]:::trait
    t_ctr["特権コンテナ<br/>NET_RAW/NET_ADMIN・Kali"]:::trait
    t_multi["多種ツールの連続実行<br/>OODA / MCP 150+"]:::trait
    t_msg["メッセージングGW<br/>Telegram/Discord/Slack"]:::trait
    t_persist["cron/スケジューラ永続化"]:::trait
    t_skill["スキル機構<br/>(安全フィルタ除去の悪用)"]:::trait
  end
  S --> t_scan & t_llm & t_ctr
  C --> t_ctr & t_multi & t_llm
  H --> t_msg & t_persist & t_skill & t_multi

  subgraph DET["③ 検知 R1–R7"]
    direction TB
    R1["R1 LLM egress"]:::det
    R2["R2 特権コンテナ"]:::det
    R3["R3 偵察列挙バースト"]:::det
    R4["R4 メッセージングC2"]:::det
    R5["R5 永続化作成"]:::det
    R7["R7 多ツール連続実行"]:::det
    R6["R6 相関（束ねる）"]:::det
    GOV["LLMガバナンス<br/>(T1562相当)"]:::det
  end
  t_scan --> R3 & R7
  t_llm --> R1
  t_ctr --> R2
  t_multi --> R7
  t_msg --> R4
  t_persist --> R5
  t_skill --> GOV
  R1 & R2 & R3 & R4 & R5 & R7 --> R6

  subgraph DEF["④ 防御コントロール"]
    direction TB
    d_allow["送信ドメイン allowlist"]:::def
    d_adm["コンテナ admission control"]:::def
    d_surf["攻撃面最小化 / 管理画面隔離"]:::def
    d_csp["決済ページ CSP"]:::def
    d_persmon["永続化監視"]:::def
    d_gov["LLM利用ガバナンス"]:::def
  end
  R1 --> d_allow
  R4 --> d_allow
  R2 --> d_adm
  R3 --> d_surf & d_csp
  R7 --> d_adm
  R5 --> d_persmon
  GOV --> d_gov

  classDef origin fill:#0f6f68,color:#fff,stroke:#0f6f68;
  classDef tool fill:#2a78d6,color:#fff,stroke:#215fa8;
  classDef trait fill:#eef2f2,color:#18262b,stroke:#d6dedf;
  classDef det fill:#eda100,color:#18262b,stroke:#b57e00;
  classDef def fill:#1baf7a,color:#06211f,stroke:#148a60;
```

> 補足: ④E2E 自律型（PentAGI/Villager 等）・⑤攻撃基盤型（HexStrike 等）も同じ要素を持つため、
> 同じ検知（特に R7・R2・R1）が横展開で効く。ローカルLLM型は R1 を回避するため **R7/R2 に重心**。

## トレーサビリティ表（要素 → 検知 → 防御 → 成果物）

| ツール | 要素 / 挙動 | 検知 | 防御 | 本リポの成果物 |
|---|---|---|---|---|
| Strix | スキャナ/自動ブラウザ | R3, R7 | 攻撃面最小化, admission control | `detections/`（r3,r7）, `strix-local-*` |
| Strix | Docker サンドボックス | R2 | admission control | `strix-local-backend-notes.md` |
| Strix/Cairn/Hermes | LLM API egress | R1 | 送信ドメイン allowlist | `detections/`（r1）, `defense-detection-notes.md` |
| Cairn | 特権ワーカーコンテナ(NET_RAW) | R2 | admission control | `detections/`（r2, falco）, `cairn-lab/` |
| Cairn | OODA の多ツール実行 | R7 | admission control | `detections/`（r7）, `cairn-lab/`（mock検証） |
| Hermes | メッセージング GW | R4 | 送信ドメイン allowlist | `detections/`（r4） |
| Hermes | cron/永続化 | R5 | 永続化監視 | `detections/`（r5, falco） |
| Hermes | スキル（安全フィルタ除去の悪用） | ガバナンス(T1562) | LLM利用ガバナンス | `defense-detection-notes.md`（§6/注意） |
| 全体 | 連鎖（速く広い） | R6 相関 | SIEM 相関設計 | `defense-detection-notes.md`（R6）, `dashboard.html` |

## 成果物の系統（何がどこに結実したか）

```mermaid
flowchart TB
  URL["起点URL usestrix/strix"]:::o --> A["3ツール解析<br/>Strix/Cairn/Hermes"]:::a
  A --> P1["Strix ローカル実行PoC<br/>strix-local-poc/"]:::b
  A --> P2["Cairn 認可ラボ<br/>cairn-lab/ (runbook, dispatch.lab.yaml, mock)"]:::b
  A --> P3["防御・検知ノート R1–R7<br/>defense-detection-notes.md"]:::b
  P3 --> P4["検知ルール実装<br/>detections/ (Sigma/Falco/Datadog)"]:::b
  P3 --> P5["統合ダッシュボード<br/>dashboard.html + Artifact(Claudeに質問)"]:::b
  A --> P6["CVP 対応<br/>cvp-readiness.md + cvp-package/"]:::b
  P1 & P2 & P3 & P4 & P5 & P6 --> PR["PR #1<br/>w-index-m/ai-agent-attack-defense"]:::c

  classDef o fill:#0f6f68,color:#fff,stroke:#0f6f68;
  classDef a fill:#2a78d6,color:#fff,stroke:#215fa8;
  classDef b fill:#eef2f2,color:#18262b,stroke:#d6dedf;
  classDef c fill:#1baf7a,color:#06211f,stroke:#148a60;
```

## R8–R14 の系統（起点が異なる追加分）

R1–R7 は単一の起点 URL（Strix）から派生したが、R8 以降はそれぞれ**別々の起点**を持つ。
会話の中でユーザーが提示した断片情報（スクリーンショット・一言の質問）が、
**一次情報での裏取りを経て**検知ルールに結実したもの・**裏取りできず不採用になったもの**の両方を含む、
この系統図自体が「未検証の情報をどう扱うか」の記録でもある。

```mermaid
flowchart LR
  subgraph ORIG["起点（情報源）"]
    direction TB
    O8["JPCERT/CC 注意喚起<br/>(2026-10-08/09)<br/>WAR内JSPの簡易Webシェル"]:::origin
    O911["llm-target-attacks.ja.md<br/>パターンC・D・E<br/>(EchoLeak系/LLMjacking/A2A)"]:::origin
    O12["DNS水攻め調査<br/>(汎用インフラ可用性)"]:::origin
    O13q["ユーザー質問<br/>「php 2shellも<br/>AI攻撃に使われる?」"]:::origin
    O14q["ユーザー提示<br/>eMudhra CA侵害の<br/>スクリーンショット"]:::origin
    Ofake["ユーザー提示<br/>「php2shell」CVEペア<br/>(CVE-2026-109618/109619)"]:::origin
  end

  O13q --> V13["調査: WebSearchで実例特定<br/>→ wp2shell と判明<br/>(CVE-2026-63030+CVE-2026-60137,<br/>Wiz 2026-10 実悪用報告)"]:::verify
  O14q --> V14["裏取り: 一次情報照合<br/>Mozilla Bugzilla #2083449 /<br/>dev-security-policy スレッド"]:::verify
  Ofake --> VX["裏取り: CVE/NVD/ニュース<br/>いずれにも該当なし<br/>→ 捏造の疑い、不採用"]:::rejected

  O8 --> R8["R8 Webシェル設置/起動"]:::det
  O911 --> R9["R9 許可リスト外送信"]:::det
  O911 --> R10["R10 メタデータ資格情報アクセス"]:::det
  O911 --> R11["R11 セッション密輸の兆候"]:::det
  O12 --> R12["R12 DNS水攻め"]:::det
  V13 --> R13["R13 wp2shell"]:::det
  V14 --> R14["R14 eMudhra CA信頼"]:::det

  R8 --> D8["detections/sigma/<br/>r8_webshell_placement_and_spawn.yml<br/>detections/falco/<br/>cairn-ai-agent.yaml<br/>jp-advisory-mapping.ja.md"]:::artifact
  R9 --> D9["detections/sigma,datadog/<br/>r9_idpi_steered_egress.*"]:::artifact
  R10 --> D10["detections/sigma,datadog/<br/>r10_metadata_service_credential_access.*"]:::artifact
  R11 --> D11["detections/datadog/<br/>r11_agent_session_smuggling.json"]:::artifact
  R12 --> D12["detections/sigma,datadog/<br/>r12_dns_water_torture.*"]:::artifact
  R13 --> D13["detections/sigma,datadog/<br/>r13_wp2shell_wordpress_batch_exploitation.*"]:::artifact
  R14 --> D14["detections/sigma,datadog/<br/>r14_emudhra_compromised_ca_trust.*"]:::artifact

  subgraph LAB["関連する教材: sqli-lab/vulnerable_app.py"]
    direction TB
    sl_sqli["/login, /review 等<br/>SQLiクラス一式"]:::lab
    sl_rce["/deserialize<br/>pickle RCE"]:::lab
    sl_ssrf["/fetch_url<br/>SSRF→内部メタデータ"]:::lab
  end
  sl_sqli -.同じ「SQLi→侵害」の構図を体験できる教材.-> R13
  sl_rce -.同じ「RCE/Webシェル着地」を体験できる教材.-> R8
  sl_ssrf -.同じ「SSRF→メタデータ窃取」の構図を体験できる教材.-> R10

  classDef origin fill:#2a78d6,color:#fff,stroke:#215fa8;
  classDef verify fill:#eef2f2,color:#18262b,stroke:#d6dedf;
  classDef rejected fill:#cc3b3b,color:#fff,stroke:#8f1f1f,stroke-dasharray: 4 3;
  classDef det fill:#eda100,color:#18262b,stroke:#b57e00;
  classDef artifact fill:#1baf7a,color:#06211f,stroke:#148a60;
  classDef lab fill:#0f6f68,color:#fff,stroke:#0a4f4a,stroke-dasharray: 2 2;
```

### トレーサビリティ表（R8–R14）

| 検知 | 起点 | 裏取り | 本リポの成果物 |
|---|---|---|---|
| R8 | JPCERT/CC 注意喚起（2026-10-08/09） | 原文確認済み | `detections/`（r8）, `jp-advisory-mapping.ja.md` |
| R9 | `llm-target-attacks.ja.md` パターンC（間接的プロンプトインジェクション） | EchoLeak(CVE-2025-32711)等、一次情報確認済み | `detections/`（r9） |
| R10 | 同パターンD（LLMjacking） | Sysdig 一次情報確認済み | `detections/`（r10） |
| R11 | 同パターンE（Agent Session Smuggling） | A2Aプロトコルの一次情報確認済み | `detections/`（r11） |
| R12 | DNS水攻め/ランダムサブドメイン攻撃の一般調査 | 攻撃手法として広く確立（AIエージェント特有ではない） | `detections/`（r12） |
| R13 | ユーザー質問「php 2shell」 | WebSearchで実例特定 → 実際は wp2shell（Wiz, 2026-10 実悪用報告） | `detections/`（r13） |
| R14 | ユーザー提示のeMudhra CA侵害スクリーンショット | Mozilla Bugzilla `#2083449` 等、一次情報で確認 | `detections/`（r14） |
| (当初不採用 → 後日訂正) | ユーザー提示の「php2shell」CVEペア（CVE-2026-109618/109619、PHP Core RCE） | 公開直後で検索に未反映のタイミングで調査し「捏造の疑い」と誤判定。翌日、ユーザーが提示した一次情報(php2shell.com)＋WebSearchでの独立した複数情報源(Wikipedia/SecurityWeek/Wiz公式ブログ等)により実在を確認、訂正した | `sqli-lab/`のバージョン照合(`check_php2shell()`、R番号なし・ツール組み込みのみ) |
| R16 | WebSearchでの一般調査(「Apache脆弱性・Nginx脆弱性も取り込んでいるか」というユーザー質問への回答として調査) | TheHackerNews/SOCPrime等、複数情報源で確認(CVE-2026-23918) | `detections/`（r16）、`sqli-lab/`の`check_apache_http2()` |
| R17 | 同上の調査 | 複数情報源で確認、実悪用の報告あり(CVE-2026-42945, 通称NGINX Rift) | `detections/`（r17）、`sqli-lab/`の`check_nginx_rewrite()` |

> 「php2shell」CVEペアの行が示す通り、ユーザーから提示された情報は**そのまま検知ルール化しない**。
> 一次情報源（CVE.org/NVD/ベンダー公式）での確認を経て採用する。ただし、この行はこの運用の
> **もう一つの側面**も示している: 不在の確認自体が「公開直後で検索に未反映」というタイミングの
> 問題だった場合、**誤って不採用と判定しうる**。実際、翌日に独立した複数情報源で実在が確認でき、
> 訂正した。「検索で出てこない」は「捏造である」の証明ではなく、時間を置いた再調査や、
> ユーザー自身が提示する一次情報（この場合はphp2shell.com本体）を軽視しないことも重要。

> 図中の `sqli-lab/` との接続は、ドキュメントだけでなく**ツール自体**にも実装している。
> `auto_vuln_scanner.py`（sqli・ssrf クラス）と `session_vuln_check.py`（deserialize クラス）は、
> 該当クラスの脆弱性を検出すると、この実例（R13・R10・R8）への参照を実行結果に併せて出力する
> （`sqli-lab/README.ja.md` の該当セクション参照）。対象の事前評価ステップ（ペイロードを撃つ前の
> `assess_target()`）では、`Server`/`X-Powered-By`ヘッダーからPHP2Shell・R16（Apache）・R17（Nginx）
> のバージョン範囲照合も行う（エクスプロイトコードは含まない）。

---
検知・防御の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
