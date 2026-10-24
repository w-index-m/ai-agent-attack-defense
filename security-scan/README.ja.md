# security-scan — 日本語インデックス

Gambit Security レポート（2026-09-22）の AI エージェント攻撃（Strix / Cairn / Hermes）を題材にした
**防御研究・検知・統制**の一式。本ディレクトリの入口（日本語）。
**検知・防御の設計に限定**し、攻撃の実行手順や安全機構の回避方法は含めない。対象は所有/認可物のみ。

## まず見るもの

- **[`dashboard.html`](dashboard.html)** — 統合ダッシュボード（ブラウザで開くだけ・オフライン・外部通信なし）。
  攻撃エージェントの俯瞰 → 検知カバレッジ → 予防コントロール → CVP 対応 → 資産リンクを 1 枚で。
- **[`dashboard-guide.ja.md`](dashboard-guide.ja.md)** — 上記ダッシュボードの、セキュリティ初心者向けガイド（専門知識なしで分かる説明、具体的にできることのチェックリスト）。
- **[`dashboard-local-llm.html`](dashboard-local-llm.html)** — 上記＋「AIに質問」を**自前の LLM**（ローカルの Ollama/LM Studio、または OpenAI 互換エンドポイント）で動かすローカル版。claude.ai のクオータ不要。接続設定はブラウザに保存、通信は指定した LLM のみ。file:// から叩くため CORS 許可が必要（Ollama: `OLLAMA_ORIGINS=*` 等）。
- **[`tools-dashboard.html`](tools-dashboard.html)** — 本リポジトリ自身の「自分の環境を確認するツール」（`scripts/*.py`・`netcheck/`）を1か所にまとめた統合索引。何を確認するか・使い方・検証状況（そのツール自身がLLMを内部で呼ぶかどうか = `patch_suggest.py`のSemgrep指摘のみ、も明記）に加え、外部の推奨ツールへのリンクも含む。`dashboard-local-llm.html`と同じ方式の「自前LLMに質問」欄つき（任意、使わなければ完全オフライン）。
- **[`local-vuln-testing-walkthrough.ja.md`](local-vuln-testing-walkthrough.ja.md)** — 自分のPCで
  脆弱性チェックを試したい人向けの入口。netcheckでの棚卸し → DVWA/Juice Shopでの練習 →
  Strix+ローカルLLMでの自動診断、という一連の流れと手順リンクをまとめたもの。

## ドキュメント

全体で25件超になったため、テーマ別に分けている。横断的な索引（検知タグ R1–R11・G1–G6の正式な定義）は [`../shared/taxonomy.json`](../shared/taxonomy.json)。

### 全体像・サマリー

| ファイル | 内容 |
|---|---|
| [`security-summary.ja.md`](security-summary.ja.md) / [`.en.md`](security-summary.en.md) | **セキュリティ問題のまとめ**。攻撃の7段と対応、既知の脆弱性、企業が取るべき対応、作ったもの、検証の状態（正直に）、次にやること。まずここから読む。 |
| [`defense-playbook.ja.md`](defense-playbook.ja.md) / [`.en.md`](defense-playbook.en.md) | **AI エージェント攻撃 防御プレイブック**。Strix / Cairn / Hermes / ARTEX の見える動きを前提に、攻撃連鎖の7段ごとの予防・検知・応答・確認、インシデント対応、罠（ハニートークン）の設計メモ、最初の1週間、**未実装の一覧**。 |
| [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md) | 防御の4層（予防・検知・応答・復旧）と、外部ロードマップ案の対応づけ・評価・不足分の補い方。R1–R8 と ③ の区別、カーネルFIM 解説つき。 |
| [`glossary.ja.md`](glossary.ja.md) / [`.en.md`](glossary.en.md) (EN) | 用語集（やさしい日本語）。FIM / CSP / WORM / egress / C2 / RCE / IAM などを1行ずつ。新語が出たら追記する。 |

### AIエージェントが攻撃する側（Gambit系：Strix / Cairn / Hermes / ARTEX）

| ファイル | 内容 |
|---|---|
| [`defense-detection-notes.md`](defense-detection-notes.md) | 3ツール横断の防御・検知ノート。SOC 運用レイヤー（データソース対応、検知ルール R1–R8、MITRE ATT&CK、トリアージ）と、攻撃用AIエージェントの広域マップ（§6）。 |
| [`artex-analysis.ja.md`](artex-analysis.ja.md) / [`.en.md`](artex-analysis.en.md) | 自律型ペネトレ AI エージェント **ARTEX** の防御解析（一次情報の静的レビュー）。アーキ分解＋R1–R8/G1–G6 対応。攻撃手順は含まない。 |
| [`unit42-ai-assisted-intrusion.ja.md`](unit42-ai-assisted-intrusion.ja.md) / [`.en.md`](unit42-ai-assisted-intrusion.en.md) | Unit 42 の実インシデント報告「AI支援サイバー攻撃」の分析。人間の攻撃者が frontier AI エージェントで侵入を自動化し、2週間相当の作業を10時間未満で完了。MITRE ATT&CK×ATLAS対応表、R1–R8/G1–G6 との接続点つき。 |
| [`jp-advisory-mapping.ja.md`](jp-advisory-mapping.ja.md) / [`.en.md`](jp-advisory-mapping.en.md) | **国内の注意喚起（2026年10月、JPCERT/CC・個人情報保護委員会など）と、このリポジトリの対応表**。API の不正操作、既知の脆弱性（BI ツールを含む）、管理不備、Web シェルの 4 つの型ごとに、予防・検知・足りない点を整理。二次情報に基づくので、原典で確認すること。 |
| [`fortimanager-peerstitch-notes.ja.md`](fortimanager-peerstitch-notes.ja.md) / [`.en.md`](fortimanager-peerstitch-notes.en.md) | **【AI関与なし】** Unit 42 の実インシデント報告「PEERSTITCH」の分析。FortiManagerの脆弱性（CVE-2024-47575）から500台超のFortiGateへ波及した侵害と、メモリ常駐型インプラントの技術解説。Gambit連鎖⑥（過剰な権限）との接続点つき。AIが関与しない対照事例として収録。 |
| [`strix-local-backend-notes.md`](strix-local-backend-notes.md) | Strix の実行フロー解析と、Docker 不要ローカル実行の設計。 |
| [`strix-local-poc/`](strix-local-poc/) | 上記の PoC（パッチ・検証スクリプト・結果）。 |
| [`cairn-lab/`](cairn-lab/) | Cairn を認可済み隔離ラボで動かすランブックと実設定（`dispatch.lab.yaml` ほか）、攻撃なし mock 設定。 |
| [`strix-local-poc/windows-wsl-ollama-setup.md`](strix-local-poc/windows-wsl-ollama-setup.md) | Windows 11 + WSL2 + ローカルOllamaで、クラウドLLM課金なしにStrixを動かす実機セットアップ手順（DVWA等の自分で立てた練習環境を対象）、Groq/OpenRouterクラウドLLMでの試行、Claude Codeクラウドサンドボックスでの試行を記録。**最終結論：断念。** 試した全構成(ローカル3サイズ・Groq・OpenRouter・クラウドサンドボックス)がそれぞれ異なる構造的な壁(ツール呼び出しJSONの崩壊/無意味なコマンドループ、無料枠のトークン/分制限、大きいリクエストで原因不明の404、LLMプロバイダ全拒否のネットワーク許可リスト)に当たった。セットアップを自動化するPowerShellスクリプト（[`start-strix-test.ps1`](strix-local-poc/start-strix-test.ps1)）も収録(今は断念した旧アプローチの記録)。 |
| [`sqli-lab/README.ja.md`](sqli-lab/README.ja.md) | **Strix PoCの代わりに完成した成果。** 11種類(SQLi・反射型/格納型XSS・OSコマンドインジェクション・パストラバーサル・CSRF・IDOR/BOLA・デシリアライズRCE・マスアサインメント・SSRF・アカウント列挙 ── 後半4つは第三者による実際のStrix実行レポートとの照合で追加)それぞれの脆弱版/修正版エンドポイントを持つ最小Flask+SQLiteアプリと、LLM不要のルールベーススクリプト2本(GETパラメータ総当たり型の`auto_vuln_scanner.py`、セッション/バイナリペイロード型の`session_vuln_check.py`)、1コマンドで全パターンを実行する`scan_all.sh`。LLM・エージェントループ・Docker不要。`netcheck`と同じく既定でローカル/プライベート範囲限定のスコープガード付き。`run_regression.py`も追加し、CIスキャンに組み込み済み(脆弱性診断ゲートではなく回帰テストとして。
`vulnerable_app.py`はこのリポジトリ自身のコードではなく意図的な脆弱デモアプリのため)。
全脆弱/修正版エンドポイントが正しく分類され続けているかを検証し、不一致を`summarize.py`の
新しい`sqli_lab`ソース経由で報告する。 |

### 【スコープ拡張】LLMシステムが標的になる側

| ファイル | 内容 |
|---|---|
| [`llm-target-attacks.ja.md`](llm-target-attacks.ja.md) / [`.en.md`](llm-target-attacks.en.md) | **LLM システム自体への攻撃**（プロンプトインジェクション、システムプロンプト漏洩、間接的プロンプトインジェクション、LLMjacking、**マルチエージェント間のセッション悪用**の5類型）の、一次情報に基づく整理。既存の R1–R8/G1–G6 との接続点つき（C・D・EはR9–R11として実装済み）。Unit 42 の CrewAI/AutoGen 実証研究・Web経由IDPIの大規模実態調査・GCP Vertex AI "Double Agents"・Agent Session Smuggling（A2Aプロトコル）も収録。 |
| [`openclaw-skill-supply-chain.ja.md`](openclaw-skill-supply-chain.ja.md) / [`.en.md`](openclaw-skill-supply-chain.en.md) | AIエージェント **OpenClaw** のスキル・マーケットプレイス **ClawHub** を舞台にした、Unit 42 の2本の一次情報の整理。悪性スキルの実例（情報窃取・スキャン回避・エージェント特有の金銭目的型）と、振る舞い整合性検証（BIV）によるレジストリ全体調査（49,943件中80%に乖離）。 |
| [`llm-defense-checklist.ja.md`](llm-defense-checklist.ja.md) / [`.en.md`](llm-defense-checklist.en.md) | `llm-target-attacks.ja.md` の5類型の予防・検知項目を、**自分のシステムで守られているか確認するチェックリスト**にしたもの。自動判定スクリプトではなく、人が確認する前提。 |

### 検知ルールの実装

| ファイル | 内容 |
|---|---|
| [`detections/`](detections/) | 検知ルールの実装：Sigma / Falco / Datadog（R1–R8、Gambit系）＋Sigma / Datadog（R9–R11、LLM標的攻撃のパターンC・D・E）＋Sigma / Datadog（R12、DNS水攻め/ランダムサブドメイン攻撃の検知。AIエージェント特有ではない汎用インフラ可用性シグナルだが同じ検知基盤に収録）＋Sigma / Datadog（R13、実在するWordPressの「wp2shell」脆弱性チェーンの検知。CVE-2026-63030のルート混同＋CVE-2026-60137のSQLiでWebシェルが設置される実際に悪用中の脆弱性で、発見自体がAI支援によるソース監査という点でも注目）＋Sigma / Datadog（R14、実在するeMudhra中間CAの秘密鍵侵害インシデント（2026年10月）の検知。失効済み中間CAをまだ信頼しているTLSクライアント＝トラストストア未更新を検知する、汎用PKI信頼性シグナル）＋Sigma / Datadog（R15、PHP2Shell——PHPコア自体に実在する重大なメモリ安全性の脆弱性チェーン(CVE-2026-109618/CVE-2026-109619、各CVSS 9.2、2026-10-21にWiz Research/OpenAI Codex Security/Califが公開)の検知。PHPランタイム自体の問題で特定の request パターンがないため、R16・R17と同じくPHP-FPM workerクラッシュパターンとバージョンバナーの2本立てで検知。`sqli-lab`のスキャナーにも同じバージョン照合を実装済み）＋Sigma / Datadog（R16・R17、代表的な2つのWebサーバーデーモン本体に実在する重大CVE。Apache httpdのmod_http2ダブルフリー(CVE-2026-23918)とNginxのngx_http_rewrite_moduleオーバーフロー(CVE-2026-42945、通称「NGINX Rift」)を、workerクラッシュパターンとバージョンバナーの手がかりの2本立てで検知。どちらも単体では悪用の確証にはならない旨を明記。`sqli-lab`のスキャナーにも同じバージョン範囲照合を実装済み）＋Sigma / Datadog（R18・R19、PHPエコシステムで今も現役の、古典的だが定番のRCEパターン2つ。PHPUnitの`eval-stdin.php`が誤って公開された`/vendor/`配下から到達可能になる悪用(CVE-2017-9841)と、ThinkPHPの`invokefunction`/`call_user_func_array`悪用RCE(CVE-2018-20062/CVE-2019-9082)。どちらもCISA KEV掲載で、R16・R17と違いURI文字列の単純一致だけで検知できる。PHP2Shellとは無関係の、別のPHPエコシステムの脆弱性）＋Sigma / Datadog（R20、Unit 42「An AI-Assisted Cyber Attack」が挙げたAIエージェント関与の痕跡3点の1つ(構造化Markdownでのエージェント間情報受け渡し)を狙った探索的ヒューリスティック。単一プロセスが複数ディレクトリへ構造化Markdownを短時間に散発書き込みするパターンを検知。Unit 42自身はIOC・ファイル名を公開しておらず、本リポジトリ独自に構成した未確証のヒューリスティックである旨を明記。`unit42-ai-assisted-intrusion.ja.md` §7参照）＋Sigma / Datadog（R21、実在する「Infinity Core」——研究者Hyunwoo Kim/V4belが2026-10-16に公開した、公開PoCつきの6件のLinuxカーネルローカル権限昇格(LPE)脆弱性チェーン(主要CVE-2026-98260等)——を狙う探索的ヒューリスティック。カーネルエクスプロイト自体はユーザー空間に決まったログを残さないため、「既知の正規の昇格経路なしに非特権プロセスがroot(UID 0)へ遷移する」という結果側から検知する。ホスト側のカーネルバージョン確認には`scripts/linux_kernel_infinitycore_check.py`を使用）＋Sigma / Datadog（R22、実在するISCの2026-10-21 BIND 9セキュリティリリース(4件のCVE、9.20.30/9.21.27で修正)の検知。目玉はCVE-2026-94300(CVSS 8.1)でGSS-TSIGメッセージのリプレイによるメモリ破損、ISC自身は「潜在的に」RCEに繋がりうるという条件付きの表現に留める。namedのassertion failureクラッシュ特有のログ(GSS-TSIG/TKEY文脈)と、別口のCHAOS版数バナーの2本立てで検知。ホスト/ネットワーク側のバージョン確認には`scripts/bind_version_check.py`を使用）＋Sigma / Datadog（R23、実在する、悪用確認済みのF5 BIG-IP APM CVE-2026-94127(CVSS 9.8、OAuth UserInfoハンドラのヒープベースバッファオーバーフロー、事前認証不要RCE、CISA KEV掲載)の検知。独自研究ではなく、F5自身(K000162605)とJPCERT/CC(JPCERT-AT-2026-0028)が公式に挙げた侵害検出方法をそのまま検知ルール化: 単一送信元からのOAuth UserInfo要求失敗の反復と、異常に長いAuthorizationヘッダーの2本立て。ホスト側の確認には`scripts/f5_bigip_apm_check.py`(BIG-IPはバージョンバナーを出す設計ではないため、実機のシェル上で動かすことが前提)を使用）＋Sigma / Datadog（R24、実在するCVE-2026-111497(通称「Node2Shell」/「HTTP2Shell」、Brotliデコーダの境界外書き込み)の検知。元々はNode.js本体の脆弱性として2026-10-21に修正されたが、2026-10-22公開のGHSA-9v8h-qqgm-4m35(Critical)でPyPIの`brotli`/`brotlicffi`(`requests`等が自動読み込み)への波及が確認された。R13・R15と違い、ベンダー/研究者公開のIOCが存在しないため、R24は本リポジトリ独自に構成した未確証の探索的ヒューリスティック(gunicorn/uwsgi等のworkerクラッシュをbrotli文脈の近くで探すだけ)である旨を明記。ホスト側のパッケージバージョン確認には`scripts/python_brotli_check.py`(使い捨てvenvに実際の脆弱版/修正版をインストールして動作検証済み)を使用）。閾値・allowlist は環境でチューニング。 |

### 自分の環境を確認するツール

参考: **[`tools-dashboard.html`](tools-dashboard.html)** に、以下すべてをまとめた統合索引があります。

| ファイル | 内容 |
|---|---|
| [`os-patch-check-notes.md`](os-patch-check-notes.md) | 自分の機器の OS 更新を確認し、SARIF で `vuln_triage` に読み込む。**Linux(RHEL系)用 `scripts/os_patch_check_linux.py`** と **Windows用 `scripts/os_patch_check_windows.py`** に分けている。確認専用。実機では未検証。 |
| [`java-cacerts-emudhra-check-notes.md`](java-cacerts-emudhra-check-notes.md) | `scripts/java_cacerts_emudhra_check.py`: ローカルJDKのcacertsに、eMudhra侵害(R14)関連のルートCAがあるかを確認し、`java -version`をIPA公表の「脆弱な版」一覧(CVE-2026-91403)と突き合わせる。確認専用。このサンドボックスの実際のJDKに対して実行・検証済み(検証中に実際のバグ――この環境では`java -version`のエラー文言がstderrではなくstdoutに出ることを発見し修正した)。該当ルートCAを実際に信頼しているJDKでは未検証。 |
| [`patch-suggest-notes.md`](patch-suggest-notes.md) | 診断結果から修正案（diff）を作る `scripts/patch_suggest.py`。自動適用はしない（人の y/N 確認つき）。gitleaks の値は LLM に送らない。小さいモデルの限界を明記。 |
| [`linux-kernel-infinitycore-check-notes.md`](linux-kernel-infinitycore-check-notes.md) | `scripts/linux_kernel_infinitycore_check.py`: 実行中のカーネル(`uname -r`)と`/etc/os-release`を、「Infinity Core」のLinuxカーネルLPE脆弱性チェーン(R21)と照合する。確認専用。ディストリビューションごとのバックポート差異のため、単純なバージョン番号比較での断定は避ける設計(例外はCloudLinux CL9——ベンダー公式アドバイザリで修正済みビルドが正確に判明している唯一のケース)。このサンドボックスで実行・検証済み。 |
| [`bind-version-check-notes.md`](bind-version-check-notes.md) | `scripts/bind_version_check.py`: BIND 9のバージョンを、ISCの2026-10-21セキュリティリリース(4件のCVE、R22。目玉はCVE-2026-94300、CVSS 8.1、GSS-TSIGリプレイによるメモリ破損)と照合する。ローカルモードは`named -v`を読み取るだけ、ネットワークモード(任意)は許可範囲内のホストへCHAOSクラスのTXT(`version.bind`)問い合わせを1回送る(`netcheck`の許可範囲判定を再利用、`zgrab2_guard.py`と同じ方式)。確認専用。バージョン判定は近似照合であり厳密なセマンティックバージョン比較ではない。バージョン判定の分岐とDNS問い合わせ/パースのロジックは合成パケットでユニットテスト済み、実際に稼働中のBINDに対しては未検証。 |
| [`f5-bigip-apm-check-notes.md`](f5-bigip-apm-check-notes.md) | `scripts/f5_bigip_apm_check.py`: F5 BIG-IP APMのCVE-2026-94127(R23。CVSS 9.8、事前認証不要RCE、悪用確認済み、CISA KEV)の露出/侵害の兆候を確認する。F5・JPCERT/CCが公式に挙げた侵害検出手順をそのまま自動化(独自の判定ロジックは追加なし): `tmsh`でのバージョン確認、apmログのOAuth UserInfo失敗の反復集計、TMMコアファイルの有無、`tmm.finish`のハッシュ算出(正常値との比較はしない——バージョン/ビルド依存のため)。他の多くの`scripts/*.py`と違い、BIG-IPはバージョンバナーを出す設計ではないため、BIG-IP実機のbashシェル上で動かすことが前提。4つの確認経路すべて、このサンドボックスで合成データに対して検証済み。実際のBIG-IP実機・実際のapmログフォーマットに対しては未検証。 |
| [`php2shell-scanner-notes.md`](php2shell-scanner-notes.md) | **外部の第三者ツール**[`aancw/php2shell-scanner`](https://github.com/aancw/php2shell-scanner)(Go製、R15/PHP2Shell向け)の利用ノート: インストール+SHA256SUMS検証、url/local/sshの3モードとフラグ、PHPのバージョン修正表(ツール自身のREADMEから転記)。本リポジトリでは実装・実行していない(ビルド環境が無いため)——スクリプトではなく利用手順書。 |
| [`php-version-check-notes.md`](php-version-check-notes.md) | `scripts/php_version_check.py`: ローカルのPHPインタプリタのバージョンをPHP2Shellの修正版表(R15)と照合し、任意でphp-fpmログからR15のSigmaルールと同じworkerクラッシュパターンを確認する(`--log-path`/`--journalctl-unit`)。確認専用——PHPコードの実行やメモリ破壊の実行は一切しない。このサンドボックスに実際にインストールされていたPHP 8.3.6(修正版8.3.36未満として正しく脆弱判定)と、合成したphp-fpmクラッシュログ(陽性/陰性の両ケース)で検証済み。 |
| [`python-brotli-check-notes.md`](python-brotli-check-notes.md) | `scripts/python_brotli_check.py`: インストール済みの`brotli`/`brotlicffi`パッケージ(このインタプリタ、または`--python <path>`でvenv指定)のバージョンを、CVE-2026-111497(通称「Node2Shell」/「HTTP2Shell」、R24、GHSA-9v8h-qqgm-4m35)の修正版表と照合し、任意でアプリログからR24独自の未確証な探索的ヒューリスティック(workerクラッシュ+brotli文脈)を確認する(R13・R15と違い、このCVEにはベンダー公開のIOCが存在しない点を明記)。確認専用。使い捨てvenvに実際に脆弱版(1.2.0)→修正版(1.2.1)をインストールして動作確認(合成データだけでなく実データで検証)、ログ確認部分は合成したgunicornクラッシュログ(陽性/陰性の両ケース)で検証済み。 |
| [`zgrab2-notes.md`](zgrab2-notes.md) | zgrab2（ZMap のアプリ層スキャナ）の出力を `vuln_triage` に取り込む方法と、対象を許可範囲に絞るガード `scripts/zgrab2_guard.py`。露出の棚卸し用で、脆弱性スキャナではない。日英。 |
| [`dep-cve-check-notes.md`](dep-cve-check-notes.md) | `scripts/dep_cve_check.py`: `requirements.txt`（pip、`==` 固定行）と npm の `package-lock.json` を、公開の脆弱性データベース OSV.dev に照合する。出力は SARIF で `vuln_triage` にそのまま読み込める。モックで検証済み、実際の OSV API は未確認。日英。 |
| [`ghsa-lookup-notes.md`](ghsa-lookup-notes.md) | `scripts/ghsa_lookup.py`: GHSA ID・CVE 番号から GitHub の公開 Advisories API の構造化データ（影響版・修正版・CWE・CVSS）を取得し、**要約せずそのまま** Markdown に転記する。2つの CVE を取り違えた過去の誤りの再発防止。モックで検証済み、実際の API はこのセッションの GitHub 連携の制約で未確認。日英。 |

### CVP（Cyber Verification Program）対応

| ファイル | 内容 |
|---|---|
| [`cvp-application-form-draft.md`](cvp-application-form-draft.md) | CVP 申請フォームの下書き（Defense Access）。提出前チェック、各項目の回答案（英語＋日本語の意味）、書いてはいけない例。**実績など本人にしか書けない項目は空欄**。 |
| [`cvp-readiness.md`](cvp-readiness.md) | Anthropic Cyber Verification Program のティア対応と申請準備。 |
| [`cvp-package/`](cvp-package/) | 申請パッケージ（HTML / PDF）。`python3 security-scan/cvp-package/build_package.py` で元の文書から再生成できる（pandoc と Chromium が必要）。 |

### その他

| ファイル | 内容 |
|---|---|
| [`sandbox-defense-model.ja.md`](sandbox-defense-model.ja.md) / [`.en.md`](sandbox-defense-model.en.md) | サンドボックス防御モデル（スキャンパターン別・使い捨ての正体）。実スキャンなしの防御解説。 |

## 検知ルール早見（優先度順）

**Gambit系（攻撃用AIエージェント、R1–R8）**

1. **R1 / R4** — サーバ系からの LLM / メッセージング API egress（最優先）
2. **R2** — 特権 / host net / 未知イメージのコンテナ起動
3. **R7** — 1 親プロセスが多種ツールを短時間連続実行（**ローカルLLM型でも残る核**）
4. **R3** — 偵察的 Web 列挙バースト
5. **R5** — 永続化（cron / systemd）の新規作成
6. **R6** — 上記を束ねる相関（単発では見えない連鎖を検知）

**LLM標的攻撃系（R9–R11、`llm-target-attacks.ja.md`のパターンC・D・E）**

- **R9** — LLM/エージェントの、許可リスト外ドメインへの指示誘導による送信（IDPIの兆候）
- **R10** — AIワークロードからのクラウドメタデータサービス資格情報エンドポイントへのアクセス
- **R11** — マルチエージェントのセッション内で、ユーザーの直接指示のないツール呼び出し（要アプリ計装）

## 言語について

- 本リポの解説・ノート・ランブックは日本語。ダッシュボードは日英併記。
- `detections/` の Sigma/Falco/Datadog ルールは、SIEM への移植性のため**説明文を英語**にしている
  （各ルールの意味は本 README と `defense-detection-notes.md`・`detections/README.md` に日本語で記載）。
- 英語版ドキュメントが必要な場合は別途作成可能。
