# LLM システム自体への攻撃（防御の視点）

English: [`llm-target-attacks.en.md`](llm-target-attacks.en.md)

> ⚠️ **このリポジトリのスコープを広げる文書。** これまでの主題は「**AI エージェントが攻撃に使われる**」（Strix/Cairn/Hermes による Gambit の事例）だった。
> ここからは、「**LLM を組み込んだシステム自体が、攻撃の標的になる**」側を扱う。攻める側ではなく、**自社が LLM・AI エージェントを使っている場合に、守るべき対象**としての整理。
> 方針は変わらない：**検知・防御の設計に限定し、攻撃の再現手順（ペイロード、エクスプロイトコード）は載せない。**

## 1. 対象の 4 類型（一次情報で確認済み）

| 類型 | 一次情報で確認できる事例 | OWASP LLM Top 10 (2025) |
|---|---|---|
| A. プロンプトインジェクション → エージェントの権限での実行 | 下記 §2 | **LLM01**（Prompt Injection）＋ **LLM06**（Excessive Agency） |
| B. システムプロンプトの漏洩 | 下記 §3（PLeak） | **LLM07**（System Prompt Leakage） |
| C. 間接的プロンプトインジェクション（外部コンテンツ経由） | 下記 §4（EchoLeak） | **LLM01** の一種 ＋ **LLM02**（Sensitive Information Disclosure） |
| D. LLMjacking（盗んだクラウド認証情報の不正利用） | 下記 §5（Sysdig） | **LLM10**（Unbounded Consumption） |

> 本リポジトリの既存の整理（R1–R8、G1–G6）は、**ネットワーク・ホストを観測して、自律型の攻撃エージェントを検知する**ための設計。LLM システム自体を守る層（アプリ内のプロンプト設計、出力の検証）は、観測点が異なる。重なる部分は §6 で示す。

---

## 2. プロンプトインジェクション → エージェントの権限での実行

一次情報で確認できる事例（いずれも、**特定のベンダー・製品の実装不備**であり、LLM 一般の欠陥ではない）。

| 事例 | 内容（高い粒度） | 出典 |
|---|---|---|
| **EchoLeak**（CVE-2025-32711） | Microsoft 365 Copilot。CVSS 9.3。詳細は §4 | Microsoft、Aim Security |
| **Semantic Kernel — CVE-2026-26030**（Python SDK） | `InMemoryVectorStore` のフィルター機能で、フィルター式の中にアクセスすべきでない危険な属性名を使うことを防げておらず、リモートでのコード実行に至る。CWE-94（コードインジェクション）。CVSS 9.9（Critical）。1.39.4 で修正 | **GitHub Security Advisory（GHSA-xjw9-4gw8-4rqx）を原文で確認済み** |
| **Semantic Kernel — CVE-2026-25592**（.NET SDK、別の脆弱性） | `SessionsPythonPlugin` のファイルのダウンロード/アップロード機能（`DownloadFileAsync`・`UploadFileAsync`）で、渡されたパスの検証が不十分で、任意の場所にファイルを書き込める。CWE-22（パストラバーサル）。CVSS 9.9（Critical）。NuGet 1.71.0・pip 1.39.3 で修正 | **GitHub Security Advisory（GHSA-2ww3-72rp-wpp4）を原文で確認済み** |
| **Context7 MCP サーバー**（CVE-2026-75130） | カスタム指示機能に、毒を仕込んだ指示を入れておくと、連携するコーディングエージェントが、環境変数ファイルから認証情報を盗み、ファイルを削除する、とされる。CVSS 3.1 で 9.0、CVSS 4.0 で 6.4 という、情報源により異なる値が出ている。発見者：Noma Security の Eli Ainhorn 氏。**修正版の有無についても情報源が食い違う**（2.1.3 で修正済みとする情報源と、2026年8月時点で未修正とする情報源がある） | 二次情報（VulnCheck、NVD とも、この環境からは接続できず未確認） |
| **ModelScope ms-agent — CVE-2026-2256** | Shell ツールの入力検証（`check_safe()` 等、呼称は二次情報による）が、プロンプト由来の入力を十分に無害化できておらず、OS コマンドの実行に至る。CWE-77。CVSS 3.1 で 6.5（Moderate）。**2026年3月4日の時点で、修正版は無い（Patched versions: None）** | **GitHub Security Advisory（GHSA-4gc2-344q-r2rw）を原文で確認済み** |

**予防**：
- エージェントが生成した文字列を、**コマンドやコードに動的に組み込まない**（文字列補間・`eval` 系の実行を避ける）。
- **ファイルパスを引数に取るツール**（ダウンロード・アップロード・読み書き）には、渡されたパスを許可リストで検証し、意図したディレクトリの外を指せないようにする（パストラバーサル対策）。
- ツール呼び出しは**許可リスト化**し、エージェントの実行権限を最小限にする（コンテナの非 root 実行、不要な capability を外す）。
- リスクのある操作（ファイル削除、外部送信、認証情報へのアクセス）には、**人の承認ゲート**を挟む。

**検知**：
- エージェントのプロセスから、**想定外の子プロセスが起動する**動き（このリポジトリの **R7**・**R8** と同じ発想：「本来の処理では呼ばれないはずのプロセスが、短時間に呼ばれる」）。
- MCP サーバーなど、外部から指示を受け取る経路への、監査ログの有無（**G1**：スキルの導入・自動生成・自己改変、**G4**：監査ログの欠落・停止）。

---

## 3. システムプロンプトの漏洩（PLeak）

- **一次情報**：Hui, Yuan, Gong, Burlina, Cao の論文「PLeak: Prompt Leaking Attacks against Large Language Model Applications」（arXiv:2405.06823）。
- **内容**：攻撃者が用意した代替（シャドー）の LLM を使い、**勾配ベースの最適化**で、対象アプリに送る敵対的な質問文を自動生成する。システムプロンプトの先頭から少しずつ、トークン単位で復元していく手法。手作業の質問文や、既存のジェイルブレイクより効果が高いとされる。実際に Poe 上の公開アプリで検証され、著者は Poe に報告している。
- **未確認の点**：この攻撃を「Trend Micro が分析した」「Azure AI Foundry のフィルターを回避した」という記述は、**一次情報（論文、Poe への報告）では確認できなかった**。検索しても、信頼できる一次の Trend Micro の記事は見つからず、転載とみられるページしか確認できていない。この点は、裏付けが取れるまで、事実として扱わない。

**予防**：
- **システムプロンプトに、認証情報や、漏れて困る情報を書かない。** 「システムプロンプトは、いずれ漏れうる」という前提で設計する（秘密の保存場所ではない）。
- 出力に、システムプロンプトの一部がそのまま含まれていないかを検査する、出力フィルタ・分類器を挟む。

**検知**：
- 同一の送信元から、**少しずつ内容を変えた質問が、短時間に繰り返される**動き。このリポジトリの **R3**（偵察的アクセスのバースト検知）と、発想は同じ（対象が Web パスの列挙か、プロンプトの反復質問かの違い）。

---

## 4. 間接的プロンプトインジェクション（EchoLeak、CVE-2025-32711）

- **一次情報**：Microsoft のセキュリティアドバイザリ（CVE-2025-32711）、Aim Security の報告。CVSS 9.3（Critical）。Microsoft は「AI command injection」に分類し、ネットワーク経由で、認証なしに情報を開示されうるとしている。2025年6月に修正済み。実際の悪用は確認されていないとされる。
- **内容（高い粒度）**：攻撃者が、メールに**隠した指示**（HTML コメントや、白地に白文字など、人の目には見えない形）を仕込んでおく。利用者が、後でまったく別の用件で Copilot に質問すると、**RAG の仕組み**が、そのメールを文脈として読み込んでしまう。隠された指示に従って、Copilot が、手元の機密情報を、外部に送信できる参照リンクに埋め込む。この経路は、Microsoft の防御分類器（XPIA）や、リンクの無害化処理を回避し、Microsoft の正規ドメインを使って情報を持ち出したとされる。Aim Security は、これを「LLM scope violation」（本来の役割の逸脱）と位置づけている。
- **一般化した構図**：LLM が、①外部の、信頼できないコンテンツを読み込み、②その結果をもとに、何らかの行動（送信、ツール呼び出し）を取れる、という組み合わせを持つシステムは、**同じ構図のリスクを持つ**。今回のリポジトリでの用語に合わせると、「取得したコンテンツを、常にデータとして扱い、指示として扱わない」ことが防御の軸になる。

**予防**：
- **外部から取得したコンテンツ（メール、Web ページ、文書）を、指示ではなく、常にデータとして扱う。** これは、このセッション自身が、GitHub の PR やノーティフィケーションの本文を扱う際の原則と、同じ考え方である。
- LLM が外部に送信できる経路（送信先ドメイン、ツール）を**許可リストで絞る**。このリポジトリの **R1/R4**（サーバ系ホストから LLM API・メッセージング API への送信を見る発想）を、「LLM 自身からの送信」に応用したもの。
- 隠しテキスト（HTML コメント、白地に白文字、ゼロ幅文字など）を、LLM に渡す前に取り除く。

**検知**：
- LLM・エージェントのサービスアカウントから、**普段使わないドメインへの送信**（R1/R4 と同じ発想）。
- 生成された外部リンクに、機密情報らしきパラメータが含まれていないかの検査。

---

## 5. LLMjacking（盗んだクラウド認証情報での不正利用）

- **一次情報**：Sysdig Threat Research Team の報告（2024年5月、同年9月の続報）。
- **内容**：攻撃者は、**脆弱な Laravel（CVE-2021-3129）**から、クラウドの認証情報を盗み出した。その認証情報で、クラウドがホストする LLM（例：Amazon Bedrock 経由の Claude など）へのアクセス権を有効化し、**他のサイバー犯罪者に転売**した。費用は、被害者のクラウド請求に乗る。Sysdig の見積もりでは、発覚しないまま続けば、1日あたり最大 10 万ドルを超える請求になりうるとしている。9月の続報では、攻撃者が `DeleteModelInvocationLoggingConfiguration` のような操作で、**ログ記録そのものを止めて**、発覚を遅らせようとしたことが報告されている。
- **Gambit の攻撃連鎖との関係**：根本原因は、**Gambit 報告の⑥（Secrets Manager の過剰な権限）と同じ構図**（認証情報の窃取＋過大な権限）。対象が LLM サービスである点が異なるだけ。

**予防**：
- クラウドの IAM を、**使う LLM サービス・モデルだけに絞った最小権限**にする（⑥と同じ対策）。
- 認証情報を、コードや設定ファイルに書かない（gitleaks で検出）。
- コスト・利用量に、**予算アラート**を設定する。

**検知**：
- クラウドの請求・利用量の急な増加（LLM 推論の呼び出し回数の異常）。
- クラウド監査ログで、**ログ記録の設定を止める操作そのもの**を検知する。これは、このリポジトリの **G4**（監査ログの欠落・停止）に、ほぼそのまま対応する実例。

---

## 6. このリポジトリの既存の整理との接続点

| 今回の類型 | 既存の整理との接続 |
|---|---|
| A. 実行権限の濫用 | R7/R8（想定外のプロセス起動）、G1（スキルの自動生成）、G4（監査ログ） |
| B. システムプロンプト漏洩 | R3（反復アクセスのバースト検知）と同じ発想 |
| C. 間接的プロンプトインジェクション | R1/R4（LLM・メッセージング API への送信の監視）を、エージェント自身の送信に応用 |
| D. LLMjacking | Gambit 連鎖の⑥（IAM の過大な権限）と同じ構図、G4（監査ログの欠落・停止） |

**ただし、これは接続点の指摘であり、検知ルールの実装ではない。** R1〜R8 のルール（Sigma/Falco/Elastic/Datadog）は、今回の 4 類型向けには作っていない。アプリ内のプロンプト設計・出力検証という層は、このリポジトリの既存ツール（netcheck、vuln_triage、検知ルール）の観測点の外にある。

## 7. 限界・未確認の点

- Semantic Kernel（2件）と ModelScope ms-agent は、**GitHub の公式 Security Advisory（GHSA）の原文**を、この環境から直接読んで確認した。Context7 は、NVD・VulnCheck ともこの環境から接続できず、二次情報（ニュース記事・脆弱性データベースの転載）のみで、**修正版の有無すら情報源により食い違う**。
- いずれも、**実際に動かして確認したものではない**（原文を読んだだけで、攻撃コードは書いていない）。
- PLeak の「Trend Micro」「Azure AI Foundry」への言及は、**裏付けが取れていない**（§3 参照）。
- LLMjacking の被害額は、Sysdig の見積もりであり、情報源により数字が異なる（他の記事では別の集計期間・金額が出ている）。正確な数字は、Sysdig の一次記事（sysdig.com/blog）で確認すること。

## 8. 参考情報（一次・準一次情報）

- GitHub Security Advisory, GHSA-xjw9-4gw8-4rqx（Semantic Kernel、CVE-2026-26030）: https://github.com/microsoft/semantic-kernel/security/advisories/GHSA-xjw9-4gw8-4rqx
- GitHub Security Advisory, GHSA-2ww3-72rp-wpp4（Semantic Kernel、CVE-2026-25592）: https://github.com/microsoft/semantic-kernel/security/advisories/GHSA-2ww3-72rp-wpp4
- GitHub Advisory Database, GHSA-4gc2-344q-r2rw（ModelScope ms-agent、CVE-2026-2256）: https://github.com/advisories/GHSA-4gc2-344q-r2rw
- Microsoft, CVE-2025-32711（EchoLeak）: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711
- Aim Security, EchoLeak の技術解説（The Hacker News 経由）: https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html
- EchoLeak の学術的な事後分析（arXiv）: https://arxiv.org/html/2509.10540v1
- Hui et al., PLeak（arXiv:2405.06823）: https://arxiv.org/abs/2405.06823
- VulnCheck, Context7 MCP サーバーの CVE-2026-75130: https://fieldguide.lutrasecurity.com/CVE-2026-75130/
- NVD, CVE-2026-2256（ModelScope ms-agent）: https://nvd.nist.gov/vuln/detail/CVE-2026-2256
- Sysdig, LLMjacking（初報）: https://sysdig.com/blog/
- OWASP, Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/

> 検知・防御の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
