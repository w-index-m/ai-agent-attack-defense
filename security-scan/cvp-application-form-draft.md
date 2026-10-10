# CVP 申請フォームの下書き（Defense Access）

[Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program) の申請フォーム（https://portal.anthropic.com/programs/cvp ）に貼るための下書き。
関連: [`cvp-readiness.md`](cvp-readiness.md) / [`cvp-readiness.en.md`](cvp-readiness.en.md)

> **使う前に必ず読む**
> - 公式ページは**フォームの項目を公開していません**。以下の項目名は想定です。実際のフォームに合わせて読み替えてください。
> - `[ ]` で囲んだ部分は、**あなたにしか分からない事実**です。下書きでは埋めていません。**事実と違うことは書かないでください**（審査は本人確認と統制の証明が前提です）。
> - 回答は英語で書いてあります（フォームが英語の想定）。日本語の意味は各項目の下に付けています。
> - 作成日 2026-10-10。制度は更新されうるので、提出前に公式ページを再確認してください。

---

## 0. 提出前チェック（これが「はい」でないなら、まだ出さない）

1. **個人で申請しますか？** → 個人が通れるのは **Defense Access のみ**。公式の条件は「**報告済み脆弱性の実績**（a track record of reported vulnerabilities）」です。
   CVE・GitHub Security Advisory・バグバウンティの報告、ベンダの謝辞などで**実績を示せますか？**
   - 示せる → §5 に書く。
   - 示せない → 個人での申請は通りにくい前提です。（a）自分の資産／認可範囲／バグバウンティで正規の報告を積む、（b）所属組織経由で申請する、を先に検討。
     **実績を作り上げて書いてはいけません。**
2. **データ保持とモニタリングを受け入れられますか？** 登録すると、不正利用の監視のためにデータが保持されます。機密・NDA の案件を、この枠では扱わない運用にできますか？
3. **書く内容はすべて事実ですか？** 特に「所属」「実績」「Claude が防御作業を断った例」。
4. **リポジトリは公開（public）ですか？** 審査側が読めること。

---

## 1. Applicant（申請者）

- Name: `[your name]`
- Email: `[your email]`
- Applicant type: `[Individual researcher]` （組織なら `[Organization: name, role]`）
- Country / region: `[ ]`
- Public profile / links: `[GitHub: https://github.com/w-index-m ]` `[other public profiles, if any]`

## 2. Tier requested（希望ティア）

**Defense Access.**
（Red Team Access は組織のみ。本件は Defense の範囲に収まるため、Red Team は申請しない。）

---

## 3. Describe the work and whose systems it covers（作業内容と、対象となるシステム）

**English (推奨・約 200 words)**

> I am an independent security researcher `[at ORGANIZATION, if applicable]`. My work is defensive. I study publicly documented offensive AI-agent tooling —
> Strix, Cairn, Hermes Agent and ARTEX — from the defender's side, and turn the findings into detection content and small exposure-checking tools, published as open source (MIT):
> https://github.com/w-index-m/ai-agent-attack-defense
>
> Concretely: (1) detection rules (Sigma, Falco, Elastic, Datadog) for observable behaviors such as LLM-API egress from servers, privileged container starts, reconnaissance bursts,
> messaging-based C2, persistence, and rapid multi-tool execution, mapped to MITRE ATT&CK; (2) a confirmation-only network exposure checker and a browser-only triage page for scanner output
> (Semgrep, Trivy, gitleaks, SARIF, zgrab2); (3) written analyses of how these tools are structured and where a defender can observe them.
>
> The systems this covers are only systems I own or am explicitly authorized to test: the repository's own code and local, isolated test environments `[add your own lab/hosts accurately]`.
> I do not test third-party or production systems, and I am not requesting Red Team Access. I do not build exploits, attack recipes, or safety-bypass techniques.

日本語の意味: 私は独立の（`[所属があれば記載]`）セキュリティ研究者で、防御目的の仕事をしています。公開されている攻撃用 AI エージェント（Strix / Cairn / Hermes / ARTEX）を防御側から調べ、
検知コンテンツと小さな露出確認ツールにして、オープンソース（MIT）で公開しています。具体的には、(1) 検知ルール（ATT&CK 対応）、(2) 確認専用の露出チェッカーとスキャナ出力のトリアージ画面、(3) これらのツールの構造と
防御側の観測点の解析。対象は、**自分が所有する、または明示的に許可を得たシステムだけ**（リポジトリ自体のコードと、隔離したローカル環境）。第三者や本番のシステムはテストせず、Red Team は申請しません。
攻撃コード・攻撃手順・安全機構の回避は作りません。

**短縮版（文字数制限がある場合・約 60 words）**

> Defensive security researcher. I analyze public offensive AI-agent tools (Strix, Cairn, Hermes, ARTEX) from the defender's side and publish detection rules (Sigma/Falco/Elastic/Datadog, mapped to ATT&CK)
> and confirmation-only exposure/triage tools as open source: https://github.com/w-index-m/ai-agent-attack-defense. Scope: only systems I own or am authorized to test. No exploit or attack-recipe development.

---

## 4. Why you need access / how you would use Claude（なぜ必要か・どう使うか）

> I would use Claude to (a) analyze the source and architecture of offensive security tools in order to identify defender-observable behaviors, (b) draft and review detection rules and their false-positive
> handling, and (c) triage and prioritize scanner and alert output. This work involves dual-use content, which general safeguards can block.
> `[Optional — include only if true: describe specific defensive tasks that Claude declined, and when.]`

日本語の意味: 攻撃ツールのソースと構造を防御目的で解析する、検知ルールの作成とレビュー、スキャナ／アラート出力のトリアージに使いたい。二面性のある内容なので、一般の防護でブロックされうる。
**「断られた具体例」は、実際にあった場合だけ**書く（無ければこの行は削除）。

> 参考：公式によれば、コードレビュー・自分のコードの脆弱性発見・アラートのトリアージは、CVP なしでも一般提供モデルで可能です。**CVP が必要な理由は「断られる作業が実際にあるか」で決まります。**

---

## 5. Track record of reported vulnerabilities（報告済み脆弱性の実績）— 個人は必須

> `[REQUIRED for individual applicants. List real, verifiable items: CVE IDs / GitHub Security Advisories / bug-bounty reports (with public links or program names) / vendor acknowledgements.]`
> `[If you have none, do not apply as an individual yet — see §0.]`

---

## 6. Security controls and responsible-use evidence（統制・責任ある取り扱いの証拠）

> All of the following are in the public repository (https://github.com/w-index-m/ai-agent-attack-defense) and can be verified:
>
> - **Authorized use only, defense scope only.** README, `SECURITY.md` and `CONTRIBUTING.md` state that tools are for owned/authorized targets only and that contributions containing exploit code,
>   attack recipes or safety-bypass techniques are declined.
> - **`netcheck`** (read-only exposure checker): refuses any target outside an allowed range **before** running (private ranges by default), requires an explicit consent each run, serves its UI on localhost only
>   with a per-launch token, caps the number of targets, throttles connections, and logs runs. It performs no exploitation.
> - **`scripts/zgrab2_guard.py`**: an allowlist guard in front of a scanner; it reuses netcheck's range rule, requires an explicit ownership flag, and outputs nothing if any single target is out of range.
> - **Attack-tool analysis policy.** Hermes, ARTEX and zgrab2 were reviewed statically only (nothing built or run). The only things executed were non-attack verifications — a Strix PoC that uses no LLM, run against
>   benign code, and a Cairn mock engine configuration that attacks nothing. Nothing was run against any real target. The analyses explicitly exclude attack recipes and safety-filter removal.
> - **Isolation design.** `security-scan/cairn-lab/cairn-authorized-lab-runbook.md` documents the preconditions, network isolation, egress limits, throwaway/snapshot practice, monitoring and a do-not list for any authorized lab run.
>   It is a design document; I have not run offensive tooling against real targets.
> - **Engineering hygiene.** Semgrep, Trivy and gitleaks run in CI on every pull request; a pre-commit secret scan is configured; no secrets are committed. Detection tags, supported scanners and the rule-coverage matrix
>   are defined once and checked by a CI consistency job.
> - **Application package.** A compiled summary is at `security-scan/cvp-package/cvp-application-package.pdf`.

日本語の意味: 上記はすべて公開リポジトリで確認できる事実。解析ポリシー（Hermes・ARTEX・zgrab2 は静的レビューのみ、実行したのは攻撃を伴わない検証のみ）と、実際の対象への攻撃は行っていないことを明記している。

---

## 7. Data retention acknowledgement（データ保持の了承）

> I understand that data is retained so Anthropic can monitor for cyber misuse, and I accept this. I will not use this access for confidential third-party or NDA-covered material.

日本語の意味: 不正利用の監視のためにデータが保持されることを理解し、了承する。第三者の機密や NDA 対象の資料にはこの枠を使わない。
**これはあなた自身の約束です。** 守れない可能性があるなら、書かないでください。

## 8. Acceptable-use commitments（利用上の約束）

> I will use this access only for defensive work on systems I own or am authorized to test. I will not attempt to cause physical harm or mass disruption, deploy ransomware, damage physical systems,
> or test high-risk safety systems, and I will not try to circumvent safeguards.

---

## 9. 書いてはいけないこと（誇張・虚偽の例）

- 脆弱性報告の実績が無いのに、「実績がある」「研究者として認定されている」と書く。
- 所属組織が無いのに、組織の代表として書く。
- Claude が防御作業を断った例が無いのに、あったと書く。
- 実際の対象に対して攻撃的なテストを行った、と読める書き方（実際は行っていない）。
- 「Anthropic 公認」「標準規格」のような表現（R1–R7 は本リポジトリ独自のラベルです）。

## 10. 提出後

- 審査は **数日を目標**（Defense）。結果が出たら、**組織の管理者がワークスペースにアクセスを割り当てる**必要があります（手順: [Claude Console のサポート記事](https://support.claude.com/en/articles/16764810-assign-a-program-to-workspaces-in-claude-console)）。
- ブロックが誤っていると思ったときの申立て: https://claude.com/form/cyber-block-false-positive-report-cvp-rejection-appeal
