# OSS Scanner への申し込み準備（このリポジトリ）

Anthropic の OSS Scanner（https://red.anthropic.com/oss-scanner/）に、このリポジトリを申し込むための下書きです。
**PR はまだ出していません。** 出す前に、下の「未了・本人の判断」を確認してください。

## 先に知っておくこと（正直に）

- 対象は「インフラやユーザーのセキュリティに重大な影響がある、確立されたプロジェクト」で、外部からの攻撃の受けやすさと、利用者・依存プロジェクトの数が見られます。このリポジトリは防御研究用の小さなツール集なので、**対象にならない可能性があります**。判断は Anthropic 側が 1 件ずつ行います。
- 申し込みでは、重要性を一文で説明することが勧められています（下に下書きあり）。
- 報告は、人のレビューなしのモデル出力で届きます。誤りや過大な重大度が混ざることがあります。
- 申し込みは、利用規約への同意を含みます。

## 用意したもの（このリポジトリ内）

| ファイル | 役割 |
|---|---|
| `Dockerfile` | スキャン用の環境。依存は標準ライブラリのみで、ビルド時に `tools/check_consistency.py` を実行する |
| `.oss-scanner/threat_model.md` | スキャナーへの注意書き（対象、敵対的な入力、範囲外、重大度、報告の形式） |

## `anthropics/oss-scanner` に追加する設定（下書き）

`projects/ai-agent-attack-defense/project.yaml`

```yaml
repo: https://github.com/w-index-m/ai-agent-attack-defense
primary_contact: <連絡先のメールアドレス>   # 本人が記入
homepage: https://github.com/w-index-m/ai-agent-attack-defense
Dockerfile: Dockerfile
# threat_model は既定の .oss-scanner/threat_model.md を使うため省略
```

メールを暗号化したい場合は `pgp:` を追加します（その場合、`auto_ccs` は使えません）。

## 重要性の説明（下書き）

> A defensive toolkit for detecting and reducing exposure to AI-agent-driven attacks: detection rules (Sigma/Falco/Elastic/Datadog), an exposure checker, and a local triage page. The scripts parse untrusted scanner output and probe hosts, so input handling and target-allowlist enforcement are the security-relevant parts.

## 未了・本人の判断

- [ ] `primary_contact` のメールアドレスを決める（ここには書いていません）
- [ ] 利用規約に同意するかを決める
- [ ] `anthropics/oss-scanner` をフォークして PR を出す（出す前に内容を確認してもらいます）
- [ ] `tools/validate.py` で設定を確認する（`anthropics/oss-scanner` のクローンが必要。**未実施**）
- [ ] Dockerfile のビルド確認（**未実施**：このセッションでは Docker のデーモンに接続できなかった。`docker build .` をローカルで実行して確認してください）
