const pptxgen = require("pptxgenjs");
const path = require("path");
const { applyTheme } = require("/mnt/skills/public/pptx/scripts/apply_theme.js");

const THEME = {
  name: "Threat Analysis",
  headFontFace: "Yu Gothic",
  bodyFontFace: "Yu Gothic",
  colors: {
    dk1: "1B1F23", lt1: "FFFFFF", dk2: "2B3A42", lt2: "EEF1F2",
    accent1: "C8431F", accent2: "0F7F76", accent3: "E0A030",
    accent4: "5B6C75", accent5: "7A9E9F", accent6: "B5C0C5",
    hlink: "0F7F76", folHlink: "5B6C75",
  },
};

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
pres.title = "AIエージェント型攻撃ツールの構造と防御";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

const FOOT = "Hermes / Strix / Cairn  構造と防御";

pres.defineSlideMaster({
  title: "TITLE",
  background: { color: C.text2 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 2.0, w: 8.2, h: 2.1, fontSize: 40, bold: true, color: C.background1, align: "left", valign: "top", margin: 0 }, text: "" } },
  ],
});

pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: C.background1 },
  slideNumber: { x: 12.1, y: 7.0, w: 0.6, h: 0.3, fontSize: 10, color: C.accent4, align: "right" },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 12.1, h: 0.9, fontSize: 32, bold: true, color: C.text1, align: "left", valign: "middle", margin: 0 }, text: "" } },
    { text: { text: FOOT, options: { x: 0.6, y: 7.0, w: 8, h: 0.3, fontSize: 10, color: C.accent4, margin: 0 } } },
  ],
});

// ---------- helpers ----------
function txt(s, text, o) {
  s.addText(text, Object.assign({ isTextBox: true, margin: 0, valign: "top", fontSize: 14, color: C.text1 }, o));
}
function bullets(s, items, o) {
  const runs = items.map((t, i) => ({ text: t, options: { bullet: true, breakLine: i < items.length - 1, paraSpaceAfter: 6 } }));
  txt(s, runs, o);
}
function card(s, x, y, w, h, fill, name, line) {
  const opt = { x, y, w, h, fill: { color: fill }, rectRadius: 0.08, objectName: name };
  opt.line = line ? { color: line, width: 1 } : { type: "none" };
  s.addShape(pres.ShapeType.roundRect, opt);
}
function badge(s, label, x, y, d, fill, color, size) {
  s.addText(label, { isTextBox: true, shape: pres.ShapeType.ellipse, x, y, w: d, h: d, fill: { color: fill }, align: "center", valign: "middle", color, bold: true, fontSize: size || 18, margin: 0 });
}
function arrow(s, type, x, y, w, h) {
  s.addShape(pres.ShapeType[type], { x, y, w, h, fill: { color: C.accent4 }, line: { type: "none" } });
}

async function icon(IconComp, hex) {
  const React = require("react");
  const ReactDOMServer = require("react-dom/server");
  const sharp = require("sharp");
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(IconComp, { color: "#" + hex, size: 256 }));
  const buf = await sharp(Buffer.from(svg)).resize(256, 256).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

async function main() {
  const fa = require("react-icons/fa");

  // ===== 1. Title =====
  pres.addSection({ title: "概要" });
  let s = pres.addSlide({ masterName: "TITLE", sectionTitle: "概要" });
  s.addText("AIエージェント型攻撃ツールの構造と防御", { placeholder: "title" });
  txt(s, "Hermes / Strix / Cairn", { x: 0.8, y: 4.3, w: 8.2, h: 0.5, fontSize: 24, color: C.accent3, bold: true });
  txt(s, "Gambit Security報告(2026年9月22日)の整理\n2026年10月6日", { x: 0.8, y: 5.0, w: 8.2, h: 0.9, fontSize: 16, color: C.accent6 });
  const chips = [["Strix", C.accent2, C.background1], ["Cairn", C.accent3, C.text1], ["Hermes", C.accent1, C.background1]];
  chips.forEach((c, i) => {
    badge(s, c[0], 9.9, 1.6 + i * 1.75, 1.5, c[1], c[2], 18);
  });

  // ===== 2. Summary =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "概要" });
  s.addText("要点", { placeholder: "title" });
  const stats = [
    ["27社以上", "侵入を確認", "9/10〜15の5日間で105件の攻撃プロジェクト"],
    ["60万件超", "カード情報が流出", "2社から。うち米国発行は約49万件"],
    ["約$25", "1標的あたりの費用", "$3〜$79。AIモデル利用料の平均"],
  ];
  stats.forEach((st, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.6, 3.9, 2.1, C.background2, "stat-card-" + (i + 1));
    txt(s, st[0], { x: x + 0.3, y: 1.75, w: 3.3, h: 0.85, fontSize: 44, bold: true, color: C.accent1 });
    txt(s, st[1], { x: x + 0.3, y: 2.6, w: 3.3, h: 0.35, fontSize: 16, bold: true });
    txt(s, st[2], { x: x + 0.3, y: 2.98, w: 3.3, h: 0.6, fontSize: 14, color: C.accent4 });
  });
  const msgs = [
    "使われたのは攻撃専用ではなく、公開されている正規のOSSの組み合わせ",
    "人の入力は短い指示のみ(260セッションで1,951プロンプト)",
    "目的はカード情報の窃取。ランサムウェアではない",
  ];
  msgs.forEach((m, i) => {
    const y = 4.05 + i * 0.85;
    card(s, 0.6, y, 12.1, 0.7, C.background2, "message-" + (i + 1));
    badge(s, String(i + 1), 0.8, y + 0.12, 0.46, C.text2, C.background1, 14);
    txt(s, m, { x: 1.5, y: y + 0.1, w: 11, h: 0.5, fontSize: 16, valign: "middle" });
  });

  // ===== 3. Roles =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "概要" });
  s.addText("攻撃連鎖での役割分担", { placeholder: "title" });
  const roles = [
    ["S", "Strix", C.accent2, C.background1, "偵察・脆弱性発見", "公開された診断用ツール。標的に対して深いモードで走査", "GLM 5.2 → DeepSeek v4 Pro"],
    ["C", "Cairn", C.accent3, C.text1, "自律的な侵入", "目標(シェル取得など)を与えられ、数時間かけて自走", "DeepSeek v4.1 Flash"],
    ["H", "Hermes", C.accent1, C.background1, "指揮・侵入後の作業", "全体を指揮し、侵入後の作業や次の指示を出す", "Claude Opus 4.6(新しいモデルに断られた後)"],
  ];
  roles.forEach((r, i) => {
    const x = 0.6 + i * 4.25;
    card(s, x, 1.6, 3.6, 3.95, C.background2, "role-card-" + r[1]);
    badge(s, r[0], x + 0.3, 1.85, 0.75, r[2], r[3], 22);
    txt(s, r[1], { x: x + 1.2, y: 1.85, w: 2.2, h: 0.75, fontSize: 24, bold: true, valign: "middle" });
    txt(s, r[4], { x: x + 0.3, y: 2.9, w: 3.0, h: 0.4, fontSize: 18, bold: true });
    txt(s, r[5], { x: x + 0.3, y: 3.4, w: 3.0, h: 0.9, fontSize: 14 });
    txt(s, "使用モデル(Gambit報告)", { x: x + 0.3, y: 4.4, w: 3.0, h: 0.3, fontSize: 12, color: C.accent4 });
    txt(s, r[6], { x: x + 0.3, y: 4.72, w: 3.0, h: 0.7, fontSize: 14, bold: true });
    if (i < 2) arrow(s, "rightArrow", x + 3.72, 3.3, 0.4, 0.4);
  });
  card(s, 0.6, 5.85, 12.1, 0.85, C.text2, "role-note");
  txt(s, "人の役割は標的と目標を短く指示すること。AIモデルはOpenRouter経由で調達されていた", { x: 0.9, y: 5.85, w: 11.5, h: 0.85, fontSize: 16, color: C.background1, valign: "middle" });

  // ===== 4. Strix =====
  pres.addSection({ title: "ツールの構造" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("Strix:診断用AIエージェント", { placeholder: "title" });
  card(s, 0.6, 1.6, 3.6, 4.85, C.background2, "strix-profile");
  badge(s, "S", 0.9, 1.85, 0.7, C.accent2, C.background1, 20);
  txt(s, "usestrix/strix", { x: 1.75, y: 1.85, w: 2.3, h: 0.7, fontSize: 16, bold: true, valign: "middle" });
  bullets(s, ["Apache-2.0", "GitHub 6.5万スター超", "本来の用途:自社アプリの脆弱性を見つけて直す", "公式の注意:許可された対象にのみ使用"], { x: 0.9, y: 2.85, w: 3.0, h: 3.4, fontSize: 14 });
  const strixRows = [
    ["入口", "CLI / TUI / GitHub Actions(PRごとの診断)"],
    ["エージェント層", "Graph of Agents:複数のエージェントが発見を共有し分担"],
    ["実行環境", "Dockerサンドボックス内にHTTPプロキシ・ブラウザ・ターミナル・Pythonランタイム・偵察ツール"],
    ["頭脳", "LiteLLM経由で任意のLLMを選択。スキル(知識パック)とMCP連携"],
    ["出力", "PoC付きの検証済み指摘、レポート、修正パッチ案"],
  ];
  strixRows.forEach((r, i) => {
    const y = 1.6 + i * 1.0;
    card(s, 4.5, y, 2.1, 0.85, C.accent2, "strix-layer-label-" + (i + 1));
    txt(s, r[0], { x: 4.5, y, w: 2.1, h: 0.85, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
    card(s, 6.7, y, 6.0, 0.85, C.background2, "strix-layer-body-" + (i + 1));
    txt(s, r[1], { x: 6.9, y, w: 5.65, h: 0.85, fontSize: 14, valign: "middle" });
  });
  txt(s, "出典:リポジトリのREADME・AGENTS.md", { x: 4.5, y: 6.6, w: 8, h: 0.3, fontSize: 10, color: C.accent4 });

  // ===== 5. Cairn =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("Cairn:共有ボード型の自律探索", { placeholder: "title" });
  // diagram
  card(s, 0.6, 1.6, 6.4, 1.2, C.accent3, "cairn-server");
  txt(s, "Cairn Server\nFact / Intent / Hint を持つ共有ボード", { x: 0.6, y: 1.6, w: 6.4, h: 1.2, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 3.6, 2.9, 0.4, 0.35);
  card(s, 0.6, 3.35, 6.4, 1.0, C.text2, "cairn-dispatcher");
  txt(s, "Dispatcher\nタスク配分・コンテナ管理・ボードへの唯一の書き手", { x: 0.6, y: 3.35, w: 6.4, h: 1.0, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 3.6, 4.45, 0.4, 0.35);
  [0, 1].forEach((i) => {
    const x = 0.6 + i * 3.3;
    card(s, x, 4.9, 3.1, 1.7, C.background2, "cairn-worker-" + (i + 1));
    txt(s, i === 0 ? "Worker Container\n(案件A)" : "Worker Container\n(案件B)", { x, y: 4.95, w: 3.1, h: 0.7, fontSize: 14, bold: true, align: "center" });
    badge(s, "W", x + 0.7, 5.75, 0.6, C.accent6, C.text1, 14);
    badge(s, "W", x + 1.8, 5.75, 0.6, C.accent6, C.text1, 14);
  });
  // concepts
  const concepts = [["Fact", "確認済みの事実"], ["Intent", "未実行の探索方向"], ["Hint", "人が随時入れる助言"]];
  concepts.forEach((c, i) => {
    const y = 1.6 + i * 0.8;
    card(s, 7.4, y, 5.3, 0.65, C.background2, "cairn-concept-" + c[0]);
    txt(s, c[0], { x: 7.6, y, w: 1.4, h: 0.65, fontSize: 16, bold: true, color: C.accent1, valign: "middle" });
    txt(s, c[1], { x: 9.0, y, w: 3.5, h: 0.65, fontSize: 14, valign: "middle" });
  });
  bullets(s, [
    "Workerに固定の役割はなく、観察→判断→実行のループで次の探索を決める",
    "Workerは共有ボード経由でのみ連携",
    "実行基盤:Claude Code / Codex / Pi",
    "AGPL-3.0、GitHub 3,200スター。Tencentのハッカソンで54/54問を解き3位",
  ], { x: 7.4, y: 4.1, w: 5.3, h: 2.6, fontSize: 14 });

  // ===== 6. Hermes =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("Hermes:自己成長型の汎用エージェント", { placeholder: "title" });
  const hf = [
    ["学習ループ", "経験からスキルを自動作成し、使いながら改善"],
    ["永続メモリ", "過去の会話をFTS5で検索し、利用者像も蓄積"],
    ["Gateway", "Telegram・Discord・Slackなどから1つのプロセスで操作"],
    ["定時実行(cron)", "自然言語で登録した作業を無人で実行"],
    ["サブエージェント", "隔離した子エージェントを並列に走らせる"],
    ["実行基盤×7種", "local・Docker・SSH・Singularity・Modal・Daytona・Vercel Sandbox"],
  ];
  hf.forEach((f, i) => {
    const x = 0.6 + (i % 3) * 2.725;
    const y = 1.6 + Math.floor(i / 3) * 2.15;
    card(s, x, y, 2.55, 2.0, C.background2, "hermes-feature-" + (i + 1));
    txt(s, f[0], { x: x + 0.2, y: y + 0.2, w: 2.15, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
    txt(s, f[1], { x: x + 0.2, y: y + 0.7, w: 2.15, h: 1.2, fontSize: 14 });
  });
  card(s, 8.9, 1.6, 3.8, 4.15, C.text2, "hermes-abuse");
  txt(s, "今回の悪用(Gambit報告)", { x: 9.15, y: 1.8, w: 3.3, h: 0.4, fontSize: 16, bold: true, color: C.accent3 });
  bullets(s, [
    "人格設定「Red Team Operator」を読み込み",
    "121スキルのうち78が攻撃用",
    "Hermes自身の安全フィルターを外すスキルを追加",
    "モデルに断られると別モデルへ切替",
  ], { x: 9.15, y: 2.4, w: 3.3, h: 3.2, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.05, 12.1, 0.65, C.background2, "hermes-banner");
  txt(s, "MIT  /  GitHub 25万スター  /  40以上のツール  /  MCP対応  /  任意のモデルに切替可能", { x: 0.6, y: 6.05, w: 12.1, h: 0.65, fontSize: 14, bold: true, align: "center", valign: "middle" });

  // ===== 6b. Cairn loop: probing step by step =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("Cairnは様子を見ながら試す", { placeholder: "title" });
  [
    ["観察", "共有ボードのこれまでの事実を読む"],
    ["判断", "次に探る方向を決める"],
    ["実行", "その方向を1つ試す"],
    ["記録", "結果を事実としてボードに書く"],
  ].forEach((f, i) => {
    const x = 0.6 + i * 3.1;
    card(s, x, 1.55, 2.8, 2.0, C.background2, "loop-step-" + (i + 1));
    badge(s, String(i + 1), x + 0.25, 1.75, 0.5, C.accent3, C.text1, 16);
    txt(s, f[0], { x: x + 0.95, y: 1.75, w: 1.7, h: 0.5, fontSize: 18, bold: true, valign: "middle" });
    txt(s, f[1], { x: x + 0.25, y: 2.5, w: 2.35, h: 0.95, fontSize: 14 });
    if (i < 3) arrow(s, "rightArrow", x + 2.84, 2.4, 0.22, 0.3);
  });
  card(s, 0.6, 3.7, 12.1, 0.5, C.text2, "loop-return");
  txt(s, "記録した結果を踏まえて、また観察へ戻る。目標を達成するか、時間切れになるまで繰り返す", { x: 0.6, y: 3.7, w: 12.1, h: 0.5, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
  card(s, 0.6, 4.4, 5.9, 2.35, C.background2, "loop-example");
  txt(s, "例:Gambit報告の1案件", { x: 0.9, y: 4.55, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
  txt(s, "ログイン画面の欠陥 → 管理画面 → ファイルの設置 → root権限 → クラウドの鍵 → カード情報", { x: 0.9, y: 5.1, w: 5.3, h: 1.5, fontSize: 14 });
  card(s, 6.8, 4.4, 5.9, 2.35, C.background1, "loop-meaning", C.accent2);
  txt(s, "ここから分かること", { x: 7.1, y: 4.55, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  bullets(s, [
    "結果を見て次を決めるので、経路は被害企業ごとに違う",
    "1つの対策だけでは連鎖を止めきれない",
    "人はヒントを入れられるが、大半は自走する",
  ], { x: 7.1, y: 5.05, w: 5.3, h: 1.6, fontSize: 14 });

  // ===== 6c. Hermes internals =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("Hermesの内部構造", { placeholder: "title" });
  card(s, 0.6, 1.5, 12.1, 0.75, C.text2, "hermes-entry");
  txt(s, "入口:ターミナル(CLI)、チャット連携(Telegram・Slack・Discordなど)", { x: 0.6, y: 1.5, w: 12.1, h: 0.75, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 6.5, 2.28, 0.3, 0.22);
  card(s, 0.6, 2.55, 12.1, 1.0, C.accent1, "hermes-loop");
  txt(s, "AIAgent(run_agent.py)\nモデルに問い合わせ、道具を使い、結果を見る。これを道具が不要になるまで繰り返す", { x: 0.6, y: 2.55, w: 12.1, h: 1.0, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 6.5, 3.58, 0.3, 0.22);
  [
    ["ツール", "70以上。各ファイルが自分を登録するので追加が容易"],
    ["スキル", "SKILL.mdの手順書。会話に差し込み、経験から自動生成も"],
    ["記憶", "会話をSQLiteに保存し、全文検索で過去を引く"],
    ["実行環境", "local・Docker・SSHなど7種。コマンドはここで動く"],
  ].forEach((c, i) => {
    const x = 0.6 + i * 3.06;
    card(s, x, 3.85, 2.9, 2.0, C.background2, "hermes-part-" + (i + 1));
    txt(s, c[0], { x: x + 0.25, y: 4.0, w: 2.4, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
    txt(s, c[1], { x: x + 0.25, y: 4.5, w: 2.4, h: 1.25, fontSize: 14 });
  });
  card(s, 0.6, 6.05, 12.1, 0.65, C.background2, "hermes-provider");
  txt(s, "モデル提供元:OpenRouter、OpenAI、Anthropicなど18以上から切り替え可能", { x: 0.6, y: 6.05, w: 12.1, h: 0.65, fontSize: 14, bold: true, align: "center", valign: "middle" });

  // ===== 6d. Hermes safety and limits =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("Hermesの安全策とその限界", { placeholder: "title" });
  card(s, 0.6, 1.5, 5.9, 4.4, C.background2, "safety-built-in");
  txt(s, "標準の安全策", { x: 0.9, y: 1.7, w: 5.3, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "危険なコマンドは、補助のAIが評価する承認(既定は「smart」)",
    "システム全体を消すような一部の操作は、常に拒否",
    "SSH鍵やクラウドの認証情報の書き換えを保護",
    "チャットの利用者は、許可リストとペアリングコードで制限",
  ], { x: 0.9, y: 2.3, w: 5.3, h: 3.5, fontSize: 14 });
  card(s, 6.8, 1.5, 5.9, 4.4, C.text2, "safety-limits");
  txt(s, "限界(今回の悪用につながった点)", { x: 7.1, y: 1.7, w: 5.3, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "承認の方式は、運用者が設定で変えられる",
    "Dockerで動かすと、承認の確認は省かれる(コンテナを境界とみなす設計)",
    "手元で動くOSSなので、運用者が手を加えられる。Gambit:安全フィルターを外すスキルを追加",
    "最後のブレーキはLLM提供元の拒否。今回は拒否されると別モデルに切り替えた",
  ], { x: 7.1, y: 2.3, w: 5.3, h: 3.5, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.1, 12.1, 0.65, C.accent3, "safety-takeaway");
  txt(s, "ツール側の安全策だけでは悪用を防げない。標的側の対策が必要", { x: 0.6, y: 6.1, w: 12.1, h: 0.65, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 7. Common patterns =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "ツールの構造" });
  s.addText("3つに共通する設計", { placeholder: "title" });
  const pats = [
    [fa.FaBullseye, "目標だけ与える", "人は短い指示を出すだけ", "人のペースを前提にした検知・対応は追いつかない"],
    [fa.FaSyncAlt, "疲れず試行を続ける", "自走ループで数時間探索", "小規模・低知名度のサイトも標的になる(1標的約$25)"],
    [fa.FaProjectDiagram, "並列で大量に実行", "コンテナやサブエージェントで同時進行", "手動の監視では間に合わず、自動の検知・遮断が要る"],
    [fa.FaBrain, "経験を蓄積する", "スキルやメモリとして手口を再利用", "ある企業で通じた手口が他社でも再利用される"],
  ];
  for (let i = 0; i < pats.length; i++) {
    const y = 1.6 + i * 1.25;
    const p = pats[i];
    card(s, 0.6, y, 12.1, 1.1, C.background2, "pattern-row-" + (i + 1));
    s.addShape(pres.ShapeType.ellipse, { x: 0.85, y: y + 0.2, w: 0.7, h: 0.7, fill: { color: C.text2 }, line: { type: "none" }, objectName: "pattern-icon-bg-" + (i + 1) });
    s.addImage({ data: await icon(p[0], "FFFFFF"), x: 1.02, y: y + 0.37, w: 0.36, h: 0.36, altText: p[1] });
    txt(s, p[1], { x: 1.8, y: y + 0.18, w: 4.2, h: 0.4, fontSize: 18, bold: true });
    txt(s, p[2], { x: 1.8, y: y + 0.62, w: 4.2, h: 0.35, fontSize: 14, color: C.accent4 });
    arrow(s, "rightArrow", 6.2, y + 0.38, 0.4, 0.34);
    txt(s, p[3], { x: 6.85, y, w: 5.65, h: 1.1, fontSize: 16, bold: true, valign: "middle" });
  }

  // ===== 8. Break the chain =====
  pres.addSection({ title: "防御" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("侵入の連鎖を断つ", { placeholder: "title" });
  txt(s, "連鎖の例(Gambit報告の1件)", { x: 0.6, y: 1.5, w: 5.6, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
  txt(s, "断つための対策", { x: 6.9, y: 1.5, w: 5.8, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  const chain = [
    ["ログイン画面のSQLインジェクション", "プレースホルダ(パラメータ化クエリ)を徹底"],
    ["OTPがDBに平文で保存(MFA回避)", "OTPはハッシュ化し、短時間で失効"],
    ["管理画面のアップロードに拡張子検証なし", "拡張子と内容を検証し、公開領域外に保存"],
    ["sudoがパスワードなしで実行可", "NOPASSWDを廃止し、最小権限に"],
    ["NFS設定不備と、設定ファイル内の認証情報", "no_root_squash回避、設定ファイルに秘密情報を置かない"],
    ["Secrets Managerの全件取得", "IAMを最小権限にし、大量取得を検知"],
    ["カード番号の暗号鍵が同じ環境から取得可", "決済代行のトークン化でカード番号を持たない"],
  ];
  chain.forEach((r, i) => {
    const y = 2.0 + i * 0.68;
    card(s, 0.6, y, 5.9, 0.58, C.background2, "chain-step-" + (i + 1));
    txt(s, r[0], { x: 0.8, y, w: 5.55, h: 0.58, fontSize: 14, valign: "middle" });
    arrow(s, "rightArrow", 6.6, y + 0.14, 0.2, 0.3);
    card(s, 6.9, y, 5.8, 0.58, C.background1, "chain-fix-" + (i + 1), C.accent2);
    txt(s, r[1], { x: 7.05, y, w: 5.55, h: 0.58, fontSize: 14, valign: "middle" });
  });

  // ===== 9. Checkout page =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("決済ページを守る", { placeholder: "title" });
  card(s, 0.6, 1.6, 5.8, 5.1, C.background2, "skimmer-routes");
  txt(s, "スキマーの設置経路(Gambit報告)", { x: 0.9, y: 1.8, w: 5.2, h: 0.4, fontSize: 18, bold: true, color: C.accent1 });
  bullets(s, [
    "既存JS(jQueryなど)の末尾に1行追記し、更新日時も偽装",
    "チェックアウトページに外部scriptタグを追加",
    "Googleタグの記述内に隠蔽",
    "CDN用S3バケットを書き換え",
    "DBの商品説明欄に混入",
    "Kubernetesのinitcontainerに混入",
    "ページキャッシュを汚染",
    "削除されても再注入するcronを設置",
  ], { x: 0.9, y: 2.4, w: 5.2, h: 4.2, fontSize: 14 });
  card(s, 6.7, 1.6, 6.0, 5.1, C.background1, "skimmer-defense", C.accent2);
  txt(s, "対策", { x: 7.0, y: 1.8, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "CSPで script-src を許可リスト化",
    "SRIでスクリプトの改ざんを検知",
    "配信中のJSハッシュを、ビルド成果物と定期照合",
    "決済はホステッドフィールドやiframeで自社JSから分離",
    "ページ上のスクリプト一覧を定期的に棚卸し",
    "S3/CDNの書込権限を絞り、変更を通知",
    "cron・K8sマニフェスト・キャッシュの変更を監査",
  ], { x: 7.0, y: 2.4, w: 5.4, h: 4.2, fontSize: 14 });

  // ===== 9b. Payment method decides the defense =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("自社の決済方式で、守り方が変わる", { placeholder: "title" });
  [
    ["A", "ホスト型決済ページ", "決済代行のページへ移動する方式", "リスク:低", C.accent2, C.background1, [
      "カード番号は自社サイトを通らない",
      "契約や設定の変更で移行できることが多い",
      "PCI対応の負担も最も小さい",
    ]],
    ["B", "埋め込み型", "iframeやホステッドフィールドで入力欄だけ表示", "リスク:中", C.accent3, C.text1, [
      "入力欄は決済代行が表示する",
      "自社ページが改ざんされると、周辺を書き換えられる",
      "スクリプト管理と改ざん検知が必要になることがある",
    ]],
    ["C", "自社フォームで受ける", "カード番号を自社サーバーで受け取る方式", "リスク:高", C.accent1, C.background1, [
      "スキマーの主な標的になる",
      "可能ならAかBへの移行を最優先にする",
      "移行までは、次ページの強化策をすべて実施",
    ]],
  ].forEach((c, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.5, 3.9, 4.5, C.background2, "method-card-" + c[0]);
    badge(s, c[0], x + 0.25, 1.7, 0.6, c[4], c[5], 18);
    txt(s, c[1], { x: x + 1.05, y: 1.7, w: 2.7, h: 0.6, fontSize: 16, bold: true, valign: "middle" });
    txt(s, c[2], { x: x + 0.3, y: 2.5, w: 3.3, h: 0.6, fontSize: 12, color: C.accent4 });
    card(s, x + 0.3, 3.15, 1.4, 0.4, c[4], "method-risk-" + c[0]);
    txt(s, c[3], { x: x + 0.3, y: 3.15, w: 1.4, h: 0.4, fontSize: 14, bold: true, color: c[5], align: "center", valign: "middle" });
    bullets(s, c[6], { x: x + 0.3, y: 3.8, w: 3.35, h: 2.1, fontSize: 14 });
  });
  card(s, 0.6, 6.15, 12.1, 0.6, C.text2, "method-note");
  txt(s, "まず今の方式を確認する。PCIの適用範囲は、決済代行やカード会社にも確認する", { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });

  // ===== 9c. Settings that strengthen the checkout page =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("設定でできる決済ページの強化(優先順)", { placeholder: "title" });
  [
    ["1 決済方式を見直す", "AまたはBへ。契約や設定の変更で足りることが多い"],
    ["2 CSPを入れる", "まずReport-Onlyで読込元を観測し、許可リストにしてから強制に切り替える"],
    ["3 SRIを付ける", "自社配信の固定JSが対象。頻繁に変わる外部スクリプトには不向き"],
    ["4 タグを減らす", "決済ページに載せるスクリプトと、広告・計測タグを最小限にする"],
    ["5 変更を監視する", "スクリプトの追加・変更を通知する。Cloudflareは無料でスクリプト監視、変更検知は上位プラン"],
    ["6 設定の変更も監視", "CSPの書き換え自体もリスク。変更履歴を残して通知する"],
  ].forEach((r, i) => {
    const y = 1.5 + i * 0.76;
    card(s, 0.6, y, 3.0, 0.66, C.accent2, "setting-label-" + (i + 1));
    txt(s, r[0], { x: 0.6, y, w: 3.0, h: 0.66, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
    card(s, 3.7, y, 9.0, 0.66, C.background2, "setting-body-" + (i + 1));
    txt(s, r[1], { x: 3.95, y, w: 8.6, h: 0.66, fontSize: 14, valign: "middle" });
  });
  card(s, 0.6, 6.15, 12.1, 0.6, C.accent3, "setting-note");
  txt(s, "CSPとSRIだけでは不十分。継続的な監視と組み合わせる", { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 10. Self-test =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("先に自社を診断する", { placeholder: "title" });
  const steps = [
    "書面で許可と範囲を決める",
    "まずステージング環境で診断する",
    "PRごとの簡易診断をCI/CDに組み込む",
    "検出→修正→再テストを回す",
    "本番は範囲・時間帯・予算上限を決めて実施",
  ];
  steps.forEach((t, i) => {
    const y = 1.6 + i * 1.0;
    card(s, 0.6, y, 7.4, 0.85, C.background2, "selftest-step-" + (i + 1));
    badge(s, String(i + 1), 0.8, y + 0.15, 0.55, C.accent2, C.background1, 16);
    txt(s, t, { x: 1.6, y, w: 6.2, h: 0.85, fontSize: 16, valign: "middle" });
  });
  card(s, 8.3, 1.6, 4.4, 4.85, C.text2, "selftest-caution");
  txt(s, "運用上の注意", { x: 8.55, y: 1.8, w: 3.9, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "許可を得た対象にのみ実行する",
    "コードや認証情報がLLM提供元へ送られる点を確認",
    "AIが破壊的操作をする恐れ。Gambit事例では180テーブルが誤削除",
    "実行前にバックアップを取り、書込・削除系を制限",
  ], { x: 8.55, y: 2.4, w: 3.9, h: 3.9, fontSize: 14, color: C.background1 });

  // ===== 11. Recovery & detection =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("復旧力と検知", { placeholder: "title" });
  card(s, 0.6, 1.6, 5.9, 5.1, C.background2, "recovery-card");
  s.addImage({ data: await icon(fa.FaUndo, "0F7F76"), x: 0.9, y: 1.85, w: 0.4, h: 0.4, altText: "復旧" });
  txt(s, "復旧力", { x: 1.45, y: 1.8, w: 4.5, h: 0.5, fontSize: 20, bold: true, valign: "middle" });
  bullets(s, [
    "バックアップは本番と別アカウントに隔離し、削除不可にする",
    "事業継続に最低限必要なシステム群を定義する",
    "「DBを戻す」で終わらず、サービス再開までの復旧を訓練する",
  ], { x: 0.9, y: 2.6, w: 5.3, h: 3.9, fontSize: 16 });
  card(s, 6.8, 1.6, 5.9, 5.1, C.background2, "detection-card");
  s.addImage({ data: await icon(fa.FaSearch, "C8431F"), x: 7.1, y: 1.85, w: 0.4, h: 0.4, altText: "検知" });
  txt(s, "検知と対応", { x: 7.65, y: 1.8, w: 4.5, h: 0.5, fontSize: 20, bold: true, valign: "middle" });
  bullets(s, [
    "管理画面への新規ログイン、新規管理者、想定外のアップロード",
    "短時間の大量アクセスにレート制限・ボット対策",
    "外向きの不審なDNS/HTTP通信",
    "Gambit公開のIOC(不審ドメイン・IP)と照合",
    "機械の速さで動く自動隔離・自動対応",
  ], { x: 7.1, y: 2.6, w: 5.3, h: 3.9, fontSize: 14 });

  // ===== 10b. AI tools for vulnerability checks =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("脆弱性を調べるAI・LLMツール", { placeholder: "title" });
  [
    ["動いているアプリを、攻撃者の目線で診断", "例:Strix(オープンソース)", "ステージングで実行。PRごとのCI診断にも対応し、再現手順つきで報告"],
    ["ソースコードを読んで、指摘と修正案を出す", "例:GitHub Copilot Autofix、Semgrep、Snyk、Claude Security", "AI搭載のコード診断。機能や料金は各社で要確認(今回は個別に検証していません)"],
    ["決済ページのスクリプトを監視する", "例:Cloudflare Client-side Security", "LLMではなく専用の監視サービス。診断ツールと併用する"],
  ].forEach((r, i) => {
    const y = 1.5 + i * 1.55;
    card(s, 0.6, y, 7.6, 1.4, C.background2, "tool-row-" + (i + 1));
    txt(s, r[0], { x: 0.85, y: y + 0.12, w: 7.1, h: 0.35, fontSize: 16, bold: true });
    txt(s, r[1], { x: 0.85, y: y + 0.5, w: 7.1, h: 0.3, fontSize: 14, bold: true, color: C.accent2 });
    txt(s, r[2], { x: 0.85, y: y + 0.85, w: 7.1, h: 0.5, fontSize: 14, color: C.accent4 });
  });
  card(s, 8.5, 1.5, 4.2, 4.5, C.text2, "tool-caution");
  txt(s, "使うときの注意", { x: 8.75, y: 1.7, w: 3.7, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "許可を得た環境にだけ使う",
    "コードや認証情報がLLM提供元へ送られる点を確認する",
    "AIの指摘には誤検知も見逃しもある。人が確認する",
    "診断だけでは直らない。修正と再診断まで回す",
  ], { x: 8.75, y: 2.3, w: 3.7, h: 3.6, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.15, 12.1, 0.6, C.accent3, "tool-note");
  txt(s, "AIは、見つけて直すための補助。最終判断は人が行う", { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 10c. After the scan =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("診断結果が出たら:対処の手順", { placeholder: "title" });
  [
    ["重大度で分ける", "カード・認証・管理画面に関わるものを最優先にする"],
    ["塞げないものは一時対処", "WAFのルール追加、機能の一時停止、アクセス制限"],
    ["根本から修正する", "プレースホルダ、アップロード検証など、前述の連鎖対策"],
    ["再診断して確認する", "同じツールで再実行し、直ったことを確かめる"],
    ["仕組みにして再発を防ぐ", "PRごとの自動診断に組み込む"],
  ].forEach((t, i) => {
    const y = 1.5 + i * 1.0;
    card(s, 0.6, y, 7.6, 0.85, C.background2, "after-step-" + (i + 1));
    badge(s, String(i + 1), 0.8, y + 0.15, 0.55, C.accent2, C.background1, 16);
    txt(s, t[0], { x: 1.6, y: y + 0.1, w: 6.4, h: 0.35, fontSize: 16, bold: true });
    txt(s, t[1], { x: 1.6, y: y + 0.47, w: 6.4, h: 0.3, fontSize: 14, color: C.accent4 });
  });
  card(s, 8.5, 1.5, 4.2, 4.85, C.text2, "after-points");
  txt(s, "ポイント", { x: 8.75, y: 1.7, w: 3.7, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "AIの診断は入口。修正の最終判断は人が行う",
    "本番での診断は、範囲・時間・予算を決めて行う",
    "実行前にバックアップを取る",
  ], { x: 8.75, y: 2.3, w: 3.7, h: 3.9, fontSize: 14, color: C.background1 });

  // ===== 10d. What tools can and cannot find =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("ツールで見つけられるものと、別の対策が要るもの", { placeholder: "title" });
  card(s, 0.6, 1.5, 5.95, 4.4, C.background2, "find-yes");
  txt(s, "診断ツール(Strixなど)で見つけやすい", { x: 0.9, y: 1.7, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "SQLインジェクションなど、入力処理の欠陥",
    "アップロード検証の不備",
    "ログインやOTPの設計上の弱点",
    "公開されたままの管理画面、設定の不備",
  ], { x: 0.9, y: 2.3, w: 5.4, h: 3.5, fontSize: 14 });
  card(s, 6.75, 1.5, 5.95, 4.4, C.text2, "find-no");
  txt(s, "診断では見つけにくい。別の対策が必要", { x: 7.05, y: 1.7, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "すでに仕込まれたスキマー(改ざんの監視が必要)",
    "社内の権限設計(sudo、NFS、クラウドの鍵)は、診断の範囲と許可に左右される",
    "バックアップと復旧体制",
    "決済方式そのもの(設計の見直し)",
  ], { x: 7.05, y: 2.3, w: 5.4, h: 3.5, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.1, 12.1, 0.65, C.accent3, "find-note");
  txt(s, "Strixを先に回せば、入口の欠陥はかなり減らせる可能性がある。ただし今回の事例での効果を検証した報告はなく、これだけでは足りない", { x: 0.8, y: 6.1, w: 11.7, h: 0.65, fontSize: 14, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 11b. Concrete actions =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("事前にやっておくべきだった対処", { placeholder: "title" });
  const acts = [
    ["決済ページ", ["CSPで読込元を自社と決済代行に限定", "全scriptタグにSRIを付ける", "決済は代行業者のiframeに任せる"]],
    ["配信ファイル", ["Webルートをアプリから書込不可に", "デプロイ時のJSハッシュを毎時照合", "差異があれば即座に通知"]],
    ["コード", ["SQLはプレースホルダのみ使用", "アップロードは拡張子を許可制に", "保存先は公開領域の外に置く"]],
    ["認証と管理画面", ["OTPはハッシュ保存、5分で失効", "試行回数を制限し、超過でロック", "管理画面はVPNかIP制限の内側に"]],
    ["サーバとクラウド", ["sudoersのNOPASSWDを削除", "NFSでno_root_squashを使わない", "Secretsは用途別に最小権限で許可"]],
    ["備えと検知", ["バックアップを別アカウントへ複製", "削除不可設定(Object Lock等)", "新規管理者作成と鍵の大量取得を通知"]],
  ];
  acts.forEach((a, i) => {
    const x = 0.6 + (i % 3) * 4.1;
    const y = 1.5 + Math.floor(i / 3) * 2.7;
    card(s, x, y, 3.9, 2.55, C.background2, "action-card-" + (i + 1));
    badge(s, String(i + 1), x + 0.25, y + 0.2, 0.45, C.accent2, C.background1, 14);
    txt(s, a[0], { x: x + 0.85, y: y + 0.2, w: 2.85, h: 0.45, fontSize: 16, bold: true, valign: "middle" });
    bullets(s, a[1], { x: x + 0.3, y: y + 0.85, w: 3.35, h: 1.6, fontSize: 14 });
  });

  // ===== 12. Roadmap =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "防御" });
  s.addText("優先度ロードマップ", { placeholder: "title" });
  const road = [
    ["今週", C.accent1, C.background1, ["決済ページのスクリプトを棚卸しし、CSP・SRIを導入", "管理画面の公開範囲とMFAを確認", "Gambit公開のIOCを照合", "バックアップの分離状況を確認"]],
    ["今月", C.accent3, C.text1, ["ステージングでAI診断を実施", "SQLi・アップロードなど既知パターンを修正", "IAM・sudo・秘密情報を棚卸し"]],
    ["四半期", C.accent2, C.background1, ["カード情報のトークン化", "CI/CDに自動診断を組み込み", "最小事業単位での復旧訓練", "自動検知・自動対応の整備"]],
  ];
  road.forEach((r, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.6, 3.9, 5.1, C.background2, "roadmap-col-" + (i + 1));
    card(s, x + 0.25, 1.85, 1.6, 0.55, r[1], "roadmap-chip-" + (i + 1));
    txt(s, r[0], { x: x + 0.25, y: 1.85, w: 1.6, h: 0.55, fontSize: 16, bold: true, color: r[2], align: "center", valign: "middle" });
    bullets(s, r[3], { x: x + 0.3, y: 2.7, w: 3.35, h: 3.9, fontSize: 14 });
  });

  // ===== 12b. How to read the numbers =====
  pres.addSection({ title: "まとめ" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "まとめ" });
  s.addText("数字の見方と報道の論点", { placeholder: "title" });
  const nums = [
    ["60万件超", "盗まれたカード情報(2社)。米国発行は488,372件(79%)"],
    ["27社", "Gambitが名指しした標的企業"],
    ["19社", "27社のうち、スキマー設置を確認できた企業"],
    ["119サイト", "BleepingComputerの数。19社に加え、別に100超のサイトで感染を検出"],
  ];
  nums.forEach((n, i) => {
    const y = 1.6 + i * 1.28;
    card(s, 0.6, y, 6.3, 1.12, C.background2, "number-card-" + (i + 1));
    txt(s, n[0], { x: 0.85, y, w: 2.5, h: 1.12, fontSize: 28, bold: true, color: C.accent1, valign: "middle" });
    txt(s, n[1], { x: 3.4, y, w: 3.35, h: 1.12, fontSize: 14, valign: "middle" });
  });
  card(s, 7.2, 1.6, 5.5, 5.0, C.background1, "rw-card", C.accent6);
  txt(s, "RuntimeWireの論点", { x: 7.5, y: 1.8, w: 4.9, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "Gambitは自社製品が扱う問題を実証する立場で、利益相反の可能性がある",
    "数は直接証拠・実在確認・エージェントのログの混合で、完全な集計ではない",
    "暫定報告で、実際の規模はより大きい可能性がある",
    "被害企業名と最終的な感染サイト数は未公表",
    "示唆:バックアップの有無でなく、復旧できるか・どれだけ速いか・いくらかかるかを測る",
  ], { x: 7.5, y: 2.4, w: 4.9, h: 4.1, fontSize: 14 });

  // ===== 12c. Three sources compared =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "まとめ" });
  s.addText("3つの情報源の違い", { placeholder: "title" });
  [
    ["G", "Gambit Security", "一次情報(原文)", C.accent2, C.background1, [
      "攻撃基盤サーバーの回収をもとに再構築",
      "侵入の連鎖、スキマーの設置方法、IOCを掲載",
      "証拠は3区分:サーバー上の直接証拠、実在確認、AIのログ",
    ]],
    ["B", "BleepingComputer", "報道による要約と周知", C.accent3, C.text1, [
      "119サイトの感染を報道(Gambitは19社+100超)",
      "Cairnは、Cisco Talosが前日公開した同名のAI解析ツールとは別物と注記",
      "低コスト化で参入障壁が下がると警告",
      "防御策の追加はなし",
    ]],
    ["R", "RuntimeWire", "数字の整理と批評", C.accent1, C.background1, [
      "27社・19社・119サイトの関係を整理",
      "Gambitの立場と、報告が暫定である点を指摘",
      "復旧できるか、速さ、費用を測るべきと提言",
    ]],
  ].forEach((c, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.6, 3.9, 4.4, C.background2, "source-card-" + (i + 1));
    badge(s, c[0], x + 0.25, 1.85, 0.6, c[3], c[4], 18);
    txt(s, c[1], { x: x + 1.05, y: 1.85, w: 2.7, h: 0.35, fontSize: 16, bold: true });
    txt(s, c[2], { x: x + 1.05, y: 2.22, w: 2.7, h: 0.3, fontSize: 12, color: C.accent4 });
    bullets(s, c[5], { x: x + 0.3, y: 2.85, w: 3.35, h: 3.0, fontSize: 14 });
  });
  card(s, 0.6, 6.15, 12.1, 0.6, C.text2, "source-note");
  txt(s, "3つとも出発点はGambitの調査。独立した裏付け調査ではない点に注意", { x: 0.9, y: 6.15, w: 11.5, h: 0.6, fontSize: 14, bold: true, color: C.background1, valign: "middle" });

  // ===== 13. Limits & sources =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "まとめ" });
  s.addText("この資料の限界と出典", { placeholder: "title" });
  card(s, 0.6, 1.6, 6.0, 5.1, C.background2, "limits-card");
  txt(s, "限界", { x: 0.9, y: 1.8, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent1 });
  bullets(s, [
    "調査範囲は3リポジトリのREADME・AGENTS.mdと公開レポート。ソースコードの実行・解析はしていない",
    "Gambitは防御製品のベンダーで、結論に立場が反映されうる",
    "119サイト(BleepingComputer)はスキマー感染サイト数。27社・19社(Gambit)とは別の集計",
    "AIのログや主張には未検証の部分がある",
  ], { x: 0.9, y: 2.4, w: 5.4, h: 4.2, fontSize: 14 });
  card(s, 6.9, 1.6, 5.8, 5.1, C.background1, "sources-card", C.accent6);
  txt(s, "出典", { x: 7.15, y: 1.8, w: 5.3, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  txt(s, [
    { text: "Gambit Security(原文レポート)", options: { bold: true, breakLine: true } },
    { text: "gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company", options: { color: C.accent4, breakLine: true } },
    { text: "BleepingComputer", options: { bold: true, breakLine: true } },
    { text: "bleepingcomputer.com/news/security/malicious-ai-agents-steal-600k-credit-cards-infect-100-plus-sites-with-skimmers", options: { color: C.accent4, breakLine: true } },
    { text: "RuntimeWire", options: { bold: true, breakLine: true } },
    { text: "runtimewire.com/article/gambit-ai-agents-credit-card-skimmers", options: { color: C.accent4, breakLine: true } },
    { text: "Cloud Security Alliance(PCI DSS 6.4.3・11.6.1)", options: { bold: true, breakLine: true } },
    { text: "cloudsecurityalliance.org/blog/2026/07/23/pci-dss-6-4-3-and-11-6-1-a-deep-dive-…", options: { color: C.accent4, breakLine: true } },
    { text: "Cloudflare(Client-side Security)", options: { bold: true, breakLine: true } },
    { text: "developers.cloudflare.com/page-shield/", options: { color: C.accent4, breakLine: true } },
    { text: "GitHub", options: { bold: true, breakLine: true } },
    { text: "github.com/usestrix/strix\ngithub.com/oritera/Cairn\ngithub.com/NousResearch/hermes-agent", options: { color: C.accent4 } },
  ], { x: 7.15, y: 2.4, w: 5.35, h: 4.2, fontSize: 12, paraSpaceAfter: 4 });

  // ================= APPENDIX =================
  pres.addSection({ title: "付録" });
  const SRC = "出典:Gambit Security 原文レポート(2026年9月22日)";
  function srcNote(sl) { txt(sl, SRC, { x: 0.6, y: 6.7, w: 9, h: 0.25, fontSize: 10, color: C.accent4 }); }

  // ---- A1 timeline and partners ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録1 経緯と協力機関", { placeholder: "title" });
  [
    ["2026年7月", "キャンペーン開始(Gambit推定)。以降、数十社以上に影響"],
    ["8月23〜31日", "Strixを146回、138ホストに対し深いモードで実行"],
    ["8月25日", "OpenRouterの残高を確認。4週間で7,005.71ドルを消費"],
    ["9月10〜15日", "Cairnが105案件を実行し、27社以上に侵入"],
    ["9月22日", "Gambitが報告を公表。攻撃は現在も継続中"],
  ].forEach((t, i) => {
    const x = 0.6 + i * 2.45;
    card(s, x, 1.5, 2.3, 2.3, C.background2, "timeline-" + (i + 1));
    badge(s, String(i + 1), x + 0.2, 1.68, 0.45, C.accent1, C.background1, 14);
    txt(s, t[0], { x: x + 0.2, y: 2.3, w: 1.95, h: 0.35, fontSize: 16, bold: true, color: C.accent1 });
    txt(s, t[1], { x: x + 0.2, y: 2.72, w: 1.95, h: 1.0, fontSize: 12 });
    if (i < 4) arrow(s, "rightArrow", x + 2.31, 2.55, 0.13, 0.25);
  });
  txt(s, "協力機関と役割", { x: 0.6, y: 4.05, w: 6, h: 0.35, fontSize: 16, bold: true, color: C.accent2 });
  [
    ["Shadowserver Foundation", "被害企業への通知と、攻撃基盤の停止に協力"],
    ["Daniel Gordon ほか業界の協力者", "通知と調査に協力"],
    ["Overwatch Data(不正対策企業)", "盗まれたカードを処理し、発行会社に通知"],
    ["Varys(セキュリティ研究者)", "100超の感染サイトの検出を支援"],
  ].forEach((p, i) => {
    const x = 0.6 + i * 3.067;
    card(s, x, 4.5, 2.9, 1.55, C.background2, "partner-" + (i + 1));
    txt(s, p[0], { x: x + 0.2, y: 4.62, w: 2.5, h: 0.5, fontSize: 14, bold: true });
    txt(s, p[1], { x: x + 0.2, y: 5.2, w: 2.5, h: 0.8, fontSize: 12 });
  });
  card(s, 0.6, 6.15, 12.1, 0.45, C.text2, "partner-note");
  txt(s, "Gambitは被害企業の多くに連絡し、発見した攻撃インフラの停止措置も実施", { x: 0.6, y: 6.15, w: 12.1, h: 0.45, fontSize: 12, bold: true, color: C.background1, align: "center", valign: "middle" });
  srcNote(s);

  // ---- A2 scale, cost, victims ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録2 規模・コスト・被害企業の詳細", { placeholder: "title" });
  [
    ["105件", "Cairnの攻撃案件(9/10〜15)"],
    ["48件", "分析できた案件。残り57件は削除済み"],
    ["27社以上", "侵入を確認(程度はさまざま)"],
    ["5社 / 19社", "スキマー設置の確認数。報告の冒頭は5社、後段では27社中19社と記載"],
    ["$25.46", "101スキャンの平均コスト($3.13〜$79.31)"],
    ["$12,000〜18,000", "全体費用の推定。4週間で7,005.71ドル、その後3週間は倍の利用量"],
  ].forEach((n, i) => {
    const x = 0.6 + (i % 3) * 4.1;
    const y = 1.5 + Math.floor(i / 3) * 1.55;
    card(s, x, y, 3.9, 1.4, C.background2, "scale-card-" + (i + 1));
    txt(s, n[0], { x: x + 0.25, y: y + 0.15, w: 3.4, h: 0.55, fontSize: 26, bold: true, color: C.accent1 });
    txt(s, n[1], { x: x + 0.25, y: y + 0.75, w: 3.4, h: 0.6, fontSize: 12 });
  });
  card(s, 0.6, 4.7, 12.1, 1.85, C.background1, "victims-card", C.accent6);
  txt(s, "影響を受けた企業の種類(ある程度のアクセスを得たと報告)", { x: 0.9, y: 4.85, w: 11.5, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  bullets(s, [
    "Fortune 500の宿泊業企業",
    "米国の大手航空会社",
    "米国の非公開の大手産業用品流通業者",
    "米国のオンラインアパレル小売業者",
  ], { x: 0.9, y: 5.35, w: 11.5, h: 1.15, fontSize: 14 });
  srcNote(s);

  // ---- A3 target selection ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録3 標的の選び方", { placeholder: "title" });
  [
    ["通販カテゴリを抽出", "ウェブのトラフィック順位サービスで、ショッピング分野を選ぶ"],
    ["主要プラットフォームを除外", "商用・オープンソースの大手プラットフォームの店は外す"],
    ["独自コードの店を残す", "攻撃者は、独自開発のほうが脆弱だと見込んだ"],
    ["一括して実行", "301件を投入。プロキシ経由で、高リスクのみスキャン"],
  ].forEach((t, i) => {
    const x = 0.6 + i * 3.1;
    card(s, x, 1.5, 2.8, 2.3, C.background2, "select-step-" + (i + 1));
    badge(s, String(i + 1), x + 0.25, 1.7, 0.5, C.accent3, C.text1, 16);
    txt(s, t[0], { x: x + 0.25, y: 2.4, w: 2.3, h: 0.55, fontSize: 14, bold: true });
    txt(s, t[1], { x: x + 0.25, y: 3.0, w: 2.3, h: 0.75, fontSize: 12 });
    if (i < 3) arrow(s, "rightArrow", x + 2.84, 2.55, 0.22, 0.3);
  });
  card(s, 0.6, 4.1, 5.9, 2.45, C.background2, "select-other");
  txt(s, "ほかの選び方", { x: 0.9, y: 4.25, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
  bullets(s, [
    "手作業で選んだ標的もある",
    "ニュージーランドの小売業者と米国のフォト印刷会社は、動作する管理者パスワードをAIに渡し、「開始」と指示",
  ], { x: 0.9, y: 4.8, w: 5.3, h: 1.7, fontSize: 14 });
  card(s, 6.8, 4.1, 5.9, 2.45, C.background1, "select-implication", C.accent2);
  txt(s, "防御側への示唆(本資料の整理)", { x: 7.1, y: 4.25, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  bullets(s, [
    "独自開発の部分ほど、先に自社で診断する",
    "管理者パスワードが漏れていないか、使い回しがないかを確認する",
  ], { x: 7.1, y: 4.8, w: 5.3, h: 1.7, fontSize: 14 });
  srcNote(s);

  // ---- A4 card countries ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録4 カード発行国の内訳", { placeholder: "title" });
  s.addChart(pres.charts.BAR, [{
    name: "カード数",
    labels: ["アラブ首長国連邦", "サウジアラビア", "英国", "ニュージーランド", "アイルランド", "シンガポール", "クウェート", "オーストラリア", "香港", "フランス", "カタール", "残り196か国"],
    values: [13559, 6785, 6522, 5710, 5483, 5305, 4676, 4672, 4459, 4295, 4075, 64025],
  }], {
    x: 0.6, y: 1.5, w: 7.8, h: 5.1, barDir: "bar", catAxisOrientation: "maxMin",
    chartColors: ["0F7F76"], showLegend: false,
    showTitle: true, title: "米国以外の発行国別カード数", titleFontSize: 14, titleColor: "1B1F23", titleFontFace: "+mn-lt",
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "#,##0", dataLabelFontSize: 11, dataLabelColor: "1B1F23", dataLabelFontFace: "+mn-lt",
    catAxisLabelFontSize: 12, catAxisLabelColor: "1B1F23", catAxisLabelFontFace: "+mn-lt",
    valAxisLabelFontSize: 10, valAxisLabelColor: "5B6C75", valAxisLabelFontFace: "+mn-lt", valAxisLabelFormatCode: "#,##0", valAxisMaxVal: 80000,
    valGridLine: { color: "E1E5E7", size: 0.5 }, catGridLine: { style: "none" },
  });
  card(s, 8.7, 1.5, 4.0, 2.4, C.accent1, "us-card");
  txt(s, "米国", { x: 8.95, y: 1.65, w: 3.5, h: 0.4, fontSize: 16, bold: true, color: C.background1 });
  txt(s, "488,372件", { x: 8.95, y: 2.1, w: 3.5, h: 0.8, fontSize: 36, bold: true, color: C.background1 });
  txt(s, "全体(60万件超)の79.0%", { x: 8.95, y: 3.0, w: 3.5, h: 0.5, fontSize: 14, color: C.background1 });
  card(s, 8.7, 4.1, 4.0, 2.45, C.background2, "country-note");
  bullets(s, [
    "盗まれたカードは2社分で、発行国は200か国超",
    "Gambitは不正対策企業のOverwatch Dataと組み、カード発行会社に通知",
  ], { x: 8.95, y: 4.3, w: 3.5, h: 2.1, fontSize: 12 });
  srcNote(s);

  // ---- A5 data wipe ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録5 データ消去と、その副作用", { placeholder: "title" });
  card(s, 0.6, 1.5, 5.9, 3.7, C.background2, "wipe-playbook");
  txt(s, "攻撃者の手順書にあった消去工程", { x: 0.9, y: 1.65, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
  bullets(s, [
    "カード情報を抽出して持ち出した後、元のデータ欄を分割して消去する",
    "数百万行のテーブルを想定した手順になっている",
    "消去後に確認用の検索を再実行し、残りが0件か確認する",
    "実際の指示では、決済関連の2テーブルについて、まず列を空にする指示を出し、のち「写し取ってから空にする」に変更",
  ], { x: 0.9, y: 2.2, w: 5.3, h: 2.9, fontSize: 12 });
  card(s, 6.8, 1.5, 5.9, 3.7, C.text2, "wipe-accident");
  txt(s, "AIの後片付けによる事故", { x: 7.1, y: 1.65, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent3 });
  bullets(s, [
    "自転車の小売店で、エージェントが作業用に「ZQ」で始まるテーブルを作成",
    "後片付けで、名前に「ZQ」または「Backup」を含む180テーブルを削除",
    "管理者が作っていたバックアップ用のテーブルも消えた",
  ], { x: 7.1, y: 2.2, w: 5.3, h: 2.9, fontSize: 12, color: C.background1 });
  card(s, 0.6, 5.45, 12.1, 1.1, C.accent3, "wipe-takeaway");
  txt(s, "データ消失は、恐喝ではなく、他人の後片付けの副作用として起こりうる。バックアップは本番と別の場所に隔離し、復旧を訓練しておく", { x: 0.85, y: 5.45, w: 11.6, h: 1.1, fontSize: 14, bold: true, color: C.text1, valign: "middle" });
  srcNote(s);

  // ---- A6 stats and recommendation ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録6 統計とGambitの提言", { placeholder: "title" });
  [
    ["月600件超", "主要ソフトウェアベンダー全体で報告された重大な脆弱性の数"],
    ["約87%", "実際に悪用された欠陥のうち、公開当日かそれ以前に攻撃されたもの"],
    ["週単位", "複雑な環境で、修復にかかる時間"],
  ].forEach((n, i) => {
    const y = 1.5 + i * 1.65;
    card(s, 0.6, y, 5.2, 1.5, C.background2, "stat2-" + (i + 1));
    txt(s, n[0], { x: 0.85, y: y + 0.15, w: 4.7, h: 0.6, fontSize: 28, bold: true, color: C.accent1 });
    txt(s, n[1], { x: 0.85, y: y + 0.85, w: 4.7, h: 0.6, fontSize: 12 });
  });
  card(s, 6.1, 1.5, 6.6, 4.8, C.background1, "rec-card", C.accent6);
  txt(s, "Gambitの提言:復旧力を指標にする", { x: 6.4, y: 1.65, w: 6.0, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  bullets(s, [
    "パッチを当てる速さだけでは足りない。サービスをどれだけ早く戻せるかを測る",
    "「最小限の事業単位」を決める。収益を回すために必要な、最小の系統のこと",
    "アプリ担当、インフラ担当、委託先の全員で合意し、その系統が実際に戻ることを確認する",
    "「データベースを戻した」で終わる復旧計画では足りない",
  ], { x: 6.4, y: 2.25, w: 6.0, h: 3.0, fontSize: 14 });
  txt(s, "注:Gambitは復旧・レジリエンス分野の企業で、提言には立場が反映されうる", { x: 6.4, y: 5.55, w: 6.0, h: 0.6, fontSize: 12, color: C.accent4 });
  txt(s, "出典:Gambit Security 原文レポート。統計はa16zの資料をGambitが引用", { x: 0.6, y: 6.7, w: 11, h: 0.25, fontSize: 10, color: C.accent4 });

  // ---- A7 IOC ----
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "付録" });
  s.addText("付録7 IOC一覧(攻撃の痕跡の指標)", { placeholder: "title" });
  const mono = { fontFace: "Courier New", fontSize: 11 };
  function monoList(sl, x, y, w, h, groups) {
    const runs = [];
    groups.forEach((g, gi) => {
      runs.push({ text: g[0], options: { fontFace: THEME.bodyFontFace, fontSize: 12, bold: true, color: C.accent1, breakLine: true } });
      g[1].forEach((v, vi) => {
        const last = gi === groups.length - 1 && vi === g[1].length - 1;
        runs.push({ text: v, options: { fontFace: "Courier New", fontSize: 11, breakLine: !last } });
      });
    });
    txt(sl, runs, { x, y, w, h, fontSize: 11 });
  }
  card(s, 0.6, 1.5, 3.6, 3.95, C.background2, "ioc-ip");
  txt(s, "IPアドレス", { x: 0.85, y: 1.62, w: 3.1, h: 0.35, fontSize: 14, bold: true, color: C.accent2 });
  monoList(s, 0.85, 2.05, 3.2, 3.3, [
    ["指令・AIコンソール", ["155.254.22.215"]],
    ["DNS流出・HTTP待受", ["209.126.4.170"]],
    ["C2(遠隔操作)", ["213.21.239.62", "172.245.224.188"]],
    ["スキマー配信", ["172.245.89.137"]],
  ]);
  card(s, 4.4, 1.5, 3.9, 3.95, C.background2, "ioc-domain");
  txt(s, "ドメイン", { x: 4.65, y: 1.62, w: 3.4, h: 0.35, fontSize: 14, bold: true, color: C.accent2 });
  monoList(s, 4.65, 2.05, 3.5, 3.3, [
    ["運用・C2", ["medbooksource[.]com", "traffic-analyzer[.]net"]],
    ["スキマー配信元", ["b8t[.]shop", "cdn[.]netlfjs[.]com", "x1opay[.]co", "static-js[.]com", "cdn[.]js-static[.]com", "js-static[.]com", "jsnetlify[.]com", "netlifyjs[.]com", "newssjs[.]com"]],
  ]);
  card(s, 8.5, 1.5, 4.2, 3.95, C.background2, "ioc-url");
  txt(s, "スキマーのURL", { x: 8.75, y: 1.62, w: 3.7, h: 0.35, fontSize: 14, bold: true, color: C.accent2 });
  monoList(s, 8.75, 2.05, 3.8, 3.3, [
    ["", ["b8t[.]shop/js/sby.js", "cdn[.]netlfjs[.]com/js/cts.js", "cdn[.]netlfjs[.]com/js/vla.js", "x1opay[.]co/js/eut.js", "x1opay[.]co/js/l.js", "static-js[.]com/js/bmws.js", "static-js[.]com/js/nrt.js", "cdn[.]js-static[.]com/js/tgo.js", "cdn[.]js-static[.]com/js/pps.js"]],
  ]);
  card(s, 0.6, 5.6, 7.7, 0.95, C.background1, "ioc-method", C.accent6);
  txt(s, "挿入コードの特徴", { x: 0.85, y: 5.67, w: 7.2, h: 0.28, fontSize: 12, bold: true, color: C.accent1 });
  txt(s, "new Function(atob('<ランダム>...'.slice(7)))()  先頭に7文字のダミーを付けたbase64", { x: 0.85, y: 5.97, w: 7.2, h: 0.55, fontSize: 11, fontFace: "Courier New" });
  card(s, 8.5, 5.6, 4.2, 0.95, C.background1, "ioc-proxy", C.accent6);
  txt(s, "攻撃に使われたプロキシ事業者", { x: 8.75, y: 5.67, w: 3.7, h: 0.28, fontSize: 12, bold: true, color: C.accent1 });
  txt(s, "IPRoyal / 711proxy / 1024proxy", { x: 8.75, y: 5.97, w: 3.7, h: 0.55, fontSize: 12 });
  txt(s, "出典:Gambit Security 原文レポート。[.]は無害化表記。アクセスせず、ログやDNSとの照合にだけ使う", { x: 0.6, y: 6.7, w: 12, h: 0.25, fontSize: 10, color: C.accent4 });

  const out = path.resolve("AI_agent_attack_tools_analysis.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("written", out);
}

main().catch((e) => { console.error(e); process.exit(1); });
