const pptxgen = require("pptxgenjs");
const path = require("path");
const { applyTheme } = require("/mnt/skills/public/pptx/scripts/apply_theme.js");

const THEME = {
  name: "Threat Analysis EN",
  headFontFace: "Calibri",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "1B1F23", lt1: "FFFFFF", dk2: "2B3A42", lt2: "EEF1F2",
    accent1: "C8431F", accent2: "0F7F76", accent3: "E0A030",
    accent4: "5B6C75", accent5: "7A9E9F", accent6: "B5C0C5",
    hlink: "0F7F76", folHlink: "5B6C75",
  },
};

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "Structure and Defense Against AI-Agent Attack Tools";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

const FOOT = "Hermes / Strix / Cairn  Structure and Defense";

pres.defineSlideMaster({
  title: "TITLE",
  background: { color: C.text2 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 1.8, w: 8.4, h: 2.4, fontSize: 42, bold: true, color: C.background1, align: "left", valign: "top", margin: 0 }, text: "" } },
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
  pres.addSection({ title: "Overview" });
  let s = pres.addSlide({ masterName: "TITLE", sectionTitle: "Overview" });
  s.addText("Structure and Defense Against AI-Agent Attack Tools", { placeholder: "title" });
  txt(s, "Hermes / Strix / Cairn", { x: 0.8, y: 4.3, w: 8.4, h: 0.5, fontSize: 24, color: C.accent3, bold: true });
  txt(s, "Summary of the Gambit Security report (Sept 22, 2026)\nOctober 6, 2026", { x: 0.8, y: 5.0, w: 8.4, h: 0.9, fontSize: 16, color: C.accent6 });
  [["Strix", C.accent2, C.background1], ["Cairn", C.accent3, C.text1], ["Hermes", C.accent1, C.background1]].forEach((c, i) => {
    badge(s, c[0], 9.9, 1.6 + i * 1.75, 1.5, c[1], c[2], 18);
  });

  // ===== 2. Key points =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Overview" });
  s.addText("Key points", { placeholder: "title" });
  [
    ["27+", "companies breached", "105 attack projects launched Sept 10-15 alone"],
    ["600K+", "card records stolen", "From two companies; about 488K issued in the US"],
    ["~$25", "per target", "Mean AI model cost; range $3 to $79"],
  ].forEach((st, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.6, 3.9, 2.1, C.background2, "stat-card-" + (i + 1));
    txt(s, st[0], { x: x + 0.3, y: 1.75, w: 3.3, h: 0.85, fontSize: 44, bold: true, color: C.accent1 });
    txt(s, st[1], { x: x + 0.3, y: 2.6, w: 3.3, h: 0.35, fontSize: 16, bold: true });
    txt(s, st[2], { x: x + 0.3, y: 2.98, w: 3.3, h: 0.6, fontSize: 14, color: C.accent4 });
  });
  [
    "Not purpose-built malware: a chain of legitimate, publicly available open-source tools",
    "Human input was minimal: 1,951 short prompts across 260 sessions",
    "The goal was card theft, not ransomware",
  ].forEach((m, i) => {
    const y = 4.05 + i * 0.85;
    card(s, 0.6, y, 12.1, 0.7, C.background2, "message-" + (i + 1));
    badge(s, String(i + 1), 0.8, y + 0.12, 0.46, C.text2, C.background1, 14);
    txt(s, m, { x: 1.5, y: y + 0.1, w: 11, h: 0.5, fontSize: 16, valign: "middle" });
  });

  // ===== 3. Roles =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Overview" });
  s.addText("Division of labor in the attack chain", { placeholder: "title" });
  [
    ["S", "Strix", C.accent2, C.background1, "Recon and vulnerability discovery", "A public security-testing tool, run in deep mode against targets", "GLM 5.2, then DeepSeek v4 Pro"],
    ["C", "Cairn", C.accent3, C.text1, "Autonomous intrusion", "Given a goal (such as a shell), it runs on its own for hours", "DeepSeek v4.1 Flash"],
    ["H", "Hermes", C.accent1, C.background1, "Orchestration and post-access work", "Directs the campaign and decides next steps after access", "Claude Opus 4.6 (after newer models refused)"],
  ].forEach((r, i) => {
    const x = 0.6 + i * 4.25;
    card(s, x, 1.6, 3.6, 3.95, C.background2, "role-card-" + r[1]);
    badge(s, r[0], x + 0.3, 1.85, 0.75, r[2], r[3], 22);
    txt(s, r[1], { x: x + 1.2, y: 1.85, w: 2.2, h: 0.75, fontSize: 24, bold: true, valign: "middle" });
    txt(s, r[4], { x: x + 0.3, y: 2.8, w: 3.0, h: 0.6, fontSize: 18, bold: true });
    txt(s, r[5], { x: x + 0.3, y: 3.5, w: 3.0, h: 0.9, fontSize: 14 });
    txt(s, "Model used (Gambit report)", { x: x + 0.3, y: 4.4, w: 3.0, h: 0.3, fontSize: 12, color: C.accent4 });
    txt(s, r[6], { x: x + 0.3, y: 4.72, w: 3.0, h: 0.7, fontSize: 14, bold: true });
    if (i < 2) arrow(s, "rightArrow", x + 3.72, 3.3, 0.4, 0.4);
  });
  card(s, 0.6, 5.85, 12.1, 0.85, C.text2, "role-note");
  txt(s, "The human only named targets and goals in short instructions. Models were sourced through OpenRouter.", { x: 0.9, y: 5.85, w: 11.5, h: 0.85, fontSize: 16, color: C.background1, valign: "middle" });

  // ===== 4. Strix =====
  pres.addSection({ title: "Tool structure" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("Strix: an AI security-testing agent", { placeholder: "title" });
  card(s, 0.6, 1.6, 3.6, 4.85, C.background2, "strix-profile");
  badge(s, "S", 0.9, 1.85, 0.7, C.accent2, C.background1, 20);
  txt(s, "usestrix/strix", { x: 1.75, y: 1.85, w: 2.3, h: 0.7, fontSize: 16, bold: true, valign: "middle" });
  bullets(s, ["Apache-2.0", "65K+ GitHub stars", "Intended use: find and fix flaws in your own apps", "Official warning: test only systems you are authorized to test"], { x: 0.9, y: 2.85, w: 3.0, h: 3.4, fontSize: 14 });
  [
    ["Entry", "CLI / TUI / GitHub Actions (scan on every pull request)"],
    ["Agent layer", "Graph of Agents: multiple agents share findings and split work"],
    ["Runtime", "Docker sandbox with HTTP proxy, browser, terminal, Python runtime, and recon tools"],
    ["Brain", "Any LLM via LiteLLM; skills (knowledge packs) and MCP integration"],
    ["Output", "Validated findings with proof of concept, reports, suggested fixes"],
  ].forEach((r, i) => {
    const y = 1.6 + i * 1.0;
    card(s, 4.5, y, 2.1, 0.85, C.accent2, "strix-layer-label-" + (i + 1));
    txt(s, r[0], { x: 4.5, y, w: 2.1, h: 0.85, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
    card(s, 6.7, y, 6.0, 0.85, C.background2, "strix-layer-body-" + (i + 1));
    txt(s, r[1], { x: 6.9, y, w: 5.65, h: 0.85, fontSize: 14, valign: "middle" });
  });
  txt(s, "Source: repository README and AGENTS.md", { x: 4.5, y: 6.6, w: 8, h: 0.3, fontSize: 10, color: C.accent4 });

  // ===== 5. Cairn =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("Cairn: autonomous search on a shared board", { placeholder: "title" });
  card(s, 0.6, 1.6, 6.4, 1.2, C.accent3, "cairn-server");
  txt(s, "Cairn Server\nShared board holding Facts, Intents, and Hints", { x: 0.6, y: 1.6, w: 6.4, h: 1.2, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 3.6, 2.9, 0.4, 0.35);
  card(s, 0.6, 3.35, 6.4, 1.0, C.text2, "cairn-dispatcher");
  txt(s, "Dispatcher\nSchedules tasks, manages containers, sole writer to the board", { x: 0.6, y: 3.35, w: 6.4, h: 1.0, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 3.6, 4.45, 0.4, 0.35);
  [0, 1].forEach((i) => {
    const x = 0.6 + i * 3.3;
    card(s, x, 4.9, 3.1, 1.7, C.background2, "cairn-worker-" + (i + 1));
    txt(s, i === 0 ? "Worker Container\n(Project A)" : "Worker Container\n(Project B)", { x, y: 4.95, w: 3.1, h: 0.7, fontSize: 14, bold: true, align: "center" });
    badge(s, "W", x + 0.7, 5.75, 0.6, C.accent6, C.text1, 14);
    badge(s, "W", x + 1.8, 5.75, 0.6, C.accent6, C.text1, 14);
  });
  [["Fact", "A confirmed finding"], ["Intent", "A direction to explore, not yet run"], ["Hint", "Human advice, added at any time"]].forEach((c, i) => {
    const y = 1.6 + i * 0.8;
    card(s, 7.4, y, 5.3, 0.65, C.background2, "cairn-concept-" + c[0]);
    txt(s, c[0], { x: 7.6, y, w: 1.4, h: 0.65, fontSize: 16, bold: true, color: C.accent1, valign: "middle" });
    txt(s, c[1], { x: 9.0, y, w: 3.5, h: 0.65, fontSize: 14, valign: "middle" });
  });
  bullets(s, [
    "Workers have no fixed roles; they loop observe, orient, decide, act",
    "Workers coordinate only through the shared board",
    "Worker backends: Claude Code, Codex, Pi",
    "AGPL-3.0, 3.2K stars. Solved 54 of 54 problems at a Tencent hackathon (3rd place)",
  ], { x: 7.4, y: 4.1, w: 5.3, h: 2.6, fontSize: 14 });

  // ===== 6. Hermes =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("Hermes: a self-improving general agent", { placeholder: "title" });
  [
    ["Learning loop", "Creates skills from experience and improves them with use"],
    ["Persistent memory", "Searches past sessions (FTS5) and builds a user profile"],
    ["Gateway", "One process serves Telegram, Discord, Slack, and more"],
    ["Scheduled jobs (cron)", "Natural-language tasks that run unattended"],
    ["Subagents", "Isolated child agents run in parallel"],
    ["7 runtime backends", "local, Docker, SSH, Singularity, Modal, Daytona, Vercel Sandbox"],
  ].forEach((f, i) => {
    const x = 0.6 + (i % 3) * 2.725;
    const y = 1.6 + Math.floor(i / 3) * 2.15;
    card(s, x, y, 2.55, 2.0, C.background2, "hermes-feature-" + (i + 1));
    txt(s, f[0], { x: x + 0.2, y: y + 0.2, w: 2.15, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
    txt(s, f[1], { x: x + 0.2, y: y + 0.7, w: 2.15, h: 1.2, fontSize: 14 });
  });
  card(s, 8.9, 1.6, 3.8, 4.15, C.text2, "hermes-abuse");
  txt(s, "How it was abused (Gambit)", { x: 9.15, y: 1.8, w: 3.3, h: 0.4, fontSize: 16, bold: true, color: C.accent3 });
  bullets(s, [
    "Loaded a \"Red Team Operator\" persona",
    "78 of 121 skills were attack skills",
    "Added a skill that removes Hermes's own safety filters",
    "Switched models when one refused",
  ], { x: 9.15, y: 2.4, w: 3.3, h: 3.2, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.05, 12.1, 0.65, C.background2, "hermes-banner");
  txt(s, "MIT  /  250K+ GitHub stars  /  40+ tools  /  MCP support  /  any model", { x: 0.6, y: 6.05, w: 12.1, h: 0.65, fontSize: 14, bold: true, align: "center", valign: "middle" });

  // ===== 6b. Cairn loop: probing step by step =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("Cairn probes and adapts", { placeholder: "title" });
  [
    ["Observe", "Read the facts gathered so far on the shared board"],
    ["Decide", "Choose the next direction to explore"],
    ["Act", "Try that one direction"],
    ["Record", "Write the result back to the board as a fact"],
  ].forEach((f, i) => {
    const x = 0.6 + i * 3.1;
    card(s, x, 1.55, 2.8, 2.0, C.background2, "loop-step-" + (i + 1));
    badge(s, String(i + 1), x + 0.25, 1.75, 0.5, C.accent3, C.text1, 16);
    txt(s, f[0], { x: x + 0.95, y: 1.75, w: 1.7, h: 0.5, fontSize: 18, bold: true, valign: "middle" });
    txt(s, f[1], { x: x + 0.25, y: 2.5, w: 2.35, h: 0.95, fontSize: 14 });
    if (i < 3) arrow(s, "rightArrow", x + 2.84, 2.4, 0.22, 0.3);
  });
  card(s, 0.6, 3.7, 12.1, 0.5, C.text2, "loop-return");
  txt(s, "With that result in hand, it loops back to observe, until the goal is met or time runs out", { x: 0.6, y: 3.7, w: 12.1, h: 0.5, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
  card(s, 0.6, 4.4, 5.9, 2.35, C.background2, "loop-example");
  txt(s, "Example: one case in the Gambit report", { x: 0.9, y: 4.55, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
  txt(s, "Login-page flaw → admin panel → file placed on server → root access → cloud keys → card data", { x: 0.9, y: 5.1, w: 5.3, h: 1.5, fontSize: 14 });
  card(s, 6.8, 4.4, 5.9, 2.35, C.background1, "loop-meaning", C.accent2);
  txt(s, "What this means", { x: 7.1, y: 4.55, w: 5.3, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  bullets(s, [
    "It decides each step from the last result, so the path differs for every victim",
    "No single fix stops the whole chain",
    "Humans can add hints, but most of the work runs on its own",
  ], { x: 7.1, y: 5.05, w: 5.3, h: 1.6, fontSize: 14 });

  // ===== 6c. Hermes internals =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("Inside Hermes", { placeholder: "title" });
  card(s, 0.6, 1.5, 12.1, 0.75, C.text2, "hermes-entry");
  txt(s, "Entry: terminal (CLI) and chat apps (Telegram, Slack, Discord, and more)", { x: 0.6, y: 1.5, w: 12.1, h: 0.75, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 6.5, 2.28, 0.3, 0.22);
  card(s, 0.6, 2.55, 12.1, 1.0, C.accent1, "hermes-loop");
  txt(s, "AIAgent (run_agent.py)\nAsk the model, use a tool, read the result. Repeat until no tool is needed", { x: 0.6, y: 2.55, w: 12.1, h: 1.0, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
  arrow(s, "downArrow", 6.5, 3.58, 0.3, 0.22);
  [
    ["Tools", "70+. Each file registers itself, so adding one is easy"],
    ["Skills", "SKILL.md playbooks injected into the chat; also auto-generated from experience"],
    ["Memory", "Sessions saved in SQLite; full-text search recalls the past"],
    ["Runtime", "7 backends such as local, Docker, SSH. Commands run here"],
  ].forEach((c, i) => {
    const x = 0.6 + i * 3.06;
    card(s, x, 3.85, 2.9, 2.0, C.background2, "hermes-part-" + (i + 1));
    txt(s, c[0], { x: x + 0.25, y: 4.0, w: 2.4, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
    txt(s, c[1], { x: x + 0.25, y: 4.5, w: 2.4, h: 1.25, fontSize: 14 });
  });
  card(s, 0.6, 6.05, 12.1, 0.65, C.background2, "hermes-provider");
  txt(s, "Model providers: switch among 18+ including OpenRouter, OpenAI, and Anthropic", { x: 0.6, y: 6.05, w: 12.1, h: 0.65, fontSize: 14, bold: true, align: "center", valign: "middle" });

  // ===== 6d. Hermes safety and limits =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("Hermes safeguards and their limits", { placeholder: "title" });
  card(s, 0.6, 1.5, 5.9, 4.4, C.background2, "safety-built-in");
  txt(s, "Built-in safeguards", { x: 0.9, y: 1.7, w: 5.3, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "Risky commands are reviewed by an auxiliary AI (default mode: smart)",
    "A few system-wrecking operations are always refused",
    "Protects SSH keys and cloud credentials from being overwritten",
    "Chat users are limited by allow-lists and pairing codes",
  ], { x: 0.9, y: 2.3, w: 5.3, h: 3.5, fontSize: 14 });
  card(s, 6.8, 1.5, 5.9, 4.4, C.text2, "safety-limits");
  txt(s, "Limits (what enabled the abuse)", { x: 7.1, y: 1.7, w: 5.3, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "The operator can change the approval mode in settings",
    "In Docker, approval checks are skipped (the container is treated as the boundary)",
    "It runs locally as open source, so operators can modify it. Gambit: a skill was added to remove its safety filters",
    "The last brake is the LLM provider's refusal; here, a refusal meant switching models",
  ], { x: 7.1, y: 2.3, w: 5.3, h: 3.5, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.1, 12.1, 0.65, C.accent3, "safety-takeaway");
  txt(s, "The tool's own safeguards cannot prevent misuse; targets need their own defenses", { x: 0.6, y: 6.1, w: 12.1, h: 0.65, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 7. Common design =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Tool structure" });
  s.addText("What the three tools share", { placeholder: "title" });
  const pats = [
    [fa.FaBullseye, "Give only a goal", "Humans send short instructions", "Detection and response built for human speed fall behind"],
    [fa.FaSyncAlt, "Keep trying without tiring", "Self-running loops explore for hours", "Small, low-profile sites become targets (about $25 each)"],
    [fa.FaProjectDiagram, "Run in parallel at scale", "Containers and subagents work at once", "Manual monitoring cannot keep up; automated detection is needed"],
    [fa.FaBrain, "Accumulate experience", "Skills and memory reuse what worked", "A technique that worked on one company is reused on others"],
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
  pres.addSection({ title: "Defense" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Break the intrusion chain", { placeholder: "title" });
  txt(s, "Example chain (one case in the Gambit report)", { x: 0.6, y: 1.5, w: 5.9, h: 0.4, fontSize: 16, bold: true, color: C.accent1 });
  txt(s, "Countermeasure", { x: 6.9, y: 1.5, w: 5.8, h: 0.4, fontSize: 16, bold: true, color: C.accent2 });
  [
    ["SQL injection on the login form", "Use parameterized queries everywhere"],
    ["OTP stored in plaintext (MFA bypass)", "Hash OTPs and expire them quickly"],
    ["Admin upload with no extension check", "Validate type and content; store outside web root"],
    ["sudo allowed without a password", "Remove NOPASSWD; use least privilege"],
    ["NFS misconfiguration; creds in config file", "Avoid no_root_squash; keep secrets out of config"],
    ["Bulk dump of Secrets Manager", "Least-privilege IAM; alert on bulk reads"],
    ["Card encryption key reachable from same environment", "Tokenize with a payment provider; hold no card numbers"],
  ].forEach((r, i) => {
    const y = 2.0 + i * 0.68;
    card(s, 0.6, y, 5.9, 0.58, C.background2, "chain-step-" + (i + 1));
    txt(s, r[0], { x: 0.8, y, w: 5.55, h: 0.58, fontSize: 14, valign: "middle" });
    arrow(s, "rightArrow", 6.6, y + 0.14, 0.2, 0.3);
    card(s, 6.9, y, 5.8, 0.58, C.background1, "chain-fix-" + (i + 1), C.accent2);
    txt(s, r[1], { x: 7.05, y, w: 5.55, h: 0.58, fontSize: 14, valign: "middle" });
  });

  // ===== 9. Checkout page =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Protect the checkout page", { placeholder: "title" });
  card(s, 0.6, 1.6, 5.8, 5.1, C.background2, "skimmer-routes");
  txt(s, "How skimmers were planted (Gambit)", { x: 0.9, y: 1.8, w: 5.2, h: 0.4, fontSize: 18, bold: true, color: C.accent1 });
  bullets(s, [
    "One line appended to an existing JS file (e.g., jQuery), file timestamp restored",
    "A foreign script tag on the checkout page",
    "Hidden inside the Google tag block",
    "S3 bucket behind the CDN overwritten",
    "Injected into product description fields in the database",
    "Added as a Kubernetes initContainer",
    "Poisoned page cache",
    "A cron job that re-injects the skimmer after removal",
  ], { x: 0.9, y: 2.4, w: 5.2, h: 4.2, fontSize: 14 });
  card(s, 6.7, 1.6, 6.0, 5.1, C.background1, "skimmer-defense", C.accent2);
  txt(s, "Countermeasures", { x: 7.0, y: 1.8, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "Allow-list script-src with CSP",
    "Detect tampering with Subresource Integrity (SRI)",
    "Compare served JS hashes with build artifacts on a schedule",
    "Isolate payment with hosted fields or a provider iframe",
    "Inventory every script on the page regularly",
    "Restrict S3/CDN write access and alert on changes",
    "Audit cron jobs, Kubernetes manifests, and caches",
  ], { x: 7.0, y: 2.4, w: 5.4, h: 4.2, fontSize: 14 });

  // ===== 9b. Payment method decides the defense =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Your payment method changes how you defend", { placeholder: "title" });
  [
    ["A", "Hosted payment page", "Customers are sent to the provider's page", "Risk: low", C.accent2, C.background1, [
      "Card numbers never pass through your site",
      "Often possible by changing the contract or settings",
      "Smallest PCI burden",
    ]],
    ["B", "Embedded", "An iframe or hosted fields show only the input", "Risk: medium", C.accent3, C.text1, [
      "The provider renders the input fields",
      "If your page is tampered with, its surroundings can be rewritten",
      "May still require script control and tamper detection",
    ]],
    ["C", "Your own form", "Your server receives the card numbers", "Risk: high", C.accent1, C.background1, [
      "The main target for skimmers",
      "Move to A or B first if you can",
      "Until then, apply every measure on the next slide",
    ]],
  ].forEach((c, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.5, 3.9, 4.5, C.background2, "method-card-" + c[0]);
    badge(s, c[0], x + 0.25, 1.7, 0.6, c[4], c[5], 18);
    txt(s, c[1], { x: x + 1.05, y: 1.7, w: 2.7, h: 0.6, fontSize: 16, bold: true, valign: "middle" });
    txt(s, c[2], { x: x + 0.3, y: 2.5, w: 3.3, h: 0.6, fontSize: 12, color: C.accent4 });
    card(s, x + 0.3, 3.15, 1.6, 0.4, c[4], "method-risk-" + c[0]);
    txt(s, c[3], { x: x + 0.3, y: 3.15, w: 1.6, h: 0.4, fontSize: 14, bold: true, color: c[5], align: "center", valign: "middle" });
    bullets(s, c[6], { x: x + 0.3, y: 3.8, w: 3.35, h: 2.1, fontSize: 14 });
  });
  card(s, 0.6, 6.15, 12.1, 0.6, C.text2, "method-note");
  txt(s, "First confirm your current method. Also ask your payment provider or card brand how PCI applies", { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });

  // ===== 9c. Settings that strengthen the checkout page =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Settings that harden the checkout page (priority order)", { placeholder: "title" });
  [
    ["1 Rethink the method", "Move to A or B; often a contract or settings change is enough"],
    ["2 Add CSP", "Start in Report-Only to observe sources, allow-list them, then enforce"],
    ["3 Add SRI", "For fixed JS you serve yourself; a poor fit for external scripts that change often"],
    ["4 Cut tags", "Keep only essential scripts, ads, and analytics on the payment page"],
    ["5 Watch for changes", "Alert on added or changed scripts. Cloudflare monitors scripts free; change detection needs a higher plan"],
    ["6 Watch the settings", "Rewriting the CSP is itself a risk; keep history and notify"],
  ].forEach((r, i) => {
    const y = 1.5 + i * 0.76;
    card(s, 0.6, y, 3.0, 0.66, C.accent2, "setting-label-" + (i + 1));
    txt(s, r[0], { x: 0.6, y, w: 3.0, h: 0.66, fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
    card(s, 3.7, y, 9.0, 0.66, C.background2, "setting-body-" + (i + 1));
    txt(s, r[1], { x: 3.95, y, w: 8.6, h: 0.66, fontSize: 14, valign: "middle" });
  });
  card(s, 0.6, 6.15, 12.1, 0.6, C.accent3, "setting-note");
  txt(s, "CSP and SRI alone are not enough; pair them with continuous monitoring", { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 10. Self-test =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Test yourself first", { placeholder: "title" });
  [
    "Get written authorization and define scope",
    "Start with a staging environment",
    "Add quick per-pull-request scans to CI/CD",
    "Cycle through find, fix, and retest",
    "In production, set scope, hours, and a budget cap",
  ].forEach((t, i) => {
    const y = 1.6 + i * 1.0;
    card(s, 0.6, y, 7.4, 0.85, C.background2, "selftest-step-" + (i + 1));
    badge(s, String(i + 1), 0.8, y + 0.15, 0.55, C.accent2, C.background1, 16);
    txt(s, t, { x: 1.6, y, w: 6.2, h: 0.85, fontSize: 16, valign: "middle" });
  });
  card(s, 8.3, 1.6, 4.4, 4.85, C.text2, "selftest-caution");
  txt(s, "Operational cautions", { x: 8.55, y: 1.8, w: 3.9, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "Run only against systems you are authorized to test",
    "Check what code and credentials are sent to the LLM provider",
    "AI can take destructive actions; in the Gambit case, 180 tables were deleted by mistake",
    "Back up first and restrict write and delete operations",
  ], { x: 8.55, y: 2.4, w: 3.9, h: 3.9, fontSize: 14, color: C.background1 });

  // ===== 10b. AI tools for vulnerability checks =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("AI and LLM tools for vulnerability checks", { placeholder: "title" });
  [
    ["Test a running app like an attacker", "Example: Strix (open source)", "Run on staging; supports per-pull-request CI scans and reports with reproduction steps"],
    ["Read source code and suggest fixes", "Examples: GitHub Copilot Autofix, Semgrep, Snyk, Claude Security", "AI-assisted code scanning. Check each vendor's features and pricing (not individually verified here)"],
    ["Monitor checkout-page scripts", "Example: Cloudflare Client-side Security", "A dedicated monitoring service, not an LLM; use it alongside scanners"],
  ].forEach((r, i) => {
    const y = 1.5 + i * 1.55;
    card(s, 0.6, y, 7.6, 1.4, C.background2, "tool-row-" + (i + 1));
    txt(s, r[0], { x: 0.85, y: y + 0.12, w: 7.1, h: 0.35, fontSize: 16, bold: true });
    txt(s, r[1], { x: 0.85, y: y + 0.5, w: 7.1, h: 0.3, fontSize: 14, bold: true, color: C.accent2 });
    txt(s, r[2], { x: 0.85, y: y + 0.85, w: 7.1, h: 0.5, fontSize: 14, color: C.accent4 });
  });
  card(s, 8.5, 1.5, 4.2, 4.5, C.text2, "tool-caution");
  txt(s, "Cautions", { x: 8.75, y: 1.7, w: 3.7, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "Use only on systems you are authorized to test",
    "Check what code and credentials are sent to the LLM provider",
    "AI findings include false alarms and misses; people verify",
    "Scanning alone fixes nothing; carry through to fix and rescan",
  ], { x: 8.75, y: 2.3, w: 3.7, h: 3.6, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.15, 12.1, 0.6, C.accent3, "tool-note");
  txt(s, "AI helps you find and fix; people make the final call", { x: 0.6, y: 6.15, w: 12.1, h: 0.6, fontSize: 16, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 10c. After the scan =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("After the scan: how to respond", { placeholder: "title" });
  [
    ["Sort by severity", "Card, auth, and admin-panel issues come first"],
    ["Contain what you cannot fix yet", "Add WAF rules, disable features, restrict access"],
    ["Fix the root cause", "Parameterized queries, upload validation, and the chain fixes shown earlier"],
    ["Rescan to confirm", "Rerun the same tool and verify the fix"],
    ["Make it routine", "Add automated per-pull-request scans"],
  ].forEach((t, i) => {
    const y = 1.5 + i * 1.0;
    card(s, 0.6, y, 7.6, 0.85, C.background2, "after-step-" + (i + 1));
    badge(s, String(i + 1), 0.8, y + 0.15, 0.55, C.accent2, C.background1, 16);
    txt(s, t[0], { x: 1.6, y: y + 0.1, w: 6.4, h: 0.35, fontSize: 16, bold: true });
    txt(s, t[1], { x: 1.6, y: y + 0.47, w: 6.4, h: 0.3, fontSize: 14, color: C.accent4 });
  });
  card(s, 8.5, 1.5, 4.2, 4.85, C.text2, "after-points");
  txt(s, "Key points", { x: 8.75, y: 1.7, w: 3.7, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "AI scanning is the entry point; people decide the fix",
    "In production, set scope, hours, and a budget",
    "Back up before you run it",
  ], { x: 8.75, y: 2.3, w: 3.7, h: 3.9, fontSize: 14, color: C.background1 });

  // ===== 10d. What tools can and cannot find =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("What scanners can find, and what needs other measures", { placeholder: "title" });
  card(s, 0.6, 1.5, 5.95, 4.4, C.background2, "find-yes");
  txt(s, "Easier for scanners (like Strix) to find", { x: 0.9, y: 1.7, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "Input-handling flaws such as SQL injection",
    "Weak upload validation",
    "Design weaknesses in login and OTP",
    "Exposed admin panels and misconfigurations",
  ], { x: 0.9, y: 2.3, w: 5.4, h: 3.5, fontSize: 14 });
  card(s, 6.75, 1.5, 5.95, 4.4, C.text2, "find-no");
  txt(s, "Hard to find by scanning; needs other measures", { x: 7.05, y: 1.7, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent3 });
  bullets(s, [
    "Skimmers already planted (needs tamper monitoring)",
    "Internal privilege design (sudo, NFS, cloud keys); depends on scan scope and permission",
    "Backups and recovery readiness",
    "The payment method itself (a design decision)",
  ], { x: 7.05, y: 2.3, w: 5.4, h: 3.5, fontSize: 14, color: C.background1 });
  card(s, 0.6, 6.1, 12.1, 0.65, C.accent3, "find-note");
  txt(s, "Running Strix first could remove many entry-point flaws, but no report here tested that, and it is not enough alone", { x: 0.8, y: 6.1, w: 11.7, h: 0.65, fontSize: 14, bold: true, color: C.text1, align: "center", valign: "middle" });

  // ===== 11. Concrete actions =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("What companies should have done beforehand", { placeholder: "title" });
  [
    ["Checkout page", ["Limit script sources with CSP", "Add SRI to every script tag", "Hand payment to a provider iframe"]],
    ["Served files", ["Make the web root read-only to the app", "Check JS hashes hourly after deploy", "Alert immediately on any difference"]],
    ["Code", ["Use only parameterized SQL", "Allow-list upload file types", "Store uploads outside the web root"]],
    ["Auth and admin", ["Hash OTPs; expire in 5 minutes", "Limit attempts and lock on excess", "Put admin behind VPN or IP allow-list"]],
    ["Servers and cloud", ["Remove NOPASSWD from sudoers", "Never use no_root_squash on NFS", "Grant secrets per use, least privilege"]],
    ["Backup and detection", ["Copy backups to a separate account", "Make them undeletable (Object Lock)", "Alert on new admins and bulk key reads"]],
  ].forEach((a, i) => {
    const x = 0.6 + (i % 3) * 4.1;
    const y = 1.5 + Math.floor(i / 3) * 2.7;
    card(s, x, y, 3.9, 2.55, C.background2, "action-card-" + (i + 1));
    badge(s, String(i + 1), x + 0.25, y + 0.2, 0.45, C.accent2, C.background1, 14);
    txt(s, a[0], { x: x + 0.85, y: y + 0.2, w: 2.85, h: 0.45, fontSize: 16, bold: true, valign: "middle" });
    bullets(s, a[1], { x: x + 0.3, y: y + 0.85, w: 3.35, h: 1.6, fontSize: 14 });
  });

  // ===== 12. Recovery & detection =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Recovery and detection", { placeholder: "title" });
  card(s, 0.6, 1.6, 5.9, 5.1, C.background2, "recovery-card");
  s.addImage({ data: await icon(fa.FaUndo, "0F7F76"), x: 0.9, y: 1.85, w: 0.4, h: 0.4, altText: "Recovery" });
  txt(s, "Recovery", { x: 1.45, y: 1.8, w: 4.5, h: 0.5, fontSize: 20, bold: true, valign: "middle" });
  bullets(s, [
    "Isolate backups in a separate account and make them undeletable",
    "Define the minimum set of systems the business needs to operate",
    "Do not stop at restoring the database; rehearse bringing the service back",
  ], { x: 0.9, y: 2.6, w: 5.3, h: 3.9, fontSize: 16 });
  card(s, 6.8, 1.6, 5.9, 5.1, C.background2, "detection-card");
  s.addImage({ data: await icon(fa.FaSearch, "C8431F"), x: 7.1, y: 1.85, w: 0.4, h: 0.4, altText: "Detection" });
  txt(s, "Detection and response", { x: 7.65, y: 1.8, w: 4.5, h: 0.5, fontSize: 20, bold: true, valign: "middle" });
  bullets(s, [
    "New admin-panel logins, new admin accounts, unexpected uploads",
    "Rate limiting and bot defense for bursts of requests",
    "Suspicious outbound DNS/HTTP traffic",
    "Match against Gambit's published IOCs (domains and IPs)",
    "Automated isolation and response at machine speed",
  ], { x: 7.1, y: 2.6, w: 5.3, h: 3.9, fontSize: 14 });

  // ===== 13. Roadmap =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Defense" });
  s.addText("Priority roadmap", { placeholder: "title" });
  [
    ["This week", C.accent1, C.background1, ["Inventory checkout-page scripts; add CSP and SRI", "Check admin exposure and MFA", "Match Gambit's published IOCs", "Confirm backup isolation"]],
    ["This month", C.accent3, C.text1, ["Run an AI scan on staging", "Fix known patterns: SQLi, uploads", "Review IAM, sudo, and secrets"]],
    ["This quarter", C.accent2, C.background1, ["Tokenize card data", "Automate scans in CI/CD", "Rehearse minimum-viable-business recovery", "Build automated detection and response"]],
  ].forEach((r, i) => {
    const x = 0.6 + i * 4.1;
    card(s, x, 1.6, 3.9, 5.1, C.background2, "roadmap-col-" + (i + 1));
    card(s, x + 0.25, 1.85, 1.8, 0.55, r[1], "roadmap-chip-" + (i + 1));
    txt(s, r[0], { x: x + 0.25, y: 1.85, w: 1.8, h: 0.55, fontSize: 16, bold: true, color: r[2], align: "center", valign: "middle" });
    bullets(s, r[3], { x: x + 0.3, y: 2.7, w: 3.35, h: 3.9, fontSize: 14 });
  });

  // ===== 14. Numbers =====
  pres.addSection({ title: "Wrap-up" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Wrap-up" });
  s.addText("Reading the numbers and the coverage", { placeholder: "title" });
  [
    ["600K+", "Card records stolen (two companies); 488,372 issued in the US (79%)"],
    ["27", "Companies named as targets by Gambit"],
    ["19", "Of those 27, companies with a confirmed skimmer"],
    ["119 sites", "BleepingComputer's count: the 19 plus 100+ other infected sites"],
  ].forEach((n, i) => {
    const y = 1.6 + i * 1.28;
    card(s, 0.6, y, 6.3, 1.12, C.background2, "number-card-" + (i + 1));
    txt(s, n[0], { x: 0.85, y, w: 2.3, h: 1.12, fontSize: 28, bold: true, color: C.accent1, valign: "middle" });
    txt(s, n[1], { x: 3.2, y, w: 3.55, h: 1.12, fontSize: 14, valign: "middle" });
  });
  card(s, 7.2, 1.6, 5.5, 5.0, C.background1, "rw-card", C.accent6);
  txt(s, "RuntimeWire's points", { x: 7.5, y: 1.8, w: 4.9, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  bullets(s, [
    "Gambit studies a problem its own product addresses, so a conflict of interest is possible",
    "Counts mix direct evidence, verified live compromises, and agent logs; not a full audit",
    "The report is interim, and the real scale may be larger",
    "Victim names and the final infected-site count are not public",
    "Takeaway: measure whether you can recover, how fast, and at what cost, not just whether backups exist",
  ], { x: 7.5, y: 2.4, w: 4.9, h: 4.1, fontSize: 14 });

  // ===== 14b. Three sources compared =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Wrap-up" });
  s.addText("How the three sources differ", { placeholder: "title" });
  [
    ["G", "Gambit Security", "Primary source (original report)", C.accent2, C.background1, [
      "Reconstructed from the recovered attacker server",
      "Includes the intrusion chain, skimmer methods, and IOCs",
      "Evidence in three tiers: server data, verified live, AI logs",
    ]],
    ["B", "BleepingComputer", "News summary and awareness", C.accent3, C.text1, [
      "Reports 119 infected sites (Gambit: 19 companies plus 100+ sites)",
      "Notes Cairn is not the same-name AI analysis tool Cisco Talos released a day earlier",
      "Warns that low cost lowers the barrier to entry",
      "Adds no new defensive advice",
    ]],
    ["R", "RuntimeWire", "Clarifying the numbers, with critique", C.accent1, C.background1, [
      "Sorts out how 27, 19, and 119 relate",
      "Flags Gambit's position and that the report is interim",
      "Urges measuring recoverability, speed, and cost",
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
  txt(s, "All three start from Gambit's research; none is an independent confirmation", { x: 0.9, y: 6.15, w: 11.5, h: 0.6, fontSize: 14, bold: true, color: C.background1, valign: "middle" });

  // ===== 15. Limits & sources =====
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Wrap-up" });
  s.addText("Limits of this deck and sources", { placeholder: "title" });
  card(s, 0.6, 1.6, 6.0, 5.1, C.background2, "limits-card");
  txt(s, "Limits", { x: 0.9, y: 1.8, w: 5.4, h: 0.4, fontSize: 18, bold: true, color: C.accent1 });
  bullets(s, [
    "Based on the READMEs and AGENTS.md of three repositories plus public reports; no source code was run or analyzed",
    "Gambit sells defensive products, so its conclusions may reflect that position",
    "119 sites (BleepingComputer) counts infected sites; 27 and 19 companies (Gambit) are separate tallies",
    "Some AI logs and claims remain unverified",
  ], { x: 0.9, y: 2.4, w: 5.4, h: 4.2, fontSize: 14 });
  card(s, 6.9, 1.6, 5.8, 5.1, C.background1, "sources-card", C.accent6);
  txt(s, "Sources", { x: 7.15, y: 1.8, w: 5.3, h: 0.4, fontSize: 18, bold: true, color: C.accent2 });
  txt(s, [
    { text: "Gambit Security (original report)", options: { bold: true, breakLine: true } },
    { text: "gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company", options: { color: C.accent4, breakLine: true } },
    { text: "BleepingComputer", options: { bold: true, breakLine: true } },
    { text: "bleepingcomputer.com/news/security/malicious-ai-agents-steal-600k-credit-cards-infect-100-plus-sites-with-skimmers", options: { color: C.accent4, breakLine: true } },
    { text: "RuntimeWire", options: { bold: true, breakLine: true } },
    { text: "runtimewire.com/article/gambit-ai-agents-credit-card-skimmers", options: { color: C.accent4, breakLine: true } },
    { text: "Cloud Security Alliance (PCI DSS 6.4.3 and 11.6.1)", options: { bold: true, breakLine: true } },
    { text: "cloudsecurityalliance.org/blog/2026/07/23/pci-dss-6-4-3-and-11-6-1-a-deep-dive-…", options: { color: C.accent4, breakLine: true } },
    { text: "Cloudflare (Client-side Security)", options: { bold: true, breakLine: true } },
    { text: "developers.cloudflare.com/page-shield/", options: { color: C.accent4, breakLine: true } },
    { text: "GitHub", options: { bold: true, breakLine: true } },
    { text: "github.com/usestrix/strix\ngithub.com/oritera/Cairn\ngithub.com/NousResearch/hermes-agent", options: { color: C.accent4 } },
  ], { x: 7.15, y: 2.4, w: 5.35, h: 4.2, fontSize: 12, paraSpaceAfter: 4 });

  const out = path.resolve("AI_agent_attack_tools_analysis_EN.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("written", out);
}

main().catch((e) => { console.error(e); process.exit(1); });
