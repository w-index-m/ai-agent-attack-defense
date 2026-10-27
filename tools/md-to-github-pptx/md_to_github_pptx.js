#!/usr/bin/env node
/**
 * Markdown (GitHub-flavored subset) -> PowerPoint, styled to look like GitHub's
 * own markdown rendering (code blocks, tables, headings, lists).
 *
 * Usage:
 *   node md_to_github_pptx.js input.md output.pptx ["Deck Title"]
 *
 * Supported markdown subset: #/##/### headings, fenced ``` code blocks,
 * pipe tables, "-"/"*" bullet lists, **bold**, `inline code`, plain paragraphs.
 */
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");

const GH = {
  bg: "FFFFFF",
  text: "1F2328",
  muted: "57606A",
  border: "D1D9E0",
  codeBg: "F6F8FA",
  tableHeaderBg: "F6F8FA",
  tableStripeBg: "FBFCFD",
};

const PAGE_W = 13.33;
const PAGE_H = 7.5;
const MARGIN_X = 0.55;
const CONTENT_W = PAGE_W - MARGIN_X * 2;
const TITLE_Y = 0.4;
const TITLE_H = 0.7;
const BODY_TOP = 1.35;
const BODY_BOTTOM = 7.05;

// ---------- Markdown parsing ----------

function parseInline(text) {
  const runs = [];
  const regex = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let lastIndex = 0;
  let m;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > lastIndex) runs.push({ text: text.slice(lastIndex, m.index) });
    const token = m[0];
    if (token.startsWith("`")) {
      runs.push({
        text: token.slice(1, -1),
        options: { fontFace: "Courier New", highlight: GH.codeBg, color: GH.text },
      });
    } else {
      runs.push({ text: token.slice(2, -2), options: { bold: true } });
    }
    lastIndex = regex.lastIndex;
  }
  if (lastIndex < text.length) runs.push({ text: text.slice(lastIndex) });
  if (runs.length === 0) runs.push({ text: "" });
  return runs;
}

function splitRow(line) {
  const parts = line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|");
  return parts.map((s) => s.trim());
}

function parseMarkdown(md) {
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === "") {
      i++;
      continue;
    }
    const hm = line.match(/^(#{1,3})\s+(.*)$/);
    if (hm) {
      blocks.push({ type: "heading", level: hm[1].length, text: hm[2].trim() });
      i++;
      continue;
    }
    if (line.trim().startsWith("```")) {
      const lang = line.trim().slice(3).trim();
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++;
      blocks.push({ type: "code", lang, lines: codeLines });
      continue;
    }
    if (line.trim().startsWith("|")) {
      const tableLines = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      const header = splitRow(tableLines[0]);
      const rows = tableLines.slice(2).map(splitRow);
      blocks.push({ type: "table", header, rows });
      continue;
    }
    const lm = line.match(/^(\s*)[-*]\s+(.*)$/);
    if (lm) {
      const items = [];
      while (i < lines.length) {
        const lm2 = lines[i].match(/^(\s*)[-*]\s+(.*)$/);
        if (!lm2) break;
        items.push(lm2[2]);
        i++;
      }
      blocks.push({ type: "list", items, ordered: false });
      continue;
    }
    const om = line.match(/^(\s*)\d+\.\s+(.*)$/);
    if (om) {
      const items = [];
      while (i < lines.length) {
        const om2 = lines[i].match(/^(\s*)\d+\.\s+(.*)$/);
        if (!om2) break;
        items.push(om2[2]);
        i++;
      }
      blocks.push({ type: "list", items, ordered: true });
      continue;
    }
    const paraLines = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].match(/^(#{1,3})\s+/) &&
      !lines[i].trim().startsWith("```") &&
      !lines[i].trim().startsWith("|") &&
      !lines[i].match(/^(\s*)[-*]\s+/)
    ) {
      paraLines.push(lines[i].trim());
      i++;
    }
    blocks.push({ type: "para", text: paraLines.join(" ") });
  }
  return blocks;
}

// ---------- height estimation (rough, used to decide continuation slides) ----------

// CJK glyphs render roughly full-width (~1em); ASCII/Latin glyphs roughly
// half that. Weighting by character width (not raw character count) keeps
// the line-wrap estimate accurate for mixed Japanese/English text.
function weightedTextWidthInches(text, fontSize) {
  const emIn = fontSize / 72; // 1em in inches
  let w = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    const isWide =
      (cp >= 0x1100 && cp <= 0x115f) || // Hangul Jamo
      (cp >= 0x2e80 && cp <= 0xa4cf) || // CJK radicals .. Yi
      (cp >= 0xac00 && cp <= 0xd7a3) || // Hangul syllables
      (cp >= 0xf900 && cp <= 0xfaff) || // CJK compat ideographs
      (cp >= 0xff00 && cp <= 0xff60) || // fullwidth forms
      (cp >= 0xffe0 && cp <= 0xffe6);
    w += isWide ? emIn * 0.95 : emIn * 0.52;
  }
  return w;
}

function wrapLineCount(text, fontSize, boxWidthIn) {
  const totalW = weightedTextWidthInches(text, fontSize);
  return Math.max(1, Math.ceil(totalW / boxWidthIn));
}

function estimateParaHeight(text, fontSize) {
  const lines = wrapLineCount(text, fontSize, CONTENT_W);
  return lines * (fontSize / 72) * 1.5 + 0.12;
}

function estimateListHeight(items, fontSize, ordered) {
  let h = 0;
  const boxW = CONTENT_W - 0.3; // bullet/number indent eats into wrap width
  for (const item of items) {
    const lines = wrapLineCount(item, fontSize, boxW);
    h += lines * (fontSize / 72) * 1.45 + 0.08;
  }
  return h + 0.1;
}

function estimateCodeHeight(lineCount) {
  return lineCount * 0.235 + 0.3;
}

function estimateTableHeight(block) {
  const cols = block.header.length;
  const colW = CONTENT_W / cols - 0.2; // inner padding per cell
  const allRows = [block.header, ...block.rows];
  let total = 0;
  for (const row of allRows) {
    let maxLines = 1;
    for (const cell of row) {
      maxLines = Math.max(maxLines, wrapLineCount(cell, 12, Math.max(0.6, colW)));
    }
    total += maxLines * (12 / 72) * 1.55 + 0.14;
  }
  return total + 0.1;
}

function estimateBlockHeight(block) {
  if (block.type === "heading") return 0.45;
  if (block.type === "para") return estimateParaHeight(block.text, 14);
  if (block.type === "list") return estimateListHeight(block.items, 14, block.ordered);
  if (block.type === "code") return estimateCodeHeight(block.lines.length);
  if (block.type === "table") return estimateTableHeight(block);
  return 0.3;
}

// ---------- slide rendering ----------

function addTitle(slide, titleText, continuation) {
  slide.addText(titleText + (continuation ? "  (続き)" : ""), {
    x: MARGIN_X,
    y: TITLE_Y,
    w: CONTENT_W,
    h: TITLE_H,
    fontFace: "Calibri",
    fontSize: 26,
    bold: true,
    color: GH.text,
    align: "left",
    valign: "top",
    isTextBox: true,
    margin: 0,
  });
}

function addPara(slide, block, y) {
  const h = estimateParaHeight(block.text, 14);
  slide.addText(parseInline(block.text), {
    x: MARGIN_X,
    y,
    w: CONTENT_W,
    h,
    fontFace: "Calibri",
    fontSize: 14,
    color: GH.text,
    align: "left",
    valign: "top",
    isTextBox: true,
    margin: 0,
  });
  return h;
}

function addSubHeading(slide, block, y) {
  slide.addText(block.text, {
    x: MARGIN_X,
    y,
    w: CONTENT_W,
    h: 0.4,
    fontFace: "Calibri",
    fontSize: 18,
    bold: true,
    color: GH.text,
    align: "left",
    valign: "top",
    isTextBox: true,
    margin: 0,
  });
  return 0.45;
}

function addList(slide, block, y) {
  const h = estimateListHeight(block.items, 14, block.ordered);
  const flat = [];
  block.items.forEach((item, idx) => {
    const runs = parseInline(item);
    runs.forEach((r, ri) => {
      const opts = Object.assign({}, r.options);
      if (ri === 0) opts.bullet = block.ordered ? { type: "number" } : true;
      if (idx < block.items.length - 1 && ri === runs.length - 1) opts.breakLine = true;
      opts.paraSpaceAfter = 6;
      flat.push({ text: r.text, options: opts });
    });
  });
  slide.addText(flat, {
    x: MARGIN_X,
    y,
    w: CONTENT_W,
    h,
    fontFace: "Calibri",
    fontSize: 14,
    color: GH.text,
    align: "left",
    valign: "top",
    isTextBox: true,
    margin: 0,
  });
  return h;
}

function addCode(slide, block, y) {
  const lineCount = Math.max(1, block.lines.length);
  const h = estimateCodeHeight(lineCount);
  slide.addShape("roundRect", {
    x: MARGIN_X,
    y,
    w: CONTENT_W,
    h,
    rectRadius: 0.06,
    fill: { color: GH.codeBg },
    line: { color: GH.border, width: 1 },
  });
  const codeRuns = [];
  block.lines.forEach((l, idx) => {
    codeRuns.push({
      text: l.length ? l : " ",
      options: { breakLine: idx < block.lines.length - 1 },
    });
  });
  slide.addText(codeRuns, {
    x: MARGIN_X + 0.15,
    y: y + 0.1,
    w: CONTENT_W - 0.3,
    h: h - 0.2,
    fontFace: "Courier New",
    fontSize: 12,
    color: GH.text,
    align: "left",
    valign: "top",
    isTextBox: true,
    margin: 0,
  });
  return h + 0.15;
}

function cellRuns(cellText) {
  // table cell "text" accepts the same rich-text run array as addText
  return parseInline(cellText).map((r) => ({ text: r.text, options: r.options }));
}

function addTable(slide, block, y) {
  const rows = [];
  rows.push(
    block.header.map((c) => ({
      text: cellRuns(c),
      options: { bold: true, fill: { color: GH.tableHeaderBg }, color: GH.text },
    }))
  );
  block.rows.forEach((r, idx) => {
    rows.push(
      r.map((c) => ({
        text: cellRuns(c),
        options: {
          fill: { color: idx % 2 === 1 ? GH.tableStripeBg : GH.bg },
          color: GH.text,
        },
      }))
    );
  });
  const h = estimateTableHeight(block);
  slide.addTable(rows, {
    x: MARGIN_X,
    y,
    w: CONTENT_W,
    h,
    fontFace: "Calibri",
    fontSize: 12,
    border: { type: "solid", color: GH.border, pt: 0.75 },
    autoPage: false,
    valign: "top",
  });
  return h + 0.15;
}

// ---------- deck builder ----------

function buildDeck(blocks, deckTitle) {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.theme = { headFontFace: "Calibri", bodyFontFace: "Calibri" };

  // cover slide
  const cover = pres.addSlide();
  cover.background = { color: GH.bg };
  cover.addText(deckTitle, {
    x: MARGIN_X,
    y: 2.8,
    w: CONTENT_W,
    h: 1.2,
    fontFace: "Calibri",
    fontSize: 40,
    bold: true,
    color: GH.text,
    align: "left",
    isTextBox: true,
    margin: 0,
  });
  cover.addText("Generated from Markdown, styled after GitHub's markdown rendering", {
    x: MARGIN_X,
    y: 4.0,
    w: CONTENT_W,
    h: 0.5,
    fontFace: "Calibri",
    fontSize: 16,
    color: GH.muted,
    align: "left",
    isTextBox: true,
    margin: 0,
  });

  let slide = null;
  let y = BODY_TOP;
  let currentTitle = deckTitle;
  let isContinuation = false;

  function newSlide(title, continuation) {
    slide = pres.addSlide();
    slide.background = { color: GH.bg };
    addTitle(slide, title, continuation);
    y = BODY_TOP;
  }

  const maxCodeLinesPerSlide = Math.max(4, Math.floor((BODY_BOTTOM - BODY_TOP - 0.3) / 0.235));

  function placeBlock(block) {
    if (slide === null) newSlide(currentTitle, false);
    const estH = block.type === "heading" ? 0.45 : estimateBlockHeight(block);
    if (y + estH > BODY_BOTTOM && y > BODY_TOP + 0.01) {
      isContinuation = true;
      newSlide(currentTitle, true);
    }
    if (block.type === "heading") {
      y += addSubHeading(slide, block, y);
    } else if (block.type === "para") {
      y += addPara(slide, block, y) + 0.12;
    } else if (block.type === "list") {
      y += addList(slide, block, y) + 0.12;
    } else if (block.type === "code") {
      y += addCode(slide, block, y) + 0.12;
    } else if (block.type === "table") {
      y += addTable(slide, block, y) + 0.12;
    }
  }

  for (const block of blocks) {
    if (block.type === "heading" && block.level <= 2) {
      currentTitle = block.text;
      isContinuation = false;
      newSlide(currentTitle, false);
      continue;
    }
    if (block.type === "code" && block.lines.length > maxCodeLinesPerSlide) {
      // split oversized code blocks across as many slides as needed
      for (let start = 0; start < block.lines.length; start += maxCodeLinesPerSlide) {
        const chunk = block.lines.slice(start, start + maxCodeLinesPerSlide);
        placeBlock({ type: "code", lang: block.lang, lines: chunk });
      }
      continue;
    }
    if (block.type === "table") {
      const fullSlideH = BODY_BOTTOM - BODY_TOP;
      if (estimateTableHeight(block) > fullSlideH && block.rows.length > 1) {
        // split oversized tables into row chunks, repeating the header each time
        let chunkRows = [];
        let chunkH = estimateTableHeight({ header: block.header, rows: [] });
        for (const row of block.rows) {
          const rowH = estimateTableHeight({ header: block.header, rows: [row] }) - chunkH;
          if (chunkRows.length > 0 && chunkH + rowH > fullSlideH) {
            placeBlock({ type: "table", header: block.header, rows: chunkRows });
            chunkRows = [];
            chunkH = estimateTableHeight({ header: block.header, rows: [] });
          }
          chunkRows.push(row);
          chunkH += rowH;
        }
        if (chunkRows.length > 0) {
          placeBlock({ type: "table", header: block.header, rows: chunkRows });
        }
        continue;
      }
    }
    placeBlock(block);
  }

  return pres;
}

// ---------- CLI ----------

async function main() {
  const [, , inputPath, outputPath, titleArg] = process.argv;
  if (!inputPath || !outputPath) {
    console.error("Usage: node md_to_github_pptx.js input.md output.pptx [\"Deck Title\"]");
    process.exit(1);
  }
  const md = fs.readFileSync(inputPath, "utf8");
  const blocks = parseMarkdown(md);
  const firstH1 = blocks.find((b) => b.type === "heading" && b.level === 1);
  const title = titleArg || (firstH1 ? firstH1.text : path.basename(inputPath, path.extname(inputPath)));
  const pres = buildDeck(blocks, title);
  await pres.writeFile({ fileName: outputPath });
  console.log("wrote", outputPath);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
