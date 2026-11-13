// Turns docs/terms.md and docs/privacy.md into apps/desktop/ui/legal.js, the
// module the app renders them from.
//
// The documents are generated rather than retyped because legal wording that
// exists in two places drifts, and the copy a user is shown before they sign
// up is the one that has to be right. docs/*.md is the source; the generated
// module is committed so the app has no build step, and ui-tests/legal.test.js
// fails if it falls behind.
//
// Only the Markdown these documents actually use is supported: a single `#`
// title, `##` sections, paragraphs, `-` lists, `---` rules, and inline `**`
// and backticks. Anything else throws rather than being passed through, so an
// unsupported construct cannot reach the app as mangled text or as markup.
//
// Run with: node scripts/build-legal.js
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const SOURCES = [
  { key: "terms", file: "docs/terms.md", label: "Terms of Service" },
  { key: "privacy", file: "docs/privacy.md", label: "Privacy Policy" },
];
const OUTPUT = "apps/desktop/ui/legal.js";

/// A placeholder the operator still has to fill in, e.g. `[CONTACT EMAIL]`.
/// Shouting case so that ordinary bracketed prose is not mistaken for one.
const PLACEHOLDER = /\[[A-Z][^\]]*\]/;

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (text) => String(text).replace(/[&<>"']/g, (c) => ESCAPES[c]);

/// Inline markup: `` `code` ``, `**bold**` and `*italic*`.
///
/// Escaped first, so the only tags in the result are the ones added here and
/// no document can introduce markup by containing a `<`.
///
/// Every marker must be consumed. A leftover one means the document used
/// something this does not understand, and the alternative to throwing is
/// printing a stray asterisk in the middle of a legal document -- which is
/// exactly what happened to "the *service* we run" before this checked.
function inline(text) {
  let html = esc(text);
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  if (html.includes("*") || html.includes("`")) {
    throw new Error(`unbalanced inline markup: ${text}`);
  }
  return html;
}

/// One document's body as HTML, and the title and subtitle lines above it.
function convert(markdown, file) {
  // Paragraphs and list items may be wrapped across lines; join them first so
  // the block parser below only ever sees whole blocks.
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const blocks = [];
  const WRAPPABLE = new Set(["p", "item"]);
  for (const raw of lines) {
    const line = raw.trim();
    const starts = line === "---" || line.startsWith("#") || line.startsWith("- ") || !line;
    // A plain line under a paragraph or a list item is that block wrapped, not
    // a new one. Markdown wraps freely, and splitting on the newline would cut
    // `**emphasis spanning two lines**` in half -- which inline() then refuses
    // rather than emitting a stray asterisk into a legal document.
    if (!starts && blocks.length && WRAPPABLE.has(blocks.at(-1).kind)) {
      blocks.at(-1).text += ` ${line}`;
      continue;
    }
    if (!line) blocks.push({ kind: "blank", text: "" });
    else if (line === "---") blocks.push({ kind: "rule", text: "" });
    else if (line.startsWith("# ")) blocks.push({ kind: "h1", text: line.slice(2).trim() });
    else if (line.startsWith("## ")) blocks.push({ kind: "h2", text: line.slice(3).trim() });
    else if (line.startsWith("- ")) blocks.push({ kind: "item", text: line.slice(2).trim() });
    else if (/^#{3,}\s/.test(line) || /^[*+]\s/.test(line) || /^\d+\.\s/.test(line) || line.startsWith(">") || raw.startsWith("    ")) {
      throw new Error(`${file}: unsupported Markdown: ${line}`);
    } else blocks.push({ kind: "p", text: line });
  }

  let title = null;
  const html = [];
  let inList = false;
  const closeList = () => {
    if (inList) html.push("</ul>");
    inList = false;
  };
  for (const block of blocks) {
    if (block.kind !== "item") closeList();
    switch (block.kind) {
      case "blank":
      case "rule":
        break;
      case "h1":
        if (title) throw new Error(`${file}: a document has one title`);
        title = block.text;
        break;
      case "h2":
        html.push(`<h3>${inline(block.text)}</h3>`);
        break;
      case "item":
        if (!inList) html.push("<ul>");
        inList = true;
        html.push(`<li>${inline(block.text)}</li>`);
        break;
      case "p":
        html.push(`<p>${inline(block.text)}</p>`);
        break;
      default:
        throw new Error(`${file}: unhandled block ${block.kind}`);
    }
  }
  closeList();
  if (!title) throw new Error(`${file}: no title`);
  return { title, html: html.join("") };
}

/// The generated module's full text, so the build and the staleness test
/// produce the same bytes from the same sources.
function buildLegalModule(read = (file) => fs.readFileSync(path.join(ROOT, file), "utf8")) {
  const documents = {};
  for (const { key, file, label } of SOURCES) {
    const markdown = read(file);
    const { title, html } = convert(markdown, file);
    documents[key] = {
      label,
      title,
      html,
      // Whether the operator still has to fill something in. The app shows a
      // notice when this is set; ui-tests/legal.test.js makes sure it cannot
      // be dropped while a placeholder is still there.
      draft: PLACEHOLDER.test(markdown),
    };
  }
  const body = JSON.stringify(documents, null, 2);
  return `// GENERATED FILE -- do not edit.
//
// Built from docs/terms.md and docs/privacy.md by scripts/build-legal.js.
// Edit those, then re-run: node scripts/build-legal.js
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Legal = factory();
})(typeof self !== "undefined" ? self : globalThis, function () {
  return ${body.split("\n").join("\n  ")};
});
`;
}

module.exports = { buildLegalModule, convert, inline, OUTPUT, PLACEHOLDER };

if (require.main === module) {
  fs.writeFileSync(path.join(ROOT, OUTPUT), buildLegalModule());
  console.log(`wrote ${OUTPUT}`);
}
