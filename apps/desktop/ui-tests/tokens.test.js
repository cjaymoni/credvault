// Tests for the two rules the colour tokens are held to, both of which used
// to live only in a comment and so were enforced by whoever happened to read
// it. Neither can be caught by looking at the app: a palette that has drifted
// renders correctly in whichever theme mode its author was in and wrong in
// the other one.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { PLATFORMS } = require("../ui/screens.js");

const UI_DIR = path.join(__dirname, "../ui");
/// Every stylesheet in ui/, read from the directory rather than listed, so a
/// palette moved into a new file cannot slip past these tests. The trade is
/// that a stylesheet vendored in from elsewhere will fail the dialect check
/// below rather than being skipped, which is deliberate: these tests would
/// otherwise quietly stop covering whatever it contains.
const STYLESHEETS = fs.readdirSync(UI_DIR).filter((name) => name.endsWith(".css")).sort();

// ----- a small CSS reader ----------------------------------------------------
//
// The stylesheets are written in a narrow dialect, and the reader below
// assumes it: block at-rules only, no nested style rules, and no delimiter of
// its own inside a string. Each assumption fails differently when broken -- a
// nested rule folds its declarations into the parent, a statement at-rule
// swallows the rule after it, a `;` in a string invents declarations that are
// not there -- and two of the three fail silently, so all three are asserted
// rather than trusted.

/// The at-rules the reader understands, all of which wrap a block.
const BLOCK_AT_RULES = ["@media", "@supports", "@keyframes", "@font-face", "@layer"];

/// Every rule in a stylesheet, flattened, as `{ at, selector, declarations }`.
///
/// `at` is the enclosing at-rule preludes outermost first, so a rule inside
/// `@media (prefers-color-scheme: dark)` can be told from the same selector
/// written at the top level. `declarations` is only the custom properties,
/// which is all these tests care about.
function rules(css, at = []) {
  const found = [];
  let i = 0;
  while (true) {
    const open = css.indexOf("{", i);
    if (open === -1) return found;
    const prelude = css.slice(i, open).trim().replace(/\s+/g, " ");
    let depth = 0;
    let close = open;
    for (; close < css.length; close++) {
      if (css[close] === "{") depth += 1;
      else if (css[close] === "}" && (depth -= 1) === 0) break;
    }
    assert.ok(close < css.length, `unbalanced braces in or before: ${prelude}`);
    const body = css.slice(open + 1, close);
    if (prelude.startsWith("@")) {
      const name = prelude.split(/[\s(]/)[0];
      assert.ok(
        BLOCK_AT_RULES.includes(name),
        `${name} is not an at-rule the reader in this file handles. If it carries no block it swallows the rule after it. Extend it.`,
      );
      found.push(...rules(body, [...at, prelude]));
    } else {
      // A nested rule is the one break that makes the reader lie rather than
      // fail: customProperties() scans the whole body, so the nested block's
      // tokens are folded into this selector and the last one wins.
      assert.ok(
        !body.includes("{"),
        `${prelude}: nested rule. The reader in this file folds its declarations into the parent. Extend it.`,
      );
      found.push({ at, selector: prelude, declarations: customProperties(body) });
    }
    i = close + 1;
  }
}

function customProperties(body) {
  return [...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]);
}

function stripComments(css) {
  return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

/// Every quoted run in some CSS. Escapes are honoured, so a `\"` inside a
/// string does not end it -- without that, text after the escape reads as if
/// it were outside the quotes and is never checked.
const QUOTED = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g;
/// The same, over CSS that still has its comments, with comments taken first
/// so their prose cannot be mistaken for a string.
const COMMENT_OR_QUOTED = /\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g;

/// Fail with a useful message if a stylesheet outgrows the reader above.
/// `raw` is the file as written; `css` is the same with comments gone.
function assertStylesheetDialect(name, raw, css) {
  assert.ok(
    !css.includes("url("),
    `${name}: url() can hold a ; or a brace, which the reader in this file splits on. Extend it.`,
  );
  // Quotes themselves are fine and everywhere -- `[data-platform="macos"]`, a
  // font stack naming "SF Pro Text". What the reader cannot survive is one of
  // its own delimiters inside a string.
  for (const [quoted] of css.matchAll(QUOTED)) {
    assert.ok(
      !/[;{}]/.test(quoted),
      `${name}: ${quoted} holds a delimiter the reader in this file splits on. Extend it.`,
    );
  }
  // Checked against the file before comments were stripped, because a comment
  // delimiter inside a string would have made stripComments() cut in the
  // wrong place and there would be nothing left to find. Comments are matched
  // first so that an apostrophe in one -- "the platform's own apps" -- is read
  // as prose rather than as the start of a string.
  for (const [token] of raw.matchAll(COMMENT_OR_QUOTED)) {
    if (token.startsWith("/*")) continue;
    assert.ok(
      !token.includes("/*") && !token.includes("*/"),
      `${name}: ${token} holds a comment delimiter, so stripComments() cuts in the wrong place. Extend it.`,
    );
  }
}

const ALL_RULES = [];
for (const name of STYLESHEETS) {
  const raw = fs.readFileSync(path.join(UI_DIR, name), "utf8");
  const css = stripComments(raw);
  assertStylesheetDialect(name, raw, css);
  ALL_RULES.push(...rules(css));
}

const DARK_MEDIA = "@media (prefers-color-scheme: dark)";

/// The custom properties one selector declares, merged in source order across
/// however many blocks carry it. `:root[data-theme="dark"]` is written twice
/// in styles.css -- once for the palette and once for `color-scheme` alone.
function declarationsFor(selector, { inDarkMedia }) {
  return ALL_RULES.filter(
    (rule) =>
      rule.selector === selector &&
      (inDarkMedia ? rule.at.includes(DARK_MEDIA) : !rule.at.includes(DARK_MEDIA)),
  ).flatMap((rule) => rule.declarations);
}

/// What a palette resolves to, which is what the browser uses: a later
/// declaration of the same token wins, and the order they were written in
/// stops mattering once they are all read.
function resolve(declarations) {
  return Object.fromEntries(declarations);
}

/// Each palette: the copy under `prefers-color-scheme` and the copy the in-app
/// Dark setting pins with `data-theme`.
const DARK_PALETTES = [
  ["the shared fallback", ':root:not([data-theme="light"])', ':root[data-theme="dark"]'],
  ["macos", ':root[data-platform="macos"]:not([data-theme="light"])', ':root[data-platform="macos"][data-theme="dark"]'],
  ["windows", ':root[data-platform="windows"]:not([data-theme="light"])', ':root[data-platform="windows"][data-theme="dark"]'],
  ["linux", ':root[data-platform="linux"]:not([data-theme="light"])', ':root[data-platform="linux"][data-theme="dark"]'],
  ["ios", ':root[data-platform="ios"]:not([data-theme="light"])', ':root[data-platform="ios"][data-theme="dark"]'],
  ["android", ':root[data-platform="android"]:not([data-theme="light"])', ':root[data-platform="android"][data-theme="dark"]'],
];

// ----- the table above has to cover the stylesheets --------------------------
//
// Every test below walks DARK_PALETTES, so a palette the stylesheets define
// but the table never names is checked by nothing -- it would pass black,
// white and drifted without a word. Both sides of every pair are enumerated,
// and neither is matched on the shape of its selector: shape is the thing
// that varies (a selector list, an unquoted attribute value, a platform
// added under the OS preference and nowhere else), so a pattern written
// around today's house style turns a palette it does not recognise into one
// that simply is not there.

/// A rule that carries tokens and so is part of some palette.
const carriesTokens = (rule) => rule.declarations.length > 0;

test("the table above names every dark palette the stylesheets define", () => {
  const underPreference = ALL_RULES.filter((rule) => rule.at.includes(DARK_MEDIA) && carriesTokens(rule));
  const underSetting = ALL_RULES.filter(
    (rule) =>
      !rule.at.includes(DARK_MEDIA) &&
      rule.selector.includes("data-theme") &&
      !rule.selector.includes("light") &&
      carriesTokens(rule),
  );
  const unique = (found) => [...new Set(found.map((rule) => rule.selector))].sort();
  assert.deepStrictEqual(unique(underPreference), DARK_PALETTES.map(([, media]) => media).sort());
  assert.deepStrictEqual(unique(underSetting), DARK_PALETTES.map(([, , theme]) => theme).sort());
});

test("the palettes are the platforms the app knows, and nothing else", () => {
  const named = DARK_PALETTES.map(([name]) => name).filter((name) => name !== "the shared fallback");
  assert.deepStrictEqual([...named].sort(), [...PLATFORMS].sort());
});

// ----- the two copies of every dark palette ----------------------------------
//
// The OS-preference copy and the in-app-setting copy are maintained by hand
// and must agree. Six palettes is twelve blocks, and a value changed in one
// of a pair is invisible until someone switches theme mode.

test("every dark palette resolves to the same tokens in both of its blocks", () => {
  for (const [name, mediaSelector, themeSelector] of DARK_PALETTES) {
    const underPreference = declarationsFor(mediaSelector, { inDarkMedia: true });
    const underSetting = declarationsFor(themeSelector, { inDarkMedia: false });
    // Guard against a selector in the table going stale: two empty lists are
    // equal, and would pass without checking anything.
    assert.ok(underPreference.length > 0, `${name}: no block matched ${mediaSelector}`);
    assert.deepStrictEqual(resolve(underSetting), resolve(underPreference), name);
  }
});

// ----- no palette bottoms out at black or writes in white --------------------
//
// Pure white on pure black is 21:1, which halos the type and smears on an
// OLED panel. platform.css's header says why each background sits above black
// and each primary text below white; this is that rule, checkable. The
// invariant is about the colour, not how it was spelled, so values are read
// to rgb first -- `black` and `rgb(0, 0, 0)` are the same mistake as `#000`.

const BLACK = [0, 0, 0];
const WHITE = [255, 255, 255];
const KEYWORDS = { black: BLACK, white: WHITE };
const BACKGROUND_TOKENS = ["--bg", "--content-bg", "--sidebar-bg"];
const CHANNEL_MAX = 255;

/// Whether `value` lets what is behind it through. Such a token has no colour
/// of its own to judge: what it renders as depends on its ancestor, which
/// this test cannot see. `rgba(255, 255, 255, 0.87)` is Material's dark body
/// text and renders near #dedede -- calling it pure white would be a
/// confident wrong answer, which is worse than declining to answer.
function isTranslucent(value) {
  const text = value.trim().toLowerCase();
  if (text === "transparent") return true;
  const functional = /^rgba?\(([^)]*)\)$/.exec(text);
  if (!functional) return false;
  const parts = functional[1].split(/[\s,/]+/).filter(Boolean);
  return parts.length > 3 && Number(parts[3]) < 1;
}

/// `value` as `[r, g, b]`, or null if it is written in a form this test does
/// not read. Only called for values isTranslucent() has already passed on,
/// so any alpha here is 1.
function toRgb(value) {
  const text = value.trim().toLowerCase();
  if (Object.hasOwn(KEYWORDS, text)) return KEYWORDS[text];
  const channel = (n) => Math.min(CHANNEL_MAX, Math.max(0, Math.round(n)));
  const hex = /^#([0-9a-f]+)$/.exec(text);
  if (hex) {
    const digits = hex[1];
    const expanded = digits.length <= 4 ? [...digits].map((d) => d + d).join("") : digits;
    if (expanded.length !== 6 && expanded.length !== 8) return null;
    return [0, 2, 4].map((at) => parseInt(expanded.slice(at, at + 2), 16));
  }
  const functional = /^rgba?\(([^)]*)\)$/.exec(text);
  if (functional) {
    const channels = functional[1].split(/[\s,/]+/).filter(Boolean).slice(0, 3).map(Number);
    if (channels.length === 3 && channels.every(Number.isFinite)) return channels.map(channel);
  }
  return null;
}

test("no dark palette uses pure black for a background or pure white for text", () => {
  for (const [name, mediaSelector, themeSelector] of DARK_PALETTES) {
    // Both copies, rather than one and a lean on the test above: these tests
    // are independent, and a run where that one fails must not leave this one
    // reporting green on a block it never read.
    for (const [selector, inDarkMedia] of [[mediaSelector, true], [themeSelector, false]]) {
      const declared = resolve(declarationsFor(selector, { inDarkMedia }));
      assert.ok(Object.keys(declared).length > 0, `${name}: no block matched ${selector}`);
      for (const token of [...BACKGROUND_TOKENS, "--text"]) {
        // A palette inherits any token it does not set, so only what it
        // declares is its to answer for.
        if (!Object.hasOwn(declared, token)) continue;
        const value = declared[token];
        if (isTranslucent(value)) continue;
        const rgb = toRgb(value);
        assert.ok(rgb, `${name}: ${token} is ${value}, which this test cannot read. Extend toRgb().`);
        const forbidden = token === "--text" ? WHITE : BLACK;
        assert.notDeepStrictEqual(rgb, forbidden, `${name}: ${token} is ${value}`);
      }
    }
  }
});

test("every dark palette sets a background, so the rule above has something to check", () => {
  for (const [name, , themeSelector] of DARK_PALETTES) {
    const declared = resolve(declarationsFor(themeSelector, { inDarkMedia: false }));
    assert.ok(Object.hasOwn(declared, "--bg"), `${name}: declares no --bg`);
  }
});
