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
//
// What is *not* assumed is the closing `;` of a declaration, which CSS makes
// optional on the last one in a block. Requiring it, as this once did, hid
// the last token of every block -- and a rule whose tokens were all hidden
// dropped out of the accounting below entirely, which is the one way left for
// a pure-black palette to pass without a word.

/// The at-rules the reader understands, all of which wrap a block.
/// @font-face is deliberately absent: it wraps a block the reader does not
/// descend into, so listing it would claim a handling that is not there.
const BLOCK_AT_RULES = ["@media", "@supports", "@keyframes", "@layer"];

/// The statement at-rules the reader understands. Each ends at a `;` and
/// wraps nothing, so the reader steps over them rather than descending.
const STATEMENT_AT_RULES = ["@layer", "@charset", "@import", "@namespace"];

/// Fail on a statement at-rule nobody has thought about, rather than folding
/// it into the prelude of the block that follows.
function assertStatementsAreKnown(text) {
  for (const statement of text.split(";").map((s) => s.trim()).filter(Boolean)) {
    assert.ok(statement.startsWith("@"), `${statement}: a declaration outside any rule`);
    const name = statement.split(/[\s(]/)[0];
    assert.ok(
      STATEMENT_AT_RULES.includes(name),
      `${name} is not a statement at-rule the reader in this file handles. Extend it.`,
    );
  }
}

/// What follows the last rule must be nothing but statements and whitespace.
function assertNoRuleAfter(text) {
  assertStatementsAreKnown(text.replace(/[\s]/g, " "));
}

/// Every rule in a stylesheet, flattened, as `{ at, layer, selector, declarations }`.
///
/// `at` is the enclosing at-rule preludes outermost first, so a rule inside
/// `@media (prefers-color-scheme: dark)` can be told from the same selector
/// written at the top level. `declarations` is only the custom properties,
/// which is all these tests care about.
function rules(css, at = [], layer = null) {
  const found = [];
  let i = 0;
  while (true) {
    const open = css.indexOf("{", i);
    if (open === -1) {
      assertNoRuleAfter(css.slice(i));
      return found;
    }
    // A statement at-rule ends at its `;` and wraps nothing. `@layer a, b;`
    // declares the order and is not the prelude of the block after it.
    const raw = css.slice(i, open);
    const lastSemicolon = raw.lastIndexOf(";");
    assertStatementsAreKnown(raw.slice(0, lastSemicolon + 1));
    const prelude = raw.slice(lastSemicolon + 1).trim().replace(/\s+/g, " ");
    let depth = 0;
    let close = open;
    for (; close < css.length; close++) {
      if (css[close] === "{") depth += 1;
      else if (css[close] === "}" && (depth -= 1) === 0) break;
    }
    assert.ok(close < css.length, `unbalanced braces in or before: ${prelude}`);
    const body = css.slice(open + 1, close);
    if (prelude.startsWith("@")) {
      // The name is not enough: @layer has both a block form and a statement
      // form, and a statement at-rule leaves its `;` in the prelude of what
      // the reader then mistakes for its block -- which is the rule after it.
      assert.ok(
        !prelude.includes(";"),
        `${prelude}: a statement at-rule, so the reader in this file swallows the rule after it. Extend it.`,
      );
      const name = prelude.split(/[\s(]/)[0];
      assert.ok(
        BLOCK_AT_RULES.includes(name),
        `${name} is not an at-rule the reader in this file handles. Extend it.`,
      );
      // A layer is not a condition: it decides which rule wins, not which
      // rules match. Kept beside `at` rather than in it, so every test that
      // asks "under which media query was this written" reads the same as it
      // did before the stylesheets were layered.
      const inner = name === "@layer"
        ? rules(body, at, prelude.slice("@layer".length).trim() || layer)
        : rules(body, [...at, prelude], layer);
      found.push(...inner);
    } else {
      // A nested rule is the one break that makes the reader lie rather than
      // fail: customProperties() scans the whole body, so the nested block's
      // tokens are folded into this selector and the last one wins.
      assert.ok(
        !body.includes("{"),
        `${prelude}: nested rule. The reader in this file folds its declarations into the parent. Extend it.`,
      );
      found.push({ at, layer, selector: prelude, declarations: customProperties(body) });
    }
    i = close + 1;
  }
}

/// `$` is safe as an ending because rules() has already asserted the body
/// holds no nested block, so it can only be the end of this declaration list.
function customProperties(body) {
  return [...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+?)\s*(?:;|$)/g)].map((m) => [m[1], m[2].trim()]);
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
}

const ALL_RULES = [];
for (const name of STYLESHEETS) {
  const raw = fs.readFileSync(path.join(UI_DIR, name), "utf8");
  const css = stripComments(raw);
  assertStylesheetDialect(name, raw, css);
  ALL_RULES.push(...rules(css));
}

const DARK_MEDIA = "@media (prefers-color-scheme: dark)";
/// Any query that asks for the dark preference, not just the bare one: a
/// combined `… and (min-width: 721px)` is still a dark palette, and matching
/// the prelude as a string would let it fall outside every net below.
const inDarkPreference = (rule) =>
  rule.at.some((at) => at.includes("prefers-color-scheme: dark") && !/\bnot\b/.test(at));
/// Written without an enclosing at-rule. The setting-side copy is top level,
/// so a conditional override of a few tokens is a separate rule rather than
/// something that merges into the palette and reads as drift.
const atTopLevel = (rule) => rule.at.length === 0;

/// The custom properties one selector declares, merged in source order across
/// however many blocks carry it. `:root[data-theme="dark"]` is written twice
/// in styles.css -- once for the palette and once for `color-scheme` alone.
function declarationsFor(selector, { inDarkMedia }) {
  return ALL_RULES.filter(
    (rule) =>
      rule.selector === selector &&
      (inDarkMedia ? inDarkPreference(rule) : atTopLevel(rule)),
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

/// A rule that carries tokens, and so is part of some palette or override.
const carriesTokens = (rule) => rule.declarations.length > 0;

/// One rule, as `context||selector`. Context matters: `:root` at the top
/// level is the light defaults, and `:root` inside the phone query is an
/// override of a few of them.
const whereAndWhat = (rule) => `${rule.at.join(" >> ")}||${rule.selector}`;

/// The token-carrying rules that are deliberately not dark palettes: the
/// light defaults each platform starts from, the blocks that override a few
/// tokens for a width, and the one rule that declares a measurement rather
/// than a colour. Anything carrying tokens that is in neither this list nor
/// DARK_PALETTES fails the test below, so a new one is a decision somebody
/// makes on purpose rather than a palette that quietly goes unchecked.
const NOT_A_PALETTE = [
  "||:root",
  '||:root[data-platform="macos"]',
  '||:root[data-platform="windows"]',
  '||:root[data-platform="linux"]',
  '||:root[data-platform="ios"]',
  '||:root[data-platform="android"]',
  "@media (max-width: 720px)||:root",
  "@media (max-width: 900px)||.app",
  '@media (min-width: 721px)||[data-platform="ios"] .app, [data-platform="android"] .app',
];

/// Where the table says each palette's two copies are written.
function paletteKeys() {
  return DARK_PALETTES.flatMap(([, media, theme]) => [`${DARK_MEDIA}||${media}`, `||${theme}`]);
}

/// Tokens that are measurements rather than colours, and so are not part of
/// any palette wherever they are declared.
const NOT_A_COLOUR = ["--search-row-h"];

/// Whether a rule carries anything a palette would have to account for.
const carriesPaletteTokens = (rule) =>
  rule.declarations.some(([name]) => !NOT_A_COLOUR.includes(name));

test("every rule that carries tokens is a palette the table names, or a listed exception", () => {
  const accounted = new Set([...paletteKeys(), ...NOT_A_PALETTE]);
  const unaccounted = ALL_RULES.filter(carriesPaletteTokens)
    .map(whereAndWhat)
    .filter((key) => !accounted.has(key));
  assert.deepStrictEqual([...new Set(unaccounted)], [], "add each to DARK_PALETTES or to NOT_A_PALETTE");
});

test("every palette the table names is actually in the stylesheets", () => {
  const present = new Set(ALL_RULES.filter(carriesTokens).map(whereAndWhat));
  assert.deepStrictEqual(paletteKeys().filter((key) => !present.has(key)), []);
});

test("every listed exception is actually in the stylesheets", () => {
  const present = new Set(ALL_RULES.filter(carriesTokens).map(whereAndWhat));
  assert.deepStrictEqual(
    NOT_A_PALETTE.filter((key) => !present.has(key)),
    [],
    "remove it from NOT_A_PALETTE, or it will excuse whatever takes that selector next",
  );
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
  // #rgba and #rrggbbaa. Material writes 87% white as #ffffffde.
  const hex = /^#([0-9a-f]+)$/.exec(text);
  if (hex) {
    const digits = hex[1];
    if (digits.length === 4) return parseInt(digits[3] + digits[3], 16) < 255;
    if (digits.length === 8) return parseInt(digits.slice(6), 16) < 255;
    return false;
  }
  const functional = /^rgba?\(([^)]*)\)$/.exec(text);
  if (!functional) return false;
  const parts = functional[1].split(/[\s,/]+/).filter(Boolean);
  if (parts.length <= 3) return false;
  const alpha = parts[3].endsWith("%") ? Number(parts[3].slice(0, -1)) / 100 : Number(parts[3]);
  return Number.isFinite(alpha) && alpha < 1;
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
