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
/// Every stylesheet, read from disk rather than listed, so a palette moved
/// into a new file cannot slip past these tests.
const STYLESHEETS = fs.readdirSync(UI_DIR).filter((name) => name.endsWith(".css")).sort();

// ----- a small CSS reader ----------------------------------------------------
//
// These two stylesheets are written in a narrow dialect: no strings or url()
// in a declaration value, no statement at-rules, no native nesting. The
// reader below assumes all three, and assertStylesheetDialect() fails loudly
// if one stops holding, because each assumption fails differently -- a quote
// invents declarations silently, a brace inside a string throws, and a
// statement at-rule would swallow the rule after it.

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
    if (prelude.startsWith("@")) found.push(...rules(body, [...at, prelude]));
    else found.push({ at, selector: prelude, declarations: customProperties(body) });
    i = close + 1;
  }
}

function customProperties(body) {
  return [...body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]);
}

function stripComments(css) {
  return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

/// Fail with a useful message if a stylesheet outgrows the reader above.
/// Takes CSS with its comments already gone, and assumes no comment opened or
/// closed inside a string -- the one assumption here that is not checked.
function assertStylesheetDialect(name, css) {
  for (const atRule of ["@import", "@charset", "@layer"]) {
    assert.ok(
      !css.includes(atRule),
      `${name}: ${atRule} has no block, so the reader in this file would swallow the rule after it. Extend it.`,
    );
  }
  assert.ok(
    !css.includes("url("),
    `${name}: url() can hold a ; or a brace, which the reader in this file splits on. Extend it.`,
  );
  // Quotes themselves are fine and everywhere -- `[data-platform="macos"]`, a
  // font stack naming "SF Pro Text". What the reader cannot survive is one of
  // its own delimiters inside a string: a `;` invents a declaration that is
  // not there, a brace throws.
  for (const [quoted] of css.matchAll(/"[^"]*"|'[^']*'/g)) {
    assert.ok(
      !/[;{}]/.test(quoted),
      `${name}: ${quoted} holds a delimiter the reader in this file splits on. Extend it.`,
    );
  }
}

const ALL_RULES = [];
for (const name of STYLESHEETS) {
  const css = stripComments(fs.readFileSync(path.join(UI_DIR, name), "utf8"));
  assertStylesheetDialect(name, css);
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
      (inDarkMedia ? rule.at.includes(DARK_MEDIA) : rule.at.length === 0),
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
// but the table never names is not checked by any of them -- it would pass
// black, white and drifted without a word. This is the same hole the shortcut
// table in screens.test.js closes, read off the CSS instead of a constant.

/// A top-level `[data-theme="dark"]` block that actually carries tokens.
/// `:root[data-theme="dark"] { color-scheme: dark; }` declares none, so the
/// length check leaves it out.
const DARK_SELECTOR = /^:root[^,{]*\[data-theme="dark"\]$/;

test("the table above names every dark palette the stylesheets define", () => {
  const inStylesheets = ALL_RULES.filter(
    (rule) => rule.at.length === 0 && DARK_SELECTOR.test(rule.selector) && rule.declarations.length > 0,
  ).map((rule) => rule.selector);
  assert.deepStrictEqual(
    [...new Set(inStylesheets)].sort(),
    DARK_PALETTES.map(([, , themeSelector]) => themeSelector).sort(),
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

/// `value` as `[r, g, b]`, or null if it is written in a form this test does
/// not read. Alpha is dropped: a token these tests cover is always opaque.
function toRgb(value) {
  const text = value.trim().toLowerCase();
  if (Object.hasOwn(KEYWORDS, text)) return KEYWORDS[text];
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
    if (channels.length === 3 && channels.every(Number.isFinite)) return channels;
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
        const rgb = toRgb(declared[token]);
        assert.ok(rgb, `${name}: ${token} is ${declared[token]}, which this test cannot read. Extend toRgb().`);
        const forbidden = token === "--text" ? WHITE : BLACK;
        assert.notDeepStrictEqual(rgb, forbidden, `${name}: ${token} is ${declared[token]}`);
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
