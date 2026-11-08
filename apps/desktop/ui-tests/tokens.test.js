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

const STYLESHEETS = ["../ui/styles.css", "../ui/platform.css"];

/// Every rule in a stylesheet, flattened, as `{ at, selector, declarations }`.
///
/// `at` is the enclosing at-rule preludes outermost first, so a rule inside
/// `@media (prefers-color-scheme: dark)` can be told from the same selector
/// written at the top level. `declarations` is only the custom properties, in
/// source order, which is all these tests care about.
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
    assert.ok(close < css.length, `unbalanced braces after ${prelude}`);
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

const ALL_RULES = STYLESHEETS.flatMap((file) =>
  rules(stripComments(fs.readFileSync(path.join(__dirname, file), "utf8"))),
);

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

// ----- the two copies of every dark palette ----------------------------------
//
// The OS-preference copy and the in-app-setting copy are maintained by hand
// and must agree. Six palettes is twelve blocks, and a value changed in one
// of a pair is invisible until someone switches theme mode.

test("every dark palette declares the same tokens in both of its blocks", () => {
  for (const [name, mediaSelector, themeSelector] of DARK_PALETTES) {
    const underPreference = declarationsFor(mediaSelector, { inDarkMedia: true });
    const underSetting = declarationsFor(themeSelector, { inDarkMedia: false });
    // Guard against a selector in the table above going stale: two empty
    // lists are equal, and would pass without checking anything.
    assert.ok(underPreference.length > 0, `${name}: no block matched ${mediaSelector}`);
    assert.deepEqual(underSetting, underPreference, name);
  }
});

// ----- no palette bottoms out at black or writes in white --------------------
//
// Pure white on pure black is 21:1, which halos the type and smears on an
// OLED panel. platform.css's header says why each background sits above black
// and each primary text below white; this is that rule, checkable.

const PURE_BLACK = ["#000", "#000000"];
const PURE_WHITE = ["#fff", "#ffffff"];
const BACKGROUND_TOKENS = ["--bg", "--content-bg", "--sidebar-bg"];

test("no dark palette uses pure black for a background or pure white for text", () => {
  for (const [name, , themeSelector] of DARK_PALETTES) {
    const declarations = declarationsFor(themeSelector, { inDarkMedia: false });
    assert.ok(declarations.length > 0, `${name}: no block matched ${themeSelector}`);
    const declared = new Map(declarations);
    // A palette inherits any token it does not set, so only what it declares
    // is its to answer for.
    for (const token of BACKGROUND_TOKENS) {
      if (!declared.has(token)) continue;
      const value = declared.get(token).toLowerCase();
      assert.ok(!PURE_BLACK.includes(value), `${name}: ${token} is ${value}`);
    }
    if (declared.has("--text")) {
      const value = declared.get("--text").toLowerCase();
      assert.ok(!PURE_WHITE.includes(value), `${name}: --text is ${value}`);
    }
  }
});

test("every dark palette sets a background, so the rule above has something to check", () => {
  for (const [name, , themeSelector] of DARK_PALETTES) {
    const declared = new Map(declarationsFor(themeSelector, { inDarkMedia: false }));
    assert.ok(declared.has("--bg"), `${name}: declares no --bg`);
  }
});
