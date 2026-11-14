// Tests for the cascade layers.
//
// The stylesheets are ordered by layer, not by specificity or source order.
// That is what lets a contextual rule beat a component default without
// inflating its selector -- the trick that used to be needed, and that kept
// being lost because it looked like noise.
//
// Two things have to hold or the scheme quietly stops working. Every rule
// must be inside a layer, because an unlayered rule beats every layered one;
// and the declared order must still list the layers in the order the files
// rely on. Both are invisible when broken: the page renders, just wrong.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI_DIR = path.join(__dirname, "../ui");
const STYLESHEETS = fs.readdirSync(UI_DIR).filter((name) => name.endsWith(".css")).sort();
const read = (name) => fs.readFileSync(path.join(UI_DIR, name), "utf8");
const withoutComments = (css) => css.replace(/\/\*[\s\S]*?\*\//g, "");

/// The top-level blocks of a stylesheet, as `{ prelude, body }`.
function topLevelBlocks(css) {
  const blocks = [];
  let i = 0;
  while (true) {
    const open = css.indexOf("{", i);
    if (open === -1) return { blocks, trailing: css.slice(i) };
    let depth = 0;
    let close = open;
    for (; close < css.length; close++) {
      if (css[close] === "{") depth += 1;
      else if (css[close] === "}" && (depth -= 1) === 0) break;
    }
    assert.ok(close < css.length, `unbalanced braces in ${css.slice(i, open).trim().slice(0, 60)}`);
    blocks.push({ prelude: css.slice(i, open).trim().replace(/\s+/g, " "), body: css.slice(open + 1, close) });
    i = close + 1;
  }
}

test("every rule lives inside a layer", () => {
  // An unlayered rule outranks every layered one, whatever its specificity,
  // so one of them silently reinstates the problem layers were adopted to
  // solve. Asserting it at the top level covers every rule beneath.
  for (const name of STYLESHEETS) {
    const { blocks, trailing } = topLevelBlocks(withoutComments(read(name)));
    for (const { prelude } of blocks) {
      const statements = prelude.split(";").map((s) => s.trim()).filter(Boolean);
      const last = statements[statements.length - 1] ?? "";
      assert.ok(
        last.startsWith("@layer "),
        `${name}: "${last.slice(0, 60)}" is outside any layer`,
      );
    }
    assert.equal(trailing.trim().replace(/;/g, ""), "", `${name}: a stray statement after the last layer`);
  }
});

test("the order is declared once, and lists every layer in use", () => {
  const declarations = read("styles.css").match(/^@layer ([^{;]+);$/m);
  assert.ok(declarations, "styles.css does not declare the layer order");
  const declared = declarations[1].split(",").map((s) => s.trim());

  const used = new Set();
  for (const name of STYLESHEETS) {
    for (const { prelude } of topLevelBlocks(withoutComments(read(name))).blocks) {
      const opened = prelude.split(";").pop().trim();
      if (opened.startsWith("@layer ")) used.add(opened.slice("@layer".length).trim());
    }
  }
  for (const layer of used) {
    assert.ok(declared.includes(layer), `${layer} is used but not in the declared order, so its place depends on load order`);
  }
});

test("the order puts each layer where the files assume it is", () => {
  const declared = read("styles.css").match(/^@layer ([^{;]+);$/m)[1].split(",").map((s) => s.trim());
  const expected = ["tokens", "base", "components", "context", "platform", "invariants"];
  assert.deepStrictEqual(declared, expected);
});

/// Every layer whose block contains `text`. A selector can legitimately
/// appear in more than one -- `.btn.danger.solid` is also named in the
/// forced-colors block in `base` -- so callers say which they mean.
function layersContaining(text) {
  const found = [];
  for (const name of STYLESHEETS) {
    for (const { prelude, body } of topLevelBlocks(withoutComments(read(name))).blocks) {
      const opened = prelude.split(";").pop().trim();
      if (opened.startsWith("@layer ") && body.includes(text)) found.push(opened.slice("@layer".length).trim());
    }
  }
  return found;
}

test("a platform cannot repaint a destructive button", () => {
  // `[data-platform="windows"] .btn` paints every button the window's surface
  // colour, and used to lose to this rule only because three classes outrank
  // two. Layers retired that accident, so the red is held deliberately now.
  const painted = ".btn.danger.solid { background: var(--danger)";
  assert.deepStrictEqual(
    layersContaining(painted),
    ["invariants"],
    "the red of a destructive button must be set in the last layer and nowhere else",
  );
});

test("row-item overrides are in context, and no longer smuggle specificity", () => {
  assert.deepStrictEqual(layersContaining(".label-row > label"), ["context"]);
  assert.deepStrictEqual(layersContaining(".custom-field .cf-hide"), ["context"]);
  // The `.field ` prefixes existed only to win a specificity tie. If one
  // comes back it means somebody did not trust the layer, which is worth
  // knowing either way.
  const css = withoutComments(read("styles.css"));
  assert.ok(!css.includes(".field .label-row"), "the specificity workaround is back");
  assert.ok(!css.includes(".field .custom-field"), "the specificity workaround is back");
});

test("platform rules are all in the platform layer", () => {
  // platform.css is wrapped whole; a rule added outside the wrapper would
  // outrank every other layer rather than just the components it dresses.
  const { blocks } = topLevelBlocks(withoutComments(read("platform.css")));
  assert.equal(blocks.length, 1, "platform.css should be one layer block");
  assert.equal(blocks[0].prelude.split(";").pop().trim(), "@layer platform");
});
