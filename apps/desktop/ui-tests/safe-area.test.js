// Tests for the safe-area insets.
//
// The status bar, the navigation bar and the notch are kept out of the
// content by four CSS properties rather than by env(safe-area-inset-*)
// directly, because Android's WebView reports those as 0 even with the window
// edge-to-edge -- a navigation bar is a window inset and only a display
// cutout reaches CSS. That left the "New secret" button drawn behind the
// navigation bar with its lower half untappable.
//
// The halves are in three files that cannot import each other, so these tests
// are what holds them together: the stylesheets read the properties, app.js
// asks the Android host for the values, and MainActivity.kt supplies them
// under the name app.js looks for.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI_DIR = path.join(__dirname, "../ui");
const STYLESHEETS = fs.readdirSync(UI_DIR).filter((name) => name.endsWith(".css")).sort();
const STYLES = fs.readFileSync(path.join(UI_DIR, "styles.css"), "utf8");
const APP_JS = fs.readFileSync(path.join(UI_DIR, "app.js"), "utf8");
const MAIN_ACTIVITY = fs.readFileSync(
  path.join(__dirname, "../gen/android/app/src/main/java/com/klavyn/desktop/MainActivity.kt"),
  "utf8",
);

const SIDES = ["top", "right", "bottom", "left"];

test("the four insets are declared once, with an env() fallback each", () => {
  for (const side of SIDES) {
    const declarations = STYLES.match(new RegExp(`^\\s*--safe-${side}:.*$`, "gm")) || [];
    assert.equal(declarations.length, 1, `--safe-${side} is declared ${declarations.length} times`);
    // The fallback is what every platform but Android uses; without it this
    // indirection would turn working iOS insets into nothing.
    assert.match(declarations[0], new RegExp(`env\\(safe-area-inset-${side}\\)`));
  }
});

/// Comments are stripped before scanning: they discuss env() by name, and a
/// test that cannot tell prose from a declaration would either fail on a
/// comment or be loosened until it stops catching the real thing.
const withoutComments = (css) => css.replace(/\/\*[\s\S]*?\*\//g, "");

test("nothing reads env(safe-area-inset-*) at the point of use", () => {
  // A rule that reads env() directly is a rule Android computes as 0, which
  // is the whole bug. Only the four declarations above may name it.
  for (const name of STYLESHEETS) {
    const offenders = withoutComments(fs.readFileSync(path.join(UI_DIR, name), "utf8"))
      .split("\n")
      .map((line, i) => [i + 1, line.trim()])
      .filter(([, line]) => line.includes("env(safe-area-inset"))
      .filter(([, line]) => !/^--safe-(top|right|bottom|left):/.test(line));
    assert.deepStrictEqual(offenders, [], `${name} reads env(safe-area-inset-*) directly`);
  }
});

test("the edges that have bars are stepped around", () => {
  // Guards the other direction: a property nothing reads keeps none of the
  // content off anything. Only top and bottom are expected -- the left and
  // right insets are a landscape cutout, which no rule lays out for yet, and
  // they are still carried so the bridge hands over a whole set rather than
  // a shape that has to change when one is wanted.
  const all = STYLESHEETS.map((name) => fs.readFileSync(path.join(UI_DIR, name), "utf8")).join("\n");
  for (const side of ["top", "bottom"]) {
    assert.ok(all.includes(`var(--safe-${side})`), `nothing uses --safe-${side}`);
  }
  const used = new Set([...all.matchAll(/var\(--safe-(\w+)\)/g)].map((m) => m[1]));
  for (const side of used) {
    assert.ok(SIDES.includes(side), `--safe-${side} is read but never declared`);
  }
});

test("the page asks the Android host under the name the host registers", () => {
  const asked = APP_JS.match(/^\s*const bridge = window\.(\w+);$/m);
  assert.ok(asked, "app.js does not look for an inset bridge");
  const registered = MAIN_ACTIVITY.match(/const val BRIDGE_NAME = "([^"]+)"/);
  assert.ok(registered, "MainActivity.kt does not name the bridge");
  assert.equal(
    asked[1],
    registered[1],
    "app.js and MainActivity.kt disagree about the bridge name, so the insets never arrive",
  );
  assert.match(MAIN_ACTIVITY, /addJavascriptInterface\(InsetBridge\(\), BRIDGE_NAME\)/);
});

test("the host sends the four values the page unpacks", () => {
  // The bridge can only return a primitive, so the contract is a count and an
  // order. A mismatch would silently apply the wrong inset to an edge.
  assert.match(MAIN_ACTIVITY, /lastInsets\.top, lastInsets\.right, lastInsets\.bottom, lastInsets\.left/);
  const sides = APP_JS.match(/^const SAFE_AREA_SIDES = \[([^\]]+)\];$/m);
  assert.ok(sides, "app.js does not declare the order it unpacks");
  assert.deepStrictEqual(
    sides[1].split(",").map((s) => s.trim().replace(/"/g, "")),
    SIDES,
  );
});

test("the page refuses an inset it cannot use", () => {
  // The values cross a bridge as text. A negative or unparseable one would
  // pull content off the edge instead of away from it.
  assert.match(APP_JS, /if \(!Number\.isFinite\(value\) \|\| value < 0\) return;/);
  assert.match(APP_JS, /if \(pixels\.length !== SAFE_AREA_SIDES\.length\) return;/);
});

test("a platform without the bridge keeps its fallbacks", () => {
  const body = APP_JS.slice(APP_JS.indexOf("function applySafeAreaInsets()"));
  assert.match(body.slice(0, 400), /if \(!bridge \|\| typeof bridge\.cssPixels !== "function"\) return;/);
});
