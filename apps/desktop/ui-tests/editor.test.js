// Tests for the secret editor's shape.
//
// The form used to show seven fields and four paragraphs before the save
// button. It now shows the three a secret usually is -- name, username,
// password -- and folds the rest behind one toggle, with the two
// explanations that are disclosures rather than tips moved behind an "i".
//
// Two things have to keep holding. Editing must never hide something that is
// already filled in, or the form stops showing what it holds. And the
// disclosures must still be reachable and still say the same thing in the
// tooltip and in the text, since a shortened disclosure that drifts from the
// full one is how a true sentence becomes a false one.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { hasMoreDetails, isSaveShortcut, shortcutKeys, shortcutLabel } = require("../ui/screens.js");

const APP_JS = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");

// ----- what the fold starts as -----------------------------------------------

test("creating starts folded", () => {
  assert.equal(hasMoreDetails(null), false);
  assert.equal(hasMoreDetails(undefined), false);
});

test("a secret with nothing in those fields starts folded", () => {
  assert.equal(hasMoreDetails({ name: "Netflix", username: "me", url: "", notes: "", project: null }), false);
  // Whitespace is not content: it would open the fold on nothing.
  assert.equal(hasMoreDetails({ url: "   ", notes: "\n\t ", project: null, fields: [] }), false);
  assert.equal(hasMoreDetails({ url: null, notes: undefined, project: null }), false);
});

test("anything already filled in opens the fold", () => {
  assert.equal(hasMoreDetails({ project: { id: 1, name: "Work" } }), true);
  assert.equal(hasMoreDetails({ url: "https://example.com" }), true);
  assert.equal(hasMoreDetails({ notes: "the recovery email is .." }), true);
  assert.equal(hasMoreDetails({ fields: [{ id: 1, label: "PIN", secret: true }] }), true);
  // An empty list is not a filled-in field.
  assert.equal(hasMoreDetails({ fields: [] }), false);
});

// ----- what the form puts where ----------------------------------------------

const formSource = () => {
  const start = APP_JS.indexOf("function renderForm(existing)");
  assert.ok(start > 0, "renderForm has moved");
  return APP_JS.slice(start, APP_JS.indexOf("\n}", APP_JS.indexOf("const form = $(\"secret-form\")")));
};

test("the three fields a secret usually is stay outside the fold", () => {
  const source = formSource();
  const fold = source.indexOf('id="more-details"');
  assert.ok(fold > 0, "the fold is gone");
  const essentials = source.slice(0, fold);
  for (const id of ["f-name", "f-username", "f-password"]) {
    assert.ok(essentials.includes(`"${id}"`), `${id} was moved behind the fold`);
  }
});

test("the rest is inside it", () => {
  const source = formSource();
  const fold = source.indexOf('id="more-details"');
  const folded = source.slice(fold);
  for (const id of ["f-project", "f-url", "f-notes", "custom-fields"]) {
    assert.ok(folded.includes(id), `${id} is not behind the fold`);
  }
});

test("the fold opens from the secret rather than from a guess", () => {
  assert.match(APP_JS, /const moreOpen = Screens\.hasMoreDetails\(existing\);/);
  assert.match(APP_JS, /aria-expanded="\$\{moreOpen\}"/);
});

// ----- the disclosures -------------------------------------------------------

test("each disclosure is written once and used for both the tooltip and the text", () => {
  // infoButtonHtml() puts the same constant in the title and the paragraph,
  // so there is no second copy to fall out of step.
  for (const name of ["PROJECT_NAME_DISCLOSURE", "EXTRA_FIELDS_DISCLOSURE"]) {
    const declared = APP_JS.match(new RegExp(`^const ${name} =`, "m"));
    assert.ok(declared, `${name} is not declared where this test can find it`);
    const uses = APP_JS.match(new RegExp(`\\b${name}\\b`, "g")) || [];
    assert.ok(uses.length >= 3, `${name} is declared but barely used`);
  }
  assert.match(APP_JS, /title="\$\{esc\(text\)\}"/);
});

test("the project disclosure still says the two things it has to", () => {
  const found = APP_JS.match(/^const PROJECT_NAME_DISCLOSURE =\n\s*"([^"]+)";$/m);
  assert.ok(found, "the project disclosure is not a single string any more");
  const text = found[1];
  // Shortening it is fine; dropping either fact is not. The unencrypted one
  // has been lost from a release note once already.
  assert.match(text, /unencrypted/);
  assert.match(text, /not shared/);
});

test("an info button says what it is for and what it controls", () => {
  const helper = APP_JS.slice(APP_JS.indexOf("function infoButtonHtml("));
  const body = helper.slice(0, helper.indexOf("\n}"));
  assert.match(body, /aria-controls="\$\{controls\}"/);
  assert.match(body, /aria-expanded="false"/);
  assert.match(body, /aria-label="What this means"/);
});

test("toggling keeps aria-expanded honest", () => {
  const helper = APP_JS.slice(APP_JS.indexOf("function toggleDisclosure("));
  const body = helper.slice(0, helper.indexOf("\n}"));
  assert.match(body, /button\.setAttribute\("aria-expanded", String\(opening\)\)/);
});

// ----- saving from the keyboard ----------------------------------------------
//
// The form holds a textarea, so Enter alone cannot be submit. ⌘↩ is what a
// Mac form does, and the macOS block also moves the default button to the
// trailing edge and stops printing the shortcut under the form.

test("either modifier saves, on every platform", () => {
  assert.equal(isSaveShortcut({ key: "Enter", metaKey: true }), true);
  assert.equal(isSaveShortcut({ key: "Enter", ctrlKey: true }), true);
});

test("Enter on its own does not save", () => {
  // It is a newline in Notes; submitting there would be data loss dressed up
  // as a shortcut.
  assert.equal(isSaveShortcut({ key: "Enter" }), false);
});

test("a combination that means something else does not save", () => {
  assert.equal(isSaveShortcut({ key: "Enter", metaKey: true, altKey: true }), false);
  assert.equal(isSaveShortcut({ key: "Enter", ctrlKey: true, shiftKey: true }), false);
  assert.equal(isSaveShortcut({ key: "a", metaKey: true }), false);
  assert.equal(isSaveShortcut({ key: "Escape", metaKey: true }), false);
});

test("a missing or empty event is not a shortcut", () => {
  for (const nothing of [undefined, null, {}]) {
    assert.equal(isSaveShortcut(nothing), false);
  }
});

test("a named key keeps the spelling each spelling wants", () => {
  // aria-keyshortcuts takes the key set's own name: "Enter", never "ENTER".
  assert.equal(shortcutKeys("macos", "Enter"), "Meta+Enter");
  assert.equal(shortcutKeys("windows", "Escape"), "Control+Escape");
  assert.equal(shortcutLabel("macos", "Enter"), "\u2318Enter");
  // A single character is still upper-cased, which is the common case.
  assert.equal(shortcutKeys("macos", "n"), "Meta+N");
  assert.equal(shortcutLabel("linux", "k"), "Ctrl+K");
});

test("the form binds the shortcut rather than re-deriving it", () => {
  assert.match(APP_JS, /if \(Screens\.isSaveShortcut\(event\)\)/);
  // requestSubmit() is Safari 16 / WebKitGTK 2.38, above this app's floor,
  // so it must be reached through a check with a fallback that runs the same
  // submit handler.
  assert.match(APP_JS, /typeof form\.requestSubmit === "function"/);
  assert.match(APP_JS, /\$\("btn-save"\)\.click\(\)/);
  // requestSubmit, not submit(): submit() skips validation and the submit
  // handler, which is where every check in this form lives.
  assert.ok(!/form\.submit\(\)/.test(APP_JS), "form.submit() bypasses the submit handler");
});

test("the save button names its shortcut where the caption no longer does", () => {
  assert.match(APP_JS, /aria-keyshortcuts="\$\{Screens\.shortcutKeys\(PLATFORM, "Enter"\)\}"/);
  assert.match(APP_JS, /title="\$\{saveShortcut\} to save"/);
  const platformCss = fs.readFileSync(path.join(__dirname, "../ui/platform.css"), "utf8");
  // No `.form ` padding the selector: the platform layer already outranks
  // components, so the extra class would be the habit STYLING.md retires.
  assert.match(platformCss, /\[data-platform="macos"\] \.form-actions \{ flex-direction: row-reverse;/);
  assert.match(platformCss, /\[data-platform="macos"\] \.form-actions \.muted \{ display: none; \}/);
  assert.ok(!platformCss.includes('[data-platform="macos"] .form .form-actions'), "the padded selector is back");
});

// ----- labels inside a centred row -------------------------------------------
//
// `.field label` carries a bottom margin (6px, 8px on a phone). A label used
// as a row item rather than above a field inherits it, and because flex and
// grid centring both count margins, the item floats above everything beside
// it. It has bitten twice: the "i" beside Project, and the Hide checkbox,
// where it read as the delete button being out of line.
//
// The cascade layers now settle it -- see layers.test.js, which asserts the
// overrides live in `context`. What is left to check here is that they still
// cover both places, since the rule is easy to delete while tidying.

test("a label used as a row item has no bottom margin", () => {
  const css = fs.readFileSync(path.join(__dirname, "../ui/styles.css"), "utf8");
  const context = css.slice(css.indexOf("@layer context {"));
  for (const selector of [".label-row > label", ".custom-field .cf-hide"]) {
    assert.ok(context.includes(selector), `${selector} is gone; the row item will float above its neighbours`);
  }
  assert.match(context, /margin-bottom: 0/);
});
