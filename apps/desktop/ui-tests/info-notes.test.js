// Tests for the "i" notes.
//
// Long descriptions that explain a screen are folded behind a button beside
// its heading. The rule for what may be folded is not a matter of length:
// an explanation of the screen folds, and what a button is about to do never
// does. These tests hold that line, because it is the kind of line that
// erodes one sentence at a time -- this repo has already lost a disclosure
// from a release note that way once.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const APP_JS = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");

/// The text of every `const *_NOTE`/`*_DISCLOSURE` string, which is what is
/// hidden until someone asks for it.
const foldedTexts = () =>
  [...APP_JS.matchAll(/^const (\w+(?:_NOTE|_DISCLOSURE)) =\n\s*"([^"]+)";$/gm)].map((m) => ({ name: m[1], text: m[2] }));

const infoButtons = () => [...APP_JS.matchAll(/infoButtonHtml\("([^"]+)",\s*(\w+)\)/g)].map((m) => ({ id: m[1], constant: m[2] }));

test("every i button has a note to reveal", () => {
  for (const { id } of infoButtons()) {
    assert.ok(
      APP_JS.includes(`class="hint hidden" id="${id}"`),
      `the button for "${id}" reveals a paragraph that does not exist`,
    );
  }
});

test("every hidden note has a button that reveals it", () => {
  // A note with no button is text nobody can ever read.
  const ids = [...APP_JS.matchAll(/class="hint hidden" id="([^"]+)"/g)].map((m) => m[1]);
  const revealed = new Set(infoButtons().map((b) => b.id));
  for (const id of ids) {
    assert.ok(revealed.has(id), `"${id}" is hidden and nothing reveals it`);
  }
});

test("the notes are wired once, for panels that redraw", () => {
  assert.match(APP_JS, /document\.addEventListener\("click", \(event\) => \{/);
  assert.match(APP_JS, /event\.target\.closest\?\.\("\[data-info-for\]"\)/);
});

test("each note is named, so the button and the text cannot drift", () => {
  const named = foldedTexts().map((n) => n.name);
  for (const { constant } of infoButtons()) {
    assert.ok(named.includes(constant), `${constant} is revealed but not declared as a note`);
  }
  assert.ok(named.length >= 5, `expected the folded notes to be declared as constants, found ${named}`);
});

// ----- what may never be folded ----------------------------------------------

/// Sentences that say what a button is about to do, or what cannot be undone.
/// Each is matched loosely, so rewording is allowed and deleting is not.
const MUST_STAY_PRINTED = [
  "There is no reset",                                  // the passphrase, at sign-up
  "can sign in to this account without your passphrase", // a linked Google account
  "Ask each person to read",                            // revoking with unconfirmed keys
  "Every other device signed in to this account is signed out", // what the button does
  "Continue only if that fingerprint came from them directly",  // accepting a key
];

test("a warning about what a button does is never folded away", () => {
  const folded = foldedTexts();
  for (const warning of MUST_STAY_PRINTED) {
    assert.ok(APP_JS.includes(warning), `"${warning}" is gone from the interface entirely`);
    for (const { name, text } of folded) {
      assert.ok(
        !text.includes(warning),
        `"${warning}" was moved into ${name}, where it is hidden until someone presses an "i"`,
      );
    }
  }
});

test("the folded notes are explanations, not consequences", () => {
  // A cheap smell test for the same line: the hidden text should not be the
  // place a reader first learns something is permanent.
  const permanent = /\b(cannot be undone|no reset|permanently|unrecoverable)\b/i;
  for (const { name, text } of foldedTexts()) {
    assert.ok(!permanent.test(text), `${name} hides the fact that something is permanent`);
  }
});
