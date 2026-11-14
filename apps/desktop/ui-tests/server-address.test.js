// Tests for the pinned server address.
//
// The sign-in screen no longer lets the address be edited (ALLOW_CUSTOM_SERVER
// in ui/app.js). Two things have to hold for that to mean anything, and
// neither is visible by looking at the screen: nothing may read the field
// while the flag is off -- an address an earlier build remembered would
// otherwise still be submitted, sending a credential somewhere the person can
// no longer see -- and the flag has to be the only switch, so turning it back
// on restores the feature rather than uncovering a half-removed one.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { serverUrlFor } = require("../ui/screens.js");

const FALLBACK = "https://vault.example.com";
const APP_JS = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");
const INDEX_HTML = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");

// ----- the decision itself ---------------------------------------------------

test("a pinned app submits the fallback whatever the field holds", () => {
  assert.equal(serverUrlFor(false, "https://somewhere.else", FALLBACK), FALLBACK);
  assert.equal(serverUrlFor(false, "", FALLBACK), FALLBACK);
  // The shapes a remembered value can come back as, none of which may win.
  assert.equal(serverUrlFor(false, null, FALLBACK), FALLBACK);
  assert.equal(serverUrlFor(false, undefined, FALLBACK), FALLBACK);
  assert.equal(serverUrlFor(false, "   http://127.0.0.1:8787  ", FALLBACK), FALLBACK);
});

test("an unpinned app submits what was typed, trimmed", () => {
  assert.equal(serverUrlFor(true, "  https://somewhere.else  ", FALLBACK), "https://somewhere.else");
});

test("an unpinned app falls back when nothing was typed", () => {
  assert.equal(serverUrlFor(true, "", FALLBACK), FALLBACK);
  assert.equal(serverUrlFor(true, "   ", FALLBACK), FALLBACK);
  assert.equal(serverUrlFor(true, null, FALLBACK), FALLBACK);
});

test("a missing fallback is refused rather than submitted blank", () => {
  // Same rule as serverSummaryText(): no address at all is a loud failure,
  // never a quiet empty string handed to the Rust side.
  for (const bad of [undefined, null, "", 0, {}]) {
    assert.throws(() => serverUrlFor(false, "whatever", bad), TypeError);
    assert.throws(() => serverUrlFor(true, "whatever", bad), TypeError);
  }
});

// ----- how app.js uses it ----------------------------------------------------
//
// `app.js` is the shipped frontend and has no module system, so it is read as
// text, the way the DEFAULT_SERVER test in screens.test.js reads it.

test("the address is pinned", () => {
  const found = APP_JS.match(/^const ALLOW_CUSTOM_SERVER = (true|false);$/m);
  assert.ok(found, "ALLOW_CUSTOM_SERVER is not declared where this test can find it");
  assert.equal(found[1], "false", "the address is editable again; this suite describes the pinned state");
});

test("nothing reads the server field except the one reader and the lock", () => {
  // Every other site must go through currentServerUrl(), which honours the
  // flag. A direct read is how a remembered address would get submitted.
  const reads = APP_JS.split("\n")
    .map((line, i) => [i + 1, line])
    .filter(([, line]) => /\$\("server"\)\.value/.test(line));
  const allowed = [
    'return Screens.serverUrlFor(ALLOW_CUSTOM_SERVER, $("server").value, DEFAULT_SERVER);',
    '$("server").value = (ALLOW_CUSTOM_SERVER && recall("server")) || DEFAULT_SERVER;',
    '  $("server-summary").textContent = Screens.serverSummaryText($("server").value, DEFAULT_SERVER);',
  ];
  for (const [lineNumber, line] of reads) {
    assert.ok(
      allowed.includes(line.trim()) || allowed.includes(line),
      `app.js:${lineNumber} reads the server field directly: ${line.trim()}`,
    );
  }
  assert.equal(reads.length, allowed.length, "a reader of the server field was added or removed");
});

test("every sign-in path asks for the address the same way", () => {
  // login, register and the Google sign-in all submit a serverUrl; each one
  // has to be the pinned reader, not the field.
  const matches = APP_JS.match(/^\s*const serverUrl = .*$/gm) || [];
  assert.equal(matches.length, 3, "a sign-in path was added or removed");
  for (const line of matches) {
    assert.equal(line.trim(), "const serverUrl = currentServerUrl();");
  }
});

test("a remembered address is only written while one can be chosen", () => {
  for (const line of APP_JS.split("\n").filter((l) => l.includes('remember("server"'))) {
    assert.match(line.trim(), /^if \(ALLOW_CUSTOM_SERVER\) remember\("server", serverUrl\);$/);
  }
});

test("the field and the phone line are both locked, not removed", () => {
  // Removing the markup would make the flag a lie: flipping it on has to
  // bring the feature back whole.
  assert.match(APP_JS, /function lockServerAddress\(\) \{/);
  assert.match(APP_JS, /^if \(!ALLOW_CUSTOM_SERVER\) lockServerAddress\(\);$/m);
  assert.ok(INDEX_HTML.includes('id="btn-server-change"'), "the phone line was removed");
  assert.ok(INDEX_HTML.includes('id="server-field"'), "the server field was removed");
});

test("unfolding the field does nothing while the address is pinned", () => {
  const body = APP_JS.slice(APP_JS.indexOf("function showServerField()"));
  assert.match(body.slice(0, 200), /if \(!ALLOW_CUSTOM_SERVER\) return;/);
});
