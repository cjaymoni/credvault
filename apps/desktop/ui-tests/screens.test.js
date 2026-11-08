// Tests for the pure presentation logic in ui/screens.js. Kept out of ui/
// because that directory is the app's frontendDist and ships in the bundle.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const { esc, serverSummaryText, listGroupHtml } = require("../ui/screens.js");

const DEFAULT_SERVER = "http://127.0.0.1:8787";

// ----- the collapsed server line --------------------------------------------
//
// This line stands in for the field naming where the login credential goes,
// so what it claims has to be what the form will actually submit.

test("the line names the host, not the scheme and path around it", () => {
  assert.equal(serverSummaryText("https://vault.example.com/", DEFAULT_SERVER), "vault.example.com");
});

test("a port is part of the host and survives", () => {
  assert.equal(serverSummaryText("http://127.0.0.1:8787", DEFAULT_SERVER), "127.0.0.1:8787");
});

test("an empty field shows the default the form would fall back to", () => {
  for (const blank of ["", "   ", "\t\n", null, undefined]) {
    assert.equal(serverSummaryText(blank, DEFAULT_SERVER), "127.0.0.1:8787");
  }
});

test("surrounding whitespace is ignored, as the form ignores it", () => {
  assert.equal(serverSummaryText("  https://vault.example.com  ", DEFAULT_SERVER), "vault.example.com");
});

/// The reason the host is shown rather than the whole URL: a long URL has to
/// be cut off somewhere, and every prefix of this one reads as the bank.
test("userinfo cannot disguise the host that will receive the credential", () => {
  assert.equal(serverSummaryText("https://my-bank.example.com@evil.tld/login", DEFAULT_SERVER), "evil.tld");
});

test("a subdomain dressed up as a domain still shows the real one after it", () => {
  const dressed = "https://my-bank-example-com.evil.tld/";
  assert.equal(serverSummaryText(dressed, DEFAULT_SERVER), "my-bank-example-com.evil.tld");
});

/// The whole reason the cut is at the front: the end is the part that says
/// who actually receives the credential.
test("a host too long for the line keeps its end and loses its front", () => {
  const long = "https://my-bank-example-com-secure-login-portal.evil.tld/";
  const shown = serverSummaryText(long, DEFAULT_SERVER, 30);
  assert.ok(shown.endsWith("evil.tld"), `expected the real host to survive, got ${shown}`);
  assert.ok(shown.startsWith("\u2026"), `expected a leading ellipsis, got ${shown}`);
  assert.equal(shown.length, 30);
});

test("a host that fits is left exactly as it is", () => {
  const host = "vault.example.com";
  assert.equal(serverSummaryText(`https://${host}/`, DEFAULT_SERVER, 30), host);
});

test("a half-typed address is shown as typed rather than silently replaced", () => {
  assert.equal(serverSummaryText("https://vau", DEFAULT_SERVER), "vau");
  assert.equal(serverSummaryText("not a url", DEFAULT_SERVER), "not a url");
});

test("a unicode host is shown in the form the URL parser resolves it to", () => {
  // Punycode is what the request will use, so it is what the line must show.
  assert.equal(serverSummaryText("https://vaült.example.com", DEFAULT_SERVER), "xn--valt-1ra.example.com");
});

// ----- one section of the secrets list ---------------------------------------
//
// #list is a listbox and the rows are its options, so the wrapper the phone
// layout draws as a card must not come between them in the accessibility tree.

test("an untitled wrapper is presentational, so the listbox still owns the rows", () => {
  const html = listGroupHtml(null, '<button role="option"></button>');
  assert.match(html, /role="presentation"/);
  assert.doesNotMatch(html, /list-heading/);
});

test("a titled wrapper is a labelled group", () => {
  const html = listGroupHtml("Shared with me", '<button role="option"></button>');
  assert.match(html, /role="group" aria-label="Shared with me"/);
});

/// Both callers pass literals today. A section named after a folder, a team
/// or a tag would not be, and this is a password manager.
test("a title is escaped in the heading and in the label it also lands in", () => {
  const html = listGroupHtml('A "B" & <C>', "<button></button>");
  assert.ok(!html.includes("<C>"), `raw markup survived: ${html}`);
  assert.match(html, /aria-label="A &quot;B&quot; &amp; &lt;C&gt;"/);
  assert.match(html, /<div class="list-heading" aria-hidden="true">A &quot;B&quot; &amp; &lt;C&gt;<\/div>/);
});

test("a title that closes the attribute cannot add one of its own", () => {
  const html = listGroupHtml('x" onmouseover="alert(1)', "<button></button>");
  assert.ok(!html.includes('onmouseover="'), `attribute escaped the quotes: ${html}`);
});

/// The group's label already carries these words; announcing the heading too
/// would say them twice.
test("a heading beside a labelled group is hidden from assistive tech", () => {
  const html = listGroupHtml("Mine", "<button></button>");
  assert.match(html, /<div class="list-heading" aria-hidden="true">Mine<\/div>/);
});

test("the heading is drawn before the card, not inside it", () => {
  const html = listGroupHtml("Mine", "<button></button>");
  assert.ok(html.indexOf("list-heading") < html.indexOf("list-group"));
});

test("a section with no rows renders nothing at all, heading included", () => {
  assert.equal(listGroupHtml("Mine", ""), "");
  assert.equal(listGroupHtml(null, ""), "");
});

test("the rows are placed inside the wrapper untouched", () => {
  const rows = '<button class="item">a</button><button class="item">b</button>';
  assert.ok(listGroupHtml("Mine", rows).includes(rows));
});

// ----- escaping --------------------------------------------------------------

test("every character that can break out of markup is replaced", () => {
  assert.equal(esc(`&<>"'`), "&amp;&lt;&gt;&quot;&#39;");
});

test("the ampersand is replaced first, so escapes are not double-encoded wrongly", () => {
  assert.equal(esc("&lt;"), "&amp;lt;");
});

test("absent text is empty, not the word undefined", () => {
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
});

test("non-strings are stringified rather than thrown at", () => {
  assert.equal(esc(0), "0");
  assert.equal(esc(false), "false");
});

// ----- the guards on serverSummaryText ---------------------------------------

test("a budget too small to ellipsize does not wrap around to the whole host", () => {
  const shown = serverSummaryText("https://a-very-long-host.example.com", "x", 1);
  assert.ok(shown.length <= 2, `expected a clamped result, got ${shown}`);
});

/// A line that quietly went blank would read as "no server" rather than
/// "unknown server", which is the more dangerous of the two.
test("a missing fallback fails loudly instead of rendering nothing", () => {
  assert.throws(() => serverSummaryText("", undefined), /fallback/);
  assert.throws(() => serverSummaryText("", ""), /fallback/);
});

/// Math.max(n, NaN) is NaN, which compares false and would wave the whole
/// host through unclamped.
test("a budget that is not a number is refused rather than ignored", () => {
  const long = "https://a-very-long-host-name.example.com";
  assert.throws(() => serverSummaryText(long, "x", NaN), /budget/);
  assert.throws(() => serverSummaryText(long, "x", "30"), /budget/);
});

// ----- which platform's look -------------------------------------------------
//
// Real user agents of each webview the app runs in. The look follows the
// platform, so a misread costs the wrong styling, never safety, but it should
// still be right.

const { PLATFORMS, platformFrom, resolvePlatform, placementFor, shortcutLabel, namesShortcuts } = require("../ui/screens.js");
const fs = require("node:fs");
const path = require("node:path");

const USER_AGENTS = {
  macos: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
  windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
  linux: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  ios: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
  android: "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 Mobile Safari/537.36",
};

test("each webview's user agent maps to its own platform", () => {
  for (const [platform, ua] of Object.entries(USER_AGENTS)) {
    assert.equal(platformFrom(ua), platform, ua);
  }
});

test("Android is not mistaken for Linux, nor iOS for macOS", () => {
  assert.equal(platformFrom(USER_AGENTS.android), "android"); // its UA also says Linux
  assert.equal(platformFrom(USER_AGENTS.ios), "ios"); // its UA also says Mac OS X
});

test("an iPad, which reports itself as a Mac, is told apart by touch points", () => {
  assert.equal(platformFrom(USER_AGENTS.macos, 5), "ios");
  assert.equal(platformFrom(USER_AGENTS.macos, 0), "macos");
});

test("an unknown or missing user agent falls back to the Linux look", () => {
  for (const ua of ["", null, undefined, "SomethingElse/1.0"]) assert.equal(platformFrom(ua), "linux");
});

test("a preview override wins only when it names a known platform", () => {
  assert.equal(resolvePlatform("android", USER_AGENTS.macos), "android");
  for (const bad of [null, "", "beos", "__proto__", "toString"]) {
    assert.equal(resolvePlatform(bad, USER_AGENTS.windows), "windows", String(bad));
  }
});

test("every platform places every moving control, each in a slot the page has", () => {
  const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
  const slots = new Set([...html.matchAll(/data-slot="([^"]+)"/g)].map((m) => m[1]));
  for (const platform of PLATFORMS) {
    const placement = placementFor(platform);
    assert.deepEqual(placement.map(([control]) => control), ["search", "newSecret", "refresh", "account", "invites"], platform);
    for (const [control, slot] of placement) assert.ok(slots.has(slot), `${platform}: ${control} -> missing slot ${slot}`);
  }
});

test("asking for a platform with no layout fails loudly", () => {
  assert.throws(() => placementFor("beos"), TypeError);
  assert.throws(() => placementFor("toString"), TypeError);
  assert.throws(() => placementFor("__proto__"), TypeError);
  assert.throws(() => placementFor(undefined), TypeError);
});

// ----- how a shortcut is spelled ---------------------------------------------
//
// Both modifiers are accepted on every platform, so this only decides which
// one is printed. Printing the wrong one is the kind of detail the native
// look exists to get right.

/// What each platform should print, spelled out rather than derived, so the
/// test fails if the rule changes and not only if the code does.
const SPELLINGS = {
  macos: "\u2318N",
  ios: "\u2318N",
  windows: "Ctrl+N",
  linux: "Ctrl+N",
  android: "Ctrl+N",
};

test("the shortcut is spelled the way the platform's own apps spell it", () => {
  for (const [platform, expected] of Object.entries(SPELLINGS)) {
    assert.equal(shortcutLabel(platform, "N"), expected, platform);
  }
  assert.equal(shortcutLabel("macos", "K"), "\u2318K");
});

test("no platform the app knows is missing from the table above", () => {
  assert.deepEqual([...PLATFORMS].sort(), Object.keys(SPELLINGS).sort());
});

test("an unknown platform gets Ctrl rather than a label from Object's prototype", () => {
  for (const unknown of ["beos", "", null, undefined, "toString", "__proto__"]) {
    assert.equal(shortcutLabel(unknown, "N"), "Ctrl+N", String(unknown));
  }
});

test("a shortcut with no key fails loudly rather than naming one that is undefined", () => {
  assert.throws(() => shortcutLabel("macos"), TypeError);
  assert.throws(() => shortcutLabel("macos", ""), TypeError);
  assert.throws(() => shortcutLabel("macos", null), TypeError);
  assert.throws(() => shortcutLabel("windows", 7), TypeError);
});

// ----- which platforms print a shortcut in the interface ---------------------
//
// The desktop looks do; the phone looks do not, whatever is plugged into the
// device. A platform the app does not know gets the Linux look, but not the
// Linux convention: an unrecognised user agent is more likely to be something
// unusual than a desktop, and a shortcut named wrongly is worse than one left
// unnamed, because it can become a control's whole accessible name.

test("only the desktop looks name a shortcut", () => {
  assert.equal(namesShortcuts("macos"), true);
  assert.equal(namesShortcuts("windows"), true);
  assert.equal(namesShortcuts("linux"), true);
  assert.equal(namesShortcuts("ios"), false);
  assert.equal(namesShortcuts("android"), false);
});

test("every platform the app knows gets an answer from the list, not from Object", () => {
  for (const platform of PLATFORMS) {
    assert.equal(typeof namesShortcuts(platform), "boolean", platform);
  }
  for (const unknown of ["beos", "", null, undefined, "toString", "__proto__"]) {
    assert.equal(namesShortcuts(unknown), false, String(unknown));
  }
});
