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
