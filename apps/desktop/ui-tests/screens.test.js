// Tests for the pure presentation logic in ui/screens.js. Kept out of ui/
// because that directory is the app's frontendDist and ships in the bundle.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { esc, serverSummaryText, appVersionLabel, listGroupHtml, listSections, namesProject, shouldPopToList, UNFILED_TITLE, SHARED_TITLE, MINE_TITLE } = require("../ui/screens.js");

const DEFAULT_SERVER = "http://127.0.0.1:8787";

// ----- the default server ----------------------------------------------------
//
// `app.js` is the shipped frontend and has no module system, so the constant
// cannot be imported; it is read as text. The test deliberately asserts the
// shape rather than the hostname, so changing which server testers are sent
// to does not touch it -- but shipping one the client would reject does.

test("the default server is a URL the Rust side will accept", () => {
  const source = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");
  const found = source.match(/^const DEFAULT_SERVER = "([^"]+)";$/m);
  assert.ok(found, "DEFAULT_SERVER is not declared where this test can find it");

  const url = new URL(found[1]);
  // http is refused for anything but loopback, and only once the password has
  // already been typed, so a bad default fails as late as it possibly could.
  assert.equal(url.protocol, "https:");
  // ServerAddress::parse rejects these outright.
  assert.equal(url.search, "");
  assert.equal(url.hash, "");
  assert.equal(url.username, "");
  assert.equal(url.password, "");
  // A path is not rejected -- `parse` keeps one, so two instances can share a
  // host. It is barred here because this literal is what the collapsed server
  // line renders, while the auth hash binds the canonical form, and a default
  // where those disagree is an inconsistency nobody would think to look for.
  // The origin check also catches an uppercase or non-ASCII host, which
  // canonicalise to something the literal no longer matches.
  assert.equal(url.pathname, "/");
  assert.equal(found[1], url.origin, "must be bare origin, no trailing slash");
});

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

// ----- the version line ------------------------------------------------------

test("the running version is labelled and shown as the bundle names it", () => {
  assert.equal(appVersionLabel("0.3.0"), "Version 0.3.0");
});

test("a pre-release suffix is carried through rather than tidied away", () => {
  assert.equal(appVersionLabel("1.0.0-rc.2"), "Version 1.0.0-rc.2");
});

test("whitespace around the number does not reach the screen", () => {
  assert.equal(appVersionLabel("  0.3.0\n"), "Version 0.3.0");
});

// The label is the easy half. What can actually break is the wiring between
// the command, the element app.js writes to, and the element index.html
// ships -- none of which a unit test of the function above would notice.
test("the version line app.js fills is the one the page ships, and it starts hidden", () => {
  const source = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");
  const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");

  assert.ok(source.includes('invoke("app_version")'), "app.js no longer asks the Rust side for the version");
  // Captured rather than written out twice: hardcoding the id on both sides
  // would let them drift together and still pass. Matched loosely on purpose
  // -- if this fails after a rename or a reformat of that line, the wiring is
  // probably fine and it is this pattern that needs updating.
  const found = source.match(/versionLine\s*=\s*\$\(\s*"([^"]+)"/);
  assert.ok(found, "app.js does not look the version line up where this test can find it");
  // The element ships hidden, so something has to unhide it; without this the
  // line could stay invisible forever with the suite still green.
  assert.ok(/versionLine\.hidden\s*=\s*false/.test(source), "nothing in app.js ever reveals the version line");

  const element = html.match(new RegExp(`<p[^>]*id="${found[1]}"[^>]*>`));
  assert.ok(element, `index.html has no element with id ${found[1]}`);
  // Hidden until the command answers, so a build that cannot name itself
  // leaves no empty row at the foot of the account panel.
  // The attribute, not the substring: `class="app-version hidden"` would
  // satisfy a plain includes() while relying on a stylesheet rule instead.
  assert.ok(/\shidden(?=[\s>=])/.test(element[0]), "the version line does not start hidden");
});

// A command that did not answer must leave the line out. The alternative --
// the word "Version" with nothing after it, or a number written into the
// markup as a fallback -- is read as a fact about the build either way.
test("nothing to show is null, not the word Version on its own", () => {
  for (const nothing of [undefined, null, "", "   "]) {
    assert.equal(appVersionLabel(nothing), null, `${JSON.stringify(nothing)} should produce no line`);
  }
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

const { PLATFORMS, platformFrom, resolvePlatform, placementFor, shortcutLabel, shortcutKeys, namesShortcuts } = require("../ui/screens.js");

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

test("on Android the account button sits beside the search field, not inside it", () => {
  // It used to ride inside the search pill, which read as a profile chip
  // glued to the input. Both halves are pinned here: it shares the row with
  // the search field, and the slot it used to sit in is gone, so it cannot
  // quietly move back.
  const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
  const placement = new Map(placementFor("android"));
  assert.equal(placement.get("account"), placement.get("search"), "account shares the search row");
  assert.ok(!html.includes('data-slot="search-end"'), "the slot inside the search pill is gone");
  for (const platform of PLATFORMS) {
    const where = new Map(placementFor(platform));
    assert.notEqual(where.get("account"), "search-end", `${platform} must not place account in the pill`);
  }
});

test("on Android the account circle is sized from the same token as the search field", () => {
  // They sit side by side on one row, so any difference in height reads as a
  // mistake. Pinned as a shared token rather than two numbers that happen to
  // agree, because two numbers drift and nothing on screen says which is wrong.
  const css = fs.readFileSync(path.join(__dirname, "../ui/platform.css"), "utf8");
  const body = (selector) => {
    const start = css.indexOf(`${selector} {`);
    assert.notEqual(start, -1, `no rule for ${selector}`);
    return css.slice(start, css.indexOf("}", start));
  };
  const ANDROID = '[data-platform="android"]';

  assert.match(body(`${ANDROID} .sidebar-search`), /--search-row-h:\s*\d+px/, "the row defines the shared height");
  for (const [selector, properties] of [
    [`${ANDROID} .sidebar-search .search`, ["height"]],
    [`${ANDROID} #btn-account`, ["width", "height"]],
    [`${ANDROID} #btn-account .acct-avatar`, ["width", "height"]],
  ]) {
    const declarations = body(selector);
    for (const property of properties) {
      assert.match(declarations, new RegExp(`${property}:\\s*var\\(--search-row-h\\)`), `${selector} -> ${property}`);
    }
  }
  // A button carries UA padding of its own, which squeezed the circle inside
  // it to 44px wide against 56px tall. Zeroing it is load-bearing, not tidying.
  assert.match(body(`${ANDROID} #btn-account`), /padding:\s*0/, "the button must not pad the circle into an oval");
});

test("the server address stays reachable on a phone", () => {
  // The narrow layout hides #server-field and shows a one-line summary in its
  // place. That is fine only while something can unfold it again: with the
  // summary a plain <p> and no rule re-showing the field, an Android user had
  // no way to change the address at any width, and the shipped default points
  // at someone else's server. Self-hosting is the product.
  const css = fs.readFileSync(path.join(__dirname, "../ui/styles.css"), "utf8");
  const html = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");
  const js = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");

  assert.match(css, /\.auth\.server-open #server-field\s*\{[^}]*display:\s*block/, "a state must re-show the field");
  // The whole tag, so the one attribute that makes it work is pinned. The
  // button sits inside <form id="auth-form">, where a missing type="button"
  // is type="submit": every tap on the server line would submit the sign-in
  // form instead of unfolding the field, which on a phone reads as "Enter
  // your email." under the line the user was trying to edit.
  const tag = html.match(/<button[^>]*id="btn-server-change"[^>]*>/);
  assert.ok(tag, "the summary must be pressable, not a caption");
  assert.match(tag[0], /type="button"/, "it must not submit the form it sits in");

  // Captured rather than grepped, so the binding has to reach the function
  // that opens the field. Four independent regexes over three files would
  // pass with the handler bound to something else entirely, as long as the
  // string appeared somewhere in app.js -- including in dead code.
  const bound = js.match(/\$\("btn-server-change"\)\.onclick\s*=\s*(\w+)/);
  assert.ok(bound, "pressing it must be wired to something");
  const handler = js.match(new RegExp(`function ${bound[1]}\\(\\)\\s*\\{[^}]*\\}`));
  assert.ok(handler, `${bound[1]}() must be a function in app.js`);
  assert.match(handler[0], /classList\.add\("server-open"\)/, "and it must open the field");

  // Clearing it on the way out is the part with no other guard: a later
  // refactor that splits resetToSignedOut loses the folded line silently, and
  // the next person to sign in sees the previous one's server already unfolded.
  const reset = js.match(/function resetToSignedOut\(\)\s*\{[\s\S]*?\n\}/);
  assert.ok(reset, "resetToSignedOut must exist");
  assert.match(reset[0], /classList\.remove\("server-open"\)/, "signing out must refold the server line");
});

test("a closed dialog stays closed: no dialog sets display outside [open]", () => {
  // A <dialog> is hidden by the browser's own `dialog:not([open]) {display:none}`.
  // Any rule that sets `display` on the element beats it, and the dialog then
  // renders in the page flow -- which is how the legal sheet came to sit at the
  // bottom of the sign-in screen, visible to anyone who scrolled that far.
  // Both stylesheets, because the page loads both and the next dialog rule
  // is as likely to be written in one as the other.
  const css = ["../ui/styles.css", "../ui/platform.css"]
    .map((sheet) => fs.readFileSync(path.join(__dirname, sheet), "utf8"))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  /// The element a selector actually targets: its last compound, with any
  /// pseudo-element or pseudo-class dropped. `.legal-dialog .legal-body`
  /// targets the body, not the dialog, and must not be flagged.
  const target = (selector) => selector.trim().split(/[\s>+~]+/).pop().replace(/::?[\w-]+(\([^)]*\))?/g, "");
  const isDialog = (compound) => /(^|[.#])(?:[\w-]*-)?dialog(?:\[[^\]]*\])*$/.test(compound);

  const offenders = [];
  for (const [, prelude, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = prelude.trim().replace(/\s+/g, " ");
    if (selector.startsWith("@") || !/(^|;)\s*display\s*:/.test(body)) continue;
    for (const one of selector.split(",")) {
      if (isDialog(target(one)) && !one.includes("[open]")) offenders.push(one.trim());
    }
  }
  assert.deepStrictEqual(offenders, [], "set display on the [open] state, or the closed dialog shows in the page");
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
  // Both spellings name the key in upper case, whatever case they are given.
  assert.equal(shortcutLabel("macos", "n"), "\u2318N");
  assert.equal(shortcutKeys("macos", "n"), "Meta+N");
});

test("no platform the app knows is missing from the table above", () => {
  assert.deepEqual([...PLATFORMS].sort(), Object.keys(SPELLINGS).sort());
});

test("an unknown platform gets Ctrl rather than a label from Object's prototype", () => {
  for (const unknown of ["beos", "", null, undefined, "toString", "__proto__"]) {
    assert.equal(shortcutLabel(unknown, "N"), "Ctrl+N", String(unknown));
  }
});

test("the announced spelling uses the spec's key names, not the printed glyph", () => {
  assert.equal(shortcutKeys("macos", "N"), "Meta+N");
  assert.equal(shortcutKeys("ios", "K"), "Meta+K");
  assert.equal(shortcutKeys("windows", "N"), "Control+N");
  assert.equal(shortcutKeys("linux", "N"), "Control+N");
  assert.equal(shortcutKeys("android", "N"), "Control+N");
});

test("the printed shortcut and the announced one agree on which modifier it is", () => {
  for (const platform of [...PLATFORMS, "beos", "", null, undefined, "__proto__"]) {
    for (const key of ["N", "k"]) {
      const printed = shortcutLabel(platform, key).startsWith("\u2318");
      const announced = shortcutKeys(platform, key).startsWith("Meta");
      assert.equal(printed, announced, `${platform} ${key}`);
    }
  }
});

test("an announced shortcut with no key fails loudly, the same as a printed one", () => {
  assert.throws(() => shortcutKeys("macos"), TypeError);
  assert.throws(() => shortcutKeys("macos", ""), TypeError);
  assert.throws(() => shortcutKeys("windows", 7), TypeError);
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

// ----- what the create-account form asks about the registration token --------
//
// The point of the `required` answer is that the form can refuse a blank
// token in its own words. Without it the app sends an empty token to a server
// it already knows will reject it, and shows the user the 403 that comes
// back -- an error written for an API caller, after a round-trip that was
// never going to work.

const { tokenPrompt } = require("../ui/screens.js");

test("logging in never asks for a registration token", () => {
  for (const answer of [true, false, undefined, null]) {
    assert.deepEqual(tokenPrompt(false, answer), { field: false, disclosure: false, required: false });
    // Not even if the user had opened the field while on the other tab.
    assert.deepEqual(tokenPrompt(false, answer, true), { field: false, disclosure: false, required: false });
  }
});

test("a server that requires a token says so before the form is submitted", () => {
  assert.deepEqual(tokenPrompt(true, true), { field: true, disclosure: false, required: true });
});

test("a server that requires a token is not also asked whether it does", () => {
  // The disclosure button's words are a question. Once the server has
  // answered it, leaving the question on screen is noise.
  assert.equal(tokenPrompt(true, true).disclosure, false);
  assert.equal(tokenPrompt(true, false).disclosure, false);
});

test("a server that needs no token shows neither the field nor the question", () => {
  assert.deepEqual(tokenPrompt(true, false), { field: false, disclosure: false, required: false });
});

test("a server that has not answered yet is the one case worth asking about", () => {
  for (const unknown of [undefined, null]) {
    assert.deepEqual(tokenPrompt(true, unknown), { field: false, disclosure: true, required: false }, String(unknown));
  }
});

test("only a literal true means required, so a truthy answer is not mistaken for one", () => {
  // `registration_token_required` arrives over IPC. Anything that is not the
  // boolean the server sent is an unknown answer, not a yes.
  for (const notTrue of ["true", 1, {}, "yes"]) {
    assert.equal(tokenPrompt(true, notTrue).required, false, String(notTrue));
  }
});

test("a field the user opened stays open across a re-render", () => {
  assert.deepEqual(tokenPrompt(true, undefined, true), { field: true, disclosure: false, required: false });
  // Including after a submit failed on a server whose capabilities said no
  // token was needed: folding it away would hide the recovery.
  assert.deepEqual(tokenPrompt(true, false, true), { field: true, disclosure: false, required: false });
});

test("the prompt cannot be mutated by whoever renders it", () => {
  // Frozen rather than throwing: screens.js is a plain script, so a sloppy
  // assignment is silently dropped. What matters is that it cannot turn a
  // required token into an optional one for the next caller.
  const prompt = tokenPrompt(true, true);
  prompt.required = false;
  assert.equal(prompt.required, true);
  assert.equal(tokenPrompt(true, true).required, true);
});

// ----- how the vault is divided into sections --------------------------------

/// `project` mirrors what the Rust hands over: an owned secret may carry an
/// id, a shared one never does.
function secret(name, { owner = true, project = null } = {}) {
  return { id: name, name, is_owner: owner, project };
}
const titles = (sections) => sections.map((s) => s.title);
const names = (section) => section.secrets.map((s) => s.name);

test("a vault with nothing to label draws one unlabelled section", () => {
  const sections = listSections([secret("Gmail"), secret("Jira")], []);
  assert.deepStrictEqual(titles(sections), [null]);
  assert.deepStrictEqual(names(sections[0]), ["Gmail", "Jira"]);
});

test("projects lead, in the order the account lists them, and unfiled follows", () => {
  const perspectiv = { id: 1, name: "Perspectiv" };
  const home = { id: 2, name: "Home" };
  const sections = listSections(
    [
      secret("Netflix"),
      secret("Cloudflare", { project: { id: 1, name: "Perspectiv" } }),
      secret("Router", { project: { id: 2, name: "Home" } }),
      secret("Jira", { project: { id: 1, name: "Perspectiv" } }),
    ],
    // Deliberately not alphabetical: the order is the server's, so renaming
    // a project cannot reshuffle the vault under someone mid-scroll.
    [perspectiv, home],
  );
  assert.deepStrictEqual(titles(sections), ["Perspectiv", "Home", UNFILED_TITLE]);
  assert.deepStrictEqual(names(sections[0]), ["Cloudflare", "Jira"]);
  assert.deepStrictEqual(names(sections[2]), ["Netflix"]);
});

test("a vault with no projects keeps the heading it had before projects existed", () => {
  // Someone who never makes a project should not find their own secrets
  // relabelled "Unfiled" the day the feature ships.
  const sections = listSections([secret("Gmail"), secret("Theirs", { owner: false })], []);
  assert.deepStrictEqual(titles(sections), [MINE_TITLE, SHARED_TITLE]);
});

test("the leftovers are only called Unfiled when there is something to be unfiled from", () => {
  const withProject = listSections(
    [secret("Cloudflare", { project: { id: 1, name: "Perspectiv" } }), secret("Netflix")],
    [{ id: 1, name: "Perspectiv" }],
  );
  assert.deepStrictEqual(titles(withProject), ["Perspectiv", UNFILED_TITLE]);
});

test("a project with nothing visible under it draws no empty heading", () => {
  const sections = listSections([secret("Netflix")], [{ id: 1, name: "Perspectiv" }]);
  assert.deepStrictEqual(titles(sections), [null]);
});

test("secrets other people own come last and are never grouped by project", () => {
  // Two owners can both have a project called Perspectiv. Grouping shared
  // secrets by that name would file two different things as one.
  const sections = listSections(
    [
      secret("Mine", { project: { id: 1, name: "Perspectiv" } }),
      secret("Hers", { owner: false, project: { id: null, name: "Perspectiv" } }),
      secret("His", { owner: false, project: { id: null, name: "Perspectiv" } }),
    ],
    [{ id: 1, name: "Perspectiv" }],
  );
  assert.deepStrictEqual(titles(sections), ["Perspectiv", SHARED_TITLE]);
  assert.deepStrictEqual(names(sections[0]), ["Mine"]);
  assert.deepStrictEqual(names(sections[1]), ["Hers", "His"]);
});

test("a secret filed under a project this list has not heard of is still shown", () => {
  // Another device renamed or created it since the list was fetched. Losing
  // the heading is survivable; losing the row is not.
  const sections = listSections([secret("Cloudflare", { project: { id: 9, name: "Perspectiv" } })], []);
  assert.deepStrictEqual(titles(sections), ["Perspectiv"]);
  assert.deepStrictEqual(names(sections[0]), ["Cloudflare"]);
});

test("a project named after an Object property is not one", () => {
  const sections = listSections(
    [
      secret("A", { project: { id: "__proto__", name: "__proto__" } }),
      secret("B", { project: { id: "toString", name: "toString" } }),
    ],
    [{ id: "__proto__", name: "__proto__" }, { id: "toString", name: "toString" }],
  );
  assert.deepStrictEqual(titles(sections), ["__proto__", "toString"]);
  assert.deepStrictEqual(names(sections[0]), ["A"]);
});

test("a project name reaches the markup escaped, in both the heading and its label", () => {
  const html = listGroupHtml('Perspectiv<img src=x onerror="alert(1)">', "<button></button>");
  assert.ok(!html.includes("<img"), html);
  assert.ok(html.includes("&lt;img"), html);
  assert.ok(html.includes('aria-label="Perspectiv&lt;img'), html);
});

test("an empty or missing vault is no sections at all", () => {
  assert.deepStrictEqual(listSections([], [{ id: 1, name: "Perspectiv" }]), []);
  assert.deepStrictEqual(listSections(undefined, undefined), []);
});

// ----- the limits the interface enforces -------------------------------------

/// `UI` holds the limits the forms enforce: a default for each, overwritten at
/// startup by what the Rust crates actually enforce. Reading one that was
/// never declared yields `undefined`, which reaches the markup as
/// `maxlength="undefined"` — an attribute browsers ignore, so the box silently
/// accepts anything and the only complaint arrives from the server, after the
/// round trip the limit existed to avoid. It is not a crash and no amount of
/// clicking shows it, which is exactly why it is worth a test.
test("every UI limit the interface reads is one it declares", () => {
  const source = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");
  const declaration = source.match(/^const UI = \{([^}]*)\};/m);
  assert.ok(declaration, "app.js should declare its UI defaults in one object literal");
  const declared = new Set([...declaration[1].matchAll(/(\w+):/g)].map((m) => m[1]));
  const used = new Set([...source.matchAll(/\bUI\.(\w+)/g)].map((m) => m[1]));
  const missing = [...used].filter((name) => !declared.has(name));
  assert.deepStrictEqual(missing, [], `UI.${missing.join(", UI.")} is read but never declared`);
});

/// The other half: a default that nothing overwrites is a number this build
/// made up. It stays in step with the crates only by luck, and the comment on
/// the startup fetch ("the defaults above match the crates today") is only
/// true while every one of them is actually fetched.
test("every UI limit the interface declares is one the backend sends", () => {
  const source = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");
  const declared = new Set([...source.match(/^const UI = \{([^}]*)\};/m)[1].matchAll(/(\w+):/g)].map((m) => m[1]));
  const assignment = source.match(/Object\.assign\(UI, \{([^}]*)\}/);
  assert.ok(assignment, "app.js should refresh its UI defaults from ui_constants");
  const refreshed = new Set([...assignment[1].matchAll(/(\w+):/g)].map((m) => m[1]));
  const stale = [...declared].filter((name) => !refreshed.has(name));
  assert.deepStrictEqual(stale, [], `UI.${stale.join(", UI.")} is a guess the backend never corrects`);
});

// ----- typing a project's name to confirm deleting it ------------------------
//
// The point of the ritual is catching "I clicked the wrong row". So the only
// question that matters about this comparison is whether it can ever accept
// the name of a *different* project, and both of the liberties an earlier
// version took could do exactly that.

test("the whole name, exactly, is what confirms a delete", () => {
  assert.ok(namesProject("Perspectiv", "Perspectiv"));
  // Ends trimmed, because the server trims before storing: a trailing space
  // was never part of the name, so refusing one would be a riddle.
  assert.ok(namesProject("  Perspectiv  ", "Perspectiv"));
  // The first word of a two-word name is the commonest way to stall here.
  assert.ok(!namesProject("Perspectiv", "Perspectiv Ops"));
  assert.ok(!namesProject("", "Perspectiv"));
  assert.ok(!namesProject("   ", "Perspectiv"));
});

test("case is not forgiven, because the server's uniqueness rule is ASCII-only", () => {
  // `projects_owner_name` is COLLATE NOCASE, which folds A-Z and nothing
  // else -- so "Café" and "CAFÉ" can both exist in one account. Lower-casing
  // here would fold them together and accept the name of the project the
  // user did *not* click.
  assert.ok(!namesProject("café", "CAFÉ"));
  assert.ok(!namesProject("perspectiv", "Perspectiv"));
});

test("interior spaces are not collapsed, because two such names can coexist", () => {
  // validate_project_name trims the ends and nothing more, so these are two
  // distinct, simultaneously creatable projects.
  assert.ok(!namesProject("Perspectiv Ops", "Perspectiv  Ops"));
  assert.ok(!namesProject("Perspectiv  Ops", "Perspectiv Ops"));
});

test("a project with no name is never confirmed by typing nothing", () => {
  assert.ok(!namesProject("", ""));
  assert.ok(!namesProject("   ", "   "));
  assert.ok(!namesProject(undefined, undefined));
});

test("a zero-width prefix makes a different project, and is treated as one", () => {
  // JS `trim` strips U+FEFF; Rust's does not, so validate_project_name stores
  // it and the index keeps the two rows apart. The two draw identically, so
  // re-trimming the *stored* name would confirm a delete on the row the user
  // did not click. That is the direction that matters, and it is refused.
  assert.ok(!namesProject("Perspectiv", "\ufeffPerspectiv"));
  // Both sides are trimmed by the server's rule rather than JavaScript's, so
  // a stored name that begins with U+FEFF is still reachable by typing it.
  // Trimming only the typed side with the built-in refused this too, which
  // left that project undeletable.
  assert.ok(namesProject("\ufeffPerspectiv", "\ufeffPerspectiv"));
  // And a zero-width character in front of what was typed no longer matches
  // a stored name without one -- the same asymmetry, the other way round.
  assert.ok(!namesProject("\ufeffPerspectiv", "Perspectiv"));
  // Ordinary padding is still forgiven, because the server trims that too.
  assert.ok(namesProject("\u00a0 Perspectiv \u2003", "Perspectiv"));
});

test("the same name composed two ways is the same name", () => {
  // Precomposed vs decomposed: identical on screen, different strings. Most
  // keyboards emit NFC, so without normalising, a decomposed name could
  // never be typed and its project could never be deleted.
  const precomposed = "Café";
  const decomposed = "Café";
  assert.notStrictEqual(precomposed, decomposed);
  assert.ok(namesProject(precomposed, decomposed));
  assert.ok(namesProject(decomposed, precomposed));
  // And it still refuses a different project.
  assert.ok(!namesProject(precomposed, "CAFÉ"));
});

// ----- when a phone falls back to the vault list -----------------------------

test("the detail screen is kept while anything is on it", () => {
  // This conjunction has been wrong once: the Projects panel was missing
  // from it, so every action in the panel bounced a phone user out of it.
  assert.ok(shouldPopToList({}));
  assert.ok(!shouldPopToList({ selected: 7 }));
  assert.ok(!shouldPopToList({ editing: true }));
  assert.ok(!shouldPopToList({ showingProjects: true }));
  assert.ok(!shouldPopToList({ inviteCount: 1 }));
});
