// Tests for the legal documents the app shows: ui/legal.js, and the
// scripts/build-legal.js converter that generates it from docs/*.md.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { buildLegalModule, convert, inline, OUTPUT } = require("../../../scripts/build-legal.js");
const Legal = require("../ui/legal.js");

const ROOT = path.join(__dirname, "..", "..", "..");
const DOCUMENTS = ["terms", "privacy"];

// ----- the committed module matches its sources -------------------------------
//
// The app has no build step, so ui/legal.js is generated and committed. That
// only works if falling behind is loud: an edit to docs/terms.md that never
// reached the app would leave users agreeing to wording nobody has read.

test("the generated module is what the current documents produce", () => {
  const committed = fs.readFileSync(path.join(ROOT, OUTPUT), "utf8");
  assert.equal(
    committed,
    buildLegalModule(),
    `${OUTPUT} is stale -- re-run: node scripts/build-legal.js`,
  );
});

test("both documents reached the app with a title and a body", () => {
  for (const key of DOCUMENTS) {
    assert.ok(Legal[key], `${key} is missing`);
    assert.ok(Legal[key].title.length > 0, `${key} has no title`);
    assert.ok(Legal[key].html.length > 1000, `${key} looks truncated`);
  }
});

// ----- the disclosures that must survive a rewrite ----------------------------
//
// These are the three things a user would be wronged by not being told, and
// the three a well-meaning edit is most likely to smooth away: that the
// operator can read entry names, that there is no recovery, and that this is
// a test service whose data may be deleted. Each is checked by meaning rather
// than by sentence, so the wording can change and the promise cannot vanish.

test("the privacy policy still says the operator can read entry names", () => {
  assert.match(Legal.privacy.html, /name you give each entry/i);
  assert.match(Legal.privacy.html, /stored in the clear/i);
});

test("both documents still say the passphrase cannot be recovered", () => {
  for (const key of DOCUMENTS) {
    assert.match(Legal[key].html, /cannot be recovered|cannot reset|no password recovery/i, key);
  }
});

test("both documents still say the data may be deleted", () => {
  for (const key of DOCUMENTS) {
    assert.match(Legal[key].html, /deleted|wipe/i, key);
  }
});

// ----- an unfinished document says it is unfinished ---------------------------

test("a document with the operator's details still blank is marked a draft", () => {
  for (const key of DOCUMENTS) {
    const hasPlaceholder = /\[[A-Z][^\]]*\]/.test(Legal[key].html.replace(/&quot;|&#39;|&amp;/g, ""));
    if (hasPlaceholder) {
      assert.equal(Legal[key].draft, true, `${key} has placeholders but is not flagged as a draft`);
    }
  }
});

test("a finished document is not flagged as a draft", () => {
  const built = buildLegalModule((file) =>
    file.endsWith("terms.md")
      ? "# Terms\n\nNothing left to fill in here.\n"
      : "# Privacy\n\nNor here.\n");
  assert.match(built, /"draft": false/);
  assert.doesNotMatch(built, /"draft": true/);
});

// ----- the converter cannot turn our text into someone else's markup ----------

test("single-asterisk emphasis is converted, not printed", () => {
  // It was printed, in both documents, until inline() started refusing a
  // leftover marker.
  assert.equal(inline("the *service* we run"), "the <em>service</em> we run");
  assert.match(Legal.terms.html, /<em>service<\/em>/);
  assert.doesNotMatch(Legal.terms.html + Legal.privacy.html, /\*/);
});

test("inline markup escapes before it emits any tag", () => {
  assert.equal(inline("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
  assert.equal(inline("**bold**"), "<strong>bold</strong>");
  assert.equal(inline("`code`"), "<code>code</code>");
  // An escaped angle bracket inside emphasis stays escaped.
  assert.equal(inline("**a <b> c**"), "<strong>a &lt;b&gt; c</strong>");
});

test("a stray emphasis marker is refused rather than printed", () => {
  assert.throws(() => inline("**unclosed"), /unbalanced/);
  assert.throws(() => inline("a `half"), /unbalanced/);
});

test("Markdown the converter does not handle stops the build", () => {
  for (const unsupported of ["### deeper heading", "* star bullet", "1. numbered", "> quoted"]) {
    assert.throws(
      () => convert(`# T\n\n${unsupported}\n`, "test.md"),
      /unsupported Markdown/,
      unsupported,
    );
  }
});

test("a paragraph wrapped across lines stays one paragraph", () => {
  // Markdown wraps freely; splitting on the newline would cut emphasis in
  // half and inline() would then refuse the document outright.
  const { html } = convert("# T\n\n**Emphasis spanning\ntwo lines** and more.\n", "test.md");
  assert.equal(html, "<p><strong>Emphasis spanning two lines</strong> and more.</p>");
});

test("a list item wrapped across lines stays one item", () => {
  const { html } = convert("# T\n\n- first item that\n  wraps\n- second\n", "test.md");
  assert.equal(html, "<ul><li>first item that wraps</li><li>second</li></ul>");
});

test("a blank line ends a list", () => {
  const { html } = convert("# T\n\n- only item\n\nA following paragraph.\n", "test.md");
  assert.equal(html, "<ul><li>only item</li></ul><p>A following paragraph.</p>");
});

test("a document needs exactly one title", () => {
  assert.throws(() => convert("No title here.\n", "test.md"), /no title/);
  assert.throws(() => convert("# One\n\n# Two\n", "test.md"), /one title/);
});
