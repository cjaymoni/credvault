// Tests for inviting several people to one secret at once.
//
// Sharing a credential with three colleagues used to mean opening the dialog
// three times and reading the same fingerprint warning three times, which is
// how people learn to click past it. The dialog now collects everybody
// first, looks every key up, and shows them side by side.
//
// Two things have to keep holding. Somebody who already has access must be
// caught while they are being typed, because the server answers a lookup for
// them exactly as it answers one for a stranger -- so without that check the
// owner compares a fingerprint for nothing. And a batch must not be
// all-or-nothing: an invite that reached the server is real, so one failure
// at the end cannot be reported as though none of them were sent.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const {
  splitAddresses, inviteeProblem, acceptAddresses, sendBatch, retypeOutstanding,
  normalizeFingerprint, sendInvitesLabel, inviteReasonText, MAX_INVITEES,
} = require("../ui/screens.js");

const APP_JS = fs.readFileSync(path.join(__dirname, "../ui/app.js"), "utf8");
const INDEX_HTML = fs.readFileSync(path.join(__dirname, "../ui/index.html"), "utf8");

// ----- reading what was typed ------------------------------------------------

test("addresses are separated by a comma, a semicolon or a space", () => {
  assert.deepEqual(splitAddresses("a@x.test, b@x.test;c@x.test d@x.test"),
    ["a@x.test", "b@x.test", "c@x.test", "d@x.test"]);
});

test("a pasted list survives its own stray whitespace and trailing commas", () => {
  assert.deepEqual(splitAddresses("  a@x.test ,\n b@x.test ,  "), ["a@x.test", "b@x.test"]);
});

test("nothing typed is nobody to invite", () => {
  for (const nothing of ["", "   ", ",;", null, undefined]) {
    assert.deepEqual(splitAddresses(nothing), [], `${JSON.stringify(nothing)} should add nobody`);
  }
});

// ----- who may be added ------------------------------------------------------

test("an ordinary address is added", () => {
  assert.equal(inviteeProblem("kofi@example.com"), null);
});

test("something that is not an address is refused, and says so with the text", () => {
  assert.match(inviteeProblem("kofi"), /"kofi" is not an email address/);
  assert.match(inviteeProblem("two people@example.com"), /is not an email address/);
  assert.match(inviteeProblem(""), /is not an email address/);
});

test("somebody who already has access is caught before a lookup is spent", () => {
  const problem = inviteeProblem("ama@example.com", { members: ["ama@example.com"] });
  assert.match(problem, /already has access/);
});

test("somebody with an invite still waiting is caught too", () => {
  assert.match(inviteeProblem("esi@example.com", { invites: ["esi@example.com"] }), /invite waiting/);
});

test("the same person is not added to one batch twice", () => {
  assert.match(inviteeProblem("yaw@example.com", { queued: ["yaw@example.com"] }), /already on the list/);
});

test("your own address is refused, with the reason", () => {
  assert.match(inviteeProblem("me@example.com", { me: "me@example.com" }), /your own address/);
});

test("case does not let a duplicate through", () => {
  // The dialog is more forgiving than the spec here on purpose: the local
  // part of an address is case-sensitive, so this can refuse two genuinely
  // different people. That costs one invite sent separately; the other way
  // round costs a fingerprint check compared for nothing.
  assert.match(inviteeProblem("AMA@Example.COM", { members: ["ama@example.com"] }), /already has access/);
  assert.match(inviteeProblem("Yaw@Example.com", { queued: ["yaw@example.com"] }), /already on the list/);
});

test("the batch has a ceiling, and it is named in the refusal", () => {
  const queued = Array.from({ length: MAX_INVITEES }, (_, i) => `p${i}@example.com`);
  const problem = inviteeProblem("one-more@example.com", { queued });
  assert.match(problem, new RegExp(`more than ${MAX_INVITEES} people`));
});

test("a full list still reports the more specific reason first", () => {
  // Being told "that is more than 20 people" about an address that was
  // already in the list sends the user looking for the wrong thing.
  const queued = Array.from({ length: MAX_INVITEES }, (_, i) => `p${i}@example.com`);
  assert.match(inviteeProblem("p3@example.com", { queued }), /already on the list/);
});

// ----- reading a whole typed or pasted list ----------------------------------

test("a list that parses is taken whole", () => {
  const { accepted, problem } = acceptAddresses("a@x.test, b@x.test c@x.test");
  assert.equal(problem, null);
  assert.deepEqual(accepted, ["a@x.test", "b@x.test", "c@x.test"]);
});

test("one bad address in a pasted list takes nothing", () => {
  // All or nothing is what lets the caller leave the box exactly as typed:
  // committing the good prefix means rewriting the rest of the line, and
  // rewriting it on every keystroke throws the caret to the end of the field
  // in the one place the user was just asked to go and edit.
  const { accepted, problem } = acceptAddresses("Alice <a@x.test> Bob <b@x.test>");
  assert.deepEqual(accepted, [], "nothing may be committed when anything fails");
  assert.match(problem, /"Alice" is not an email address/);
});

test("a duplicate inside one paste is caught, not just one against the list", () => {
  const { accepted, problem } = acceptAddresses("a@x.test b@x.test a@x.test");
  assert.deepEqual(accepted, []);
  assert.match(problem, /already on the list/);
});

test("the list already collected is what a paste is checked against", () => {
  const { problem } = acceptAddresses("c@x.test", { queued: ["c@x.test"] });
  assert.match(problem, /already on the list/);
  assert.equal(acceptAddresses("d@x.test", { queued: ["c@x.test"] }).problem, null);
});

test("an empty box accepts nobody and complains about nothing", () => {
  assert.deepEqual(acceptAddresses("  ,; "), { accepted: [], problem: null });
  assert.deepEqual(acceptAddresses(""), { accepted: [], problem: null });
});

// ----- what the send button says ---------------------------------------------

test("the button counts the people it is about to invite", () => {
  assert.equal(sendInvitesLabel(1), "Fingerprint matches, proceed");
  assert.equal(sendInvitesLabel(3), "Fingerprints match, proceed with 3 people");
});

test("a key that had to be retyped makes the button say so", () => {
  assert.equal(sendInvitesLabel(1, 1), "New fingerprint confirmed, invite anyway");
  assert.equal(sendInvitesLabel(4, 2), "New fingerprints confirmed, invite 4 people");
});

// ----- what the dialog does with them ----------------------------------------

// ----- assertions about the wiring, and what they are worth ------------------
//
// The tests below read app.js as text. That is the house style here, and for
// "this must live in index.html" or "this sentence must still be printed" it
// is the right tool. It is a poor one for a guard: the first version of the
// cancel guard was asserted this way and the assertion passed while the
// guard compared the wrong thing.
//
// So the rules that decide who gets an invite do not live here any more --
// they are Screens.sendBatch and Screens.retypeOutstanding, tested above
// against real inputs -- and the dialog's behaviour is driven through a real
// DOM in invite-dialog.test.js. What is left here is a handful of
// assertions about where a thing is written, which is the one job this
// technique is good at. Anything about what the interface *does* belongs in
// the other file; checked by putting the bug back and watching which file
// notices.

/// The body of one function, by name.
const bodyOf = (name) => {
  const start = APP_JS.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} is gone from app.js`);
  return APP_JS.slice(start, APP_JS.indexOf("\n}", start));
};

test("one lookup failure does not throw away the others", () => {
  const sweep = bodyOf("lookUpInvitees");
  const one = bodyOf("lookUpOne");
  assert.match(one, /catch \(error\) \{/, "a failed lookup must be caught");
  assert.match(one, /person\.error = error;/, "and kept on the person it belongs to");
  assert.ok(!/throw/.test(one), "a lookup that failed for one person must not abandon the rest");
  assert.ok(!/throw/.test(sweep), "nor may the sweep over all of them");
});

test("two checks on the same person cannot race", () => {
  // Both would see `info === null`, both would ask, and the slower answer
  // would land last -- overwriting a fingerprint that had just been typed in
  // from the other person's window with the result of an older lookup.
  const one = bodyOf("lookUpOne");
  assert.match(one, /if \(person\.pending\) return;/);
  assert.match(one, /person\.pending = true;/);
  assert.match(one, /finally \{\n\s*person\.pending = false;/);
});

test("pressing Check asks about that person and nobody else", () => {
  const body = bodyOf("recheckInvitee");
  assert.match(body, /await lookUpOne\(person\);/);
  assert.ok(!/lookUpInvitees/.test(body), "a sweep would spend a round trip on rows nobody pressed");
});

test("a fingerprint typed in from elsewhere survives the next redraw", () => {
  // The check step is rebuilt on every drop, recheck and partial failure.
  const row = bodyOf("inviteCheckRow");
  assert.match(row, /value="\$\{esc\(person\.retyped \?\? ""\)\}"/, "the field is seeded from the person");
  assert.match(bodyOf("renderInviteCheck"), /person\.retyped = input\.value;/, "and written back as it is typed");
});

// ----- sending the batch -----------------------------------------------------
//
// These drive the real loop with a fake `send`, so they fail when the
// behaviour is wrong rather than when the source is reworded. The two they
// replace asserted that `if (state.inviteFor !== id) break;` appeared before
// the invite -- which it did, while the guard it described compared the
// wrong thing and the cancel did nothing at all.

/// A person as the dialog holds one, with just enough on them to be sent.
const someone = (email, extra = {}) => ({ email, info: { email, public_key: `pk-${email}`, status: "new" }, ...extra });

test("everyone in the batch is sent to, in order", async () => {
  const people = [someone("a@x.test"), someone("b@x.test"), someone("c@x.test")];
  const seen = [];
  const { sent, failed, stopped } = await sendBatch(people, { send: async (p) => { seen.push(p.email); } });
  assert.deepEqual(seen, ["a@x.test", "b@x.test", "c@x.test"]);
  assert.equal(sent.length, 3);
  assert.deepEqual(failed, []);
  assert.equal(stopped, false);
});

test("abandoning the batch stops it, and the rest are never sent", async () => {
  // The dialog is modal: Escape reaches it while this is running.
  const people = [someone("a@x.test"), someone("b@x.test"), someone("c@x.test")];
  const seen = [];
  let gone = false;
  const { sent, stopped } = await sendBatch(people, {
    abandoned: () => gone,
    send: async (p) => { seen.push(p.email); gone = true; },
  });
  assert.deepEqual(seen, ["a@x.test"], "only the invite already in flight may go out");
  assert.equal(sent.length, 1);
  assert.equal(stopped, true, "an abandoned batch is not a finished one");
});

test("a batch abandoned before it starts sends to nobody", async () => {
  const seen = [];
  const { sent, stopped } = await sendBatch([someone("a@x.test")], {
    abandoned: () => true,
    send: async (p) => { seen.push(p.email); },
  });
  assert.deepEqual(seen, []);
  assert.deepEqual(sent, []);
  assert.equal(stopped, true);
});

test("somebody taken out of the batch while it runs is not invited", async () => {
  // Removing a person is an access decision, and the loop walks a snapshot.
  const people = [someone("a@x.test"), someone("b@x.test"), someone("c@x.test")];
  const live = [...people];
  const seen = [];
  await sendBatch(people, {
    wanted: (person) => live.includes(person),
    send: async (p) => { seen.push(p.email); live.splice(live.indexOf(people[1]), 1); },
  });
  assert.deepEqual(seen, ["a@x.test", "c@x.test"], "b was taken out mid-batch and must not be invited");
});

test("one failure does not stop the rest, and is kept with the person", async () => {
  // An invite that reached the server is real: the ones that worked stay
  // sent and only the rest are left on screen to try again.
  const people = [someone("a@x.test"), someone("b@x.test"), someone("c@x.test")];
  const { sent, failed, stopped } = await sendBatch(people, {
    send: async (p) => { if (p.email === "b@x.test") throw { code: "server", message: "refused" }; },
  });
  assert.deepEqual(sent.map((p) => p.email), ["a@x.test", "c@x.test"]);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].person.email, "b@x.test");
  assert.equal(failed[0].error.message, "refused");
  assert.equal(stopped, false);
});

test("a batch cannot be sent without something to send with", async () => {
  await assert.rejects(() => sendBatch([someone("a@x.test")], {}), TypeError);
});

// ----- the changed-key gate, out of the view ---------------------------------

test("a key that changed is outstanding until the new fingerprint is typed", () => {
  const changed = { info: { status: "changed", fingerprint: "11bb-22cc-33dd-44ee-55ff-6677" } };
  assert.equal(retypeOutstanding(changed), true, "nothing typed");
  assert.equal(retypeOutstanding({ ...changed, retyped: "0000-0000-0000-0000-0000-0000" }), true, "wrong");
  assert.equal(retypeOutstanding({ ...changed, retyped: "11bb22cc33dd44ee55ff6677" }), false, "right, unspaced");
  assert.equal(retypeOutstanding({ ...changed, retyped: "11BB-22CC-33DD-44EE-55FF-6677" }), false, "right, shouted");
});

test("a key that did not change is never outstanding", () => {
  for (const status of ["new", "known"]) {
    assert.equal(retypeOutstanding({ info: { status, fingerprint: "aaaa" } }), false, status);
  }
  assert.equal(retypeOutstanding({}), false, "nobody looked up yet");
  assert.equal(retypeOutstanding(undefined), false);
});

test("only the hex digits of a fingerprint carry meaning", () => {
  assert.equal(normalizeFingerprint("11BB-22cc 33dd"), "11bb22cc33dd");
  assert.equal(normalizeFingerprint(null), "");
});

// ----- how the dialog wires that up ------------------------------------------

test("the send is guarded by the dialog session, not the secret", () => {
  // Closing and reopening the dialog on the same secret put the id back and
  // re-armed every guard that watched it, so a cancelled batch resumed into
  // the dialog that had just replaced it.
  const body = bodyOf("sendInvites");
  assert.match(body, /const session = state\.inviteSession;/);
  assert.match(body, /abandoned: \(\) => state\.inviteSession !== session/);
  assert.ok(!/state\.inviteFor !== id/.test(body), "the secret id is not a dialog session");
  assert.match(bodyOf("openInviteDialog"), /state\.inviteSession = \+\+inviteSessions;/);
});

test("a batch cannot be started twice, and the flag cannot leak", () => {
  const body = bodyOf("sendInvites");
  assert.match(body, /if \(sendingSession === session\) return;/);
  assert.match(body, /freezeInviteCheck\(true\);/, "the step is frozen while it runs");
  // Everything that can throw is read before the flag goes up, and the flag
  // goes up inside the try: it is module state nothing else resets, so a
  // throw in between would wedge every later send for the life of the
  // process, with no error and no busy state to show for it.
  const raise = body.indexOf("sendingSession = session;");
  const guarded = body.indexOf("try {");
  const reads = body.indexOf('$("invite-message").value.trim()');
  assert.ok(guarded < raise, "the flag must go up inside the try that clears it");
  assert.ok(reads < raise, "nothing that can throw may run between the flag and the try");
  assert.match(body, /if \(sendingSession === session\) sendingSession = null;/, "cleared only if still ours");
});

test("the way out of a batch is never frozen", () => {
  // Escape is the only other route to it, and two of the five platforms
  // have no Escape key.
  assert.match(bodyOf("freezeInviteCheck"), /el\.id === "btn-invite-abandon"/);
  assert.match(bodyOf("renderInviteCheck"), /id="btn-invite-abandon"/, "the step draws its own way out");
  assert.match(bodyOf("renderInviteCheck"), /\$\("btn-invite-abandon"\)\.onclick = closeInviteDialog;/);
});

// The freeze is tested in invite-dialog.test.js, by running the step with a
// batch in flight and checking the controls are dead. It was asserted here
// for a round, by grepping this function for the call -- which matched a
// copy of the line sitting inside an event handler, where it could never
// run. The grep passed; the interface was broken. Removed rather than kept
// alongside, because a reader who sees two tests for one guard will trust
// the cheap one.

test("a person with no key is refused at the send, not only by the button", () => {
  assert.match(bodyOf("sendInvites"), /if \(!person\.info\) \{/);
});

test("a key the server substituted is an alarm, not a hint", () => {
  // `key_changed` means the server answered with a key whose fingerprint is
  // not the one it was asked for. It reached the owner as grey helper text
  // under a badge reading "Not checked", which reads as "you mis-typed".
  const row = bodyOf("inviteCheckRow");
  assert.match(row, /const substituted = code === "key_changed";/);
  assert.match(row, /badge danger">Key does not match/);
  assert.match(row, /notice danger" role="alert"/);
});

test("the changed-key gate is asked per person at send time", () => {
  assert.match(bodyOf("sendInvites"), /Screens\.retypeOutstanding\(person\)/);
});

test("the invites that were sent stay sent when a later one fails", () => {
  const body = bodyOf("sendInvites");
  assert.match(body, /state\.invitees = failed\.map\(/, "only the failures are left to try again");
  assert.match(body, /if \(sent\.length\) toast\(/, "what did go through is reported");
  assert.match(body, /renderInviteCheck\(id, /, "and the dialog stays open on the ones that did not");
});

test("every recipient gets their own invite, with the key that was confirmed", () => {
  const body = bodyOf("sendInvites");
  assert.match(body, /Screens\.sendBatch\(people, \{/, "one request per person, through the tested loop");
  assert.match(body, /confirmedPublicKey: person\.info\.public_key/, "the whole key goes back, not the fingerprint");
  assert.match(body, /email: person\.info\.email/, "and the address from the same answer as the key");
});

test("the send button is dead until every key is accounted for", () => {
  const body = bodyOf("syncInviteCheck");
  assert.match(body, /state\.invitees\.some\(\(p\) => !p\.info\)/, "an unresolved person blocks the send");
  assert.match(body, /!matched/, "and so does a fingerprint that was not typed back correctly");
});

test("the warning about where a fingerprint came from is printed, not folded", () => {
  const body = bodyOf("renderInviteCheck");
  assert.match(body, /Continue only if that fingerprint came from them directly/);
  assert.match(body, /class="dialog-lead"/, "it is the lead paragraph, not something behind an \"i\"");
});

test("a changed key is still typed back in, for every person it applies to", () => {
  const row = bodyOf("inviteCheckRow");
  assert.match(row, /info\.status === "changed"/);
  assert.match(row, /data-expect="\$\{esc\(info\.fingerprint\)\}"/);
  assert.match(row, /Confirmed before/, "the pinned fingerprint is shown beside the new one");
});

test("the list of who already has access belongs to the open secret", () => {
  // It is read by the dialog to refuse somebody who is already a member. Left
  // standing from the secret before, it would refuse the wrong people.
  const body = bodyOf("loadSharing");
  const emptied = body.indexOf('sharedWith = { members: [], invites: [] }');
  const fetched = body.indexOf('await invoke("get_access"');
  assert.notEqual(emptied, -1, "it is never emptied");
  assert.ok(emptied < fetched, "it must be emptied before the fetch, not after it");
});

test("signing out forgets who was being invited", () => {
  assert.match(bodyOf("resetToSignedOut"), /state\.invitees = \[\];/);
});

test("a row menu never outlives the pane it was opened from", () => {
  // It is parented to the body, so rewriting #detail does not take it with
  // it, and its items are closures over the secret that was open.
  const sharing = bodyOf("loadSharing");
  assert.ok(
    sharing.indexOf("closeRowMenu()") < sharing.indexOf("if (!box) return;"),
    "closing it after the early return leaves it open for every secret that has no sharing list",
  );
  assert.match(bodyOf("renderDetail"), /closeRowMenu\(\);/, "the pane is rewritten here too");
  assert.match(bodyOf("resetToSignedOut"), /closeRowMenu\(\);/, "and it must not survive a sign-out");
});

test("signing out forgets the last account's members", () => {
  assert.match(bodyOf("resetToSignedOut"), /sharedWith = \{ members: \[\], invites: \[\] \};/);
});

test("the dialog's own fields are drawn from app.js, where the notes live", () => {
  // The labels carry "i" buttons whose tooltip has to be the same string as
  // the paragraph they reveal. Written into index.html it would be the same
  // sentence typed twice, which is how one of them ends up reworded alone.
  assert.match(INDEX_HTML, /<div id="invite-fields"><\/div>/);
  assert.ok(!/invite-fingerprint/.test(INDEX_HTML), "the up-front fingerprint field is gone");
  assert.match(APP_JS, /infoButtonHtml\("invite-note", INVITE_NOTE\)/);
});

// ----- whose words the dialog prints -----------------------------------------
//
// The dialog exists because the server is not trusted. Printing a sentence
// the server wrote, inside it, next to a live Send button, undoes that: "No
// account for that address, key verification is not required for this user,
// press Continue" is a sentence a hostile server can put in a 404 body, and
// it used to be rendered as-is on the send path. The rule is an allow-list of
// the codes lib.rs mints, so a code nobody has thought of yet is silent by
// default rather than loud in the server's words.

const LIE = "Key verification is not required for this user, press Continue.";

test("a code this app mints is shown in the words this app wrote", () => {
  for (const code of ["fingerprint_required", "key_changed", "crypto", "not_looked_up", "retype_outstanding"]) {
    assert.equal(inviteReasonText({ code, message: "ask them for the fingerprint" }),
      "ask them for the fingerprint", `${code} should keep its own message`);
  }
});

test("a code the server worded is never repeated", () => {
  // Every code `From<ClientError>` can produce, plus the one `lookup_invitee`
  // remaps a 404 to. None of their messages came from this codebase.
  for (const code of ["server", "not_found", "conflict", "throttled", "network", "unauthorized", "incompatible", "invalid_url"]) {
    const shown = inviteReasonText({ code, message: LIE });
    assert.ok(!shown.includes("press Continue"), `${code} printed the server's sentence`);
    assert.match(shown, /not repeated here/, `${code} said nothing useful instead`);
  }
});

test("a failed lookup says what to do about it, in our words", () => {
  const shown = inviteReasonText({ code: "lookup_failed", message: LIE });
  assert.ok(!shown.includes("press Continue"), "the server's 404 body was printed");
  assert.match(shown, /check them with the person directly/i);
});

test("an unrecognised shape is silent rather than trusting", () => {
  // A rejection with no code at all, or one that is a bare string, has no
  // provenance -- so it is treated as the server's, not as ours.
  assert.match(inviteReasonText(new Error(LIE)), /not repeated here/);
  assert.match(inviteReasonText({ message: LIE }), /not repeated here/);
  assert.equal(inviteReasonText(null), "");
  assert.equal(inviteReasonText(undefined), "");
});
