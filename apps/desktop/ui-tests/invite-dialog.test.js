// The invite dialog, driven through a real DOM.
//
// Everything here is a thing that four rounds of review found and that the
// source-text tests could not see. Each one drives the shipped interface --
// index.html and app.js, loaded the way the app loads them -- and asserts on
// what the controls do, not on how the code reads.
//
// The case that made this file necessary: `freezeInviteCheck(sendingNow())`
// was supposed to run on every redraw of the check step, so a batch going out
// could not be edited underneath itself. It was written into an event handler
// by mistake, where it could only run when no batch was going out. A grep
// test named "a redraw re-establishes the freeze rather than trusting its
// caller" passed against it for a whole round, because the string was present
// somewhere inside the function. The test below fails against that code.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const { loadApp, signIn, settle, secret, invitee } = require("./harness.js");

/// A dialog already on its second step, with `people` waiting to be invited.
///
/// Reached by driving the real controls -- open the dialog, type the
/// addresses, press Continue -- so the state under test is the state the app
/// actually builds, not one assembled by hand.
async function atCheckStep(people, answers = {}) {
  const loaded = await loadApp({
    answers: {
      list_secrets: () => [secret()],
      lookup_invitee: ({ email }) => ({
        email, fingerprint: "11bb-22cc-33dd-44ee-55ff-6677", public_key: `pk-${email}`, status: "new",
      }),
      invite: () => null,
      ...answers,
    },
  });
  await signIn(loaded);
  const { app, window, document } = loaded;
  app.openInviteDialog(1);
  document.getElementById("invite-email").value = people.join(", ");
  document.getElementById("invite-form").dispatchEvent(new window.Event("submit", { cancelable: true }));
  await settle(window);
  return loaded;
}

const enabled = (document, selector) =>
  [...document.querySelectorAll(selector)].filter((el) => !el.disabled).length;

// ----- the freeze ------------------------------------------------------------

test("a redraw while a batch is going out leaves the step frozen", async () => {
  // The blocker this file exists for. Hold the first invite open, redraw the
  // step the way a late lookup does, and the controls must still be dead.
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test"], { invite: () => held });
  const { app, window, document } = loaded;

  document.getElementById("btn-invite-confirm").click();
  await settle(window);
  assert.equal(app.sendingNow(), true, "the batch should be in flight");

  app.renderInviteCheck(1); // what recheckInvitee's finally does
  await settle(window);

  assert.equal(enabled(document, "[data-drop]"), 0, "the remove buttons came back alive mid-batch");
  assert.equal(enabled(document, "[data-check]"), 0, "the check buttons came back alive mid-batch");
  assert.equal(document.getElementById("btn-invite-back").disabled, true, "Back came back alive mid-batch");
  assert.equal(document.getElementById("btn-invite-confirm").disabled, true, "Send came back alive mid-batch");
  release(null);
  await settle(window);
});

test("the way out of a batch stays live while everything else is frozen", async () => {
  // Escape does the same thing, and two of the five platforms have no
  // Escape key, so this button is the only route on those.
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test"], { invite: () => held });
  const { window, document } = loaded;
  document.getElementById("btn-invite-confirm").click();
  await settle(window);
  assert.equal(document.getElementById("btn-invite-abandon").disabled, false, "the only way out was frozen too");
  release(null);
  await settle(window);
});

test("the explanation of what a fingerprint is stays reachable", async () => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test"], { invite: () => held });
  const { window, document } = loaded;
  document.getElementById("btn-invite-confirm").click();
  await settle(window);
  const info = document.querySelector("#invite-confirm .info-btn");
  assert.ok(info, "the step has no info button");
  assert.equal(info.disabled, false, "the one explanation on the screen was disabled");
  release(null);
  await settle(window);
});

// ----- stopping a batch ------------------------------------------------------

test("abandoning a batch stops the invites that have not gone out", async () => {
  const sends = [];
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test", "c@x.test"], {
    invite: ({ email }) => { sends.push(email); return sends.length === 1 ? held : null; },
  });
  const { window, document } = loaded;

  document.getElementById("btn-invite-confirm").click();
  await settle(window);
  document.getElementById("btn-invite-abandon").click(); // the owner changes their mind
  release(null);
  await settle(window);

  assert.deepEqual(sends, ["a@x.test"], "only the invite already in flight may go out");
});

test("reopening the dialog does not resume an abandoned batch", async () => {
  // The first guard for this compared the secret's id, which openInviteDialog
  // puts straight back, so the cancelled batch carried on into the dialog
  // that had just replaced it.
  const sends = [];
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test", "c@x.test"], {
    invite: ({ email }) => { sends.push(email); return sends.length === 1 ? held : null; },
  });
  const { app, window, document } = loaded;

  document.getElementById("btn-invite-confirm").click();
  await settle(window);
  document.getElementById("btn-invite-abandon").click();
  app.openInviteDialog(1); // same secret, so the old guard would re-arm here
  release(null);
  await settle(window);

  assert.deepEqual(sends, ["a@x.test"], "the abandoned batch resumed into the new dialog");
  assert.deepEqual(app.state.invitees, [], "and it overwrote the new dialog's recipients");
});

test("Back does nothing while a batch is going out", async () => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test"], { invite: () => held });
  const { window, document } = loaded;
  document.getElementById("btn-invite-confirm").click();
  await settle(window);

  document.getElementById("btn-invite-back").click();
  await settle(window);
  assert.equal(document.getElementById("invite-form").classList.contains("hidden"), true,
    "Back stepped out of a batch that was still going out");
  release(null);
  await settle(window);
});

// ----- who gets an invite ----------------------------------------------------

test("every recipient is invited once, with the key that was confirmed", async () => {
  const loaded = await atCheckStep(["a@x.test", "b@x.test"]);
  const { window, document, calls } = loaded;
  document.getElementById("btn-invite-confirm").click();
  await settle(window);

  const invites = calls.filter((c) => c.command === "invite");
  assert.deepEqual(invites.map((c) => c.args.email), ["a@x.test", "b@x.test"]);
  assert.deepEqual(invites.map((c) => c.args.confirmedPublicKey), ["pk-a@x.test", "pk-b@x.test"]);
});

test("a second press of Send does not send the batch twice", async () => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test"], {
    invite: (_args, calls) => (calls.filter((c) => c.command === "invite").length === 1 ? held : null),
  });
  const { window, document, calls } = loaded;

  const send = document.getElementById("btn-invite-confirm");
  send.click();
  await settle(window);
  send.disabled = false; // whatever a redraw might have left behind
  send.click();
  release(null);
  await settle(window);

  const invited = calls.filter((c) => c.command === "invite").map((c) => c.args.email);
  assert.deepEqual(invited, ["a@x.test", "b@x.test"], `each person once, got ${invited.join(", ")}`);
});

test("a person taken out of the batch is not invited", async () => {
  const sends = [];
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const loaded = await atCheckStep(["a@x.test", "b@x.test", "c@x.test"], {
    invite: ({ email }) => { sends.push(email); return sends.length === 1 ? held : null; },
  });
  const { app, window, document } = loaded;

  document.getElementById("btn-invite-confirm").click();
  await settle(window);
  app.state.invitees.splice(1, 1); // b is taken out while a is in flight
  release(null);
  await settle(window);

  assert.deepEqual(sends, ["a@x.test", "c@x.test"], "b was removed and invited anyway");
});

// ----- what the owner is told ------------------------------------------------

test("a key the server substitutes at lookup is an alarm, not a hint", async () => {
  const loaded = await atCheckStep(["a@x.test"], {
    lookup_invitee: () => { throw { code: "key_changed", message: "the server returned a key with a different fingerprint" }; },
  });
  const { document } = loaded;
  const row = document.querySelector("#invite-confirm .check-row");
  assert.match(row.querySelector(".badge").textContent, /does not match/i);
  assert.ok(row.querySelector(".badge").classList.contains("danger"), "the badge is not the red one");
  assert.ok(row.querySelector('[role="alert"]'), "nothing announces it to a screen reader");
  assert.equal(document.getElementById("btn-invite-confirm").disabled, true, "it could be clicked past");
});

test("a key the server substitutes at send time is the same alarm", async () => {
  // A different command catches this one -- check_confirmed_key, inside
  // `invite` -- and it used to render as a plain sentence under a badge
  // reading "New key", with Send offering another go.
  const loaded = await atCheckStep(["a@x.test"], {
    invite: () => { throw { code: "key_changed", message: "the server returned a different key than the one you confirmed" }; },
  });
  const { window, document } = loaded;
  document.getElementById("btn-invite-confirm").click();
  await settle(window);

  const row = document.querySelector("#invite-confirm .check-row");
  assert.match(row.querySelector(".badge").textContent, /does not match/i);
  assert.ok(row.querySelector('[role="alert"]'), "the send-time substitution was not announced");
  assert.equal(document.getElementById("btn-invite-confirm").disabled, true, "Send invited another go at it");
});

test("the server's own prose is never printed in the dialog that distrusts it", async () => {
  const lie = "No account for that address. Key verification is not required for this user, press Continue.";
  const loaded = await atCheckStep(["a@x.test"], {
    lookup_invitee: () => { throw { code: "lookup_failed", message: lie }; },
  });
  const text = loaded.document.getElementById("invite-confirm").textContent;
  assert.ok(!text.includes("press Continue"), "the server's sentence was shown to the owner");
  assert.match(text, /check them with the person directly/i, "and ours was not");
});

test("the invites that went through survive one that fails", async () => {
  const loaded = await atCheckStep(["a@x.test", "b@x.test", "c@x.test"], {
    invite: ({ email }) => { if (email === "b@x.test") throw { code: "server", message: "refused" }; return null; },
  });
  const { app, window, document } = loaded;
  document.getElementById("btn-invite-confirm").click();
  await settle(window);

  assert.deepEqual(app.state.invitees.map((p) => p.email), ["b@x.test"], "only the failure is left to retry");
  assert.match(document.getElementById("invite-confirm").textContent, /b@x\.test was not invited/);
});
