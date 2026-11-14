// Runs the real interface under a real DOM.
//
// Everything else in this directory tests a pure function or reads app.js as
// text. Neither catches a guard that is written correctly and wired to the
// wrong place: the freeze that stops a batch being edited while it is going
// out was asserted by a source grep for three rounds of review, and passed
// the whole time against a call sitting inside an event handler where it
// could never run. This loads index.html and app.js as the app does and
// drives the controls, so a test fails when the interface misbehaves rather
// than when the source is reworded.
//
// It is dev-only. The app ships no JavaScript dependencies and apps/desktop/ui
// is still plain files with no build step; jsdom never reaches a build.
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const UI = path.join(__dirname, "../ui");
const read = (name) => fs.readFileSync(path.join(UI, name), "utf8");

/// What the Rust side would answer, as far as these tests care.
///
/// Every command returns a promise, and `calls` records what was asked for
/// in order -- which is how a test says "exactly one invite went out, and it
/// was for this person with this key".
function stubBackend(answers = {}) {
  const calls = [];
  const defaults = {
    ui_constants: () => ({
      min_password_length: 12, max_message_length: 1000, generated_password_length: 20,
      max_custom_fields: 20, max_label_length: 100, max_field_length: 4096, max_project_name_length: 100,
    }),
    app_version: () => "0.0.0-test",
    startup_warnings: () => [],
    server_capabilities: () => ({ password_sign_in: true, google_sign_in: false, registration_token_required: false, registration_closed: false }),
    session_info: () => null,
    list_secrets: () => [],
    list_projects: () => [],
    list_invites: () => [],
    get_access: () => ({ members: [], invites: [] }),
    logout: () => null,
  };
  const invoke = (command, args) => {
    calls.push({ command, args });
    const answer = answers[command] ?? defaults[command];
    if (!answer) return Promise.reject({ code: "unstubbed", message: `no answer for ${command}` });
    try {
      return Promise.resolve(answer(args ?? {}, calls));
    } catch (error) {
      return Promise.reject(error);
    }
  };
  return { invoke, calls };
}

/// Load the interface. Returns the window, the backend's recorded calls, and
/// `app`, which is the script's own scope -- its functions and module state,
/// reached through the context it was evaluated in.
///
/// `platform` picks the look the same way boot.js does from the user agent.
async function loadApp({ platform = "macos", phone = false, answers = {} } = {}) {
  const dom = new JSDOM(read("index.html"), { runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;
  const backend = stubBackend(answers);
  window.__TAURI__ = { core: { invoke: backend.invoke } };
  // jsdom has no clipboard; the app only ever writes to it.
  window.navigator.clipboard = { writeText: async () => {} };
  window.document.documentElement.dataset.platform = platform;

  // jsdom implements <dialog> as an element but not its modal behaviour.
  // The app only needs opening, closing and the `close` event; making
  // everything behind it inert is the browser's job and nothing here reads
  // it. Escape is delivered by dispatching `cancel` directly in the tests,
  // which is what the key press does.
  const Dialog = window.HTMLDialogElement;
  if (Dialog && typeof Dialog.prototype.showModal !== "function") {
    Dialog.prototype.showModal = function showModal() { this.open = true; };
    Dialog.prototype.close = function close() {
      if (!this.open) return;
      this.open = false;
      this.dispatchEvent(new window.Event("close"));
    };
  }

  // jsdom has no media queries. The app asks once, at load, and listens for
  // changes; `phone` decides which layout it believes it is in.
  window.matchMedia = (media) => ({
    media,
    matches: Boolean(phone) && /max-width/.test(media),
    addEventListener() {}, removeEventListener() {},
    addListener() {}, removeListener() {},
  });

  // These three put themselves on `window`, the way the page loads them.
  for (const file of ["screens.js", "legal.js", "fields.js"]) window.eval(read(file));
  // app.js does not: its `const` declarations live in the evaluated script's
  // own lexical scope, which is not `window` and is not shared between two
  // eval calls. So the names the tests drive are collected by an epilogue
  // appended to the same source, inside the same scope.
  window.eval(`${read("app.js")}
    ;window.__app = {
      state, sendingNow, showApp, openInviteDialog, closeInviteDialog, backToInviteFields,
      renderInviteCheck, syncInviteCheck, freezeInviteCheck, sendInvites, recheckInvitee,
      loadSharing, renderDetail, openRowMenu, closeRowMenu, commitTypedInvitees,
    };`);
  // The startup commands are promises; let them settle before anything is
  // driven, so a test never races the app's own first paint.
  await new Promise((resolve) => window.setTimeout(resolve, 0));
  return { window, document: window.document, app: window.__app, calls: backend.calls };
}

/// Put the app into its signed-in state, without a password.
///
/// `showApp` is what the real sign-in calls once Rust hands back the user,
/// so this is the same entry point rather than a shortcut around it -- which
/// means it clears the state and refetches, and the vault's contents come
/// from the backend stub's `list_secrets`, not from here.
async function signIn(loaded, { user = {} } = {}) {
  const { app, window } = loaded;
  app.showApp({
    email: "me@example.com",
    server_url: "https://vault.example.test",
    fingerprint: "4f2a-91cd-77b0-2e14-aa39-50c8",
    password_login: true,
    google_email: null,
    ...user,
  });
  await settle(window);
  return loaded;
}

/// Let every pending promise and timer resolve.
const settle = (window, turns = 4) =>
  new Promise((resolve) => {
    let left = turns;
    const tick = () => (left-- > 0 ? window.setTimeout(tick, 0) : resolve());
    tick();
  });

/// A secret as `list_secrets` reports one.
const secret = (over = {}) => ({
  id: 1, name: "Cloudflare", username: "ops@example.test", url: "", notes: "", fields: [],
  is_owner: true, owner_email: "me@example.com", updated_at: new Date().toISOString(),
  error: null, project: null, ...over,
});

/// A recipient as the invite dialog holds one, already looked up.
const invitee = (email, over = {}) => ({
  email, fingerprint: "", retyped: "", error: null,
  info: { email, fingerprint: "11bb-22cc-33dd-44ee-55ff-6677", public_key: `pk-${email}`, status: "new" },
  ...over,
});

module.exports = { loadApp, signIn, settle, secret, invitee, stubBackend };
