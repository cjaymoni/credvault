// klavyn desktop UI. All cryptography lives in Rust; this file only renders
// state and calls Tauri commands.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

// Pre-fills the Server URL field so testers are not handed an address to
// type. Only a default: the field stays editable and a typed value is
// remembered, so anyone self-hosting sets theirs once. Must stay https --
// the Rust side refuses http for anything but loopback, and it refuses it
// after the password has been entered. Checked by ui-tests/screens.test.js.
const DEFAULT_SERVER = "https://vault.klavyn.com";

/// Whether the sign-in screen lets the address be edited.
///
/// Off for now: every build signs in to DEFAULT_SERVER. The address is still
/// shown -- it is where the credential is about to be sent, and that is worth
/// seeing before it is sent -- but the field is inert and the phone line has
/// no "Change".
///
/// Turning this back on is the whole switch: the markup, the styles and the
/// Rust command all still take an address, so nothing else has to move.
const ALLOW_CUSTOM_SERVER = false;
const REVEAL_HIDE_AFTER_MS = 30_000;
const TOAST_MS = 2200;
const MASKED = "••••••••••••";
// Limits owned by the Rust crates; `ui_constants` overwrites these defaults at startup.
const UI = { minPasswordLength: 12, maxMessageLength: 1000, generatedPasswordLength: 20, maxCustomFields: 20, maxLabelLength: 100, maxFieldLength: 4096, maxProjectNameLength: 100 };
// What the token field says, and what the form says when it is left empty.
// The server would also refuse a blank token, but its answer is written for
// an API caller ("a registration token is required") and arrives only after a
// round-trip that was never going to succeed.
/// Descriptions that explain a screen rather than warn about what a button is
/// about to do. Each one is reachable from the "i" beside its heading.
///
/// The line between these and the text that stays on screen is what the
/// button does next: a consequence of pressing it is not an explanation and
/// is never folded away. That is why the warning about revoking with
/// unconfirmed keys, the passphrase's "there is no reset", and the line
/// saying a linked Google account can sign in without the passphrase are all
/// still printed in full.
const SHARING_NOTE =
  "People you invite get read-only access to this one secret. Revoking re-encrypts it with a new key.";
const INVITE_NOTE =
  "Everyone you add gets read-only access to this one secret, and nothing else in your vault. Use the address each of them signed up with.";
const INVITE_PROJECT_NOTE =
  "They will see the project's name on this secret. Once they accept, you can change your mind for each person from the Sharing list.";
const FINGERPRINT_NOTE =
  "A fingerprint is the short code under \u201cYour key\u201d in the other person's account settings. Ask them for it by phone or in person \u2014 anything except this server, which is what the check is for.";
const PROJECTS_NOTE =
  "Headings your secrets are grouped under. Deleting one never deletes the secrets in it \u2014 they simply stop being grouped.";
const GOOGLE_LINK_NOTE =
  "Sign in to this server with your Google account next time. Your passphrase is still what unlocks the vault \u2014 Google only proves who you are.";
const SIGN_OUT_OTHERS_NOTE =
  "This is the thing to do first if you think someone else is signed in as you. Nothing they can do stops it \u2014 and because you stay signed in here, you can go straight on to remove a Google sign-in they added, before they have time to come back.";

/// Said once, in the one place it applies, and reachable rather than always
/// on screen. It is a disclosure, not a tip: a project name does not get the
/// encryption the rest of a secret gets, and someone choosing a project is
/// entitled to know that before they type a client's name into it. Kept as a
/// constant so the button's tooltip and the text it reveals cannot drift
/// apart. See docs/privacy.md, which is where the standing version lives.
const PROJECT_NAME_DISCLOSURE =
  "The project name is stored unencrypted, like the secret's name, and is not shared with anyone you share this secret with unless you say so.";

/// What "Hide" does, which is not guessable from the word: it also clears the
/// value from the clipboard the way the password does.
const EXTRA_FIELDS_DISCLOSURE =
  "A PIN, a recovery code, an account number. Hide masks a value and clears it from the clipboard, like the password.";

const TOKEN_REQUIRED_HINT = "This server only creates accounts for people who have its token. Whoever invited you can give you one.";
const TOKEN_OPTIONAL_HINT = "Only needed if the server was set up to ask for one.";
const TOKEN_MISSING_ERROR = "Paste the registration token for this server. Ask whoever invited you for it.";
const THEME_KEY = "theme";
const THEME_CHOICES = ["system", "light", "dark"];

const state = { secrets: [], projects: [], selected: null, editing: false, editTitle: "", authMode: "login", inviteCount: 0, formFields: [],
  // The Projects panel is open in the detail pane, the way the invitations
  // view is. Renaming and deleting live there; filing lives in the form.
  showingProjects: false,
  // Which row of the Projects panel is open and for what:
  // `{ id, mode: "rename" }`, or `{ id: null, mode: "new" }` for the row
  // that creates one. Null when every row is at rest. Deleting is not here:
  // it is confirmed in a dialog, not on the row.
  projectRow: null,
  // The invitations view is open in the detail pane (reached from the
  // invitations entry in the list), and the secret the invite dialog is for.
  showingInvites: false, inviteFor: null,
  // The people the invite dialog is collecting, in the order they were
  // typed. Each is `{ email, fingerprint, info, error }`: `info` is what
  // `lookup_invitee` answered and `error` why it could not, so one address
  // that cannot be resolved does not hold up the rest.
  invitees: [],
  // Which run of the invite dialog is current. Compared instead of the
  // secret's id, because closing and reopening the dialog on the *same*
  // secret put the id back and re-armed every guard that watched it -- a
  // cancelled batch would resume into the dialog that had just replaced it.
  inviteSession: 0,
  // Every address the server was caught substituting a key for, for the life
  // of one run of the dialog. Keyed by address rather than flagged on the
  // person, because dropping somebody from the batch and typing them in
  // again builds a new person object -- which would have been a way to clear
  // the one alarm this dialog exists to raise by retyping an address.
  caughtSubstituting: new Set(),
  // What the server at the URL in the box offers, and the Google sign-in
  // waiting for a passphrase, if there is one.
  capabilities: null, google: null, user: null,
  // The user opened the registration-token field themselves, on a server that
  // did not say it needs one. Kept so a re-render does not fold it away again.
  tokenFieldOpen: false,
  // Set when the server at that URL answered but speaks a protocol this build
  // cannot use; null the rest of the time.
  incompatible: null };
const MOBILE_QUERY = window.matchMedia("(max-width: 720px)");
const isMobile = () => MOBILE_QUERY.matches;
// Rotating a large phone crosses 720px, and the empty state names either a
// keyboard shortcut or the button that replaces it. Registered once, here,
// rather than from anything that runs more than once.
//
// It re-renders only when the empty state is what is on screen, which is
// exactly `selected === null && !editing`. Everything else the detail pane
// can hold — an edit in progress, the invite form, a fingerprint typed in
// from another person's screen, a delete confirmation — would be thrown away
// by a re-render, and none of it sets `editing`.
MOBILE_QUERY.addEventListener("change", () => {
  if (state.editing || state.selected !== null) return;
  if ($("app").classList.contains("hidden")) return; // signed out: the pane is deliberately empty
  renderDetail();
});
const timers = { toast: null };

// Set by boot.js before the page drew, from the webview's user agent.
const PLATFORM = document.documentElement.dataset.platform || "linux";
/// How long a toast carrying an action stays up: long enough to reach it.
const ACTION_TOAST_MS = 10_000;
// Both modifiers work everywhere; these name the one this platform prints.
const NEW_SECRET_SHORTCUT = Screens.shortcutLabel(PLATFORM, "N");
const SEARCH_SHORTCUT = Screens.shortcutLabel(PLATFORM, "K");

/// The elements behind each name in Screens.placementFor().
const PLACED = {
  search: () => $("search-box"),
  newSecret: () => $("btn-new"),
  refresh: () => $("btn-refresh"),
  account: () => $("btn-account"),
  invites: () => $("invites-banner"),
};

/// Move each control that lives in a different place per platform into its
/// slot. Runs once, before anything is shown; a missing slot is a markup bug
/// and fails loudly rather than leaving a control stranded off screen.
function placeControls() {
  for (const [control, slotName] of Screens.placementFor(PLATFORM)) {
    const slot = document.querySelector(`[data-slot="${slotName}"]`);
    const element = PLACED[control]();
    if (!slot || !element) throw new Error(`cannot place ${control} in slot ${slotName}`);
    slot.append(element);
  }
}
placeControls();

/// Put the shortcut in the two tooltips that can carry one. Written here
/// rather than in the markup because the right spelling is not known until
/// the platform is, and on a phone there is no right spelling at all.
function labelShortcuts() {
  // Announced on every platform, because the shortcut works on every
  // platform: an iPad with a keyboard attached presses ⌘N like any Mac.
  // aria-keyshortcuts is the attribute that says so without becoming the
  // control's name, which is the only reason the tooltip is held back below.
  $("btn-new").setAttribute("aria-keyshortcuts", Screens.shortcutKeys(PLATFORM, "N"));
  $("filter").setAttribute("aria-keyshortcuts", Screens.shortcutKeys(PLATFORM, "K"));
  if (!Screens.namesShortcuts(PLATFORM)) return;
  $("btn-new").title = `New secret (${NEW_SECRET_SHORTCUT})`;
  $("filter").title = `Search (${SEARCH_SHORTCUT})`;
}
labelShortcuts();

// ----- helpers ---------------------------------------------------------------

const esc = Screens.esc;

const ICONS = {
  lock: '<path d="M7 11V7a5 5 0 0 1 10 0v4"/><rect x="4" y="11" width="16" height="10" rx="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M17.94 17.94A10.5 10.5 0 0 1 12 19c-6.5 0-10-7-10-7a18 18 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.9 9.9 0 0 1 12 4c6.5 0 10 8 10 8a18 18 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><path d="m2 2 20 20"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  alert: '<path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>',
  wand: '<path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3Z"/><path d="m19 17 .7 2.3L22 20l-2.3.7L19 23l-.7-2.3L16 20l2.3-.7L19 17Z"/>',
  mail: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 7 10-7"/>',
  note: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  chevronRight: '<path d="m9 6 6 6-6 6"/>',
  more: '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
  close: '<path d="M18 6 6 18M6 6l12 12"/>',
};
function icon(name) {
  return `<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
}

/// Show a short confirmation. With `action` ({ label, run }) it also carries a
/// button, stays up long enough to reach it, and goes away once it is used.
function toast(message, action = null) {
  const el = $("toast");
  el.innerHTML = `${icon("check")}<span class="toast-text">${esc(message)}</span>`;
  el.classList.toggle("has-action", Boolean(action));
  if (action) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "toast-action";
    button.textContent = action.label;
    button.onclick = async () => {
      hideToast();
      try { await action.run(); } catch (error) { setError("main-error", error); }
    };
    el.append(button);
  }
  el.classList.add("show");
  clearTimeout(timers.toast);
  timers.toast = setTimeout(hideToast, action ? ACTION_TOAST_MS : TOAST_MS);
}
function hideToast() {
  clearTimeout(timers.toast);
  const el = $("toast");
  el.classList.remove("show", "has-action");
  // An action button must not stay reachable by Tab once it is out of sight.
  el.querySelector(".toast-action")?.remove();
}
/// Command errors arrive as `{ code, message }`; anything else is shown as text.
function setError(id, error) {
  const el = $(id);
  const text = error?.message ?? error;
  if (el) el.textContent = text ? String(text) : "";
}
/// A warning that must not be cleared by the next keystroke: it stays until
/// the user dismisses it.
function showStartupWarning(text) {
  const host = $("auth-error")?.parentElement;
  if (!host) return;
  const banner = document.createElement("div");
  banner.className = "notice danger startup-warning";
  banner.setAttribute("role", "alert");
  banner.innerHTML = `${icon("alert")}<div>${esc(text)}</div>`;
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "btn";
  dismiss.textContent = "Dismiss";
  dismiss.onclick = () => banner.remove();
  banner.append(dismiss);
  host.insertBefore(banner, $("auth-error"));
}

function remember(key, value) {
  try { localStorage.setItem(key, value); } catch (_) { /* storage may be unavailable */ }
}
function recall(key) {
  try { return localStorage.getItem(key) || ""; } catch (_) { return ""; }
}

/// A small "i" that reveals `text` under the field it belongs to.
///
/// The text is both the tooltip and the revealed paragraph, so a pointer gets
/// it on hover and a finger gets it on tap. `controls` is the id of the
/// paragraph, which starts hidden.
function infoButtonHtml(controls, text) {
  return `<button type="button" class="info-btn" data-info-for="${controls}"
    aria-controls="${controls}" aria-expanded="false"
    aria-label="What this means" title="${esc(text)}">${icon("info")}</button>`;
}

/// Focus something in the editor, opening "More details" first if it is
/// folded away.
///
/// focus() on a hidden element does nothing, so an error that points at a
/// folded field leaves the message on screen with no field to act on -- the
/// same failure the fold is opened for when editing a secret that already
/// has those fields filled in.
function focusInForm(element) {
  if (!element) return;
  const fold = element.closest?.("#more-details");
  if (fold?.classList.contains("hidden")) toggleDisclosure($("btn-more-details"), fold);
  element.focus();
}

/// Show or hide `panel`, keeping `button`'s aria-expanded honest.
///
/// Returns whether the panel ended up open, which is what callers that move
/// focus into it need.
function toggleDisclosure(button, panel) {
  const opening = panel.classList.contains("hidden");
  panel.classList.toggle("hidden", !opening);
  button.setAttribute("aria-expanded", String(opening));
  return opening;
}

/// Disable a button while its action runs; `label` swaps the visible text.
function setBusy(button, busy, label) {
  if (!button) return;
  if (busy) {
    button.dataset.idle = button.innerHTML;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    if (label) button.textContent = label;
  } else {
    if (button.dataset.idle !== undefined) button.innerHTML = button.dataset.idle;
    delete button.dataset.idle;
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

/// "1 secret", "3 secrets": the plural category comes from the locale, not from n === 1.
const pluralRules = new Intl.PluralRules(navigator.language || "en");
function plural(count, one, other) {
  return `${count} ${pluralRules.select(count) === "one" ? one : other}`;
}

function formatDate(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/// Stable hue per name so the same secret always gets the same tint.
function hashHue(text) {
  let hue = 0;
  for (const ch of String(text)) hue = (hue * 31 + ch.codePointAt(0)) % 360;
  return hue;
}
function avatar(name, { size = "", broken = false } = {}) {
  const first = Array.from(String(name ?? "").trim())[0] || "?";
  const classes = ["avatar", size, broken ? "broken" : ""].filter(Boolean).join(" ");
  return `<span class="${classes}" style="--h:${hashHue(name)}" aria-hidden="true">${broken ? icon("alert") : esc(first.toUpperCase())}</span>`;
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copied`);
  } catch (error) {
    setError("main-error", `Could not copy ${label.toLowerCase()}: ${error}`);
  }
}

/// Open a <dialog> modally. showModal() makes everything behind it inert and
/// gives Escape to the dialog's `cancel` event.
function openDialog(dialog) {
  if (dialog && !dialog.open) dialog.showModal();
}
function closeDialog(dialog) {
  if (dialog?.open) dialog.close();
}

/// Show a legal document, and remember which one so the switch reflects it.
///
/// The text comes from ui/legal.js, which scripts/build-legal.js generates
/// from docs/terms.md and docs/privacy.md. It is assigned as HTML because it
/// *is* markup, built at generation time from our own files with every
/// inline value escaped -- nothing a user or a server can influence reaches
/// it. See scripts/build-legal.js.
function showLegal(which) {
  const document_ = Legal[which];
  if (!document_) throw new Error(`no legal document named ${JSON.stringify(which)}`);
  $("legal-title").textContent = document_.title;
  $("legal-body").innerHTML = document_.html;
  $("legal-body").scrollTop = 0;
  // Only a draft says so, and it says so above the text rather than inside
  // it, so nobody reads a placeholder as a term they agreed to.
  $("legal-draft").classList.toggle("hidden", !document_.draft);
  for (const [id, key] of [["tab-terms", "terms"], ["tab-privacy", "privacy"]]) {
    $(id).setAttribute("aria-pressed", String(key === which));
  }
  openDialog($("legal-dialog"));
  $("legal-body").focus();
}

/// The first of these that is actually on screen: the same action can sit in
/// a different place per platform, and focus has to return to the one shown.
function firstVisible(...ids) {
  return ids.map($).find((el) => el && el.getClientRects().length > 0) ?? null;
}

function togglePasswordInput(input, button) {
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.innerHTML = icon(show ? "eyeOff" : "eye");
  button.setAttribute("aria-pressed", String(show));
  button.setAttribute("aria-label", show ? "Hide password" : "Show password");
  button.title = show ? "Hide password" : "Show password";
}

// ----- phone screens ---------------------------------------------------------
// On narrow screens the list and the detail pane are separate screens; the
// data-screen attribute picks one. Desktop CSS ignores it and shows both.

function mobileTitle() {
  if (state.editing) return state.editTitle;
  if (state.showingInvites) return "Invitations";
  const secret = state.secrets.find((s) => s.id === state.selected);
  return secret ? secret.name : "";
}
/// What the phone chrome has to agree on: the nav bar names the screen, and
/// a screen that is a form keeps the invitations out of its way.
function syncScreenChrome() {
  $("mobile-title").textContent = mobileTitle();
  $("main").classList.toggle("has-form", state.editing);
  syncBarActions(state.editing || state.showingInvites ? null : state.secrets.find((s) => s.id === state.selected));
}

/// Edit in the top bar (GNOME, iOS, Android) and Android's "more" menu, which
/// holds Delete. Hidden when no secret is open, while a form is, and (Edit)
/// for a secret that is shared with this account or cannot be decrypted.
function syncBarActions(secret) {
  closeBarMenu();
  const edit = $("btn-bar-edit");
  edit.classList.toggle("hidden", !(secret && secret.is_owner && !secret.error));
  $("btn-bar-more").classList.toggle("hidden", !secret);
  if (secret) {
    edit.setAttribute("aria-label", `Edit ${secret.name}`);
    $("btn-menu-delete").textContent = secret.is_owner ? "Delete" : "Remove from vault";
  }
}

/// The items of the "more" menu, in order.
function barMenuItems() {
  return [...$("bar-menu").querySelectorAll('[role="menuitem"]')];
}
function openBarMenu() {
  $("bar-menu").hidden = false;
  $("btn-bar-more").setAttribute("aria-expanded", "true");
  barMenuItems()[0]?.focus();
}
/// `restoreFocus` sends focus back to the button, for Escape and for an item
/// that was chosen; a click elsewhere or Tab leaves it where it went.
function closeBarMenu({ restoreFocus = false } = {}) {
  const menu = $("bar-menu");
  if (menu.hidden) return;
  menu.hidden = true;
  $("btn-bar-more").setAttribute("aria-expanded", "false");
  if (restoreFocus) $("btn-bar-more").focus();
}
// ----- row menus -------------------------------------------------------------
//
// A small menu dropped from the "more" button on a row of a list.
//
// It is placed against the viewport and parented to the body rather than
// drawn inside the row, because the lists these open from are cards that
// clip their contents on two of the five platforms -- a menu laid out inside
// one would be cut off at the card's edge. The row expanded to hold its
// controls before this, which pushed everything below it down the screen to
// answer a question about one person.

/// The open menu: `{ menu, button }`, or null.
let rowMenu = null;

function rowMenuItems() {
  return rowMenu ? [...rowMenu.menu.querySelectorAll('[role^="menuitem"]')] : [];
}

function closeRowMenu({ restoreFocus = false } = {}) {
  if (!rowMenu) return;
  const { menu, button } = rowMenu;
  rowMenu = null;
  menu.remove();
  button.setAttribute("aria-expanded", "false");
  if (restoreFocus && button.isConnected) button.focus();
}

/// Put the menu under its button, or above it when there is no room below.
/// Clamped to the window on both sides so a row near an edge cannot push it
/// off screen.
function placeRowMenu(menu, button) {
  const box = button.getBoundingClientRect();
  const margin = 8;
  const below = window.innerHeight - box.bottom - margin;
  const top = menu.offsetHeight <= below ? box.bottom + 4 : Math.max(margin, box.top - menu.offsetHeight - 4);
  const left = Math.min(
    Math.max(margin, box.right - menu.offsetWidth),
    window.innerWidth - menu.offsetWidth - margin,
  );
  menu.style.top = `${Math.round(top)}px`;
  menu.style.left = `${Math.round(Math.max(margin, left))}px`;
}

/// Open a menu of `items` from `button`. Each item is
/// `{ label, icon, run, danger?, checked? }`: `icon` names one of ICONS and
/// is drawn at the leading edge, and an item with `checked` is a checkbox
/// item -- it says so to a screen reader and carries a tick at the trailing
/// edge while it is on.
function openRowMenu(button, items) {
  const wasOpen = rowMenu?.button === button;
  closeRowMenu();
  if (wasOpen) return; // a second press on the same button closes it
  const menu = document.createElement("div");
  menu.className = "row-menu";
  menu.setAttribute("role", "menu");
  menu.setAttribute("aria-label", button.getAttribute("aria-label") ?? "Options");
  menu.innerHTML = items.map((item, index) => {
    const checkable = item.checked !== undefined;
    return `<button type="button" class="row-menu-item${item.danger ? " danger" : ""}" data-index="${index}"
      role="${checkable ? "menuitemcheckbox" : "menuitem"}"${checkable ? ` aria-checked="${Boolean(item.checked)}"` : ""}
      tabindex="-1">${icon(item.icon)}<span class="row-menu-label">${esc(item.label)}</span>${checkable && item.checked ? `<span class="row-menu-tick">${icon("check")}</span>` : ""}</button>`;
  }).join("");
  document.body.append(menu);
  rowMenu = { menu, button };
  button.setAttribute("aria-expanded", "true");
  placeRowMenu(menu, button);
  menu.addEventListener("keydown", rowMenuKeydown);
  for (const el of menu.querySelectorAll("[data-index]")) {
    el.onclick = () => {
      const item = items[Number(el.dataset.index)];
      closeRowMenu({ restoreFocus: true });
      item.run();
    };
  }
  rowMenuItems()[0]?.focus({ preventScroll: true });
}

/// The same keys the top bar's menu takes: arrows, Home and End move between
/// items; Escape closes back to the button; Tab closes and lets focus move on.
function rowMenuKeydown(event) {
  const items = rowMenuItems();
  const index = items.indexOf(document.activeElement);
  const last = items.length - 1;
  const moves = { ArrowDown: index >= last ? 0 : index + 1, ArrowUp: index <= 0 ? last : index - 1, Home: 0, End: last };
  if (event.key in moves) { event.preventDefault(); items[moves[event.key]]?.focus(); return; }
  if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeRowMenu({ restoreFocus: true }); return; }
  if (event.key === "Tab") closeRowMenu();
}

/// The APG menu keys: arrows, Home and End move between items; Escape closes
/// back to the button; Tab closes and lets focus move on.
function barMenuKeydown(event) {
  const items = barMenuItems();
  const index = items.indexOf(document.activeElement);
  const last = items.length - 1;
  const moves = { ArrowDown: index >= last ? 0 : index + 1, ArrowUp: index <= 0 ? last : index - 1, Home: 0, End: last };
  if (event.key in moves) { event.preventDefault(); items[moves[event.key]]?.focus(); return; }
  if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeBarMenu({ restoreFocus: true }); return; }
  if (event.key === "Tab") closeBarMenu();
}
function showDetailScreen() {
  syncScreenChrome();
  $("app").dataset.screen = "detail";
  $("main").scrollTop = 0;
}
function showListScreen() {
  $("app").dataset.screen = "list";
  const active = $("list").querySelector(".item.active");
  if (active && isMobile()) active.focus();
}
/// Back behaves like Cancel while editing, otherwise it pops to the list.
function goBack() {
  if (state.editing) {
    state.editing = false;
    renderDetail();
    if (state.selected !== null) return;
  }
  showListScreen();
}
/// After a refresh the detail screen may have nothing left to show.
function syncScreenAfterRefresh() {
  // `showingProjects` belongs here for the same reason `editing` does: the
  // detail screen has something on it. Without it, every create, rename or
  // delete refreshed, found "nothing to show" and dropped a phone user back
  // on the vault list, because the panel sets `selected` to null and leaves
  // `editing` false. The invites view escapes only by accident, its count
  // being non-zero whenever it is up.
  if (isMobile() && $("app").dataset.screen === "detail" && Screens.shouldPopToList(state)) showListScreen();
}

/// Everything outside the sheet goes inert while it is open, so Tab cannot
/// land on controls hidden under the backdrop. The trigger stays live so it
/// can close the sheet again.
function behindSheet() {
  return [document.querySelector(".sidebar"), document.querySelector(".content"), document.querySelector(".bottombar")];
}
function openAccountSheet() {
  const sheet = $("account-tools");
  for (const el of behindSheet()) if (el) el.inert = true;
  $("app").classList.add("account-open");
  $("btn-account").setAttribute("aria-expanded", "true");
  sheet.setAttribute("role", "dialog");
  sheet.setAttribute("aria-modal", "true");
  sheet.setAttribute("aria-label", "Account and settings");
  $("btn-fingerprint").focus();
  // The chip is how an unwanted Google link becomes visible, so what it shows
  // is re-read from the server each time this opens rather than left at
  // whatever sign-in put there. A link added from another device would
  // otherwise stay invisible for the life of this session.
  refreshAccountFacts();
}

/// Re-read the signed-in account from the server and redraw what depends on
/// it. Silent on failure: this runs on opening a panel, and a chip showing
/// slightly stale text is better than an error over a screen the user opened
/// to do something else.
async function refreshAccountFacts() {
  try {
    state.user = await invoke("refresh_account");
    renderGoogleChip();
  } catch (error) {
    console.warn("could not refresh the account panel", error);
  }
}
function closeAccountSheet({ restoreFocus = true } = {}) {
  const app = $("app");
  if (!app.classList.contains("account-open")) return;
  app.classList.remove("account-open");
  for (const el of behindSheet()) if (el) el.inert = false;
  $("btn-account").setAttribute("aria-expanded", "false");
  for (const attr of ["role", "aria-modal", "aria-label"]) $("account-tools").removeAttribute(attr);
  if (restoreFocus) $("btn-account").focus();
}

// ----- theme -----------------------------------------------------------------

/// "system" removes the override so the OS preference applies; "light" and
/// "dark" pin the theme via data-theme on <html>.
function applyTheme(choice) {
  const theme = THEME_CHOICES.includes(choice) ? choice : "system";
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === theme));
  }
}
function chooseTheme(choice) {
  applyTheme(choice);
  remember(THEME_KEY, choice);
}

// ----- auth ------------------------------------------------------------------

function setAuthMode(mode) {
  state.authMode = mode;
  const isRegister = mode === "register";
  $("tab-login").setAttribute("aria-pressed", String(!isRegister));
  $("tab-register").setAttribute("aria-pressed", String(isRegister));
  $("auth-title").textContent = isRegister ? "Create your account" : "Welcome back";
  if (!isRegister) state.tokenFieldOpen = false;
  renderTokenPrompt();
  $("password-hint").classList.toggle("hidden", !isRegister);
  $("password").autocomplete = isRegister ? "new-password" : "current-password";
  $("btn-auth").textContent = isRegister ? "Create account" : "Log in";
  setError("auth-error", "");
  // Switching tabs abandons a Google sign-in that was waiting for a passphrase.
  if (state.google) { state.google = null; showGoogleForm(false); }
}

/// The phone layout shows the server as one line and keeps the field folded
/// behind it, because the address is right far more often than it is wrong.
/// Tapping the line unfolds the field: wrong is the case that matters, and a
/// default that cannot be corrected is how someone's vault ends up on a
/// stranger's server.
function showServerField() {
  if (!ALLOW_CUSTOM_SERVER) return;
  $("auth").classList.add("server-open");
  $("server").focus();
}

/// Put the real window insets into the four --safe-* properties.
///
/// Only Android needs this: its WebView reports env(safe-area-inset-*) as 0
/// even with the window edge-to-edge, so styles.css reads the properties and
/// MainActivity.kt measures them. It pushes them too, but the page is loaded
/// after it does that and the push lands on a document that is thrown away --
/// so the page asks here, where there is one to style. Everywhere else the
/// bridge is absent and the properties keep their env() fallbacks.
const SAFE_AREA_SIDES = ["top", "right", "bottom", "left"];
function applySafeAreaInsets() {
  const bridge = window.__klavynInsets;
  if (!bridge || typeof bridge.cssPixels !== "function") return;
  let pixels;
  try {
    pixels = String(bridge.cssPixels()).split(",");
  } catch (_) {
    return; // a bridge that cannot answer leaves the fallbacks in place
  }
  if (pixels.length !== SAFE_AREA_SIDES.length) return;
  SAFE_AREA_SIDES.forEach((side, i) => {
    const value = Number(pixels[i]);
    // A negative or unreadable inset would push content off the screen
    // instead of away from an edge.
    if (!Number.isFinite(value) || value < 0) return;
    document.documentElement.style.setProperty(`--safe-${side}`, `${value}px`);
  });
}

/// The address this app signs in to. Never reads the field while
/// ALLOW_CUSTOM_SERVER is off; see Screens.serverUrlFor().
function currentServerUrl() {
  return Screens.serverUrlFor(ALLOW_CUSTOM_SERVER, $("server").value, DEFAULT_SERVER);
}

/// Say what happened to an install whose account is on another server.
///
/// The address is forced for every install, this one included, so there is
/// nothing to offer here but an explanation. It is worth printing anyway:
/// `auth_hash` ties the credential to the address it was made under, so this
/// account cannot be opened here at all, and the server answers that with a
/// rejection the sign-in screen can only report as a wrong passphrase.
/// Saying so beforehand is the difference between "my vault is on my own
/// server" and "I have forgotten my passphrase".
///
/// See Screens.strandedAddress() for which installs this is shown to.
function noteStrandedServer(address) {
  const notice = $("server-stranded");
  notice.innerHTML = `${icon("alert")}<div>This app signs in to <strong>${esc(DEFAULT_SERVER)}</strong>.
    You last used <strong>${esc(address)}</strong>, and an account made there can only be opened there \u2014
    its password is tied to that address, so signing in here will be refused.</div>`;
  notice.classList.remove("hidden");
}

/// Take the address out of the person's hands without taking it out of sight.
///
/// The desktop layout shows the field and the phone layout shows the summary
/// line, so both are dealt with: the input goes read-only, and the line loses
/// its "Change" and stops being a button.
function lockServerAddress() {
  $("auth").classList.add("server-locked");
  const field = $("server");
  field.readOnly = true;
  field.setAttribute("aria-readonly", "true");
  field.tabIndex = -1;
  const change = $("btn-server-change");
  change.disabled = true;
  change.tabIndex = -1;
}

function syncServerSummary() {
  $("server-summary").textContent = Screens.serverSummaryText($("server").value, DEFAULT_SERVER);
}

/// Draw the registration-token field for whatever the server has said about
/// itself. See Screens.tokenPrompt() for the three cases.
///
/// A server that requires a token gets the field open and marked required, so
/// the demand is visible before the form is filled in rather than after it is
/// submitted -- and so authenticate() can refuse an empty one here instead of
/// relaying the server's 403.
function renderTokenPrompt() {
  const prompt = Screens.tokenPrompt(
    state.authMode === "register",
    state.capabilities?.registration_token_required,
    state.tokenFieldOpen,
  );
  $("token-field").classList.toggle("hidden", !prompt.field);
  $("btn-show-token").classList.toggle("hidden", !prompt.disclosure);
  $("btn-show-token").setAttribute("aria-expanded", String(prompt.field));
  const input = $("registration-token");
  input.required = prompt.required;
  input.setAttribute("aria-required", String(prompt.required));
  $("token-hint").textContent = prompt.required ? TOKEN_REQUIRED_HINT : TOKEN_OPTIONAL_HINT;
  return prompt;
}

/// Open the field because the user asked for it, and keep it open.
function showTokenField() {
  state.tokenFieldOpen = true;
  renderTokenPrompt();
  $("registration-token").focus();
}

async function authenticate(event) {
  event.preventDefault();
  setError("auth-error", "");
  const isRegister = state.authMode === "register";
  const serverUrl = currentServerUrl();
  const email = $("email").value.trim();
  const password = $("password").value;
  if (!email) { setError("auth-error", "Enter your email."); $("email").focus(); return; }
  if (!password) { setError("auth-error", "Enter your account password."); $("password").focus(); return; }
  if (isRegister && password.length < UI.minPasswordLength) {
    setError("auth-error", `Use at least ${UI.minPasswordLength} characters for your account password.`);
    $("password").focus();
    return;
  }
  const registrationToken = $("registration-token").value.trim();
  if (isRegister && !registrationToken && renderTokenPrompt().required) {
    setError("auth-error", TOKEN_MISSING_ERROR);
    $("registration-token").focus();
    return;
  }
  const args = { serverUrl, email, password };
  if (isRegister) args.registrationToken = registrationToken || null;
  setBusy($("btn-auth"), true, isRegister ? "Creating account…" : "Unlocking…");
  try {
    const user = await invoke(isRegister ? "register" : "login", args);
    if (ALLOW_CUSTOM_SERVER) remember("server", serverUrl);
    remember("email", email);
    $("password").value = "";
    $("registration-token").value = "";
    state.tokenFieldOpen = false;
    showApp(user);
  } catch (error) {
    setError("auth-error", error);
    if (isRegister && /token/i.test(String(error?.message ?? error))) showTokenField();
  } finally {
    setBusy($("btn-auth"), false);
  }
}

// ----- sign in with Google ----------------------------------------------------
// Google only establishes who someone is. The vault key comes from the
// passphrase either way, so every path here ends at a passphrase prompt.

/// Ask the server what it offers, so the button appears only where it works.
/// A server that cannot be reached simply has no button: there is nothing the
/// user can do about it from this screen, and an error here would fire on
/// every keystroke in the URL box.
///
/// A protocol mismatch is the exception and is shown. It means a server did
/// answer, so it is not keystroke noise, and it is the one failure here that
/// tells the user something they must act on: nothing on this screen will work
/// until the app or the server is updated.
async function refreshCapabilities() {
  const serverUrl = currentServerUrl();
  const wasIncompatible = state.incompatible;
  try {
    state.capabilities = await invoke("server_capabilities", { serverUrl });
    state.incompatible = null;
  } catch (error) {
    state.capabilities = null;
    state.incompatible = error?.code === "incompatible" ? String(error.message) : null;
  }
  // Only ever write the shared error line about this: clearing it
  // unconditionally would wipe a sign-in error the user still needs to read.
  if (state.incompatible) setError("auth-error", state.incompatible);
  else if (wasIncompatible) setError("auth-error", "");
  const offered = Boolean(state.capabilities?.google_sign_in) && !state.google;
  $("google-block").classList.toggle("hidden", !offered);
  // A different server can have a different answer about the token.
  renderTokenPrompt();
  renderGoogleChip();
}

/// The chip says what the account actually has, not what the server offers.
///
/// Hidden for an account that signs in with Google already: its link is the
/// only way in and cannot be removed, so there is nothing to offer. For a
/// password account it reads "Link Google" or names the address that can sign
/// in, which is what makes an unwanted link visible.
function renderGoogleChip() {
  const supported = Boolean(state.capabilities?.google_sign_in);
  const user = state.user;
  const canLink = supported && user?.password_login !== false;
  const chip = $("btn-link-google");
  chip.classList.toggle("hidden", !canLink);
  if (!canLink) return;
  const linked = user?.google_email || null;
  chip.querySelector(".chip-label").textContent = linked || "Link Google";
  chip.title = linked
    ? `${linked} can sign in to this account. Click to review or remove it.`
    : "Use your Google account to sign in to this server next time. Your passphrase is still what unlocks the vault.";
}

/// Swap the password form for the passphrase prompt, or back again.
function showGoogleForm(show) {
  $("auth-form").classList.toggle("hidden", show);
  $("google-block").classList.toggle("hidden", show || !state.capabilities?.google_sign_in);
  $("google-form").classList.toggle("hidden", !show);
  document.querySelector(".segmented").classList.toggle("hidden", show);
  if (!show) {
    $("google-password").value = "";
    $("google-registration-token").value = "";
    renderGoogleTokenPrompt(false, false);
    setError("google-error", "");
  }
}

async function startGoogleSignIn() {
  setError("auth-error", "");
  const serverUrl = currentServerUrl();
  setBusy($("btn-google"), true, "Waiting for your browser…");
  try {
    const stage = await invoke("google_sign_in", { serverUrl });
    if (ALLOW_CUSTOM_SERVER) remember("server", serverUrl);
    state.google = stage;
    const creating = stage.stage === "create_account";
    $("auth-title").textContent = creating ? "Create your vault" : "Unlock your vault";
    $("google-lead").textContent = creating
      ? `Signed in to Google as ${stage.email}. Choose a passphrase to encrypt this vault — it is never sent anywhere, and nobody can reset it.`
      : `Signed in to Google as ${stage.email}. Enter the passphrase that unlocks this vault.`;
    $("google-password-hint").textContent = creating
      ? `At least ${UI.minPasswordLength} characters. There is no passphrase reset.`
      : "Google cannot unlock your vault; only this passphrase can.";
    $("google-password").autocomplete = creating ? "new-password" : "current-password";
    $("btn-google-submit").textContent = creating ? "Create vault" : "Unlock vault";
    renderGoogleTokenPrompt(creating, stage.registration_token_required);
    showGoogleForm(true);
    $("google-password").focus();
  } catch (error) {
    setError("auth-error", error);
  } finally {
    setBusy($("btn-google"), false);
  }
}

/// The Google path has no disclosure button: by the time it is on screen the
/// server has already answered, in the sign-in stage itself. So the field is
/// either open and required or not there at all.
function renderGoogleTokenPrompt(isCreating, serverRequires) {
  const prompt = Screens.tokenPrompt(isCreating, Boolean(serverRequires));
  $("google-token-field").classList.toggle("hidden", !prompt.field);
  const input = $("google-registration-token");
  input.required = prompt.required;
  input.setAttribute("aria-required", String(prompt.required));
  $("google-token-hint").textContent = TOKEN_REQUIRED_HINT;
}

async function submitGooglePassphrase(event) {
  event.preventDefault();
  setError("google-error", "");
  const creating = state.google?.stage === "create_account";
  const password = $("google-password").value;
  if (!password) { setError("google-error", "Enter your passphrase."); $("google-password").focus(); return; }
  if (creating && password.length < UI.minPasswordLength) {
    setError("google-error", `Use at least ${UI.minPasswordLength} characters for your passphrase.`);
    $("google-password").focus();
    return;
  }

  const registrationToken = $("google-registration-token").value.trim();
  if (creating && !registrationToken && state.google?.registration_token_required) {
    setError("google-error", TOKEN_MISSING_ERROR);
    $("google-registration-token").focus();
    return;
  }
  const args = creating
    ? { password, registrationToken: registrationToken || null }
    : { password };
  setBusy($("btn-google-submit"), true, creating ? "Creating vault…" : "Unlocking…");
  try {
    const user = await invoke(creating ? "google_create_account" : "google_unlock", args);
    remember("email", user.email);
    state.google = null;
    showGoogleForm(false);
    showApp(user);
  } catch (error) {
    setError("google-error", error);
    if (creating && /token/i.test(String(error?.message ?? error))) {
      // The stage said no token was wanted and the server disagreed. Believe
      // the server, so the next submit is checked here rather than there.
      if (state.google) state.google.registration_token_required = true;
      renderGoogleTokenPrompt(true, true);
    }
  } finally {
    setBusy($("btn-google-submit"), false);
  }
}

/// Abandon a Google sign-in and go back to the password form. The attempt is
/// dropped on the Rust side the next time one starts, and the session it was
/// holding is never installed.
function cancelGoogleSignIn() {
  state.google = null;
  showGoogleForm(false);
  setAuthMode(state.authMode);
}

/// Review the Google link: add one, or remove the one that is there.
///
/// Both ask for the passphrase, because both change how this account can be
/// signed into and a session alone must not be enough to do that. The server
/// enforces it; asking here is what makes the rule visible and catches a typo
/// before a trip through the browser.
///
/// `afterEviction` means the user has just signed out their other devices and
/// was brought straight here. It adds the two things they need and cannot
/// infer: that the eviction worked, and that "too many requests" on the
/// removal means wait and try again rather than it failed.
function renderGoogleLinkForm({ afterEviction = false } = {}) {
  closeAccountSheet({ restoreFocus: false });
  state.selected = null;
  state.editing = true;
  state.showingInvites = false;
  syncInvitesView();
  const linked = state.user?.google_email || null;
  state.editTitle = linked ? "Google sign-in" : "Link Google";
  renderList();
  showDetailScreen();
  $("detail").innerHTML = `
    <form class="card" id="google-link-form" novalidate aria-labelledby="google-link-title">
      <h2 id="google-link-title" class="card-title pane-title">${icon("lock")} ${esc(state.editTitle)}${linked ? "" : infoButtonHtml("google-link-note", GOOGLE_LINK_NOTE)}</h2>
      ${linked ? "" : `<p class="hint hidden" id="google-link-note">${esc(GOOGLE_LINK_NOTE)}</p>`}
      ${afterEviction
        ? `<p class="card-lead">
             Your other devices are signed out. If someone else added this sign-in, removing it
             now is what keeps them out &mdash; they would have to go through Google again to
             get back.
           </p>`
        : ""}
      ${linked
        ? `<p class="card-lead"><strong>${esc(linked)}</strong> can sign in to this account without your
           passphrase. Remove it if you did not add it, or if you no longer want to sign in that way.</p>`
        : ""}
      <div class="field">
        <label for="gl-current">Your passphrase</label>
        <input id="gl-current" type="password" autocomplete="current-password" spellcheck="false">
        <p class="hint">
          ${linked
            ? "Removing a way to sign in needs more than an unlocked app."
            : "Adding a way to sign in needs more than an unlocked app."}
        </p>
      </div>
      <div class="error" id="gl-error" role="alert"></div>
      <div class="actions">
        <button type="submit" class="btn ${linked ? "danger" : "primary"}" id="btn-gl-save">
          ${linked ? `${icon("trash")} Remove link` : `${icon("check")} Link Google`}
        </button>
        <button type="button" class="btn" id="btn-gl-cancel">Cancel</button>
      </div>
    </form>`;

  $("btn-gl-cancel").onclick = () => { state.editing = false; renderDetail(); showListScreen(); };
  $("google-link-form").onsubmit = submitGoogleLinkChange;
  $("gl-current").focus();
}

/// Confirmation for ending every other session.
///
/// Deliberately not behind the passphrase. Someone reaches for this because
/// they think another session is open that should not be, and the whole value
/// of the route is that nothing the other session does can block it — adding a
/// derivation and a verify in front would hand it a way to.
///
/// This device keeps its session on purpose, so whatever the user does next
/// about the party they just evicted goes out straight away rather than after
/// a sign-in they would have to sit through.
function renderSignOutOthersForm() {
  closeAccountSheet({ restoreFocus: false });
  state.selected = null;
  state.editing = true;
  state.showingInvites = false;
  syncInvitesView();
  state.editTitle = "Sign out other devices";
  renderList();
  showDetailScreen();
  $("detail").innerHTML = `
    <form class="card" id="sign-out-others-form" novalidate aria-labelledby="sign-out-others-title">
      <h2 id="sign-out-others-title" class="card-title pane-title">${icon("alert")} ${esc(state.editTitle)}${infoButtonHtml("sign-out-others-note", SIGN_OUT_OTHERS_NOTE)}</h2>
      <p class="card-lead">
        Every other device signed in to this account is signed out. This one stays
        signed in. Your secrets are untouched and your passphrase does not change.
      </p>
      <p class="hint hidden" id="sign-out-others-note">${esc(SIGN_OUT_OTHERS_NOTE)}</p>
      <div class="error" id="soa-error" role="alert"></div>
      <div class="actions">
        <button type="submit" class="btn danger solid" id="btn-soa-save">
          ${icon("check")} Sign out other devices
        </button>
        <button type="button" class="btn" id="btn-soa-cancel">Cancel</button>
      </div>
    </form>`;

  $("btn-soa-cancel").onclick = () => { state.editing = false; renderDetail(); showListScreen(); };
  $("sign-out-others-form").onsubmit = submitSignOutOthers;
  $("btn-soa-cancel").focus();
}

async function submitSignOutOthers(event) {
  event.preventDefault();
  setError("soa-error", "");
  setBusy($("btn-soa-save"), true, "Signing out…");
  try {
    state.user = await invoke("sign_out_other_devices");
    renderGoogleChip();
    toast("Other devices signed out");
    // The few seconds this just bought are the whole point, so spend them on
    // the thing it bought them for rather than leaving the user to find the
    // chip themselves. Only when there is a link to remove: otherwise the list
    // is where they should land.
    if (state.user?.google_email) {
      renderGoogleLinkForm({ afterEviction: true });
      return;
    }
    state.editing = false;
    renderDetail();
    showListScreen();
  } catch (error) {
    // Both failure codes mean this device is signed out as well, so follow it
    // here rather than leaving a card over a vault this app no longer holds a
    // session for. The message says which of the two it was.
    const code = String(error?.code ?? "");
    if (code === "ambiguous" || code === "signed-out") {
      signOutAfterAmbiguousChange(String(error?.message ?? error));
      return;
    }
    setError("soa-error", code === "throttled" ? retryLater(error) : error);
  } finally {
    // The success path replaces `#detail`, so this button may be gone. Checked
    // rather than left to `setBusy` to absorb, matching `submitPassphraseChange`.
    if ($("btn-soa-save")?.isConnected) setBusy($("btn-soa-save"), false);
  }
}

async function submitGoogleLinkChange(event) {
  event.preventDefault();
  setError("gl-error", "");
  const current = $("gl-current").value;
  if (!current) {
    setError("gl-error", "Enter your passphrase.");
    $("gl-current").focus();
    return;
  }
  const linked = Boolean(state.user?.google_email);
  setBusy($("btn-gl-save"), true, linked ? "Removing\u2026" : "Waiting for your browser\u2026");
  try {
    const user = await invoke(linked ? "google_unlink" : "google_link", { current });
    state.user = user;
    renderGoogleChip();
    toast(linked ? "Google sign-in removed" : "Google account linked");
    state.editing = false;
    renderDetail();
    showListScreen();
  } catch (error) {
    // Throttling is not failure, and the difference matters most to someone
    // trying to remove a sign-in that should not be there. Say what to do.
    setError("gl-error", String(error?.code ?? "") === "throttled" ? retryLater(error) : error);
  } finally {
    setBusy($("btn-gl-save"), false);
  }
}

/// Past this, the server's suggested wait is reported as "later" rather than
/// relayed as a number. Five minutes is already far longer than any bucket
/// here refills in.
const RETRY_HINT_CEILING_SECS = 300;

/// Turn a throttled error into an instruction rather than a verdict.
///
/// Written here from the number the server sent rather than built on the
/// sentence it sent. That sentence is a string a hostile server chooses, and
/// appending "nothing was changed" to it would read as this app vouching for
/// it. The wait is a fact we can state ourselves.
function retryLater(error) {
  const secs = Number(error?.retry_after_secs);
  // The number is the server's, and the server is the party this app guards
  // against. It cannot do anything worse here than keep refusing, but relaying
  // "try again in thirty-one years" would turn an instruction into nonsense,
  // so anything past a few minutes is reported as a few minutes.
  const when = !Number.isFinite(secs) || secs <= 0
    ? "in a few seconds"
    : secs > RETRY_HINT_CEILING_SECS
      ? "later"
      : `in ${Math.ceil(secs)} ${Math.ceil(secs) === 1 ? "second" : "seconds"}`;
  return `Nothing was changed. The server is limiting how often this can be asked — try again ${when}.`;
}

function showApp(user) {
  state.user = user;
  $("who-email").textContent = user.email;
  $("who-server").textContent = user.server_url;
  $("who-server").title = user.server_url;
  $("fingerprint").textContent = user.fingerprint;
  $("acct-email").textContent = user.email;
  $("acct-fp").textContent = user.fingerprint;
  $("acct-initial").textContent = (Array.from(String(user.email ?? "").trim())[0] || "?").toUpperCase();
  renderGoogleChip();
  $("auth").classList.add("hidden");
  $("app").classList.remove("hidden");
  state.secrets = []; state.projects = []; state.selected = null; state.editing = false; state.inviteCount = 0;
  state.showingInvites = false; state.showingProjects = false; state.projectRow = null;
  $("filter").value = "";
  syncSearchClear();
  $("app").dataset.screen = "list";
  renderDetail();
  refresh();
}

/// Everything the signed-out state needs cleared, in one place.
///
/// Three paths reach it — logging out, a passphrase change whose answer was
/// lost, and signing out after an eviction that could not be confirmed — and
/// they used to each keep their own copy, which had already drifted apart.
function resetToSignedOut() {
  clearReveals();
  // Dropped with the rest of it: the chip reads the signed-in account, and a
  // stale one would describe the last person to use this app.
  state.user = null;
  state.secrets = []; state.projects = []; state.selected = null; state.editing = false; state.inviteCount = 0;
  state.showingInvites = false; state.showingProjects = false; state.projectRow = null;
  state.invitees = []; state.inviteFor = null; state.inviteSession = 0;
  // Both belong to the account that is going away: the menu would otherwise
  // sit over the sign-in screen naming one of its members, with live handlers
  // behind it, and the next account would read the last one's member list.
  closeRowMenu();
  sharedWith = { members: [], invites: [] };
  closeDialog($("invite-dialog"));
  closeDialog($("form-dialog"));
  // Lives outside #detail, so emptying that below does not reach it: a modal
  // left open would sit over the sign-in screen still naming a project.
  closeDialog($("project-delete-dialog"));
  syncScreenChrome();
  $("list").innerHTML = ""; $("detail").innerHTML = ""; $("invites").innerHTML = ""; $("invites-banner").innerHTML = "";
  closeAccountSheet({ restoreFocus: false });
  setError("main-error", "");
  $("app").classList.add("hidden");
  $("auth").classList.remove("hidden");
  // The next person to use this app gets the folded server line back.
  $("auth").classList.remove("server-open");
}

async function logout() {
  await invoke("logout");
  resetToSignedOut();
  $("password").focus();
}

// ----- data ------------------------------------------------------------------

function setSyncing(syncing) {
  const button = $("btn-refresh");
  button.disabled = syncing;
  if (syncing) button.setAttribute("aria-busy", "true"); else button.removeAttribute("aria-busy");
  $("list").setAttribute("aria-busy", String(syncing));
}

async function refresh() {
  setError("main-error", "");
  setSyncing(true);
  try {
    // One round trip for all three: the list cannot be grouped without the
    // projects, so fetching them after it would draw the vault twice.
    const [secrets, invites, projects] = await Promise.all([
      invoke("list_secrets"),
      invoke("list_invites"),
      invoke("list_projects"),
    ]);
    state.secrets = secrets;
    state.projects = projects;
    renderList();
    renderInvites(invites);
    if (state.selected !== null && !secrets.some((s) => s.id === state.selected)) state.selected = null;
    // The Projects panel owns the detail pane while it is open, and redraws
    // itself after the refreshes it starts.
    if (!state.editing && !state.showingProjects) renderDetail();
    syncScreenAfterRefresh();
  } catch (error) {
    setError("main-error", error);
    if (error?.code === "unauthorized") logout().catch((e) => setError("main-error", e));
  } finally {
    setSyncing(false);
  }
}

async function act(command, args, successMessage, button) {
  setError("main-error", "");
  setBusy(button, true);
  try {
    await invoke(command, args);
    if (successMessage) toast(successMessage);
    await refresh();
    return true;
  } catch (error) {
    setError("main-error", error);
    return false;
  } finally {
    if (button?.isConnected) setBusy(button, false);
  }
}

// ----- list ------------------------------------------------------------------

function matchesFilter(secret, needle) {
  if (!needle) return true;
  // The project name is searchable too: typing "Perspectiv" should pull up
  // what is filed under it, which is the whole reason for filing it there.
  const fields = [secret.name, secret.username, secret.url, secret.project?.name];
  return fields.some((v) => String(v ?? "").toLowerCase().includes(needle));
}

function itemHtml(s) {
  const selected = s.id === state.selected;
  // The words go in their own span. `.item-sub` is a flex container so that
  // the broken-secret icon sits beside them, and `text-overflow` does not
  // reach the anonymous box a bare text node gets inside one: an address too
  // long for the row was cut off mid-character with no ellipsis to say so,
  // while the name above it -- not a flex container -- ellipsised properly.
  const subtitle = s.error
    ? `${icon("alert")}<span class="item-sub-text">Cannot be decrypted</span>`
    : `<span class="item-sub-text">${s.username ? esc(s.username) : "<em>No username</em>"}</span>`;
  // Shared rows sit under a "Shared with me" heading that already says so, so
  // the badge is the icon alone and gives the row's name the ~45px the word
  // was taking. What the word did not say -- who shared it -- is what is
  // left: in the tooltip for a pointer, and in text for a screen reader,
  // which would otherwise be read the icon's absence of a name.
  const shared = s.is_owner ? "" : `
      <span class="badge" title="Shared by ${esc(s.owner_email)}">${icon("users")}<span class="sr-only">Shared by ${esc(s.owner_email)}</span></span>`;
  return `
    <button type="button" class="item${selected ? " active" : ""}${s.error ? " broken" : ""}"
      role="option" aria-selected="${selected}" data-id="${s.id}" tabindex="${selected ? 0 : -1}">
      ${avatar(s.name, { broken: Boolean(s.error) })}
      <span class="item-text">
        <span class="item-name">${esc(s.name)}</span>
        <span class="item-sub">${subtitle}</span>
      </span>${shared}
      <span class="chev">${icon("chevronRight")}</span>
    </button>`;
}

function renderList() {
  const needle = $("filter").value.trim().toLowerCase();
  const rows = state.secrets
    .filter((s) => matchesFilter(s, needle))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  const total = state.secrets.length;
  const sharedTotal = state.secrets.filter((s) => !s.is_owner).length;
  $("count").textContent = needle
    ? `${rows.length} of ${total} match`
    : `${plural(total, "secret", "secrets")}${sharedTotal ? ` · ${sharedTotal} shared with you` : ""}`;
  // macOS repeats the count under the toolbar title and iOS in its bottom
  // toolbar; both are the same sentence as the list's own count line.
  $("toolbar-sub").textContent = $("count").textContent;
  $("bottom-count").textContent = $("count").textContent;

  const list = $("list");
  if (!rows.length) {
    list.innerHTML = `<p class="list-empty">${needle ? "No secrets match your search." : "Your vault is empty."}</p>`;
    return;
  }
  // Always wrapped, titled or not: the phone layout draws each group as one
  // inset card with hairlines between its rows.
  list.innerHTML = Screens.listSections(rows, state.projects)
    .map((section) => Screens.listGroupHtml(section.title, section.secrets.map(itemHtml).join("")))
    .join("");

  const items = list.querySelectorAll(".item");
  if (!list.querySelector('.item[tabindex="0"]') && items.length) items[0].tabIndex = 0;
  for (const el of items) el.onclick = () => selectSecret(Number(el.dataset.id));
}

/// Arrow keys move focus within the list; Enter/Space activate the focused item.
/// Show the clear button only while there is something to clear, and give
/// the field the room it needs while it is there.
function syncSearchClear() {
  const typed = $("filter").value.length > 0;
  $("search-box").classList.toggle("has-text", typed);
  $("btn-clear-search").hidden = !typed;
}

/// Empty the search and put the cursor back in it. Focus matters: the button
/// disappears the moment it is used, so leaving focus on it would strand it
/// on nothing.
function clearSearch() {
  $("filter").value = "";
  syncSearchClear();
  renderList();
  $("filter").focus();
}

function listKeydown(event) {
  const items = [...$("list").querySelectorAll(".item")];
  const index = items.indexOf(document.activeElement);
  if (!items.length || index === -1) return;
  const moves = { ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: items.length - 1 };
  if (!(event.key in moves)) return;
  event.preventDefault();
  const next = items[Math.max(0, Math.min(items.length - 1, moves[event.key]))];
  for (const el of items) el.tabIndex = -1;
  next.tabIndex = 0;
  next.focus();
}

function selectSecret(id) {
  state.selected = id;
  state.editing = false;
  state.showingInvites = false;
  state.showingProjects = false;
  state.projectRow = null;
  renderList();
  renderDetail();
  showDetailScreen();
}

function startNew() {
  state.selected = null;
  state.showingInvites = false;
  state.showingProjects = false;
  state.projectRow = null;
  renderList();
  renderForm(null);
  showDetailScreen();
}

function showInvitesScreen() {
  state.selected = null;
  state.editing = false;
  state.showingInvites = true;
  state.showingProjects = false;
  state.projectRow = null;
  closeDialog($("form-dialog"));
  renderList();
  renderDetail();
  showDetailScreen();
  renderInvitesBanner(state.inviteCount);
  $("invites-title")?.focus();
}

// ----- invites ---------------------------------------------------------------

function renderInvites(invites) {
  const box = $("invites");
  state.inviteCount = invites.length;
  $("main").classList.toggle("has-invites", invites.length > 0);
  // Answering the last invitation leaves nothing to show in that view.
  if (!invites.length && state.showingInvites) {
    state.showingInvites = false;
    syncInvitesView();
  }
  renderInvitesBanner(invites.length);
  if (!invites.length) { box.innerHTML = ""; return; }
  box.innerHTML = `
    <section aria-labelledby="invites-title">
      <h2 id="invites-title" class="section-title" tabindex="-1">${icon("inbox")} Invitations <span class="count-pill">${invites.length}</span></h2>
      ${invites.map((i) => `
        <div class="card invite">
          <div class="invite-body">
            ${avatar(i.inviter_email)}
            <div class="invite-text">
              <div><strong>${esc(i.inviter_email)}</strong> wants to share <strong>${esc(i.secret_name)}</strong> with you.</div>
              ${i.message ? `<blockquote class="quote">${esc(i.message)}</blockquote>` : ""}
              <div class="muted small">${formatDate(i.created_at)}</div>
            </div>
          </div>
          <div class="actions">
            <button type="button" class="btn primary" data-accept="${i.id}">${icon("check")} Accept</button>
            <button type="button" class="btn" data-decline="${i.id}">Decline</button>
          </div>
        </div>`).join("")}
    </section>`;
  for (const el of box.querySelectorAll("[data-accept]")) {
    el.onclick = () => act("accept_invite", { inviteId: Number(el.dataset.accept) }, "Added to your vault", el);
  }
  for (const el of box.querySelectorAll("[data-decline]")) {
    el.onclick = () => act("decline_invite", { inviteId: Number(el.dataset.decline) }, "Invite declined", el);
  }
}

/// The invitations entry in the list. One button whose parts each platform
/// shows or hides: a source-list row with a count on macOS and iOS, an info
/// bar on Windows, a banner across the content on GNOME, a card on Android.
/// "View" is drawn as a button but is text inside this one, so there is a
/// single control to reach rather than two doing the same thing.
function renderInvitesBanner(count) {
  const banner = $("invites-banner");
  if (!count) { banner.innerHTML = ""; return; }
  const waiting = `${plural(count, "invitation", "invitations")} waiting`;
  banner.innerHTML = `
    <button type="button" class="invites-banner" id="btn-invites" aria-current="${state.showingInvites ? "page" : "false"}">
      <span class="ib-icon">${icon("inbox")}</span>
      <span class="ib-label">Invitations</span>
      <span class="ib-sentence">${waiting}</span>
      <span class="count-pill">${count}</span>
      <span class="ib-view">View</span>
      <span class="ib-chev">${icon("chevronRight")}</span>
    </button>`;
  $("btn-invites").onclick = showInvitesScreen;
}

/// The detail pane shows either the invitations or the selected secret.
function syncInvitesView() {
  $("main").classList.toggle("showing-invites", state.showingInvites);
  $("btn-invites")?.setAttribute("aria-current", state.showingInvites ? "page" : "false");
}

// ----- detail ----------------------------------------------------------------

function emptyDetailHtml() {
  if (!state.secrets.length) {
    return `
      <div class="card empty">
        <div class="empty-icon">${icon("lock")}</div>
        <h2>Your vault is empty</h2>
        <p>Create your first secret. It is encrypted on this device before anything is sent to the server.</p>
        <button type="button" class="btn primary" id="btn-empty-new">${icon("plus")} New secret</button>
      </div>`;
  }
  return `
    <div class="card empty">
      <div class="empty-icon">${icon("key")}</div>
      <h2>No secret selected</h2>
      <p>${isMobile()
        ? "Pick one from your vault, or tap + to create a new one."
        : `Pick one from the list, or press <span class="kbd">${esc(NEW_SECRET_SHORTCUT)}</span> to create a new one.`}</p>
    </div>`;
}

function kvRow(iconName, label, value, { mono = false, copyLabel = null } = {}) {
  const hasValue = Boolean(value);
  const valueHtml = hasValue
    ? `<div class="value${mono ? " mono" : ""}">${esc(value)}</div>`
    : `<div class="value none">None</div>`;
  const actions = hasValue && copyLabel
    ? `<div class="kv-actions"><button type="button" class="icon-btn" data-copy="${esc(value)}" data-copy-label="${esc(copyLabel)}" aria-label="Copy ${esc(copyLabel.toLowerCase())}" title="Copy">${icon("copy")}</button></div>`
    : "";
  return `<div class="kv-row"><dt>${icon(iconName)}<span class="kv-label">${esc(label)}</span></dt><dd>${valueHtml}${actions}</dd></div>`;
}

/// Extra details, in the order they were saved. A value the user marked as
/// hidden is masked and fetched one field at a time, like the password; the
/// rest are shown outright, like the username.
function customFieldRows(secret) {
  return (secret.fields ?? [])
    .map((field, index) =>
      field.secret
        ? secretRow("lock", field.label, `f${index}`)
        : kvRow("note", field.label, field.value, { copyLabel: field.label }))
    .join("");
}

/// Where the secret is filed. The owner gets a picker that moves it; anyone
/// else gets the name, and only when the owner chose to show it.
///
/// A secret shared with you has no row at all when its project was withheld,
/// rather than one reading "None": you have not been told it is unfiled, you
/// have been told nothing, and the two should not look like the same claim.
function projectRow(secret) {
  if (!secret.is_owner) {
    return secret.project ? kvRow("folder", "Project", secret.project.name) : "";
  }
  return `
    <div class="kv-row"><dt>${icon("folder")}<span class="kv-label">Project</span></dt>
      <dd>${projectSelectHtml(secret.project, { id: "detail-project", includeNew: false })}</dd></div>`;
}

function renderDetail() {
  clearReveals();
  // The pane is about to be rewritten. loadSharing() closes the menu too, but
  // it only runs for a secret this account owns -- a shared or broken one, or
  // the empty state, would leave a menu floating over the new screen with its
  // handlers still closed over the secret that is no longer open.
  closeRowMenu();
  syncScreenChrome();
  const s = state.secrets.find((x) => x.id === state.selected);
  $("main").classList.toggle("has-selection", Boolean(s));
  syncInvitesView();
  if (!s) {
    $("detail").innerHTML = emptyDetailHtml();
    const newButton = $("btn-empty-new");
    if (newButton) newButton.onclick = startNew;
    return;
  }
  if (s.error) { renderBroken(s); return; }

  const ownership = s.is_owner
    ? `${icon("user")} Owned by you`
    : `${icon("users")} Shared by ${esc(s.owner_email)}`;
  $("detail").innerHTML = `
    <article class="card" aria-labelledby="detail-title">
      <header class="detail-head">
        ${avatar(s.name, { size: "lg" })}
        <div class="detail-title">
          <h2 id="detail-title">${esc(s.name)}</h2>
          <div class="detail-meta">
            <span>${ownership}</span>
            <span class="dot"></span>
            <span>${icon("clock")} Updated ${formatDate(s.updated_at)}</span>
          </div>
        </div>
        <div class="actions">
          ${s.is_owner ? `<button type="button" class="btn" id="btn-edit">${icon("edit")} Edit</button>` : ""}
          <button type="button" class="btn danger" id="btn-delete">${icon("trash")} ${s.is_owner ? "Delete" : "Remove"}</button>
        </div>
      </header>
      <div id="confirm-delete"></div>
      <dl class="kv">
        ${projectRow(s)}
        ${kvRow("user", "Username", s.username, { mono: true, copyLabel: "Username" })}
        ${secretRow("key", "Password", "pw")}
        ${s.url ? kvRow("globe", "URL", s.url, { copyLabel: "URL" }) : ""}
        ${s.notes ? kvRow("note", "Notes", s.notes) : ""}
        ${customFieldRows(s)}
      </dl>
    </article>
    ${s.is_owner ? `
      <section class="card" id="sharing" aria-labelledby="sharing-title">
        <h3 id="sharing-title" class="card-title">${icon("users")} Sharing</h3>
        <p class="muted">Loading…</p>
      </section>` : ""}
    <button type="button" class="btn danger delete-bottom" id="btn-delete-bottom">${s.is_owner ? "Delete Secret" : "Remove from Vault"}<span class="ell">…</span></button>`;

  for (const el of $("detail").querySelectorAll("[data-copy]")) {
    el.onclick = () => copyText(el.dataset.copy, el.dataset.copyLabel);
  }
  const stillShowing = () => state.selected === s.id;
  wireSecretRow(
    "pw",
    () => invoke("reveal_password", { id: s.id }),
    () => invoke("copy_password", { id: s.id }),
    stillShowing,
    "Password",
  );
  // Each hidden custom field is fetched by its own id, so showing one does
  // not bring the others back to the UI with it.
  (s.fields ?? []).forEach((field, index) => {
    if (!field.secret) return;
    wireSecretRow(
      `f${index}`,
      () => invoke("reveal_field", { id: s.id, fieldId: field.id }),
      () => invoke("copy_field", { id: s.id, fieldId: field.id }),
      stillShowing,
      field.label,
    );
  });
  const moveSelect = $("detail-project");
  if (moveSelect) moveSelect.onchange = async () => {
    const projectId = moveSelect.value === NO_PROJECT ? null : Number(moveSelect.value);
    moveSelect.disabled = true;
    // `act` refreshes, which redraws this pane with the new filing in place.
    if (!await act("move_secret", { id: s.id, projectId }, "Secret moved", null)) {
      // Put the picker back to what is stored rather than leaving it showing
      // a move that did not happen.
      moveSelect.value = s.project?.id ?? NO_PROJECT;
      moveSelect.disabled = false;
    }
  };
  $("btn-delete").onclick = () => renderDeleteConfirm(s);
  $("btn-delete-bottom").onclick = () => renderDeleteConfirm(s);
  if (s.is_owner) {
    $("btn-edit").onclick = () => renderForm(s);
    loadSharing(s.id);
  }
}

/// Reveal state, one entry per masked value on screen: the password and each
/// sensitive custom field count down and hide themselves independently. Every
/// value is masked again after REVEAL_HIDE_AFTER_MS, and whenever the detail
/// pane re-renders.
const reveals = new Map();

function clearReveals() {
  for (const { hide, tick } of reveals.values()) { clearTimeout(hide); clearInterval(tick); }
  reveals.clear();
}

/// The three elements making up one masked value, by the key in its ids.
function revealSlot(key) {
  return { value: $(`val-${key}`), timer: $(`timer-${key}`), button: $(`btn-reveal-${key}`) };
}

function setRevealButton(button, shown) {
  if (!button) return;
  button.innerHTML = icon(shown ? "eyeOff" : "eye");
  button.setAttribute("aria-pressed", String(shown));
  button.setAttribute("aria-label", shown ? "Hide" : "Show");
  button.title = shown ? "Hide" : "Show";
}

function hideValue(key, slots) {
  const timers = reveals.get(key);
  if (timers) { clearTimeout(timers.hide); clearInterval(timers.tick); reveals.delete(key); }
  const { value, timer, button } = slots ?? revealSlot(key);
  if (!value) return;
  value.textContent = MASKED;
  value.dataset.shown = "0";
  if (timer) { timer.textContent = ""; timer.classList.add("hidden"); }
  setRevealButton(button, false);
}

function showValue(key, slots, text) {
  // Whatever is already counting down under this key is replaced, not left
  // running: an orphaned interval keeps writing into a countdown beside a
  // value that has since been masked, and its timeout hides the next reveal
  // early.
  const existing = reveals.get(key);
  if (existing) { clearTimeout(existing.hide); clearInterval(existing.tick); }
  const { value, timer, button } = slots;
  if (!value) return;
  value.textContent = text;
  value.dataset.shown = "1";
  setRevealButton(button, true);
  const until = Date.now() + REVEAL_HIDE_AFTER_MS;
  const tick = () => {
    if (!timer) return;
    timer.textContent = `Hides in ${Math.max(0, Math.ceil((until - Date.now()) / 1000))}s`;
    timer.classList.remove("hidden");
  };
  tick();
  reveals.set(key, {
    hide: setTimeout(() => hideValue(key, slots), REVEAL_HIDE_AFTER_MS),
    tick: setInterval(tick, 1000),
  });
}

/// A masked value with Show and Copy buttons. `key` makes its element ids.
function secretRow(iconName, label, key) {
  const lower = esc(label.toLowerCase());
  return `
    <div class="kv-row">
      <dt>${icon(iconName)}<span class="kv-label">${esc(label)}</span></dt>
      <dd>
        <code class="value mono" id="val-${key}" data-shown="0">${MASKED}</code>
        <span class="pw-timer hidden" id="timer-${key}" aria-live="off"></span>
        <div class="kv-actions">
          <button type="button" class="icon-btn" id="btn-reveal-${key}" aria-label="Show ${lower}" aria-pressed="false" title="Show">${icon("eye")}</button>
          <button type="button" class="icon-btn" id="btn-copy-${key}" aria-label="Copy ${lower}" title="Copy">${icon("copy")}</button>
        </div>
      </dd>
    </div>`;
}

/// Wire Show and Copy for one masked value. Both go through Rust, which holds
/// the plaintext for as little time as it can and clears the clipboard after.
/// `stillShowing` guards against the view changing while the call is in flight.
function wireSecretRow(key, fetchValue, copyValue, stillShowing, subject = "Value") {
  const reveal = $(`btn-reveal-${key}`);
  const copy = $(`btn-copy-${key}`);
  // Captured now, not looked up again when the value arrives. The key is
  // positional, so if the pane re-renders while the fetch is in flight —
  // a refresh picking up a field another device added above this one —
  // the same key would name a different field's row, and the plaintext
  // would be written under the wrong label.
  const slots = revealSlot(key);
  const slot = slots.value;
  // A reveal is a network round trip, so the button stays clickable for as
  // long as it takes. A second click must not become a second reveal: the
  // first would land after the user had hidden the value again and put it
  // back on screen for another thirty seconds, unasked.
  let inFlight = false;
  if (reveal) reveal.onclick = async () => {
    if (inFlight) return;
    if (slot?.dataset.shown === "1") { hideValue(key, slots); return; }
    setError("main-error", "");
    inFlight = true;
    reveal.disabled = true;
    try {
      const text = await fetchValue();
      // A re-render detaches this node, which is how we know the row we
      // were wired to is gone rather than merely scrolled away.
      if (!stillShowing() || !slot?.isConnected) return;
      showValue(key, slots, text);
    } catch (error) {
      setError("main-error", error);
    } finally {
      inFlight = false;
      if (reveal.isConnected) reveal.disabled = false;
    }
  };
  if (copy) copy.onclick = async () => {
    setError("main-error", "");
    try {
      const seconds = await copyValue();
      // Android's snackbar carries the one action that fits a copy: undo it.
      const clearAction = PLATFORM === "android" ? { label: "Clear now", run: clearClipboardNow } : null;
      toast(`${subject} copied · clipboard clears in ${seconds}s`, clearAction);
    } catch (error) { setError("main-error", error); }
  };
}

/// Wipe the clipboard now instead of when the timer runs out. Rust only clears
/// it if it still holds what this app put there.
async function clearClipboardNow() {
  const cleared = await invoke("clear_copied_value");
  toast(cleared ? "Clipboard cleared" : "Clipboard has changed since, so it was left alone");
}

/// Inline confirmation instead of window.confirm(), which the webview may not show.
function renderDeleteConfirm(s) {
  const box = $("confirm-delete");
  const verb = s.is_owner ? "Delete secret" : "Remove from vault";
  const question = s.is_owner
    ? `Delete <strong>${esc(s.name)}</strong>? It disappears for everyone it is shared with. This cannot be undone.`
    : `Remove <strong>${esc(s.name)}</strong> from your vault? The owner can invite you again later.`;
  box.innerHTML = `
    <div class="confirm-bar" role="alertdialog" aria-labelledby="confirm-delete-text">
      ${icon("alert")}
      <span id="confirm-delete-text">${question}</span>
      <div class="actions">
        <button type="button" class="btn" id="btn-delete-cancel">Cancel</button>
        <button type="button" class="btn danger solid" id="btn-delete-confirm">${verb}</button>
      </div>
    </div>`;
  const cancel = () => {
    box.innerHTML = "";
    firstVisible("btn-delete", "btn-bar-more", "btn-delete-bottom")?.focus();
  };
  $("btn-delete-cancel").onclick = cancel;
  box.firstElementChild.addEventListener("keydown", (e) => { if (e.key === "Escape") cancel(); });
  $("btn-delete-confirm").onclick = async () => {
    if (await act("delete_secret", { id: s.id }, s.is_owner ? "Secret deleted" : "Removed from your vault", $("btn-delete-confirm"))) {
      state.selected = null;
      renderList();
      renderDetail();
      showListScreen();
    }
  };
  $("btn-delete-cancel").focus();
}

function renderBroken(s) {
  $("detail").innerHTML = `
    <article class="card" aria-labelledby="detail-title">
      <header class="detail-head">
        ${avatar(s.name, { size: "lg", broken: true })}
        <div class="detail-title">
          <h2 id="detail-title">${esc(s.name)}</h2>
          <div class="detail-meta">
            <span>${s.is_owner ? `${icon("user")} Owned by you` : `${icon("users")} Shared by ${esc(s.owner_email)}`}</span>
          </div>
        </div>
        <div class="actions">
          <button type="button" class="btn danger" id="btn-delete">${icon("trash")} ${s.is_owner ? "Delete" : "Remove"}</button>
        </div>
      </header>
      <div id="confirm-delete"></div>
      <div class="notice danger">
        ${icon("alert")}
        <div>
          <div><strong>This secret cannot be decrypted.</strong> ${esc(s.error)}</div>
          <div class="muted small" style="margin-top:4px">${s.is_owner
            ? "The stored data is damaged. Delete it and create it again."
            : "Ask the owner to revoke your access and invite you again, or remove it from your vault."}</div>
        </div>
      </div>
    </article>`;
  $("btn-delete").onclick = () => renderDeleteConfirm(s);
}

// ----- sharing ---------------------------------------------------------------

/// Who the open secret is already shared with, as the last `get_access`
/// reported it. The invite dialog reads it so somebody who is already on the
/// list is caught while they are being typed, rather than after a lookup and
/// a fingerprint check have been spent on them.
let sharedWith = { members: [], invites: [] };

async function loadSharing(id) {
  // Before the early return, not after it: the menu is parented to the body
  // and outlives the pane it was opened from.
  closeRowMenu();
  const box = $("sharing");
  if (!box) return;
  // Emptied before the fetch, not after it: it belongs to whichever secret
  // is open, and the previous one's members must not be left standing while
  // this one loads -- the invite dialog reads it, and would refuse somebody
  // on the grounds that they can see a different secret.
  sharedWith = { members: [], invites: [] };
  try {
    const access = await invoke("get_access", { id });
    if (!box.isConnected || state.selected !== id) return; // user moved on
    sharedWith = access;
    // Members and pending invites in one list, each saying where it stands,
    // the way every platform's own sharing list reads.
    //
    // One row per person: who they are, where they stand, and one button
    // holding everything that can be done about them. A wide pane fits that
    // on a line; the phone layout wraps the status under the address, which
    // is the only way all three fit at 360dp without the address being cut
    // short -- and the address is what says whose access this is.
    const filed = state.secrets.find((s) => s.id === id)?.project ?? null;
    const personRow = (email, status, key) => `
      <li class="person">${avatar(email, { size: "sm" })}<span class="who">${esc(email)}</span>
        <span class="people-status">${esc(status)}</span>
        <button type="button" class="icon-btn row-more" data-menu="${key}" aria-haspopup="menu" aria-expanded="false"
          aria-label="Options for ${esc(email)}" title="Options">${icon("more")}</button></li>`;
    const people = [
      ...access.members.map((m) => personRow(m.email, "Can view", `m${m.user_id}`)),
      ...access.invites.map((i) => personRow(i.email, "Invite pending", `i${i.id}`)),
    ];
    box.innerHTML = `
      <div class="share-head">
        <div class="share-head-text">
          <h3 id="sharing-title" class="card-title">${icon("users")} Sharing${infoButtonHtml("sharing-note", SHARING_NOTE)}</h3>
          <p class="hint hidden" id="sharing-note">${esc(SHARING_NOTE)}</p>
        </div>
        <button type="button" class="btn primary share-invite" id="btn-open-invite">${icon("plus")} <span>Invite People<span class="ell">\u2026</span></span></button>
      </div>
      <div id="revoke-confirm"></div>
      <ul class="people" id="members">${people.length ? people.join("") : `<li class="only-you">Only you have access.</li>`}</ul>`;

    $("btn-open-invite").onclick = () => openInviteDialog(id);
    // The project item is offered even when the secret is filed nowhere. The
    // flag belongs to the membership, not to the project, and it outlives any
    // particular filing: leaving the item out while a secret is unfiled hid a
    // grant that was still switched on, which the owner could neither see nor
    // clear -- and filing the secret under a *different* project later would
    // have shown that person its name without anyone being asked again.
    for (const member of access.members) {
      const button = box.querySelector(`[data-menu="m${member.user_id}"]`);
      if (!button) continue;
      button.onclick = () => openRowMenu(button, [
        {
          label: filed ? `Can see this is in ${filed.name}` : "Can see which project this is in",
          icon: "folder",
          checked: member.sees_project,
          run: () => setMemberProject(id, member, !member.sees_project),
        },
        { label: "Revoke access\u2026", icon: "trash", danger: true, run: () => revokeMember(id, member.user_id, button, []) },
      ]);
    }
    for (const invite of access.invites) {
      const button = box.querySelector(`[data-menu="i${invite.id}"]`);
      if (!button) continue;
      button.onclick = () => openRowMenu(button, [
        { label: "Cancel invite", icon: "close", danger: true, run: () => cancelInvite(id, invite.id, button) },
      ]);
    }
  } catch (error) {
    if (box.isConnected) box.innerHTML = `<h3 id="sharing-title" class="card-title">${icon("users")} Sharing</h3><div class="error">${esc(error?.message ?? error)}</div>`;
  }
}

/// Let one member see which project the secret is filed under, or stop them.
///
/// The list is redrawn from what the server then reports rather than from
/// what was asked for: a failure must not leave the menu saying somebody can
/// see something they cannot, which is the wrong direction to be wrong in.
async function setMemberProject(id, member, wanted) {
  try {
    await invoke("set_member_project", { id, userId: member.user_id, shareProject: wanted });
    toast(wanted ? "They can see the project" : "They can no longer see the project");
  } catch (error) {
    setError("main-error", error);
  }
  loadSharing(id);
}

async function cancelInvite(id, inviteId, button) {
  if (await act("cancel_invite", { id, inviteId }, "Invite cancelled", button)) loadSharing(id);
}

// ----- inviting --------------------------------------------------------------
//
// One dialog, two steps, any number of people. Step one collects addresses;
// step two shows the key the server offers for each of them and sends the
// invites once the owner has said the fingerprints are right.
//
// It takes several people at once because the thing being avoided is not the
// typing, it is the checking: handing one credential to three colleagues used
// to mean opening the dialog three times, and re-reading the same warning
// three times is how people learn to click past it.

/// Counts the runs of the invite dialog; `state.inviteSession` holds the
/// current one. Numbers are never reused, so a guard that captured an
/// earlier run can always tell that it is no longer the one on screen.
let inviteSessions = 0;

/// The dialog session whose batch is going out, or null. A session rather
/// than a flag: an abandoned batch keeps its last invite in flight for a
/// moment, and a plain boolean left the dialog that replaced it with dead
/// controls and no explanation for them.
///
/// This is the invariant. The disabled controls are only the view of it, so
/// everything that can start work asks this, not the DOM.
let sendingSession = null;

/// Whether the dialog on screen is mid-send.
function sendingNow() {
  return sendingSession !== null && sendingSession === state.inviteSession;
}

/// The invite dialog, emptied, for the secret `id`.
function openInviteDialog(id) {
  state.inviteFor = id;
  state.inviteSession = ++inviteSessions;
  state.invitees = [];
  state.caughtSubstituting = new Set();
  // `form.reset()` puts the fields back but not the button: `btn-invite` is
  // static markup outside the region `renderInviteFields` rewrites, so it is
  // the same node this dialog's predecessor left behind. One abandoned
  // mid-lookup used to hand its busy state over, and Continue came up dead.
  $("invite-form").reset();
  setBusy($("btn-invite"), false);
  $("invite-form").classList.remove("hidden");
  $("invite-confirm").innerHTML = "";
  setError("invite-error", "");
  renderInviteFields();
  openDialog($("invite-dialog"));
  $("invite-email").focus();
}

/// Step one: who, what to say, and whether the project's name goes with it.
///
/// Drawn here rather than written into index.html because two of its labels
/// carry an "i", and the text an "i" reveals has to be the same string as the
/// one in its tooltip -- which is a constant in this file, not a sentence
/// typed twice in two places that can drift apart.
function renderInviteFields() {
  // Nothing to offer when the secret is filed nowhere, and a checkbox that
  // did nothing would still read as a promise that something was shared.
  const project = state.secrets.find((s) => s.id === state.inviteFor)?.project ?? null;
  $("invite-dialog").setAttribute("aria-label", "Invite people");
  $("invite-fields").innerHTML = `
    <div class="label-row">
      <h2 class="dialog-title">Invite people</h2>
      ${infoButtonHtml("invite-note", INVITE_NOTE)}
    </div>
    <p class="hint hidden" id="invite-note">${esc(INVITE_NOTE)}</p>
    <div class="field">
      <label for="invite-email">Email</label>
      <ul class="recipients hidden" id="invite-recipients" aria-label="People this will be sent to" aria-live="polite"></ul>
      <input id="invite-email" type="email" placeholder="friend@example.com" autocomplete="off" spellcheck="false" inputmode="email">
      <p class="hint">Press Enter after each one to invite several people at once.</p>
    </div>
    <div class="field">
      <label for="invite-message">Message <span class="label-note">(optional)</span></label>
      <input id="invite-message" placeholder="e.g. The shared Wi-Fi password">
    </div>
    ${project ? `
      <div class="field" id="invite-project-field">
        <div class="label-row">
          <label class="checkbox"><input type="checkbox" id="invite-share-project">
            Also tell them this is in ${esc(project.name)}</label>
          ${infoButtonHtml("invite-project-note", INVITE_PROJECT_NOTE)}
        </div>
        <p class="hint hidden" id="invite-project-note">${esc(INVITE_PROJECT_NOTE)}</p>
      </div>` : ""}`;
  $("invite-message").maxLength = UI.maxMessageLength;
  const box = $("invite-email");
  box.onkeydown = (event) => {
    if (event.key === "Enter") { event.preventDefault(); commitTypedInvitees(); return; }
    // Backspace in an empty box takes the last person back into it, the way
    // every other recipient field behaves.
    if (event.key === "Backspace" && box.value === "" && state.invitees.length) {
      box.value = state.invitees.pop().email;
      renderRecipients();
    }
  };
  // A separator typed or pasted ends an address. This covers a pasted list
  // as well as a typed one, which is why it is not done on keydown alone.
  box.oninput = () => { if (/[,;\s]/.test(box.value)) commitTypedInvitees({ keepFocus: true }); };
  renderRecipients();
}

/// Turn whatever is in the box into recipients, all or nothing.
///
/// Nothing is added unless every address in the box can be. The box is then
/// either emptied or left exactly as it was typed, which is what makes a
/// mis-parsed paste fixable: an earlier version committed the good prefix
/// and rewrote the rest of the line, so every keystroke after the error
/// re-normalised the text under the caret and threw the caret to the end,
/// in the one place the user had been asked to go and edit.
///
/// Returns whether the box emptied, which is what submitting reads to decide
/// between going on and stopping on the error.
function commitTypedInvitees({ keepFocus = false } = {}) {
  const box = $("invite-email");
  if (!box) return true;
  const { accepted, problem } = Screens.acceptAddresses(box.value, {
    me: state.user?.email,
    queued: state.invitees.map((p) => p.email),
    members: sharedWith.members.map((m) => m.email),
    invites: sharedWith.invites.map((i) => i.email),
  });
  if (problem) {
    setError("invite-error", problem);
    return false;
  }
  for (const email of accepted) state.invitees.push({ email, fingerprint: "", info: null, error: null });
  box.value = "";
  setError("invite-error", "");
  renderRecipients();
  if (keepFocus) box.focus();
  return true;
}

function renderRecipients() {
  const list = $("invite-recipients");
  if (!list) return;
  list.innerHTML = state.invitees.map((person, index) => `
    <li class="recipient">${avatar(person.email, { size: "sm" })}<span class="who">${esc(person.email)}</span>
      <button type="button" class="icon-btn" data-remove="${index}" aria-label="Remove ${esc(person.email)}" title="Remove">${icon("close")}</button></li>`).join("");
  list.classList.toggle("hidden", state.invitees.length === 0);
  for (const el of list.querySelectorAll("[data-remove]")) el.onclick = () => {
    state.invitees.splice(Number(el.dataset.remove), 1);
    renderRecipients();
    $("invite-email").focus();
  };
  const button = $("btn-invite");
  if (button) button.textContent = state.invitees.length > 1 ? `Check ${state.invitees.length} keys` : "Continue";
}

/// Closing the dialog, by Cancel, Escape or a sent invite, hands focus back
/// to the button that opened it.
function closeInviteDialog() {
  closeDialog($("invite-dialog"));
  state.inviteFor = null;
  state.inviteSession = 0;
  state.invitees = [];
  state.caughtSubstituting = new Set();
  $("btn-open-invite")?.focus();
}

/// Look everybody up and show what came back. Nothing is sent yet.
async function submitInvite(event) {
  event.preventDefault();
  const id = state.inviteFor;
  if (id === null) return;
  const session = state.inviteSession;
  if (!commitTypedInvitees()) { $("invite-email").focus(); return; }
  if (!state.invitees.length) {
    setError("invite-error", "Add the email of at least one person to invite.");
    $("invite-email").focus();
    return;
  }
  setError("invite-error", "");
  setBusy($("btn-invite"), true, "Checking…");
  try {
    await lookUpInvitees();
    if (state.inviteSession !== session) return; // this dialog has been and gone
    renderInviteCheck(id);
  } finally {
    // Only if this run is still the one on screen. The session check above
    // returns early for an abandoned dialog, but a `finally` runs anyway --
    // and this button survives a close and a reopen, so clearing it
    // unconditionally reached into whatever dialog had replaced this one.
    // It cleared the busy flag with the *old* label and, on the way in,
    // left Continue disabled until an abandoned lookup happened to return.
    if (state.inviteSession === session) setBusy($("btn-invite"), false);
  }
}

/// Fetch the key for everyone who does not have one yet, one at a time.
///
/// A failure is kept on the person rather than thrown: one address that is
/// not registered, or one person whose key this device has never confirmed,
/// must not throw away the other nine lookups that worked.
async function lookUpInvitees() {
  // A snapshot, and a membership check before each one: the recipients are
  // still removable while this runs, and `for...of` over a live array walks
  // by index -- splicing one out mid-sweep made the iterator skip the next
  // person, who then reached the check step unlooked-up and unexplained.
  for (const person of [...state.invitees]) {
    if (person.info || !state.invitees.includes(person)) continue;
    await lookUpOne(person);
  }
}

/// Fetch one person's key, and never twice at once.
///
/// The `pending` flag is what stops two Check presses racing. Both would
/// otherwise see `info === null` for the same person, both would ask, and
/// the slower answer would land last -- so a fingerprint typed in from the
/// other person's own window could be overwritten by the result of a lookup
/// made before it was typed, putting the row back to "needs a fingerprint"
/// with nothing on screen to explain why.
async function lookUpOne(person) {
  if (person.pending) return;
  person.pending = true;
  try {
    // Blank means "use the key I pinned for them"; the command says so if
    // there is no pin to fall back on.
    person.info = await invoke("lookup_invitee", { email: person.email, fingerprint: person.fingerprint || null });
    person.error = null;
  } catch (error) {
    person.info = null;
    person.error = error;
    noteSubstitution(person, error);
  } finally {
    person.pending = false;
  }
}

/// Comparing fingerprints by eye, and the rule about a key that changed,
/// both live in screens.js where they can be tested without a dialog.
const normalizeFingerprint = Screens.normalizeFingerprint;

/// Said when a key arrives for somebody the server was already caught
/// substituting one for. Not a per-version disclosure and not a hint: it is
/// the record of the one event this dialog exists to catch.
const SUBSTITUTION_SEEN =
  "Earlier in this dialog the server answered for this person with a key that did not match the fingerprint you entered. This one does match. The server has still been caught once, so do not go on unless this fingerprint came from them directly.";

/// What to tell the owner about a failure, in words this app chose rather
/// than the server's. The rule itself is in screens.js, with the others.
const inviteReasonText = Screens.inviteReasonText;

/// Remember a substitution against the address, for as long as this dialog
/// lives. Called from both paths that can catch one: the lookup and the send.
function noteSubstitution(person, error) {
  if (error?.code === "key_changed") state.caughtSubstituting.add(person.email);
}

/// Whether this dialog has already caught the server substituting a key for
/// this person. A later lookup that succeeds does not undo it: the evidence
/// is the point, and it used to disappear the moment the row redrew green.
function caughtSubstituting(person) {
  return state.caughtSubstituting.has(person.email);
}

/// One person in the check step: the key the server offers for them, or the
/// field that fetches it.
///
/// Every row can be dropped from the batch, from the same place: the "x" in
/// its heading, where the recipients in step one carry theirs. It used to be
/// a worded button under the field, which only appeared on the rows that
/// were failing and sat in the one place a button could be mistaken for part
/// of the field above it.
function inviteCheckRow(person, index) {
  const drop = `<button type="button" class="icon-btn" data-drop="${index}"
      aria-label="Leave ${esc(person.email)} out of this invite" title="Leave out">${icon("close")}</button>`;
  const head = (badge) => `
    <div class="check-head">${avatar(person.email, { size: "sm" })}<span class="who">${esc(person.email)}</span>
      ${badge}${drop}</div>`;
  const info = person.info;
  if (info && info.status === "changed") {
    return `
      <li class="check-row">
        ${head('<span class="badge danger">Changed</span>')}
        <div class="check-body">
          <div class="fp-compare">
            <div class="fp-box good"><div class="k">Confirmed before</div><code class="fp">${esc(info.pinned_fingerprint)}</code></div>
            <div class="fp-box bad"><div class="k">Server reports now</div><code class="fp">${esc(info.fingerprint)}</code></div>
          </div>
          <div class="field">
            <label for="fp-${index}">Type their new fingerprint to continue</label>
            <input id="fp-${index}" class="mono" data-expect="${esc(info.fingerprint)}" data-row="${index}"
              value="${esc(person.retyped ?? "")}" autocomplete="off"
              spellcheck="false" placeholder="0000-0000-0000-0000-0000-0000">
          </div>
        </div>
      </li>`;
  }
  if (info) {
    // A key that arrives after a substitution was caught keeps the red
    // notice. It was drawn from `person.error.code` alone, which the next
    // lookup overwrites, so the one event this dialog exists to record
    // vanished as soon as the server relented and served an honest key.
    //
    // The notice stays; Send does not stay dead. The only way back to a key
    // at all is a lookup that matched a fingerprint the owner typed in from
    // the other person's own window, so the check has been made, not skipped
    // -- and a second challenge for the same fingerprint would be theatre.
    const caught = caughtSubstituting(person);
    const known = info.status === "known";
    const badge = caught
      ? `<span class="badge danger">Was substituted</span>`
      : `<span class="badge${known ? " accent" : ""}">${known ? "Confirmed before" : "New key"}</span>`;
    return `
      <li class="check-row">
        ${head(badge)}
        <div class="check-body">
          ${caught ? `<div class="notice danger" role="alert">${icon("alert")}<div>${esc(SUBSTITUTION_SEEN)}</div></div>` : ""}
          <code class="fp">${esc(info.fingerprint)}</code>
          ${person.error ? `<p class="error">${esc(inviteReasonText(person.error))}</p>` : ""}</div>
      </li>`;
  }
  // No key yet, and the three reasons do not mean the same thing.
  //
  // `key_changed` is what this whole dialog exists to catch: the server
  // answered with a key whose fingerprint is not the one it was asked for.
  // There is no innocent reading of that -- either their key really did
  // change and the owner is working from a stale fingerprint, or the server
  // is substituting one. So it gets the red notice and an alert, the same
  // as a key that changed since it was pinned. It used to arrive here as
  // grey hint text under a badge reading "Not checked", which was the wrong
  // colour and the wrong sentence: it read as "you mis-typed, try again".
  //
  // `fingerprint_required` is the ordinary first-time case and needs
  // nothing beyond the badge -- the "i" at the top of the step says where a
  // fingerprint comes from, and repeating it once per person is noise.
  // Anything else is a plain failure and says whatever it said.
  const code = person.error?.code;
  const needsFingerprint = code === "fingerprint_required";
  const substituted = code === "key_changed";
  // Our words, not the server's; `inviteReasonText` is where that is
  // decided, for every code and both paths at once.
  const reason = esc(inviteReasonText(person.error));
  const badge = substituted
    ? `<span class="badge danger">Key does not match</span>`
    : `<span class="badge">${needsFingerprint ? "Needs a fingerprint" : "Not checked"}</span>`;
  const why = substituted
    ? `<div class="notice danger" role="alert">${icon("alert")}<div>${reason}</div></div>`
    : needsFingerprint ? "" : `<p class="hint">${reason}</p>`;
  return `
    <li class="check-row">
      ${head(badge)}
      <div class="check-body">
        ${why}
        <div class="input-row">
          <input id="fp-need-${index}" class="mono" value="${esc(person.fingerprint)}" autocomplete="off"
            spellcheck="false" placeholder="0000-0000-0000-0000-0000-0000"
            aria-label="Key fingerprint for ${esc(person.email)}">
          <button type="button" class="btn" data-check="${index}">Check</button>
        </div>
      </div>
    </li>`;
}


/// Where the caret is inside `box`, as `{ id, start, end }`, or null when it
/// is somewhere else. Read before a redraw; the element itself does not
/// survive one.
function heldCaret(box) {
  const el = document.activeElement;
  if (!el || !el.id || !box?.contains(el)) return null;
  return { id: el.id, start: el.selectionStart, end: el.selectionEnd };
}

/// Put the caret back after a redraw. Answers whether it went anywhere, so
/// the caller knows not to move focus itself.
function restoreCaret(held) {
  const el = held && $(held.id);
  if (!el) return false;
  el.focus();
  if (held.start !== null && typeof el.setSelectionRange === "function") {
    el.setSelectionRange(held.start, held.end);
  }
  return true;
}

/// Step two: every key side by side, and one button that sends the lot.
///
/// `problem` is what went wrong last time the invites were sent, which
/// survives the redraw that follows a partial failure.
function renderInviteCheck(id, problem = "") {
  if (!state.invitees.length) { backToInviteFields(); return; }
  const held = heldCaret($("invite-confirm"));
  $("invite-dialog").setAttribute("aria-label", "Check their keys");
  $("invite-form").classList.add("hidden");
  const changed = state.invitees.some((p) => p.info?.status === "changed");
  const caught = state.invitees.some(caughtSubstituting);
  const unresolved = state.invitees.some((p) => !p.info);
  $("invite-confirm").innerHTML = `
    <div class="confirm-step" role="region" aria-label="Check their keys">
      <div class="label-row">
        <h2 class="dialog-title">Check their keys</h2>
        ${infoButtonHtml("fingerprint-note", FINGERPRINT_NOTE)}
      </div>
      <p class="hint hidden" id="fingerprint-note">${esc(FINGERPRINT_NOTE)}</p>
      <p class="dialog-lead">Continue only if that fingerprint came from them directly rather than from anything the server told you.</p>
      ${changed ? `<div class="notice danger">${icon("alert")}<div>A key marked <strong>Changed</strong> differs from one you confirmed before. Either they re-created their account, or the server is lying. Do not continue unless they read the new fingerprint to you directly.</div></div>` : ""}
      ${caught ? `<div class="notice danger">${icon("alert")}<div>This server has already answered once in this dialog with a key that did not match the fingerprint you entered. Whatever it serves now, treat it as a server that has been caught.</div></div>` : ""}
      <ul class="people check-list">${state.invitees.map(inviteCheckRow).join("")}</ul>
      <div class="error" id="invite-confirm-error" role="alert">${esc(problem)}</div>
      <div class="dialog-actions">
        <button type="button" class="btn ${changed || caught ? "danger solid" : "primary"}" id="btn-invite-confirm"></button>
        <button type="button" class="btn" id="btn-invite-back">Back</button>
        <button type="button" class="btn" id="btn-invite-abandon">Cancel</button>
      </div>
    </div>`;
  const box = $("invite-confirm");
  $("btn-invite-back").onclick = backToInviteFields;
  // The only control that stays live while a batch is going out, because it
  // is the only one that stops the invites still to come. Escape does the
  // same thing, which is no help on the two platforms without one.
  $("btn-invite-abandon").onclick = closeInviteDialog;
  $("btn-invite-confirm").onclick = () => {
    // Not floating: a throw after the freeze went on used to leave the step
    // disabled, the button stuck on "Inviting...", and nothing anywhere to
    // say why.
    sendInvites(id).catch((error) => {
      // The same rule as the rows: whatever threw, the owner is told in
      // words from this file. The original goes to the console, which is
      // where a fault in this code is diagnosed -- and not somewhere a
      // server can put a sentence in front of anyone.
      console.error("sending the invite batch failed", error);
      setError("invite-confirm-error", inviteReasonText(error));
      freezeInviteCheck(false);
      setBusy($("btn-invite-confirm"), false);
    });
  };
  // Kept on the person, not only in the field: this step is redrawn by every
  // drop, every recheck and every partial failure, and it is the one value
  // the owner had to get by reading it out of somebody else's window. Losing
  // it means making that call again, which is how a careful step gets rushed.
  for (const input of box.querySelectorAll("input[data-expect]")) input.oninput = () => {
    const person = state.invitees[Number(input.dataset.row)];
    if (person) person.retyped = input.value;
    syncInviteCheck();
  };
  for (const el of box.querySelectorAll("[data-check]")) el.onclick = () => recheckInvitee(id, Number(el.dataset.check));
  // Typed straight onto the person, the same as the retyped fingerprint
  // above: this step is rebuilt whenever any other row resolves, and a
  // fingerprint being transcribed from a phone call must not vanish because
  // somebody else's lookup came back.
  for (const el of box.querySelectorAll("input[id^='fp-need-']")) el.oninput = () => {
    const person = state.invitees[Number(el.id.slice("fp-need-".length))];
    if (person) person.fingerprint = el.value.trim();
  };
  // Enter in a fingerprint field does what the button beside it does. The
  // field is not inside a form of its own -- the dialog's form is the one
  // behind this step -- so without this Enter would do nothing, or worse,
  // submit the step that is already behind us.
  for (const el of box.querySelectorAll("input[id^='fp-need-']")) el.onkeydown = (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    recheckInvitee(id, Number(el.id.slice("fp-need-".length)));
  };
  for (const el of box.querySelectorAll("[data-drop]")) el.onclick = () => {
    if (sendingNow()) return; // the batch is already going out
    state.invitees.splice(Number(el.dataset.drop), 1);
    renderInviteCheck(id);
  };
  // Re-established by the redraw itself, not left to whoever called it: this
  // step is rebuilt fully enabled, and a batch can still be going out while
  // that happens. The previous attempt put a guard in each caller instead,
  // which is how the next new call site brings the bug back -- and the
  // attempt after that put this very line inside an event handler, where it
  // ran only when nothing was being sent.
  freezeInviteCheck(sendingNow());
  syncInviteCheck();
  // A fingerprint that has to be typed in from somebody else's screen is
  // where the work is, so focus goes to the first of those. With none left,
  // a list that still has a changed or unresolved key defaults to Back
  // rather than to the button that would send anyway.
  //
  // Unless somebody was already typing. This step is rebuilt whenever any
  // other row resolves, and taking the caret out of a half-entered
  // fingerprint is the same interruption the field itself was fixed to
  // avoid -- so the caret goes back where it was first.
  if (restoreCaret(held)) return;
  const firstInput = box.querySelector(".check-row input");
  if (firstInput) firstInput.focus();
  else (changed || caught || unresolved ? $("btn-invite-back") : $("btn-invite-confirm")).focus();
}

function backToInviteFields() {
  // The freeze disables this button, but the freeze is the view of the rule
  // and this is the rule: stepping back while invites are going out lands
  // the owner on a list the batch is about to overwrite. Cancel is the way
  // out of a running batch.
  if (sendingNow()) return;
  $("invite-dialog").setAttribute("aria-label", "Invite people");
  $("invite-confirm").innerHTML = "";
  $("invite-form").classList.remove("hidden");
  renderRecipients();
  $("invite-email").focus();
}

/// Look one person up again with the fingerprint just typed for them.
async function recheckInvitee(id, index) {
  const person = state.invitees[index];
  if (!person || person.pending || sendingNow()) return;
  const session = state.inviteSession;
  // A missing field means nothing was typed, which is not the same as the
  // field being empty: keep whatever this person already had.
  person.fingerprint = $(`fp-need-${index}`)?.value.trim() ?? person.fingerprint;
  const button = $("invite-confirm").querySelector(`[data-check="${index}"]`);
  setBusy(button, true, "Checking…");
  try {
    // This row only. Sweeping every unresolved person would spend a round
    // trip each on people whose button nobody pressed, change their rows
    // under the reader, and leave the one button that was pressed spinning
    // until the whole sweep had finished.
    await lookUpOne(person);
  } finally {
    if (state.inviteSession === session) renderInviteCheck(id);
  }
}

/// Keep the send button honest: it is live only when every person has a key
/// and every changed key has been typed back in from the other person's own
/// window.
function syncInviteCheck() {
  const button = $("btn-invite-confirm");
  if (!button) return;
  const challenges = [...$("invite-confirm").querySelectorAll("input[data-expect]")];
  for (const input of challenges) {
    const typed = normalizeFingerprint(input.value);
    const expected = normalizeFingerprint(input.dataset.expect);
    input.classList.toggle("mismatch", typed.length > 0 && !expected.startsWith(typed));
  }
  const matched = challenges.every((i) => normalizeFingerprint(i.value) === normalizeFingerprint(i.dataset.expect));
  const count = state.invitees.length;
  button.disabled = sendingNow() || !count || state.invitees.some((p) => !p.info) || !matched;
  button.innerHTML = `${icon("check")} ${esc(Screens.sendInvitesLabel(count, challenges.length))}`;
}

/// Freeze or release the check step while a batch is going out.
///
/// The flag above is the invariant; this is what the owner sees of it. Every
/// control in the step stayed live during the sends, so taking somebody out
/// mid-batch quietly did nothing (the loop walks a snapshot), and any redraw
/// replaced the busy Send button with a fresh enabled one -- a second press
/// then started a second batch over the same people.
function freezeInviteCheck(frozen) {
  for (const el of $("invite-confirm").querySelectorAll("button, input")) {
    // setBusy owns the send button, and the way out must never be frozen:
    // abandoning the batch is the only thing that stops the invites still
    // to come, and on a phone there is no Escape key to do it with.
    if (el.id === "btn-invite-confirm" || el.id === "btn-invite-abandon") continue;
    if (el.classList.contains("info-btn")) continue; // the one explanation on the screen
    el.disabled = frozen;
  }
}

/// Send one invite per person, in order, and report what happened.
///
/// The loop itself is Screens.sendBatch(), which is where the rule about who
/// gets an invite lives and where it is tested. This supplies the sending,
/// says when the batch has been abandoned, and says who is still in it.
async function sendInvites(id) {
  const session = state.inviteSession;
  if (sendingSession === session) return;
  // Everything that can throw is read before the flag goes up. It is module
  // state that nothing else resets, so a throw between raising it and the
  // `try` would have wedged every later send for the life of the process,
  // silently -- no error, no busy state, nothing in the log.
  const button = $("btn-invite-confirm");
  const message = $("invite-message").value.trim();
  const shareProject = Boolean($("invite-share-project")?.checked);
  const people = [...state.invitees];
  setError("invite-confirm-error", "");
  setBusy(button, true, "Inviting\u2026");
  let outcome;
  try {
    sendingSession = session;
    freezeInviteCheck(true);
    outcome = await Screens.sendBatch(people, {
      abandoned: () => state.inviteSession !== session,
      wanted: (person) => state.invitees.includes(person),
      send: (person) => {
        // Checked here rather than only in the view: the button that got us
        // this far is disabled from `syncInviteCheck`, which reads the DOM,
        // and the DOM is rebuilt by half a dozen paths. A key the server
        // changed must have been typed back in, whatever the button says.
        // Neither of these should be reachable -- the send button is dead
        // without them -- but that button's state is computed from the DOM,
        // and the DOM is rebuilt by half a dozen paths. The rule belongs
        // where a redraw cannot reach it.
        // Carry a code, so `inviteReasonText` can tell these apart from a
        // rejection the server worded and print them as written.
        if (!person.info) {
          throw Object.assign(new Error("this person's key has not been looked up yet"), { code: "not_looked_up" });
        }
        if (Screens.retypeOutstanding(person)) {
          throw Object.assign(
            new Error("this key changed and the new fingerprint has not been confirmed"),
            { code: "retype_outstanding" });
        }
        // The whole key goes back, not the fingerprint: the command compares
        // bytes. shareProject is a separate answer from sharing the secret
        // at all: off unless the form's own checkbox asked for it.
        return invoke("invite", {
          id,
          email: person.info.email,
          message,
          confirmedPublicKey: person.info.public_key,
          shareProject,
        });
      },
    });
  } finally {
    // Only if it is still ours: a later dialog may have started its own.
    if (sendingSession === session) sendingSession = null;
  }

  const { sent, failed, stopped } = outcome;
  // The key stays on a person whose send failed: it was confirmed by eye a
  // moment ago and nothing about a failed send unconfirms it. Dropping it
  // would leave the row asking for a fingerprint that is already in hand.
  for (const { person, error } of failed) {
    person.error = error;
    // `check_confirmed_key` catches the server substituting a key between
    // the lookup and the send -- the same attack as `check_served_key`, one
    // step later. Dropping the key puts the row back into the state that
    // draws the red alarm, and keeps the send button dead until the owner
    // has looked them up again. Left as it was, it rendered as a plain
    // sentence under "Confirmed before" with Send inviting another go.
    if (error?.code === "key_changed") person.info = null;
    noteSubstitution(person, error);
  }
  if (sent.length) toast(sent.length === 1 ? `Invited ${sent[0].email}` : `Invited ${sent.length} people`);

  // Abandoned part way: this dialog is gone, and whatever is on screen now
  // belongs to a later one. What did go out has been toasted and is on the
  // server; show it by redrawing the list rather than by writing into a
  // dialog that is no longer ours.
  if (stopped || state.inviteSession !== session) {
    await refresh();
    // Only if that secret is still the one open: loadSharing() empties
    // `sharedWith` before it fetches and then bails when the selection has
    // moved, which would leave the open secret's member list blank -- and
    // the invite dialog reads it to catch people who already have access.
    if (state.selected === id) loadSharing(id);
    return;
  }

  state.invitees = failed.map(({ person }) => person);
  if (state.invitees.length) {
    renderInviteCheck(id, state.invitees.length === 1
      ? `${state.invitees[0].email} was not invited.`
      : `${state.invitees.length} of these ${sent.length + state.invitees.length} people were not invited.`);
  } else {
    closeInviteDialog();
  }
  await refresh();
  if (state.selected === id) loadSharing(id);
}

// ----- revoking --------------------------------------------------------------

/// A key that differs from one already confirmed is the one case where the
/// server is provably not telling the truth, so clicking through is not
/// enough: the new fingerprint has to be typed in from the other person's
/// window. A key never seen before carries no such evidence and only needs the
/// usual out-of-band check.
function changedKeyChallenge(members) {
  return members
    .filter((m) => m.status === "changed")
    .map((m) => `
      <div class="field">
        <label for="fp-${m.user_id}">Type ${esc(m.email)}'s new fingerprint to continue</label>
        <input id="fp-${m.user_id}" class="mono" data-expect="${esc(m.fingerprint)}" autocomplete="off"
          spellcheck="false" placeholder="0000-0000-0000-0000-0000-0000">
      </div>`)
    .join("");
}

/// Wire the typed-fingerprint inputs to the confirm button: it stays disabled
/// until every challenge matches the key the server is serving now.
function armChangedKeyChallenge(container, confirmButton) {
  const inputs = [...container.querySelectorAll("input[data-expect]")];
  if (!inputs.length) return;
  const check = () => {
    const allMatch = inputs.every((i) => normalizeFingerprint(i.value) === normalizeFingerprint(i.dataset.expect));
    confirmButton.disabled = !allMatch;
    for (const input of inputs) {
      const typed = normalizeFingerprint(input.value);
      const expected = normalizeFingerprint(input.dataset.expect);
      input.classList.toggle("mismatch", typed.length > 0 && !expected.startsWith(typed));
    }
  };
  for (const input of inputs) input.oninput = check;
  check();
  inputs[0].focus();
}

/// Revoking rotates the key, so every remaining member's key must be one this
/// device has confirmed. The command refuses otherwise and hands back the
/// unconfirmed members; the user compares fingerprints and we call again with
/// the keys they approved.
async function revokeMember(id, userId, button, confirmed) {
  setError("main-error", "");
  setBusy(button, true);
  try {
    const outcome = await invoke("revoke_access", { id, userId, confirmed });
    if (outcome.status === "confirm") { renderRevokeConfirm(id, userId, outcome.members); return; }
    const n = outcome.cancelled_invites;
    toast(n ? `Access revoked · ${plural(n, "pending invite", "pending invites")} cancelled` : "Access revoked");
    await refresh();
    loadSharing(id);
  } catch (error) {
    setError("main-error", error);
  } finally {
    if (button?.isConnected) setBusy(button, false);
  }
}

function renderRevokeConfirm(id, userId, members) {
  const box = $("revoke-confirm");
  const changed = members.some((m) => m.status === "changed");
  const rows = members.map((m) => `
    <li>${avatar(m.email, { size: "sm" })}<span class="who">${esc(m.email)}</span>
      <code class="fp">${esc(m.fingerprint)}</code>
      <span class="badge">${m.status === "changed" ? "Changed" : "Not confirmed"}</span></li>`).join("");
  box.innerHTML = `
    <div class="card" style="margin-top:14px" role="region" aria-label="Confirm who keeps access">
      <h3 class="card-title">${icon("key")} Confirm who keeps access</h3>
      <p class="card-lead">Revoking re-encrypts this secret for everyone who keeps access, and this device has not confirmed these keys yet. Ask each person to read the <strong>Your key</strong> fingerprint from their klavyn account settings and continue only if every one matches.</p>
      ${changed ? `<div class="notice danger">${icon("alert")}<div>A key marked <strong>Changed</strong> differs from one you confirmed before. Either they re-created their account, or the server is lying. Do not continue unless they read the new fingerprint to you directly.</div></div>` : ""}
      <ul class="people">${rows}</ul>
      ${changedKeyChallenge(members)}
      <div class="actions" style="margin-top:12px">
        <button type="button" class="btn ${changed ? "danger solid" : "primary"}" id="btn-revoke-confirm">${icon("check")} Fingerprints match, revoke</button>
        <button type="button" class="btn" id="btn-revoke-cancel">Cancel</button>
      </div>
    </div>`;
  $("btn-revoke-cancel").onclick = () => { box.innerHTML = ""; };
  $("btn-revoke-confirm").onclick = () => {
    const confirmed = members.map((m) => ({ user_id: m.user_id, public_key: m.public_key }));
    revokeMember(id, userId, $("btn-revoke-confirm"), confirmed);
  };
  armChangedKeyChallenge(box, $("btn-revoke-confirm"));
  if (!changed) $("btn-revoke-confirm").focus();
}

// ----- changing the passphrase -----------------------------------------------

/// Everything the passphrase derives is replaced at once, so this is a single
/// form and a single request. For an account that signs in with Google the
/// passphrase is not the login, and the copy says so rather than implying the
/// Google password is involved.
/// Create, rename and delete the headings secrets are grouped under.
///
/// Every action happens on the row it belongs to. The first version of this
/// panel could not create a project at all -- its empty state sent you to the
/// secret form to make one -- and put the rename box and the delete
/// confirmation in a single slot above the list, so with several projects the
/// only thing saying which one you were about to change was the wording
/// inside the box.
function renderProjectsPanel() {
  closeAccountSheet({ restoreFocus: false });
  state.selected = null;
  state.editing = false;
  state.showingInvites = false;
  state.showingProjects = true;
  state.projectRow = null;
  syncInvitesView();
  renderList();
  showDetailScreen();
  drawProjectsPanel();
}

/// Redraw the panel's contents only. Separate from the screen switching above
/// so that acting on one row does not re-run the navigation, which would
/// scroll the pane and throw focus away mid-edit.
function drawProjectsPanel({ focus = null } = {}) {
  const open = state.projectRow;
  const nameBox = (value, label) =>
    `<input class="project-name" id="project-name" value="${esc(value)}" aria-label="${esc(label)}"
       autocomplete="off" spellcheck="false" maxlength="${UI.maxProjectNameLength}" placeholder="e.g. Perspectiv">`;

  const rows = state.projects.map((p) => {
    const mode = open && open.id === p.id ? open.mode : null;
    if (mode === "rename") {
      return `
        <li class="project-row editing">
          <form class="project-inline" id="project-form">
            ${nameBox(p.name, `New name for ${p.name}`)}
            <button type="submit" class="btn primary sm" id="btn-project-save">Save</button>
            <button type="button" class="btn sm" data-cancel-row>Cancel</button>
          </form>
        </li>`;
    }
    return `
      <li class="project-row">
        <span class="who">${esc(p.name)}</span>
        <span class="people-status">${plural(p.secret_count, "secret", "secrets")}</span>
        <button type="button" class="btn sm" data-rename="${p.id}" aria-label="Rename ${esc(p.name)}"><span>Rename<span class="ell">\u2026</span></span></button>
        <button type="button" class="btn danger sm" data-delete="${p.id}" aria-label="Delete ${esc(p.name)}"><span>Delete<span class="ell">\u2026</span></span></button>
      </li>`;
  });

  const adding = Boolean(open) && open.id === null;
  if (adding) {
    rows.push(`
      <li class="project-row editing">
        <form class="project-inline" id="project-form">
          ${nameBox("", "Name for the new project")}
          <button type="submit" class="btn primary sm" id="btn-project-save">Create</button>
          <button type="button" class="btn sm" data-cancel-row>Cancel</button>
        </form>
      </li>`);
  }
  const empty = `<li class="only-you">No projects yet. Make one here, or from the Project box when you add a secret.</li>`;

  $("detail").innerHTML = `
    <section class="card" aria-labelledby="projects-title">
      <h2 id="projects-title" class="card-title pane-title">${icon("folder")} Projects${infoButtonHtml("projects-note", PROJECTS_NOTE)}</h2>
      <p class="hint hidden" id="projects-note">${esc(PROJECTS_NOTE)}</p>
      <div class="error" id="projects-error" role="alert"></div>
      <ul class="people" id="project-list">${rows.length ? rows.join("") : empty}</ul>
      <div class="actions">
        ${adding ? "" : `<button type="button" class="btn primary" id="btn-project-new">${icon("plus")} New project</button>`}
        <button type="button" class="btn" id="btn-projects-done">Done</button>
      </div>
    </section>`;

  const openRow = (id, mode) => {
    setError("projects-error", "");
    state.projectRow = { id, mode };
    drawProjectsPanel();
    // The control that replaced the one just clicked takes the focus, so the
    // keyboard stays where the eye is.
    const box = $("project-name");
    box?.focus();
    box?.select();
  };

  $("btn-projects-done").onclick = () => {
    state.showingProjects = false;
    state.projectRow = null;
    renderDetail();
  };
  $("btn-project-new")?.addEventListener("click", () => openRow(null, "new"));
  for (const el of $("detail").querySelectorAll("[data-rename]")) {
    el.onclick = () => openRow(Number(el.dataset.rename), "rename");
  }
  for (const el of $("detail").querySelectorAll("[data-delete]")) {
    el.onclick = () => openProjectDeleteDialog(Number(el.dataset.delete), el);
  }
  const backToRow = () => (open && open.id != null ? `[data-rename="${open.id}"]` : "#btn-project-new");
  for (const el of $("detail").querySelectorAll("[data-cancel-row]")) {
    el.onclick = () => {
      state.projectRow = null;
      setError("projects-error", "");
      drawProjectsPanel({ focus: backToRow() });
    };
  }
  const form = $("project-form");
  if (form) {
    form.onsubmit = (event) => {
      event.preventDefault();
      const name = $("project-name").value.trim();
      if (!name) {
        setError("projects-error", "Give the project a name.");
        $("project-name").focus();
        return;
      }
      // `adding` is the one bit of the row's identity the markup does not
      // carry, because a new project has no id to put in an attribute yet.
      // `create_project` answers with the new id; a rename keeps the one it
      // had. Either way focus lands on that project's own Rename button.
      const rowOf = (id) => `[data-rename="${id}"]`;
      if (adding) {
        runProjectAction("create_project", { name }, $("btn-project-save"), "Project created", (id) => rowOf(id));
      } else {
        runProjectAction("rename_project", { id: open.id, name }, $("btn-project-save"), "Project renamed", () =>
          rowOf(open.id));
      }
    };
    // Escape leaves the row alone rather than the panel, which is the
    // smaller undo and the one a half-typed name wants.
    form.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      state.projectRow = null;
      drawProjectsPanel({ focus: backToRow() });
    });
  }

  // Redrawing replaces the whole pane, so whatever had focus is detached and
  // focus falls to <body>. An action that succeeded says where to put it
  // back: someone who renames a project with the keyboard should land on
  // that project, not at the top of the page.
  if (focus) (document.querySelector(focus) ?? $("btn-project-new"))?.focus();
}

/// Confirm deleting a project by typing its name.
///
/// The name is required rather than a plain yes/no because a project is a
/// heading several secrets sit under: the delete itself is recoverable --
/// every secret survives and simply stops being grouped -- but rebuilding
/// the grouping by hand is tedious, and the rows in this list differ by one
/// word. Typing the name is the step that makes you read which row you are
/// on.
///
/// `opener` is the button that was clicked, so focus can go back to it if
/// the dialog is dismissed.
function openProjectDeleteDialog(id, opener) {
  const project = state.projects.find((p) => p.id === id);
  if (!project) return;
  const dialog = $("project-delete-dialog");
  const confirm = $("btn-project-delete-confirm");
  const box = $("project-delete-name");

  // Built as nodes rather than markup: the name is the one part of these
  // sentences the user wrote, and setting it as `textContent` on its own
  // element means there is no string for it to escape out of.
  const named = (text) => {
    const strong = document.createElement("strong");
    strong.textContent = text;
    return strong;
  };
  $("project-delete-lead").replaceChildren(
    named(project.name),
    document.createTextNode(
      ` holds ${plural(project.secret_count, "secret", "secrets")}. ` +
      "They are kept and simply stop being grouped; only the heading goes.",
    ),
  );

  setError("project-delete-error", "");
  box.value = "";
  box.setAttribute("aria-label", `Type ${project.name} to confirm deleting it`);
  box.maxLength = UI.maxProjectNameLength;
  // setBusy(.., false) ends by enabling the button, so it has to run before
  // the line that disables it -- the other order leaves the confirmation
  // armed before anything has been typed, which is the whole point lost.
  setBusy(confirm, false);
  confirm.disabled = true;

  const matches = () => Screens.namesProject(box.value, project.name);

  const hint = $("project-delete-hint");
  // A disabled button with nothing to explain it is a dead end, and the
  // commonest way to reach one here is typing the first word of a name that
  // has two. The hint says which state you are in as you type.
  const sayState = () => {
    const typed = box.value.trim();
    hint.replaceChildren(
      ...(!typed
        ? [document.createTextNode("Type "), named(project.name), document.createTextNode(" exactly.")]
        : matches()
          ? [document.createTextNode("That matches \u2014 Delete project is ready.")]
          : [document.createTextNode("Doesn't match "), named(project.name), document.createTextNode(" yet.")]),
    );
    box.setAttribute("aria-invalid", String(Boolean(typed) && !matches()));
  };
  box.oninput = () => {
    confirm.disabled = !matches();
    sayState();
  };

  const close = ({ restoreFocus = true } = {}) => {
    closeDialog(dialog);
    box.oninput = null;
    if (restoreFocus && opener?.isConnected) opener.focus();
  };
  $("btn-project-delete-cancel").onclick = () => close();
  // Escape reaches `cancel` (a native dialog's backdrop does not, unless it
  // is wired up, and this one is not). Either way the handlers of a project
  // that is no longer on screen should not stay attached.
  dialog.oncancel = () => close();
  $("project-delete-form").onsubmit = async (event) => {
    event.preventDefault();
    if (!matches()) {
      setError("project-delete-error", `That is not the whole name. Type ${project.name} exactly, or cancel.`);
      box.focus();
      return;
    }
    setError("project-delete-error", "");
    setBusy(confirm, true);
    try {
      // Where focus goes once this row is gone: the project that takes its
      // place, or the button that makes a new one when nothing is left.
      // Worked out before the refresh, while the old order is still known.
      const order = state.projects.map((p) => p.id);
      const next = order[order.indexOf(id) + 1] ?? order[order.indexOf(id) - 1];
      await invoke("delete_project", { id });
      state.projectRow = null;
      await refresh();
      close({ restoreFocus: false });
      drawProjectsPanel({ focus: next === undefined ? "#btn-project-new" : `[data-rename="${next}"]` });
      toast("Project deleted");
    } catch (error) {
      // Reported inside the dialog: the panel's own error line is behind it.
      setError("project-delete-error", error);
      setBusy(confirm, false);
    }
  };

  sayState();
  openDialog(dialog);
  box.focus();
}

/// Run one project command, then redraw from fresh data.
///
/// Shared by all three because they differ only in the call: each needs the
/// same busy state, the same error slot, and the same guarantee that the
/// button comes back on failure so the panel can be retried rather than
/// stranded.
async function runProjectAction(command, args, button, success, focusFor = null) {
  setError("projects-error", "");
  setBusy(button, true);
  try {
    const result = await invoke(command, args);
    state.projectRow = null;
    await refresh();
    drawProjectsPanel({ focus: focusFor ? focusFor(result) : null });
    toast(success);
  } catch (error) {
    setError("projects-error", error);
    if (button?.isConnected) setBusy(button, false);
  }
}

function renderPassphraseForm() {
  closeAccountSheet({ restoreFocus: false });
  state.selected = null;
  state.editing = true;
  state.showingInvites = false;
  syncInvitesView();
  state.editTitle = "Change passphrase";
  renderList();
  showDetailScreen();
  const isLogin = state.user?.password_login !== false;
  $("detail").innerHTML = `
    <form class="card" id="passphrase-form" novalidate aria-labelledby="passphrase-title">
      <h2 id="passphrase-title" class="card-title pane-title">${icon("lock")} ${esc(state.editTitle)}</h2>
      <p class="card-lead">
        ${isLogin
          ? "This is what encrypts your vault and what you sign in with. Every other device is signed out."
          : "This is what encrypts your vault. You will still sign in with Google, and every other device is signed out."}
        Your secrets stay exactly as they are &mdash; only the key protecting them changes.
      </p>
      <div class="field">
        <label for="pp-current">Current passphrase</label>
        <input id="pp-current" type="password" autocomplete="current-password" spellcheck="false">
      </div>
      <div class="field">
        <label for="pp-new">New passphrase</label>
        <input id="pp-new" type="password" autocomplete="new-password" spellcheck="false">
        <p class="hint">At least ${UI.minPasswordLength} characters. There is no reset: forget it and the vault is gone.</p>
      </div>
      <div class="field">
        <label for="pp-confirm">Repeat new passphrase</label>
        <input id="pp-confirm" type="password" autocomplete="new-password" spellcheck="false">
      </div>
      <div class="error" id="pp-error" role="alert"></div>
      <div class="actions">
        <button type="submit" class="btn primary" id="btn-pp-save">${icon("check")} Change passphrase</button>
        <button type="button" class="btn" id="btn-pp-cancel">Cancel</button>
      </div>
    </form>`;

  $("btn-pp-cancel").onclick = () => { state.editing = false; renderDetail(); showListScreen(); };
  $("passphrase-form").onsubmit = submitPassphraseChange;
  $("pp-current").focus();
}

async function submitPassphraseChange(event) {
  event.preventDefault();
  setError("pp-error", "");
  const current = $("pp-current").value;
  const next = $("pp-new").value;
  if (next !== $("pp-confirm").value) {
    setError("pp-error", "The new passphrases do not match.");
    $("pp-confirm").focus();
    return;
  }
  if (next === current) {
    setError("pp-error", "That is the passphrase you already have.");
    $("pp-new").focus();
    return;
  }
  // Re-wrapping is one key per secret, so a large vault takes a moment and
  // the button has to say so rather than looking stuck.
  setBusy($("btn-pp-save"), true, "Re-encrypting your keys\u2026");
  try {
    await invoke("change_password", { current, newPassword: next });
    toast("Passphrase changed");
    state.editing = false;
    renderDetail();
    showListScreen();
    await refresh();
  } catch (error) {
    // Two outcomes mean the change may already have happened and the answer
    // was lost. Showing them as a form error would be read as "it failed",
    // and a user who believes that throws away the passphrase that now opens
    // their vault. They get the sign-in screen and a banner that stays put.
    if (error?.code === "changed_but_unconfirmed" || error?.code === "changed_but_unknown") {
      signOutAfterAmbiguousChange(error.message);
      return;
    }
    // This form's two neighbouring failures are "changed but unconfirmed" and
    // "changed but unknown", so red here reads as "my vault may have a new
    // passphrase". Throttling means the request never ran; say so.
    setError("pp-error", error?.code === "throttled" ? retryLater(error) : error);
    if (error?.code === "locked") $("pp-current").focus();
  } finally {
    if ($("btn-pp-save")?.isConnected) setBusy($("btn-pp-save"), false);
  }
}

/// Drop back to the sign-in screen carrying a warning that does not vanish.
///
/// Both codes that reach here have already had the session dropped on the Rust
/// side, master key included, so there is nothing left to log out of and this
/// only resets what is on screen. A reload will land on the sign-in screen too,
/// because `session_info` now has nothing to report.
function signOutAfterAmbiguousChange(message) {
  resetToSignedOut();
  showStartupWarning(message);
  $("password").focus();
}

// ----- create / edit form ----------------------------------------------------

/// The form's extra fields live in `state.formFields` rather than in the DOM,
/// so adding or removing a row never depends on reading half-filled inputs
/// back out. `kept` marks a hidden value the list did not send us: it stays
/// as it is unless the user types a new one.
function renderFormFields() {
  const box = $("custom-fields");
  if (!box) return;
  box.innerHTML = state.formFields.map((field, index) => `
    <div class="custom-field" data-index="${index}">
      <input class="cf-label" value="${esc(field.label)}" placeholder="Label" autocomplete="off"
        maxlength="${UI.maxLabelLength}" aria-label="Label for extra field ${index + 1}">
      <input class="cf-value" type="${field.secret ? "password" : "text"}" value="${esc(field.value)}"
        placeholder="${field.kept ? "Unchanged" : "Value"}" autocomplete="off"
        maxlength="${UI.maxFieldLength}" aria-label="Value for extra field ${index + 1}">
      <label class="cf-hide"><input type="checkbox" ${field.secret ? "checked" : ""}
        aria-label="Hide the value of extra field ${index + 1}"> Hide</label>
      <button type="button" class="icon-btn danger" data-remove="${index}"
        aria-label="Remove extra field ${index + 1}" title="Remove">${icon("trash")}</button>
    </div>`).join("");

  for (const row of box.querySelectorAll(".custom-field")) {
    const index = Number(row.dataset.index);
    const label = row.querySelector(".cf-label");
    const value = row.querySelector(".cf-value");
    const hide = row.querySelector(".cf-hide input");
    label.oninput = () => { state.formFields[index].label = label.value; };
    value.oninput = () => {
      // Clearing the box again returns a hidden row to "unchanged", so a
      // keystroke typed and deleted does not destroy a value nobody can see.
      const field = (state.formFields[index] = Fields.valueEdited(state.formFields[index], value.value));
      value.placeholder = field.kept ? "Unchanged" : "Value";
    };
    hide.onchange = () => {
      state.formFields[index] = Fields.secretToggled(state.formFields[index], hide.checked);
      renderFormFields(); // the value input swaps between text and password
      // The re-render replaced the checkbox that was just clicked.
      box.querySelectorAll(".custom-field")[index]?.querySelector(".cf-hide input")?.focus();
    };
    row.querySelector("[data-remove]").onclick = () => {
      state.formFields.splice(index, 1);
      renderFormFields();
    };
  }
}

function addFormField() {
  if (state.formFields.length >= UI.maxCustomFields) {
    setError("form-error", `A secret can have at most ${UI.maxCustomFields} extra fields.`);
    return;
  }
  setError("form-error", "");
  state.formFields.push(Fields.newFormField());
  renderFormFields();
  const rows = $("custom-fields").querySelectorAll(".custom-field");
  rows[rows.length - 1]?.querySelector(".cf-label").focus();
}

/// The value the picker carries for "file this nowhere" and for "make a new
/// project". Strings, because that is what a `<select>` holds; a numeric id
/// could never collide with either, but naming them keeps the comparison
/// readable rather than magic.
const NO_PROJECT = "";
const NEW_PROJECT = "new";

/// The project picker, with `selected` chosen. Built here rather than in
/// screens.js because it is one element with no ordering decisions of its
/// own: the list is already in the order the server gave.
function projectSelectHtml(filed, { id = "f-project", includeNew = true } = {}) {
  const selected = filed?.id ?? null;
  const options = state.projects.map((p) =>
    `<option value="${p.id}"${p.id === selected ? " selected" : ""}>${esc(p.name)}</option>`).join("");
  // A secret can name a project this list has not caught up with -- renamed
  // or created on another device since the last refresh. Without an option
  // for it nothing is selected, the browser falls back to the first ("No
  // project"), and saving the form would quietly unfile the secret. The row
  // carries the name, so the picker can show the truth instead.
  const unknown = selected !== null && !state.projects.some((p) => p.id === selected)
    ? `<option value="${esc(selected)}" selected>${esc(filed.name)}</option>`
    : "";
  // The detail pane's picker moves the secret on the spot and has nowhere to
  // put a name box, so it offers only projects that already exist.
  const makeNew = includeNew ? `<option value="${NEW_PROJECT}">New project\u2026</option>` : "";
  // Wrapped so the caret has something to position against; a `select` on
  // its own cannot carry one, because the shared field rule sets `background`
  // and a later one resets it on phones.
  return `
    <span class="select-wrap"><select id="${id}" aria-label="Project">
      <option value="${NO_PROJECT}"${selected === null ? " selected" : ""}>No project</option>
      ${unknown}
      ${options}
      ${makeNew}
    </select></span>`;
}

/// What the form is asking for, in the three states [`ProjectAssignment`]
/// uses on the Rust side, creating a project first if that is what was
/// chosen.
///
/// `keep` is never returned -- the form always shows an answer, so it always
/// states one. It exists so that a form which somehow submits nothing means
/// "leave it alone" rather than "unfile it".
///
/// Creating before saving means a secret that then fails to save leaves an
/// empty project behind. That is the better failure of the two: the project
/// is visible in the Projects panel and can be deleted in one click, whereas
/// creating it afterwards would mean a saved secret silently landing in no
/// project at all.
async function chosenProject() {
  const choice = $("f-project").value;
  if (choice === NO_PROJECT) return { action: "clear" };
  if (choice !== NEW_PROJECT) return { action: "set", project_id: Number(choice) };
  const name = $("f-new-project").value.trim();
  if (!name) {
    const error = new Error("Give the new project a name, or pick No project.");
    error.field = "f-new-project";
    throw error;
  }
  return { action: "set", project_id: await invoke("create_project", { name }) };
}

function renderForm(existing) {
  state.editing = true;
  state.editTitle = existing ? "Edit secret" : "New secret";
  clearReveals();
  state.formFields = Fields.formFieldsFrom(existing);
  syncScreenChrome();
  $("main").classList.add("has-selection");
  const s = existing || { name: "", username: "", url: "", notes: "", project: null };
  // Windows edits a secret in a dialog over the vault; every other platform
  // uses the detail pane, which on a phone is its own screen.
  const inDialog = PLATFORM === "windows";
  const host = inDialog ? $("form-dialog") : $("detail");
  // Closed when creating, open when there is already something in it; see
  // Screens.hasMoreDetails().
  const moreOpen = Screens.hasMoreDetails(existing);
  // ⌘↩ on a Mac, Ctrl+↩ elsewhere. Named on the button rather than printed
  // under it: a caption is read once and then stops being seen.
  const saveShortcut = Screens.shortcutLabel(PLATFORM, "Enter").replace(/ENTER$/i, "\u21a9");
  host.innerHTML = `
    <form class="card form" id="secret-form" novalidate aria-labelledby="form-title">
      <h2 id="form-title" class="card-title pane-title">${existing ? icon("edit") : icon("plus")} ${esc(state.editTitle)}</h2>
      <div class="field">
        <label for="f-name">Name</label>
        <input id="f-name" value="${esc(s.name)}" placeholder="e.g. Netflix" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-username">Username</label>
        <input id="f-username" value="${esc(s.username)}" placeholder="Email or username" autocomplete="off" spellcheck="false">
      </div>
      <div class="field">
        <label for="f-password">Password</label>
        <div class="input-row stack">
          <input id="f-password" type="password" autocomplete="new-password" placeholder="${existing ? "Unchanged" : ""}">
          <button type="button" class="icon-btn bordered" id="btn-toggle-pw" aria-label="Show password" aria-pressed="false" title="Show password">${icon("eye")}</button>
          <button type="button" class="btn" id="btn-generate" title="Generate a strong ${UI.generatedPasswordLength}-character password">${icon("wand")} Generate</button>
        </div>
        ${existing ? `<p class="hint">Leave blank to keep the current password.</p>` : ""}
      </div>
      <button type="button" class="link-btn" id="btn-more-details"
        aria-expanded="${moreOpen}" aria-controls="more-details">More details</button>
      <div class="more-details${moreOpen ? "" : " hidden"}" id="more-details">
        <div class="field">
          <div class="label-row">
            <label for="f-project">Project <span class="label-note">(optional)</span></label>
            ${infoButtonHtml("project-note", PROJECT_NAME_DISCLOSURE)}
          </div>
          ${projectSelectHtml(s.project ?? null)}
          <div class="field hidden" id="new-project-field">
            <label for="f-new-project">New project name</label>
            <input id="f-new-project" placeholder="e.g. Perspectiv" autocomplete="off"
              maxlength="${UI.maxProjectNameLength}">
          </div>
          <p class="hint hidden" id="project-note">${esc(PROJECT_NAME_DISCLOSURE)}</p>
        </div>
        <div class="field">
          <label for="f-url">URL <span class="label-note">(optional)</span></label>
          <input id="f-url" value="${esc(s.url)}" placeholder="https://" autocomplete="off" spellcheck="false" inputmode="url">
        </div>
        <div class="field">
          <label for="f-notes">Notes <span class="label-note">(optional)</span></label>
          <textarea id="f-notes">${esc(s.notes)}</textarea>
        </div>
        <div class="field">
          <div class="label-row">
            <span class="field-label">Extra details <span class="label-note">(optional)</span></span>
            ${infoButtonHtml("extra-note", EXTRA_FIELDS_DISCLOSURE)}
          </div>
          <p class="hint hidden" id="extra-note">${esc(EXTRA_FIELDS_DISCLOSURE)}</p>
          <div id="custom-fields"></div>
          <button type="button" class="btn" id="btn-add-field">${icon("plus")} Add field</button>
        </div>
      </div>
      <div class="error" id="form-error" role="alert"></div>
      <div class="actions form-actions">
        <button type="submit" class="btn primary" id="btn-save"
          aria-keyshortcuts="${Screens.shortcutKeys(PLATFORM, "Enter")}"
          title="${saveShortcut} to save">${existing ? "Save changes" : "Create secret"}</button>
        <button type="button" class="btn" id="btn-cancel" aria-keyshortcuts="Escape" title="Esc to cancel">Cancel</button>
        <span class="muted small">Esc to cancel</span>
      </div>
    </form>`;

  const form = $("secret-form");
  const cancel = () => {
    state.editing = false;
    if (inDialog) { closeDialog(host); host.innerHTML = ""; }
    renderDetail();
    if (inDialog) firstVisible("btn-edit", "btn-new")?.focus();
  };
  if (inDialog) openDialog(host);
  $("btn-toggle-pw").onclick = () => togglePasswordInput($("f-password"), $("btn-toggle-pw"));
  $("btn-generate").onclick = async () => {
    setError("form-error", "");
    try {
      $("f-password").value = await invoke("generate_password", { length: UI.generatedPasswordLength, symbols: true });
      if ($("f-password").type === "password") togglePasswordInput($("f-password"), $("btn-toggle-pw"));
    } catch (error) { setError("form-error", error); }
  };
  $("btn-cancel").onclick = cancel;
  $("btn-add-field").onclick = addFormField;
  $("btn-more-details").onclick = () => toggleDisclosure($("btn-more-details"), $("more-details"));
  const projectSelect = $("f-project");
  projectSelect.onchange = () => {
    const naming = projectSelect.value === NEW_PROJECT;
    $("new-project-field").classList.toggle("hidden", !naming);
    if (naming) $("f-new-project").focus();
  };
  renderFormFields();
  form.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.preventDefault(); cancel(); return; }
    // Enter alone is a newline inside Notes, so saving from there needs the
    // modifier; requestSubmit() runs the same path as the button.
    if (Screens.isSaveShortcut(event)) {
      event.preventDefault();
      // requestSubmit() is Safari 16 / WebKitGTK 2.38, above the floor this
      // app holds itself to; clicking the button runs the same onsubmit.
      if (typeof form.requestSubmit === "function") form.requestSubmit();
      else $("btn-save").click();
    }
  });
  form.onsubmit = async (event) => {
    event.preventDefault();
    setError("form-error", "");
    const entry = {
      name: $("f-name").value.trim(),
      username: $("f-username").value,
      password: $("f-password").value,
      url: $("f-url").value.trim(),
      notes: $("f-notes").value,
      fields: Fields.submittedFields(state.formFields),
    };
    if (!entry.name) { setError("form-error", "Give the secret a name."); $("f-name").focus(); return; }
    // A row that gave up its claim on an unseen value and has nothing typed
    // in its place would be saved as empty, destroying it with no warning.
    const needValues = Fields.rowsNeedingAValue(state.formFields);
    if (needValues.length) {
      const names = needValues.map((row) => row.label).join(", ");
      setError(
        "form-error",
        `Enter a value for ${names}. Its stored value was never shown here, so saving now would erase it. ` +
          "To leave it exactly as it was, press Esc to discard this edit. " +
          "To get rid of the field instead, use its Remove button.",
      );
      const rows = $("custom-fields").querySelectorAll(".custom-field");
      focusInForm(rows[needValues[0].index]?.querySelector(".cf-value"));
      return;
    }

    // Catch a missing label here too, so the row is named and focused rather
    // than coming back as a generic error after a round trip through
    // encryption. A new row has no stored name to fall back on.
    const unlabelled = state.formFields.findIndex((field) => field.label.trim() === "" && (field.kept || field.value));
    if (unlabelled !== -1) {
      setError("form-error", "Give every extra field a label, or remove it.");
      focusInForm($("custom-fields").querySelectorAll(".custom-field")[unlabelled]?.querySelector(".cf-label"));
      return;
    }
    if (!existing && !entry.password) { setError("form-error", "Enter a password or generate one."); $("f-password").focus(); return; }
    setBusy($("btn-save"), true, "Saving…");
    try {
      // May create a project first, so it is inside the try: a name the
      // server refuses has to land on the form, not in the console.
      // snake_case: this object is deserialised into `SecretForm` as-is,
      // unlike a command's own arguments, which Tauri converts.
      entry.project = await chosenProject();
      if (existing) {
        // A blank password means "keep it"; the current one never passes through here.
        if (!entry.password) entry.password = null;
        await invoke("update_secret", { id: existing.id, form: entry });
        toast("Changes saved");
      } else {
        state.selected = await invoke("create_secret", { form: entry });
        toast("Secret created");
      }
      state.editing = false;
      if (inDialog) { closeDialog(host); host.innerHTML = ""; }
      await refresh();
      renderDetail();
    } catch (error) {
      setError("form-error", error);
      // A field the error names gets the focus, the way the checks above do.
      if (error?.field) focusInForm($(error.field));
      setBusy($("btn-save"), false);
    }
  };
  $("f-name").focus();
}

// ----- wiring ----------------------------------------------------------------

$("tab-login").onclick = () => setAuthMode("login");
$("tab-register").onclick = () => setAuthMode("register");
$("auth-form").onsubmit = authenticate;
$("btn-auth-toggle-pw").onclick = () => togglePasswordInput($("password"), $("btn-auth-toggle-pw"));
$("btn-show-token").onclick = () => showTokenField();
// Every control that names a document opens it: the two lines under the sign-in
// forms, the two tabs inside the dialog, and the entry in the vault.
for (const control of document.querySelectorAll("[data-legal]")) {
  control.onclick = () => showLegal(control.dataset.legal);
}
$("btn-legal-close").onclick = () => closeDialog($("legal-dialog"));
$("btn-google").onclick = startGoogleSignIn;
$("google-form").onsubmit = submitGooglePassphrase;
$("btn-google-cancel").onclick = cancelGoogleSignIn;
$("btn-google-toggle-pw").onclick = () => togglePasswordInput($("google-password"), $("btn-google-toggle-pw"));
$("btn-link-google").onclick = () => renderGoogleLinkForm();
$("btn-projects").onclick = () => renderProjectsPanel();
$("btn-change-passphrase").onclick = () => renderPassphraseForm();
$("btn-sign-out-others").onclick = () => renderSignOutOthersForm();
// The button belongs to whichever server is in the box, so re-ask when it
// settles rather than on every keystroke.
$("server").onchange = () => refreshCapabilities();
$("server").onblur = () => refreshCapabilities();
$("btn-server-change").onclick = showServerField;
$("server").oninput = syncServerSummary;
$("btn-logout").onclick = () => logout().catch((error) => setError("main-error", error));
$("btn-refresh").onclick = () => { closeAccountSheet({ restoreFocus: false }); refresh(); };
$("btn-back").onclick = goBack;
$("btn-account").onclick = () => ($("app").classList.contains("account-open") ? closeAccountSheet() : openAccountSheet());
$("account-backdrop").onclick = () => closeAccountSheet();
$("btn-new").onclick = startNew;
// The top-bar Edit and Delete act on the open secret through the same
// buttons the detail pane draws, so there is one code path for each.
$("btn-bar-edit").onclick = () => $("btn-edit")?.click();
$("btn-bar-more").onclick = () => ($("bar-menu").hidden ? openBarMenu() : closeBarMenu({ restoreFocus: true }));
$("bar-menu").addEventListener("keydown", barMenuKeydown);
$("btn-menu-delete").onclick = () => { closeBarMenu({ restoreFocus: true }); $("btn-delete")?.click(); };
// A press anywhere outside the menu and its button closes it.
document.addEventListener("pointerdown", (event) => {
  if (!event.target.closest?.(".bar-menu-wrap")) closeBarMenu();
  if (!event.target.closest?.(".row-menu") && !event.target.closest?.(".row-more")) closeRowMenu();
});
// A row menu is placed against the viewport, so anything that moves the row
// out from under it has to take it away rather than leave it pointing at
// whatever has scrolled into that spot.
window.addEventListener("resize", () => closeRowMenu());
$("main").addEventListener("scroll", () => closeRowMenu(), { passive: true });
document.addEventListener("scroll", (event) => {
  // Not the menu's own scrolling, which would close it as it was being read.
  if (event.target?.closest?.(".row-menu")) return;
  closeRowMenu();
}, { capture: true, passive: true });
$("invite-form").onsubmit = submitInvite;
$("btn-invite-close").onclick = closeInviteDialog;
// Escape closes a dialog natively; route it through the same paths as the
// buttons so state and focus are put back the same way.
$("invite-dialog").addEventListener("cancel", (event) => { event.preventDefault(); closeInviteDialog(); });
$("form-dialog").addEventListener("cancel", (event) => { event.preventDefault(); $("btn-cancel")?.click(); });
$("btn-fingerprint").onclick = () => copyText($("fingerprint").textContent, "Your key fingerprint");
$("filter").oninput = () => { syncSearchClear(); renderList(); };
$("btn-clear-search").onclick = clearSearch;
// Escape empties the field rather than reaching the document handler, which
// would close the account sheet behind it. With nothing typed it is not ours.
$("filter").addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || !$("filter").value) return;
  event.preventDefault();
  event.stopPropagation();
  clearSearch();
});
$("list").addEventListener("keydown", listKeydown);

document.addEventListener("keydown", (event) => {
  if ($("app").classList.contains("hidden")) return;
  if (event.key === "Escape" && $("app").classList.contains("account-open")) { closeAccountSheet(); return; }
  const modifier = event.metaKey || event.ctrlKey;
  if (!modifier || event.altKey || event.shiftKey) return;
  if (event.key === "k") { event.preventDefault(); $("filter").focus(); $("filter").select(); }
  if (event.key === "n" && !state.editing) { event.preventDefault(); startNew(); }
});

for (const button of document.querySelectorAll("[data-theme-choice]")) {
  button.onclick = () => chooseTheme(button.dataset.themeChoice);
}
// Every "i" in the app, wired once. The panels are drawn by half a dozen
// render functions and redrawn whenever their data changes, so binding at the
// button would mean remembering to rebind in each of them.
document.addEventListener("click", (event) => {
  const button = event.target.closest?.("[data-info-for]");
  if (!button) return;
  const note = $(button.dataset.infoFor);
  if (note) toggleDisclosure(button, note);
});

applySafeAreaInsets();
applyTheme(recall(THEME_KEY) || "system");

$("server").value = (ALLOW_CUSTOM_SERVER && recall("server")) || DEFAULT_SERVER;
$("server").placeholder = DEFAULT_SERVER;
// An install that was signed in somewhere else keeps the field; everyone
// else gets the pinned address. See unlockServerFor().
const strandedServer = ALLOW_CUSTOM_SERVER ? null : Screens.strandedAddress(recall("server"), DEFAULT_SERVER);
if (!ALLOW_CUSTOM_SERVER) lockServerAddress();
if (strandedServer) noteStrandedServer(strandedServer);
syncServerSummary();
$("email").value = recall("email");
setAuthMode("login");
($("email").value ? $("password") : $("email")).focus();
invoke("ui_constants")
  .then((c) => Object.assign(UI, {
    minPasswordLength: c.min_password_length,
    maxMessageLength: c.max_message_length,
    generatedPasswordLength: c.generated_password_length,
    maxCustomFields: c.max_custom_fields,
    maxLabelLength: c.max_label_length,
    maxFieldLength: c.max_field_length,
    maxProjectNameLength: c.max_project_name_length,
  }))
  // Served rather than written into the markup, so the floor is stated in
  // one place: the crate that enforces it.
  .then(() => {
    const hint = $("password-hint");
    if (hint) hint.textContent = `At least ${UI.minPasswordLength} characters. There is no password reset.`;
  })
  .catch(() => { /* the defaults above match the crates today */ });
// Served rather than written into the markup for the same reason the limits
// above are: the crate that is running is the only thing that knows which
// version it is, and a number typed into the HTML would survive the next bump.
//
// Two separate things can go wrong here and they get separate messages: the
// markup no longer carries the line, or the command did not answer. Rolled
// into one catch, the first would be reported as the second, and whoever read
// the warning would go looking in the wrong half of the app.
//
// The line stays hidden until there is a number to put in it: a build that
// cannot say which build it is says nothing.
const versionLine = $("app-version");
if (!versionLine) {
  console.warn("index.html no longer carries #app-version, so the version line cannot be shown");
} else {
  // The rejection handler is the second argument rather than a .catch, so it
  // covers the command and not the handler beside it: a throw from the lines
  // below is this file's bug and should not be reported as the server-side
  // one.
  invoke("app_version").then(
    (version) => {
      const label = Screens.appVersionLabel(version);
      if (label === null) {
        console.warn("the app_version command answered with no version, so the version line stays hidden");
        return;
      }
      versionLine.textContent = label;
      versionLine.hidden = false;
    },
    (error) => console.warn("could not read the app version", error),
  );
}
invoke("startup_warnings")
  // This is the only notice that the pinned-key file was corrupt and moved
  // aside, i.e. that every key confirmed so far must be confirmed again
  // before the next invite. It goes in its own banner rather than the error
  // slot, which both setAuthMode and submitting the form blank.
  .then((warnings) => { if (warnings.length) showStartupWarning(warnings.join("\n")); })
  .catch((error) => showStartupWarning(`Could not read startup warnings: ${error?.message ?? error}`));
refreshCapabilities();
invoke("session_info")
  .then((user) => { if (user) showApp(user); })
  .catch((error) => setError("auth-error", error));
