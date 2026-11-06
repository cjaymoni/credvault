// credvault desktop UI. All cryptography lives in Rust; this file only renders
// state and calls Tauri commands.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

const DEFAULT_SERVER = "http://127.0.0.1:8787";
const REVEAL_HIDE_AFTER_MS = 30_000;
const TOAST_MS = 2200;
const MASKED = "••••••••••••";
// Limits owned by the Rust crates; `ui_constants` overwrites these defaults at startup.
const UI = { minPasswordLength: 12, maxMessageLength: 1000, generatedPasswordLength: 20, maxCustomFields: 20, maxLabelLength: 100, maxFieldLength: 4096 };
const THEME_KEY = "theme";
const THEME_CHOICES = ["system", "light", "dark"];

const state = { secrets: [], selected: null, editing: false, authMode: "login", inviteCount: 0, formFields: [],
  // What the server at the URL in the box offers, and the Google sign-in
  // waiting for a passphrase, if there is one.
  capabilities: null, google: null, user: null,
  // Set when the server at that URL answered but speaks a protocol this build
  // cannot use; null the rest of the time.
  incompatible: null };
const MOBILE_QUERY = window.matchMedia("(max-width: 720px)");
const isMobile = () => MOBILE_QUERY.matches;
const timers = { toast: null };

// ----- helpers ---------------------------------------------------------------

function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

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
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  chevronRight: '<path d="m9 6 6 6-6 6"/>',
};
function icon(name) {
  return `<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
}

function toast(message) {
  const el = $("toast");
  el.innerHTML = `${icon("check")}<span>${esc(message)}</span>`;
  el.classList.add("show");
  clearTimeout(timers.toast);
  timers.toast = setTimeout(() => el.classList.remove("show"), TOAST_MS);
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
  if (state.editing) return state.selected === null ? "New secret" : "Edit secret";
  const secret = state.secrets.find((s) => s.id === state.selected);
  return secret ? secret.name : "Invitations";
}
function updateMobileTitle() {
  $("mobile-title").textContent = mobileTitle();
}
function showDetailScreen() {
  updateMobileTitle();
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
  const nothingToShow = state.selected === null && !state.editing && state.inviteCount === 0;
  if (isMobile() && $("app").dataset.screen === "detail" && nothingToShow) showListScreen();
}

/// Everything outside the sheet goes inert while it is open, so Tab cannot
/// land on controls hidden under the backdrop. The trigger stays live so it
/// can close the sheet again.
function behindSheet() {
  return [$("main"), document.querySelector(".sidebar"), $("btn-back"), document.querySelector(".topbar .brand"), $("mobile-title")];
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
  $("btn-show-token").classList.toggle("hidden", !isRegister);
  if (!isRegister) showTokenField(false);
  $("password-hint").classList.toggle("hidden", !isRegister);
  $("password").autocomplete = isRegister ? "new-password" : "current-password";
  $("btn-auth").textContent = isRegister ? "Create account" : "Log in";
  setError("auth-error", "");
  // Switching tabs abandons a Google sign-in that was waiting for a passphrase.
  if (state.google) { state.google = null; showGoogleForm(false); }
}

/// The registration token is only needed on servers that require one, so the
/// field stays folded away until asked for.
function showTokenField(show) {
  $("token-field").classList.toggle("hidden", !show);
  $("btn-show-token").classList.toggle("hidden", show || state.authMode !== "register");
  $("btn-show-token").setAttribute("aria-expanded", String(show));
  if (show) $("registration-token").focus();
}

async function authenticate(event) {
  event.preventDefault();
  setError("auth-error", "");
  const isRegister = state.authMode === "register";
  const serverUrl = $("server").value.trim() || DEFAULT_SERVER;
  const email = $("email").value.trim();
  const password = $("password").value;
  if (!email) { setError("auth-error", "Enter your email."); $("email").focus(); return; }
  if (!password) { setError("auth-error", "Enter your account password."); $("password").focus(); return; }
  if (isRegister && password.length < UI.minPasswordLength) {
    setError("auth-error", `Use at least ${UI.minPasswordLength} characters for your account password.`);
    $("password").focus();
    return;
  }
  const args = { serverUrl, email, password };
  if (isRegister) args.registrationToken = $("registration-token").value.trim() || null;
  setBusy($("btn-auth"), true, isRegister ? "Creating account…" : "Unlocking…");
  try {
    const user = await invoke(isRegister ? "register" : "login", args);
    remember("server", serverUrl);
    remember("email", email);
    $("password").value = "";
    $("registration-token").value = "";
    showApp(user);
  } catch (error) {
    setError("auth-error", error);
    if (isRegister && /token/i.test(String(error?.message ?? error))) showTokenField(true);
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
  const serverUrl = $("server").value.trim() || DEFAULT_SERVER;
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
  $("btn-link-google").classList.toggle("hidden", !state.capabilities?.google_sign_in);
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
    setError("google-error", "");
  }
}

async function startGoogleSignIn() {
  setError("auth-error", "");
  const serverUrl = $("server").value.trim() || DEFAULT_SERVER;
  setBusy($("btn-google"), true, "Waiting for your browser…");
  try {
    const stage = await invoke("google_sign_in", { serverUrl });
    remember("server", serverUrl);
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
    $("google-token-field").classList.toggle("hidden", !(creating && stage.registration_token_required));
    showGoogleForm(true);
    $("google-password").focus();
  } catch (error) {
    setError("auth-error", error);
  } finally {
    setBusy($("btn-google"), false);
  }
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

  const args = creating
    ? { password, registrationToken: $("google-registration-token").value.trim() || null }
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
      $("google-token-field").classList.remove("hidden");
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

async function linkGoogle() {
  setBusy($("btn-link-google"), true);
  try {
    await invoke("google_link");
    toast("Google account linked");
  } catch (error) {
    setError("main-error", error);
  } finally {
    setBusy($("btn-link-google"), false);
  }
}

function showApp(user) {
  state.user = user;
  $("who-email").textContent = user.email;
  $("who-server").textContent = user.server_url;
  $("who-server").title = user.server_url;
  $("fingerprint").textContent = user.fingerprint;
  $("auth").classList.add("hidden");
  $("app").classList.remove("hidden");
  state.secrets = []; state.selected = null; state.editing = false; state.inviteCount = 0;
  $("filter").value = "";
  $("app").dataset.screen = "list";
  renderDetail();
  refresh();
}

async function logout() {
  await invoke("logout");
  clearReveals();
  state.secrets = []; state.selected = null; state.editing = false;
  $("list").innerHTML = ""; $("detail").innerHTML = ""; $("invites").innerHTML = ""; $("invites-banner").innerHTML = "";
  closeAccountSheet({ restoreFocus: false });
  setError("main-error", "");
  $("app").classList.add("hidden");
  $("auth").classList.remove("hidden");
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
    const [secrets, invites] = await Promise.all([invoke("list_secrets"), invoke("list_invites")]);
    state.secrets = secrets;
    renderList();
    renderInvites(invites);
    if (state.selected !== null && !secrets.some((s) => s.id === state.selected)) state.selected = null;
    if (!state.editing) renderDetail();
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
  return [secret.name, secret.username, secret.url].some((v) => String(v ?? "").toLowerCase().includes(needle));
}

function itemHtml(s) {
  const selected = s.id === state.selected;
  const subtitle = s.error
    ? `${icon("alert")} Cannot be decrypted`
    : (s.username ? esc(s.username) : "<em>No username</em>");
  return `
    <button type="button" class="item${selected ? " active" : ""}${s.error ? " broken" : ""}"
      role="option" aria-selected="${selected}" data-id="${s.id}" tabindex="${selected ? 0 : -1}">
      ${avatar(s.name, { broken: Boolean(s.error) })}
      <span class="item-text">
        <span class="item-name">${esc(s.name)}</span>
        <span class="item-sub">${subtitle}</span>
      </span>
      ${s.is_owner ? "" : `<span class="badge" title="Shared by ${esc(s.owner_email)}">${icon("users")} Shared</span>`}
      <span class="chev">${icon("chevronRight")}</span>
    </button>`;
}

function renderList() {
  const needle = $("filter").value.trim().toLowerCase();
  const rows = state.secrets
    .filter((s) => matchesFilter(s, needle))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  const mine = rows.filter((s) => s.is_owner);
  const shared = rows.filter((s) => !s.is_owner);

  const total = state.secrets.length;
  const sharedTotal = state.secrets.filter((s) => !s.is_owner).length;
  $("count").textContent = needle
    ? `${rows.length} of ${total} match`
    : `${plural(total, "secret", "secrets")}${sharedTotal ? ` · ${sharedTotal} shared with you` : ""}`;

  const list = $("list");
  if (!rows.length) {
    list.innerHTML = `<p class="list-empty">${needle ? "No secrets match your search." : "Your vault is empty."}</p>`;
    return;
  }
  const group = (title, items) => items.length
    ? `<div role="group" aria-label="${title}"><div class="list-heading">${title}</div>${items.map(itemHtml).join("")}</div>`
    : "";
  list.innerHTML = shared.length ? group("Mine", mine) + group("Shared with me", shared) : mine.map(itemHtml).join("");

  const items = list.querySelectorAll(".item");
  if (!list.querySelector('.item[tabindex="0"]') && items.length) items[0].tabIndex = 0;
  for (const el of items) el.onclick = () => selectSecret(Number(el.dataset.id));
}

/// Arrow keys move focus within the list; Enter/Space activate the focused item.
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
  renderList();
  renderDetail();
  showDetailScreen();
}

function startNew() {
  state.selected = null;
  renderList();
  renderForm(null);
  showDetailScreen();
}

function showInvitesScreen() {
  state.selected = null;
  state.editing = false;
  renderList();
  renderDetail();
  showDetailScreen();
}

// ----- invites ---------------------------------------------------------------

function renderInvites(invites) {
  const box = $("invites");
  state.inviteCount = invites.length;
  $("main").classList.toggle("has-invites", invites.length > 0);
  renderInvitesBanner(invites.length);
  if (!invites.length) { box.innerHTML = ""; return; }
  box.innerHTML = `
    <section aria-labelledby="invites-title">
      <h2 id="invites-title" class="section-title">${icon("inbox")} Invitations <span class="count-pill">${invites.length}</span></h2>
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

/// Phone list screen: a tappable banner that opens the invitations.
function renderInvitesBanner(count) {
  const banner = $("invites-banner");
  if (!count) { banner.innerHTML = ""; return; }
  banner.innerHTML = `
    <button type="button" class="invites-banner" id="btn-invites">
      ${icon("inbox")}
      <span>${plural(count, "invitation", "invitations")} waiting</span>
      <span class="count-pill">${count}</span>
      ${icon("chevronRight")}
    </button>`;
  $("btn-invites").onclick = showInvitesScreen;
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
      <p>Pick one from the list, or press <span class="kbd">⌘N</span> / <span class="kbd">Ctrl+N</span> to create a new one.</p>
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
  return `<div class="kv-row"><dt>${icon(iconName)} ${esc(label)}</dt><dd>${valueHtml}${actions}</dd></div>`;
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

function renderDetail() {
  clearReveals();
  updateMobileTitle();
  const s = state.secrets.find((x) => x.id === state.selected);
  $("main").classList.toggle("has-selection", Boolean(s));
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
      </section>` : ""}`;

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
  $("btn-delete").onclick = () => renderDeleteConfirm(s);
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
      <dt>${icon(iconName)} ${esc(label)}</dt>
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
      toast(`${subject} copied · clipboard clears in ${seconds}s`);
    } catch (error) { setError("main-error", error); }
  };
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
  const cancel = () => { box.innerHTML = ""; const b = $("btn-delete"); if (b) b.focus(); };
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

async function loadSharing(id) {
  const box = $("sharing");
  if (!box) return;
  try {
    const access = await invoke("get_access", { id });
    if (!box.isConnected || state.selected !== id) return; // user moved on
    const members = access.members.length
      ? access.members.map((m) => `
          <li>${avatar(m.email, { size: "sm" })}<span class="who">${esc(m.email)}</span>
            <button type="button" class="btn ghost danger sm" data-revoke="${m.user_id}" aria-label="Revoke access for ${esc(m.email)}">Revoke</button></li>`).join("")
      : `<li class="only-you">Only you have access.</li>`;
    const pending = access.invites.length ? `
      <h3 class="sub-title">Pending invites</h3>
      <ul class="people">${access.invites.map((i) => `
        <li>${avatar(i.email, { size: "sm" })}<span class="who">${esc(i.email)}</span><span class="badge">Pending</span>
          <button type="button" class="btn ghost sm" data-cancel="${i.id}" aria-label="Cancel invite for ${esc(i.email)}">Cancel</button></li>`).join("")}</ul>` : "";
    box.innerHTML = `
      <h3 id="sharing-title" class="card-title">${icon("users")} Sharing</h3>
      <p class="card-lead">Invite someone by the email they signed up with. They get read-only access to this one secret.
        Revoking someone re-encrypts it with a new key and cancels any pending invites.</p>
      <form class="invite-form" id="invite-form" novalidate>
        <div class="field">
          <label for="invite-email">Email</label>
          <input id="invite-email" type="email" placeholder="friend@example.com" autocomplete="off" spellcheck="false">
        </div>
        <div class="field">
          <label for="invite-fingerprint">Their key fingerprint</label>
          <input id="invite-fingerprint" class="mono" placeholder="0000-0000-0000-0000-0000-0000"
            autocomplete="off" spellcheck="false">
          <p class="hint">Ask them to read it from the top of their credvault window. Leave blank for someone you have already shared with.</p>
        </div>
        <div class="field wide">
          <label for="invite-message">Message <span class="label-note">(optional)</span></label>
          <input id="invite-message" placeholder="e.g. The shared Wi-Fi password" maxlength="${UI.maxMessageLength}">
        </div>
        <button type="submit" class="btn primary" id="btn-invite">${icon("mail")} Invite</button>
      </form>
      <div id="invite-confirm"></div>
      <h3 class="sub-title">People with access</h3>
      <ul class="people" id="members">${members}</ul>
      ${pending}`;

    $("invite-form").onsubmit = async (event) => {
      event.preventDefault();
      const email = $("invite-email").value.trim();
      if (!email) { setError("main-error", "Enter the email of the person to invite."); $("invite-email").focus(); return; }
      setError("main-error", "");
      setBusy($("btn-invite"), true);
      try {
        // Blank means "use the key I pinned for them"; the command says so if
        // there is no pin to fall back on.
        const fingerprint = $("invite-fingerprint").value.trim() || null;
        const info = await invoke("lookup_invitee", { email, fingerprint });
        renderInviteConfirm(id, info);
      } catch (error) {
        setError("main-error", error);
        // Both of these are answered by typing the fingerprint in, so send the
        // user straight there instead of leaving them on the email field.
        if (error?.code === "fingerprint_required" || error?.code === "lookup_failed") $("invite-fingerprint").focus();
      } finally {
        setBusy($("btn-invite"), false);
      }
    };
    for (const el of box.querySelectorAll("[data-revoke]")) {
      el.onclick = () => revokeMember(id, Number(el.dataset.revoke), el, []);
    }
    for (const el of box.querySelectorAll("[data-cancel]")) el.onclick = async () => {
      if (await act("cancel_invite", { id, inviteId: Number(el.dataset.cancel) }, "Invite cancelled", el)) loadSharing(id);
    };
  } catch (error) {
    if (box.isConnected) box.innerHTML = `<h3 id="sharing-title" class="card-title">${icon("users")} Sharing</h3><div class="error">${esc(error?.message ?? error)}</div>`;
  }
}

/// Fingerprints are compared by eye, so accept any spacing or case: only the
/// hex digits carry meaning.
function normalizeFingerprint(text) {
  return String(text ?? "").toLowerCase().replace(/[^0-9a-f]/g, "");
}

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
  const box = $("invite-confirm");
  const changed = members.some((m) => m.status === "changed");
  const rows = members.map((m) => `
    <li>${avatar(m.email, { size: "sm" })}<span class="who">${esc(m.email)}</span>
      <code class="fp">${esc(m.fingerprint)}</code>
      <span class="badge">${m.status === "changed" ? "Changed" : "Not confirmed"}</span></li>`).join("");
  box.innerHTML = `
    <div class="card" style="margin-top:14px" role="region" aria-label="Confirm who keeps access">
      <h3 class="card-title">${icon("key")} Confirm who keeps access</h3>
      <p class="card-lead">Revoking re-encrypts this secret for everyone who keeps access, and this device has not confirmed these keys yet. Ask each person to read the <strong>Your key</strong> fingerprint from their credvault window and continue only if every one matches.</p>
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

/// The server told us this person's key; the user must confirm its fingerprint
/// matches what the invitee's own app shows before we encrypt anything to it.
function renderInviteConfirm(id, info) {
  const changed = info.status === "changed";
  const known = info.status === "known";
  const compare = changed ? `
    <div class="fp-compare">
      <div class="fp-box good"><div class="k">Confirmed before</div><code class="fp">${esc(info.pinned_fingerprint)}</code></div>
      <div class="fp-box bad"><div class="k">Server reports now</div><code class="fp">${esc(info.fingerprint)}</code></div>
    </div>` : `
    <div class="fp-compare">
      <div class="fp-box${known ? " good" : ""}"><div class="k">${esc(info.email)}</div><code class="fp">${esc(info.fingerprint)}</code></div>
    </div>`;
  const guidance = changed
    ? `<div class="notice danger">${icon("alert")}<div>This key differs from the one you confirmed before. Either they re-created their account, or the server is lying. Continue only if they read you this new fingerprint themselves.</div></div>`
    : known
      ? `<div class="notice">${icon("check")}<div>Matches the key you confirmed before.</div></div>`
      : `<div class="notice">${icon("info")}<div>This key's fingerprint is the one you entered, checked on this device. Continue only if that fingerprint came from them directly rather than from anything the server told you.</div></div>`;
  $("invite-confirm").innerHTML = `
    <div class="card" style="margin-top:14px" role="region" aria-label="Confirm fingerprint">
      <h3 class="card-title">${icon("key")} Confirm ${esc(info.email)}'s key</h3>
      ${compare}
      ${guidance}
      <div class="actions">
        ${changed
          ? `<button type="button" class="btn danger solid" id="btn-invite-confirm">New fingerprint confirmed, invite anyway</button>`
          : `<button type="button" class="btn primary" id="btn-invite-confirm">${icon("check")} Fingerprint matches, invite</button>`}
        <button type="button" class="btn" id="btn-invite-cancel">Cancel</button>
      </div>
    </div>`;
  $("btn-invite-cancel").onclick = () => { $("invite-confirm").innerHTML = ""; $("invite-email").focus(); };
  $("btn-invite-confirm").onclick = async () => {
    // The whole key goes back, not the fingerprint: the command compares bytes.
    const args = { id, email: info.email, message: $("invite-message").value.trim(), confirmedPublicKey: info.public_key };
    if (await act("invite", args, `Invited ${info.email}`, $("btn-invite-confirm"))) loadSharing(id);
  };
  // The lookup already required this fingerprint, so there is nothing left to
  // retype here; a changed key still defaults to Cancel.
  (changed ? $("btn-invite-cancel") : $("btn-invite-confirm")).focus();
}

// ----- changing the passphrase -----------------------------------------------

/// Everything the passphrase derives is replaced at once, so this is a single
/// form and a single request. For an account that signs in with Google the
/// passphrase is not the login, and the copy says so rather than implying the
/// Google password is involved.
function renderPassphraseForm() {
  closeAccountSheet({ restoreFocus: false });
  state.selected = null;
  state.editing = true;
  renderList();
  showDetailScreen();
  const isLogin = state.user?.password_login !== false;
  $("detail").innerHTML = `
    <form class="card" id="passphrase-form" novalidate aria-labelledby="passphrase-title">
      <h2 id="passphrase-title" class="card-title">${icon("lock")} Change passphrase</h2>
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
    setError("pp-error", error);
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
  clearReveals();
  state.secrets = []; state.selected = null; state.editing = false; state.user = null;
  $("list").innerHTML = ""; $("detail").innerHTML = ""; $("invites").innerHTML = ""; $("invites-banner").innerHTML = "";
  closeAccountSheet({ restoreFocus: false });
  setError("main-error", "");
  $("app").classList.add("hidden");
  $("auth").classList.remove("hidden");
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

function renderForm(existing) {
  state.editing = true;
  clearReveals();
  state.formFields = Fields.formFieldsFrom(existing);
  updateMobileTitle();
  $("main").classList.add("has-selection");
  const s = existing || { name: "", username: "", url: "", notes: "" };
  $("detail").innerHTML = `
    <form class="card form" id="secret-form" novalidate aria-labelledby="form-title">
      <h2 id="form-title" class="card-title pane-title">${existing ? icon("edit") : icon("plus")} ${existing ? "Edit secret" : "New secret"}</h2>
      <p class="card-lead">${existing ? "Changes are re-encrypted on this device before they are saved." : "Everything except the name is encrypted on this device before it is saved."}</p>
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
        <div class="input-row">
          <input id="f-password" type="password" autocomplete="new-password" placeholder="${existing ? "Unchanged" : ""}">
          <button type="button" class="icon-btn bordered" id="btn-toggle-pw" aria-label="Show password" aria-pressed="false" title="Show password">${icon("eye")}</button>
          <button type="button" class="btn" id="btn-generate" title="Generate a strong ${UI.generatedPasswordLength}-character password">${icon("wand")} Generate</button>
        </div>
        <p class="hint">${existing ? "Leave blank to keep the current password." : `Generate makes a random ${UI.generatedPasswordLength}-character password with symbols.`}</p>
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
        <span class="field-label">Extra details <span class="label-note">(optional)</span></span>
        <p class="hint">Anything else worth keeping here: a PIN, a recovery code, an account number. Tick <strong>Hide</strong> to mask a value and have it cleared from the clipboard, the same as the password.</p>
        <div id="custom-fields"></div>
        <button type="button" class="btn" id="btn-add-field">${icon("plus")} Add field</button>
      </div>
      <div class="error" id="form-error" role="alert"></div>
      <div class="actions form-actions">
        <button type="submit" class="btn primary" id="btn-save">${existing ? "Save changes" : "Create secret"}</button>
        <button type="button" class="btn" id="btn-cancel">Cancel</button>
        <span class="muted small">Esc to cancel</span>
      </div>
    </form>`;

  const form = $("secret-form");
  const cancel = () => { state.editing = false; renderDetail(); };
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
  renderFormFields();
  form.addEventListener("keydown", (event) => { if (event.key === "Escape") { event.preventDefault(); cancel(); } });
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
      rows[needValues[0].index]?.querySelector(".cf-value")?.focus();
      return;
    }

    // Catch a missing label here too, so the row is named and focused rather
    // than coming back as a generic error after a round trip through
    // encryption. A new row has no stored name to fall back on.
    const unlabelled = state.formFields.findIndex((field) => field.label.trim() === "" && (field.kept || field.value));
    if (unlabelled !== -1) {
      setError("form-error", "Give every extra field a label, or remove it.");
      $("custom-fields").querySelectorAll(".custom-field")[unlabelled]?.querySelector(".cf-label")?.focus();
      return;
    }
    if (!existing && !entry.password) { setError("form-error", "Enter a password or generate one."); $("f-password").focus(); return; }
    setBusy($("btn-save"), true, "Saving…");
    try {
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
      await refresh();
      renderDetail();
    } catch (error) {
      setError("form-error", error);
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
$("btn-show-token").onclick = () => showTokenField(true);
$("btn-google").onclick = startGoogleSignIn;
$("google-form").onsubmit = submitGooglePassphrase;
$("btn-google-cancel").onclick = cancelGoogleSignIn;
$("btn-google-toggle-pw").onclick = () => togglePasswordInput($("google-password"), $("btn-google-toggle-pw"));
$("btn-link-google").onclick = () => linkGoogle();
$("btn-change-passphrase").onclick = () => renderPassphraseForm();
// The button belongs to whichever server is in the box, so re-ask when it
// settles rather than on every keystroke.
$("server").onchange = () => refreshCapabilities();
$("server").onblur = () => refreshCapabilities();
$("btn-logout").onclick = () => logout().catch((error) => setError("main-error", error));
$("btn-refresh").onclick = () => { closeAccountSheet({ restoreFocus: false }); refresh(); };
$("btn-back").onclick = goBack;
$("btn-account").onclick = () => ($("app").classList.contains("account-open") ? closeAccountSheet() : openAccountSheet());
$("account-backdrop").onclick = () => closeAccountSheet();
$("btn-new").onclick = startNew;
$("btn-fingerprint").onclick = () => copyText($("fingerprint").textContent, "Your key fingerprint");
$("filter").oninput = renderList;
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
applyTheme(recall(THEME_KEY) || "system");

$("server").value = recall("server") || DEFAULT_SERVER;
$("server").placeholder = DEFAULT_SERVER;
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
  }))
  // Served rather than written into the markup, so the floor is stated in
  // one place: the crate that enforces it.
  .then(() => {
    const hint = $("password-hint");
    if (hint) hint.textContent = `At least ${UI.minPasswordLength} characters. There is no password reset.`;
  })
  .catch(() => { /* the defaults above match the crates today */ });
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
