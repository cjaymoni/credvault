// Pure presentation logic, kept out of app.js so it can be exercised without
// a DOM. Loaded as an ordinary script by the app and required directly by the
// tests in ../ui-tests/. Same shape as fields.js, for the same reason.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Screens = factory();
})(typeof self !== "undefined" ? self : globalThis, function () {
  /// Everything interpolated into markup goes through this first. It lives
  /// here rather than in app.js so the builders below cannot be written
  /// without it in reach, and so it is covered by the same tests they are.
  const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  function esc(text) {
    return String(text ?? "").replace(/[&<>"']/g, (c) => ESCAPES[c]);
  }

  /// What the phone's collapsed server line shows.
  ///
  /// It stands in for the field that says where the login credential is about
  /// to be sent, so it has to name the host that will actually receive it.
  /// Two things follow:
  ///
  /// - The empty-field fallback is mirrored, because `authenticate()` submits
  ///   `value.trim() || DEFAULT_SERVER` and the line must not disagree with it.
  /// - The host is shown rather than the whole URL. The line is one row on a
  ///   phone, so a long URL would be cut off at its end — which is the end
  ///   that carries the registrable domain. `https://my-bank.example.com.evil
  ///   .tld/…` truncated from the right reads as the bank. A host never
  ///   needs truncating, and `URL.host` reports the real authority even when
  ///   the URL carries userinfo meant to disguise it.
  ///
  /// Anything that is not a URL yet is shown verbatim: it is what the user is
  /// typing, and the full field is one tap away in either case.
  ///
  /// A host long enough to overrun the line is cut from its *front*, never its
  /// end. CSS ellipsis does the opposite, and the end is where the registrable
  /// domain sits: `my-bank-example-com-secure-login.evil.tld` cut the usual way
  /// reads as the bank, cut this way reads as `…secure-login.evil.tld`.
  const MAX_SERVER_SUMMARY_CHARS = 30;
  /// Below this the ellipsis costs more than it saves, and at 1 the slice
  /// below would wrap around to the whole string.
  const MIN_SERVER_SUMMARY_CHARS = 2;

  /// `fallback` is what the form itself falls back to and is required: a line
  /// that quietly went blank would be worse than a loud failure, because the
  /// blank would be read as "no server" rather than "unknown server".
  function serverSummaryText(rawValue, fallback, maxChars = MAX_SERVER_SUMMARY_CHARS) {
    if (typeof fallback !== "string" || !fallback) {
      throw new TypeError("serverSummaryText needs the fallback the form submits for an empty field");
    }
    // Math.max(n, NaN) is NaN, which would compare false and hand back the
    // whole host unclamped. A budget that is not a number is not a budget.
    if (!Number.isFinite(maxChars)) {
      throw new TypeError("serverSummaryText needs a numeric character budget");
    }
    const limit = Math.max(MIN_SERVER_SUMMARY_CHARS, maxChars);
    const value = String(rawValue ?? "").trim() || fallback;
    let shown;
    try {
      shown = new URL(value).host || value;
    } catch {
      shown = value;
    }
    return shown.length > limit ? `\u2026${shown.slice(-(limit - 1))}` : shown;
  }

  /// Which address a sign-in actually submits.
  ///
  /// `allowCustom` off pins every sign-in to `fallback`, whatever is in the
  /// field: the field is not editable then, but a value an earlier build
  /// remembered would otherwise still be read out of it and a credential sent
  /// somewhere the person can no longer see. See ALLOW_CUSTOM_SERVER in
  /// app.js for why it is off.
  ///
  /// `fallback` is required for the same reason it is in serverSummaryText():
  /// submitting a blank address is worse than failing loudly.
  function serverUrlFor(allowCustom, rawValue, fallback) {
    if (typeof fallback !== "string" || !fallback) {
      throw new TypeError("serverUrlFor needs the address the form falls back to");
    }
    if (!allowCustom) return fallback;
    return String(rawValue ?? "").trim() || fallback;
  }

  /// The address this install was last signed in to, when it is not the one
  /// the app now forces. Null when there is nothing to say.
  ///
  /// `auth_hash` mixes the server's address into the credential, so an
  /// account made on someone's own host cannot sign in to `fallback` at all,
  /// and the rejection reads as a wrong passphrase. The address is forced
  /// either way -- this only decides whether the screen says so first.
  ///
  /// Compared loosely -- case, trailing slash, whitespace -- because this
  /// decides whether to warn, and warning once too often is much cheaper
  /// than locking somebody out of their vault. A superseded default is
  /// reported too: signing in to `fallback` would have worked for it (the
  /// Rust side retries those bindings), so the notice is redundant there
  /// rather than wrong.
  function strandedAddress(remembered, fallback) {
    if (typeof fallback !== "string" || !fallback) {
      throw new TypeError("strandedAddress needs the address the app now signs in to");
    }
    const canonical = (value) => {
      const text = String(value ?? "").trim().replace(/\/+$/, "");
      if (!text) return "";
      try {
        const url = new URL(text);
        return `${url.protocol}//${url.host}${url.pathname}`.replace(/\/+$/, "").toLowerCase();
      } catch {
        return text.toLowerCase();
      }
    };
    const was = canonical(remembered);
    return was && was !== canonical(fallback) ? String(remembered).trim() : null;
  }

  /// Whether the editor's "More details" section starts open.
  ///
  /// Creating, it is closed: a name, a username and a password are what a
  /// secret usually is, and the rest is a second screenful that most people
  /// scroll past. Editing is the opposite case -- a project, a URL, notes or
  /// an extra field that someone already filled in must not be hidden behind
  /// a toggle they have no reason to open, because a form that does not show
  /// what it holds is a form that loses it.
  function hasMoreDetails(existing) {
    if (!existing) return false;
    const filled = (value) => String(value ?? "").trim() !== "";
    return Boolean(existing.project) ||
      filled(existing.url) ||
      filled(existing.notes) ||
      (Array.isArray(existing.fields) && existing.fields.length > 0);
  }

  /// Whether a keystroke is "save this form".
  ///
  /// Either modifier counts on every platform, the way the vault's other
  /// shortcuts are handled: the interface names one of them per platform,
  /// but refusing the other buys nothing and surprises anyone on a keyboard
  /// that is not their machine's own. Alt and Shift are excluded so a
  /// combination meaning something else does not also save.
  ///
  /// It exists because the form holds a textarea, where Enter is a newline
  /// and so cannot be submit. ⌘↩ is what a Mac form does there.
  function isSaveShortcut(event) {
    const { key, metaKey, ctrlKey, altKey, shiftKey } = event ?? {};
    if (key !== "Enter") return false;
    if (altKey || shiftKey) return false;
    return Boolean(metaKey || ctrlKey);
  }

  /// One section of the secrets list: an optional heading, then the rows.
  ///
  /// `#list` is a listbox and the rows are its options, so the wrapper the
  /// phone layout draws as one inset card must not come between them in the
  /// accessibility tree. An untitled wrapper is presentational; a titled one
  /// is a group, and its label already carries the heading's words, so the
  /// heading itself is hidden to avoid announcing them twice.
  /// `title` is escaped here rather than by the caller: it reaches both text
  /// and an attribute, and a section named after anything a user controls --
  /// a folder, a team, a tag -- would otherwise be an injection point. The
  /// rows are already-built markup and are inserted as they are.
  function listGroupHtml(title, itemsHtml) {
    if (!itemsHtml) return "";
    const safeTitle = esc(title);
    const heading = title ? `<div class="list-heading" aria-hidden="true">${safeTitle}</div>` : "";
    const wrapper = title ? `role="group" aria-label="${safeTitle}"` : `role="presentation"`;
    return `${heading}<div class="list-group" ${wrapper}>${itemsHtml}</div>`;
  }

  /// The heading unfiled secrets sit under, and the one for secrets other
  /// people own. Both come last, in that order: your own filing first, then
  /// the leftovers, then what is not yours.
  const UNFILED_TITLE = "Unfiled";
  const SHARED_TITLE = "Shared with me";
  /// What the owned secrets are called when no project is in play at all.
  ///
  /// This is the heading the list used before projects existed, and someone
  /// who never makes a project should not notice they arrived: "Unfiled" is
  /// a fair name for the leftovers beneath Perspectiv and Home, but a poor
  /// one for a whole vault, because it describes an absence the person has
  /// not opted into.
  const MINE_TITLE = "Mine";

  /// Split the visible secrets into the sections the list draws, in order.
  ///
  /// Returns `[{ title, secrets }]`, where `title` is `null` only in the one
  /// case the list has nothing to label: everything is owned and unfiled.
  /// A section is omitted when it is empty, so a vault with no shared
  /// secrets draws no "Shared with me" heading over nothing.
  ///
  /// Owned secrets are grouped by project *id*, never by name. Two different
  /// owners may both have a project called Perspectiv, and grouping by what
  /// is written on the heading would file their secrets together as though
  /// they were one thing. Shared secrets are not grouped by project at all,
  /// for the same reason and a stronger one: a member is given a name and no
  /// id (see `SecretProject` in the Rust), so there is nothing to group on
  /// that would mean the same thing twice.
  ///
  /// `projects` is the account's own list, used for the order the headings
  /// appear in and so that a project whose secrets are all filtered out does
  /// not jump position. Projects with nothing visible under them are left
  /// out: an empty heading in the vault says a group exists and has nothing
  /// in it, which is a question the Projects panel answers properly.
  function listSections(secrets, projects = []) {
    const rows = Array.isArray(secrets) ? secrets : [];
    const owned = rows.filter((s) => s.is_owner);
    const shared = rows.filter((s) => !s.is_owner);

    // Own key lookup only: a project named "__proto__" must not reach
    // Object's, and a secret naming an id nobody owns must not invent one.
    const byProject = new Map();
    for (const secret of owned) {
      const id = secret.project && secret.project.id != null ? secret.project.id : null;
      if (!byProject.has(id)) byProject.set(id, []);
      byProject.get(id).push(secret);
    }

    const sections = [];
    for (const project of Array.isArray(projects) ? projects : []) {
      const items = byProject.get(project.id);
      if (items && items.length) sections.push({ title: project.name, secrets: items });
      byProject.delete(project.id);
    }
    // Anything filed under a project the list does not know about -- renamed
    // or deleted on another device since this list was fetched. Its own name
    // is the best label available, and dropping the rows would hide secrets.
    for (const [id, items] of byProject) {
      if (id === null) continue;
      sections.push({ title: items[0].project?.name ?? UNFILED_TITLE, secrets: items });
    }
    const unfiled = byProject.get(null) ?? [];
    // The one case with nothing to label: no projects in play and nothing
    // shared, so a heading would only name the whole list.
    if (unfiled.length && !sections.length && !shared.length) {
      return [{ title: null, secrets: unfiled }];
    }
    if (unfiled.length) {
      sections.push({ title: sections.length ? UNFILED_TITLE : MINE_TITLE, secrets: unfiled });
    }
    if (shared.length) sections.push({ title: SHARED_TITLE, secrets: shared });
    return sections;
  }

  /// Whether what someone typed into the delete confirmation names
  /// `projectName`.
  ///
  /// The whole string, compared exactly, with only the ends trimmed -- which
  /// is the one liberty the server itself takes, since `validate_project_name`
  /// trims before storing, so a trailing space was never part of the name.
  ///
  /// Nothing else is forgiven, and an earlier version that forgave more was
  /// wrong twice. It lower-cased, on the grounds that the unique index is
  /// `NOCASE` so no two projects differ only by case: true of A-Z only, so
  /// `Café` and `CAFÉ` can both exist while JavaScript folds both to `café`.
  /// It also collapsed runs of whitespace, on the grounds that `a  b` and
  /// `a b` cannot both exist: they can, because nothing collapses interior
  /// spaces on the way in. Either slip accepts the name of a *different*
  /// project, which is exactly the mistake -- clicking the wrong row -- that
  /// typing the name is there to catch.
  ///
  /// Both sides are trimmed by the rule the *server* uses, which is not the
  /// rule `String.prototype.trim` uses. Rust's `str::trim` strips characters
  /// with the Unicode White_Space property; JavaScript's also strips U+FEFF,
  /// which has no such property. That one difference matters twice, in
  /// opposite directions, so neither side may use the built-in.
  ///
  /// Trimming the stored name with the built-in would let `Perspectiv` match
  /// a stored `\u{feff}Perspectiv`. Those draw identically in the list, so it
  /// is a false accept on a row the user did not click -- exactly what typing
  /// the name is here to prevent.
  ///
  /// Trimming only the typed side with the built-in refuses the other
  /// direction too: nothing typable survives to match a stored name that
  /// begins with U+FEFF, leaving that project undeletable. Using the server's
  /// own rule on both sides keeps the false accept closed and keeps every
  /// stored name reachable by typing it.
  ///
  /// Both sides are normalised to NFC, because a precomposed and a decomposed
  /// `Café` are different strings that draw the same glyphs. Without it a
  /// decomposed name could never be typed, since most keyboards emit NFC, and
  /// the dialog would refuse forever with no way forward. Normalising is the
  /// one liberty that cannot accept a different project: NFC is a function,
  /// so two names that differ before it differ after it.
  /// `\s` is no use here: JavaScript's character class includes U+FEFF, which
  /// is the whole character this has to leave alone. `\p{White_Space}` is the
  /// Unicode property Rust's `trim` reads, and does not.
  const SERVER_TRIM = /^\p{White_Space}+|\p{White_Space}+$/gu;
  const trimAsStored = (text) => String(text ?? "").replace(SERVER_TRIM, "");

  function namesProject(typed, projectName) {
    const name = trimAsStored(projectName).normalize("NFC");
    return name !== "" && trimAsStored(typed).normalize("NFC") === name;
  }

  /// Whether a refresh should drop a phone back to the vault list.
  ///
  /// Pure, and here rather than in app.js, because it is four flags and a
  /// conjunction that has already been wrong once: the Projects panel was
  /// missing from it, so every create, rename or delete bounced a phone user
  /// out of the panel they were working in.
  function shouldPopToList({ selected = null, editing = false, showingProjects = false, inviteCount = 0 } = {}) {
    return selected === null && !editing && !showingProjects && inviteCount === 0;
  }

  /// What a server with no token asks for, and what every form that is not
  /// creating an account shows.
  const NO_TOKEN_PROMPT = Object.freeze({ field: false, disclosure: false, required: false });

  /// What the create-account form should do about the registration token.
  ///
  /// There are three answers, not two. `serverRequires` is what the server
  /// said about itself -- `true`, `false`, or neither when it could not be
  /// asked, which is the case before the first capabilities fetch lands and
  /// whenever the address in the box does not answer. The third case is why
  /// the disclosure button ("Does the server require a registration token?")
  /// exists at all: it is the question to ask when nobody knows the answer.
  /// Once the server has answered there is nothing to ask, so the button goes
  /// and the field either stands open and required or is not there.
  ///
  /// `unfolded` is the user having opened the field themselves. It keeps the
  /// field open across a re-render, including the one that follows a failed
  /// submit on a server whose capabilities said no token was needed -- stale
  /// or wrong, but recoverable as long as the field does not snap shut.
  ///
  /// `required` is what makes the difference the user sees: it lets the form
  /// refuse an empty token in its own words instead of sending a blank one
  /// and reading back the server's 403.
  function tokenPrompt(isCreating, serverRequires, unfolded = false) {
    if (!isCreating) return NO_TOKEN_PROMPT;
    if (serverRequires === true) return Object.freeze({ field: true, disclosure: false, required: true });
    const field = Boolean(unfolded);
    return Object.freeze({ field, disclosure: serverRequires !== false && !field, required: false });
  }

  /// The platforms the interface has a native look for. Anything else gets
  /// the Linux look, the most generic of the five.
  const PLATFORMS = ["macos", "windows", "linux", "ios", "android"];
  const FALLBACK_PLATFORM = "linux";
  /// iPadOS reports itself as a Mac; a Mac has no touch points, an iPad has 5.
  const IPAD_MIN_TOUCH_POINTS = 2;

  /// Which platform the app is running on, from the webview's user agent.
  ///
  /// The answer only picks a look: nothing security-relevant depends on it,
  /// so a spoofed or unusual user agent costs at most the wrong styling.
  /// Order matters: Android user agents also say "Linux", and iOS ones also
  /// say "Mac OS X".
  function platformFrom(userAgent, maxTouchPoints = 0) {
    const ua = String(userAgent ?? "");
    if (/Android/i.test(ua)) return "android";
    if (/iPhone|iPad|iPod/i.test(ua)) return "ios";
    if (/Macintosh|Mac OS X/i.test(ua)) return maxTouchPoints >= IPAD_MIN_TOUCH_POINTS ? "ios" : "macos";
    if (/Windows/i.test(ua)) return "windows";
    if (/Linux|X11|CrOS/i.test(ua)) return "linux";
    return FALLBACK_PLATFORM;
  }

  /// A platform named explicitly (a `?platform=` override used when
  /// previewing the interface in a browser) wins when it is one we know.
  function resolvePlatform(override, userAgent, maxTouchPoints) {
    return PLATFORMS.includes(override) ? override : platformFrom(userAgent, maxTouchPoints);
  }

  /// The platforms whose own apps print ⌘ rather than Ctrl.
  const COMMAND_KEY_PLATFORMS = ["macos", "ios"];

  /// How to write the shortcut for `key` on `platform`, e.g. `⌘N` or `Ctrl+N`.
  ///
  /// The handler accepts `metaKey` or `ctrlKey` on every platform, so both
  /// shortcuts always work and this only picks which one to *name*. Naming
  /// both, as the interface used to, puts a key no Mac has in front of a Mac
  /// user and vice versa.
  ///
  /// An unknown platform gets Ctrl, matching the Linux look it is given.
  /// A missing key is a bug rather than a label, and says so: printing
  /// "⌘undefined" in a tooltip would be worse than failing here.
  /// A key as both spellings want it written.
  ///
  /// A single character is upper-cased, because a shortcut is ⌘N and
  /// `aria-keyshortcuts` names that key "N". A key with a name of its own --
  /// Enter, Escape, Tab -- is left alone: the spec's key set spells it
  /// "Enter", and "ENTER" is not a key any of it names.
  function namedKey(key) {
    return key.length === 1 ? key.toUpperCase() : key;
  }

  function shortcutLabel(platform, key) {
    if (typeof key !== "string" || !key) {
      throw new TypeError("shortcutLabel needs the key the shortcut is pressed with");
    }
    // Upper case in both spellings: a shortcut is written ⌘N, not ⌘n, and
    // aria-keyshortcuts takes the key's own name, which is "N".
    const named = namedKey(key);
    return COMMAND_KEY_PLATFORMS.includes(platform) ? `⌘${named}` : `Ctrl+${named}`;
  }

  /// The same shortcut in the spelling `aria-keyshortcuts` takes, e.g.
  /// `Meta+N`. Those names come from the spec's key set, which has no ⌘, so
  /// this cannot reuse shortcutLabel() -- but both must agree on which
  /// platforms press Meta, so both read COMMAND_KEY_PLATFORMS.
  ///
  /// The handler accepts either modifier everywhere; this declares the one
  /// the interface names, which is what a screen reader should read out.
  function shortcutKeys(platform, key) {
    if (typeof key !== "string" || !key) {
      throw new TypeError("shortcutKeys needs the key the shortcut is pressed with");
    }
    const modifier = COMMAND_KEY_PLATFORMS.includes(platform) ? "Meta" : "Control";
    return `${modifier}+${namedKey(key)}`;
  }

  /// The platforms whose own apps print shortcuts in the interface at all.
  const SHORTCUT_NAMING_PLATFORMS = ["macos", "windows", "linux"];

  /// Whether `platform` is one that names shortcuts in its interface.
  ///
  /// This is a convention, not a claim about the hardware: an iPad with a
  /// keyboard attached can press ⌘N perfectly well, and the handler takes it,
  /// but iOS and Android apps do not print shortcuts on their controls and
  /// neither does this one. Naming one costs more than the tooltip, because
  /// the new-secret button's own label is hidden on three of the five looks,
  /// which leaves `title` as the whole of what a screen reader reads out.
  function namesShortcuts(platform) {
    return SHORTCUT_NAMING_PLATFORMS.includes(platform);
  }

  /// The controls that move between platforms, and the slot each one goes to.
  ///
  /// Every control exists once in the page and is moved into its slot at
  /// startup, so DOM order (and therefore Tab order and what a screen reader
  /// reads next) matches where the control is drawn. Slots are elements with
  /// a matching `data-slot` attribute.
  const PLACEMENT = {
    macos: { search: "toolbar-end", newSecret: "toolbar-actions", refresh: "toolbar-actions", account: "sidebar-foot", invites: "sidebar-top" },
    windows: { search: "toolbar-center", newSecret: "pane-actions", refresh: "pane-actions", account: "toolbar-end", invites: "sidebar-top" },
    linux: { search: "sidebar-search", newSecret: "pane-head-start", refresh: "account-menu", account: "pane-head-end", invites: "content-top" },
    ios: { search: "sidebar-search", newSecret: "bottombar-end", refresh: "account-menu", account: "pane-head-end", invites: "sidebar-top" },
    android: { search: "sidebar-search", newSecret: "fab", refresh: "account-menu", account: "sidebar-search", invites: "sidebar-top" },
  };
  const PLACED_CONTROLS = ["search", "newSecret", "refresh", "account", "invites"];

  /// Where each moving control goes on `platform`, as `[control, slot]` pairs
  /// in the order they should be appended.
  function placementFor(platform) {
    // Own keys only: "toString" or "__proto__" must not find Object's.
    const table = Object.hasOwn(PLACEMENT, String(platform)) ? PLACEMENT[platform] : null;
    if (!table) throw new TypeError(`no placement for platform ${JSON.stringify(platform)}`);
    return PLACED_CONTROLS.map((control) => [control, table[control]]);
  }

  /// What the account panel shows for the build that is running.
  ///
  /// `null` when there is nothing to show, which the caller answers by
  /// leaving the line hidden rather than drawing the word "Version" with a
  /// blank after it. The string comes from our own binary and is not user
  /// input; the guard is there for the one case that can really happen, which
  /// is the command not answering at all.
  ///
  /// The number is given on its own, unprefixed by a `v`, because it is read
  /// out loud and typed into bug reports as often as it is read.
  function appVersionLabel(version) {
    const shown = String(version ?? "").trim();
    return shown ? `Version ${shown}` : null;
  }

  return { esc, serverSummaryText, serverUrlFor, strandedAddress, hasMoreDetails, isSaveShortcut, appVersionLabel, listGroupHtml, listSections, namesProject, shouldPopToList, UNFILED_TITLE, SHARED_TITLE, MINE_TITLE, tokenPrompt, PLATFORMS, platformFrom, resolvePlatform, placementFor, shortcutLabel, shortcutKeys, namesShortcuts };
});
