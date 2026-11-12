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
  function shortcutLabel(platform, key) {
    if (typeof key !== "string" || !key) {
      throw new TypeError("shortcutLabel needs the key the shortcut is pressed with");
    }
    // Upper case in both spellings: a shortcut is written ⌘N, not ⌘n, and
    // aria-keyshortcuts takes the key's own name, which is "N".
    const named = key.toUpperCase();
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
    return `${modifier}+${key.toUpperCase()}`;
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

  return { esc, serverSummaryText, listGroupHtml, tokenPrompt, PLATFORMS, platformFrom, resolvePlatform, placementFor, shortcutLabel, shortcutKeys, namesShortcuts };
});
