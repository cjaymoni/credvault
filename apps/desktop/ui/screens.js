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

  return { esc, serverSummaryText, listGroupHtml };
});
